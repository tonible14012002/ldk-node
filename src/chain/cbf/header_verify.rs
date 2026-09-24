// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Header consensus checks for a client that takes its headers from a single, untrusted
//! [`FilterSource`](crate::chain::cbf::source::FilterSource).
//!
//! A header is accepted only when it links to the one below it, carries the proof of work its
//! own target claims, claims exactly the target the network rules require at its height, and
//! has a timestamp above the median of the eleven before it and not too far in the future.
//! These are Bitcoin Core's `ContextualCheckBlockHeader` and `GetNextWorkRequired`, restricted
//! to what a header chain can show; checkpoints and the minimum-chain-work floor are left to the
//! resume anchor, which comes from this node's own persisted state and is trusted.

use std::fmt;

use bitcoin::block::Header;
use bitcoin::consensus::Params;
use bitcoin::{BlockHash, CompactTarget, Network};

/// How many preceding timestamps the median-time-past rule looks at.
pub(crate) const MEDIAN_TIME_SPAN: u32 = 11;

/// How far past this node's clock a header's timestamp may be (Core's `MAX_FUTURE_BLOCK_TIME`).
pub(crate) const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 2 * 60 * 60;

/// BIP94: on testnet4 the first block of a retarget period may not be timestamped more than
/// this many seconds before the block below it.
const BIP94_MAX_TIMEWARP_SECS: u32 = 600;

/// Which header check failed, and where. Named in the error log, so the operator can tell a
/// broken source from a lying one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeaderCheck {
	/// The header does not build on the block below it.
	Link { height: u32, expected_prev: BlockHash, got_prev: BlockHash },
	/// The header's hash does not meet the target it claims.
	ProofOfWork { height: u32 },
	/// The header claims a target other than the one the network rules require.
	Difficulty { height: u32, expected: CompactTarget, got: CompactTarget },
	/// The header's timestamp is not above the median of the eleven before it.
	MedianTimePast { height: u32, time: u32, median: u32 },
	/// The header's timestamp is more than two hours past this node's clock.
	FutureTime { height: u32, time: u32 },
	/// BIP94 (testnet4): a retarget block timestamped too far before its parent.
	Timewarp { height: u32 },
	/// A header the rules need at `needed` is not held — a bug in how much of the chain the
	/// client keeps, never the source's fault.
	MissingAncestor { height: u32, needed: u32 },
}

impl HeaderCheck {
	/// The name of the check, for logs.
	pub(crate) fn name(&self) -> &'static str {
		match self {
			Self::Link { .. } => "header link (prev_blockhash)",
			Self::ProofOfWork { .. } => "proof of work",
			Self::Difficulty { .. } => "difficulty (required target)",
			Self::MedianTimePast { .. } => "median time past",
			Self::FutureTime { .. } => "future timestamp",
			Self::Timewarp { .. } => "BIP94 timewarp",
			Self::MissingAncestor { .. } => "ancestor held for verification",
		}
	}
}

impl fmt::Display for HeaderCheck {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Link { height, expected_prev, got_prev } => write!(
				f,
				"{} failed at height {}: builds on {}, expected {}",
				self.name(),
				height,
				got_prev,
				expected_prev
			),
			Self::ProofOfWork { height } => {
				write!(f, "{} failed at height {}", self.name(), height)
			},
			Self::Difficulty { height, expected, got } => write!(
				f,
				"{} failed at height {}: bits {:#010x}, required {:#010x}",
				self.name(),
				height,
				got.to_consensus(),
				expected.to_consensus()
			),
			Self::MedianTimePast { height, time, median } => write!(
				f,
				"{} failed at height {}: time {} is not above the median {}",
				self.name(),
				height,
				time,
				median
			),
			Self::FutureTime { height, time } => write!(
				f,
				"{} failed at height {}: time {} is more than {}s ahead of this node's clock",
				self.name(),
				height,
				time,
				MAX_FUTURE_BLOCK_TIME_SECS
			),
			Self::Timewarp { height } => write!(f, "{} failed at height {}", self.name(), height),
			Self::MissingAncestor { height, needed } => write!(
				f,
				"{} failed at height {}: the header at {} is not held",
				self.name(),
				height,
				needed
			),
		}
	}
}

/// The retarget interval of `network`, in blocks (2016 everywhere).
pub(crate) fn retarget_interval(network: Network) -> u32 {
	Params::new(network).difficulty_adjustment_interval() as u32
}

/// The compact target a header at `height` must carry, per Bitcoin Core's
/// `GetNextWorkRequired`. `header` is the header being checked (its timestamp matters on the
/// networks that allow minimum-difficulty blocks); `ancestor` looks up a held header by height.
///
/// * Between retargets the target is the parent's — except on testnet3/testnet4/regtest, where
///   a block more than twenty minutes after its parent may drop to the proof-of-work limit, and
///   otherwise inherits the last target in the period that was not such a minimum-difficulty
///   block.
/// * At a retarget the parent's target is scaled by the period's actual timespan (last block's
///   time minus the first's), clamped to a factor of four, and capped at the limit. Regtest
///   never retargets. Testnet4 (BIP94) scales the period's *first* target instead of the last.
pub(crate) fn expected_bits<A>(
	network: Network, height: u32, header: &Header, ancestor: A,
) -> Result<CompactTarget, HeaderCheck>
where
	A: Fn(u32) -> Option<Header>,
{
	let params = Params::new(network);
	let interval = retarget_interval(network);
	let fetch =
		|needed: u32| ancestor(needed).ok_or(HeaderCheck::MissingAncestor { height, needed });
	let prev_height =
		height.checked_sub(1).ok_or(HeaderCheck::MissingAncestor { height, needed: 0 })?;
	let prev = fetch(prev_height)?;

	if height % interval != 0 {
		if params.allow_min_difficulty_blocks {
			let limit = params.max_attainable_target.to_compact_lossy();
			let spacing = params.pow_target_spacing as u32;
			if header.time > prev.time.saturating_add(2 * spacing) {
				return Ok(limit);
			}
			// The last target in this period that was not a minimum-difficulty exception.
			let mut walk_height = prev_height;
			let mut walk = prev;
			while walk_height % interval != 0 && walk.bits == limit {
				walk_height -= 1;
				walk = fetch(walk_height)?;
			}
			return Ok(walk.bits);
		}
		return Ok(prev.bits);
	}

	if params.no_pow_retargeting {
		return Ok(prev.bits);
	}
	let first = fetch(height - interval)?;
	// Core computes the timespan in signed arithmetic; a negative span clamps to the minimum,
	// which a zero does as well.
	let timespan = (i64::from(prev.time) - i64::from(first.time)).max(0) as u64;
	let base = if network == Network::Testnet4 { first.bits } else { prev.bits };
	Ok(CompactTarget::from_next_work_required(base, timespan, &params))
}

/// The median of the timestamps of up to [`MEDIAN_TIME_SPAN`] headers below `height`, or `None`
/// when none is held (a header right above genesis has only genesis).
pub(crate) fn median_time_past<A>(height: u32, ancestor: A) -> Option<u32>
where
	A: Fn(u32) -> Option<Header>,
{
	let lowest = height.saturating_sub(MEDIAN_TIME_SPAN);
	let mut times: Vec<u32> =
		(lowest..height).filter_map(|h| ancestor(h).map(|a| a.time)).collect();
	if times.is_empty() {
		return None;
	}
	times.sort_unstable();
	Some(times[times.len() / 2])
}

/// Every contextual check a header at `height` must pass to extend the chain whose block at
/// `height - 1` is `prev_hash`. Returns the header's hash.
///
/// `ancestor` must hold at least the eleven headers below `height` and, at or after a retarget
/// period's first block, the whole period so far; `now_secs` is this node's clock.
pub(crate) fn verify_header<A>(
	network: Network, height: u32, header: &Header, prev_hash: BlockHash, ancestor: A,
	now_secs: u64,
) -> Result<BlockHash, HeaderCheck>
where
	A: Fn(u32) -> Option<Header> + Copy,
{
	if header.prev_blockhash != prev_hash {
		return Err(HeaderCheck::Link {
			height,
			expected_prev: prev_hash,
			got_prev: header.prev_blockhash,
		});
	}

	let expected = expected_bits(network, height, header, ancestor)?;
	if header.bits != expected {
		return Err(HeaderCheck::Difficulty { height, expected, got: header.bits });
	}
	let block_hash =
		header.validate_pow(header.target()).map_err(|_| HeaderCheck::ProofOfWork { height })?;

	if let Some(median) = median_time_past(height, ancestor) {
		if header.time <= median {
			return Err(HeaderCheck::MedianTimePast { height, time: header.time, median });
		}
	}
	if u64::from(header.time) > now_secs.saturating_add(MAX_FUTURE_BLOCK_TIME_SECS) {
		return Err(HeaderCheck::FutureTime { height, time: header.time });
	}
	if network == Network::Testnet4 && height % retarget_interval(network) == 0 {
		let prev = ancestor(height - 1)
			.ok_or(HeaderCheck::MissingAncestor { height, needed: height - 1 })?;
		if header.time < prev.time.saturating_sub(BIP94_MAX_TIMEWARP_SECS) {
			return Err(HeaderCheck::Timewarp { height });
		}
	}
	Ok(block_hash)
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::collections::BTreeMap;

	use bitcoin::consensus::encode::deserialize_hex;
	use bitcoin::hashes::Hash;

	fn header(hex: &str) -> Header {
		deserialize_hex(hex).expect("a mainnet header")
	}

	// Mainnet, fetched from a public explorer and pinned here: the first and last headers of
	// the retarget period ending at 32255, and 32256 — the first difficulty *increase* in
	// Bitcoin's history.
	const MAINNET_30240: &str = "01000000e6bf7fd7f7790a63786faa878d0dc7fd8f2ff365732e45862c66075100000000700d342f65c7b6834dffb615358a1897016f0448913372190cbe3d27a4b53355b1512b4bffff001dbfb02519";
	const MAINNET_32255: &str = "0100000049c1daab3b6536ff1b2633c3a316a6e06ec287676cdeec4ca7baae6b00000000ac10b36b8f354b3353207de15940a5edbc05bb8364af75b4b5409e7823f2b48923ec3a4bffff001dbd5fa412";
	const MAINNET_32256: &str = "010000004b0360d834a330ec7833e30e1f523ee05a0793361e29a73421964f980000000027b64a020af294e903feed93768705336a20090612a043f47af462a2f5e5b564f8ee3a4b6ad8001dd3a43707";
	// The same for the period 864864..=866879 and the retarget at 866880 (a modern decrease).
	const MAINNET_864864: &str = "0000003a5f00e7df93f80524b5d0bca74ae81577d8e937ab4b9201000000000000000000e44b8cd6f5baf8ddaa1284a4a6235f5ade7015ec93e9f8c92206ff7e034fe0f4cf260667cd0e0317d37b1c47";
	const MAINNET_866879: &str = "00001022983c89b4d75d30477e574cfcaf078ed0e6757e4ecfd400000000000000000000af29e2d462f963e3fa4748a12ea2cc29cc8429db77e15db3903566bb49e9cbc0e2e81767cd0e03176f0ce81f";
	const MAINNET_866880: &str = "00c06d33abfd7611d95588541b36cf913627c5e05fc8d9ec7d7c00000000000000000000437f827366461f1e5e8253ca36ae6fb3c5bb8b023d9bfb68eafb3991d7bb3e394de9176728f102177a39728a";

	fn assert_retarget(first_height: u32, first: &str, last: &str, next: &str) {
		let (first, last, next) = (header(first), header(last), header(next));
		let next_height = first_height + 2016;
		let held: BTreeMap<u32, Header> =
			[(first_height, first), (next_height - 1, last)].into_iter().collect();
		let ancestor = |h: u32| held.get(&h).copied();

		assert_eq!(next.prev_blockhash, last.block_hash(), "the pinned headers are consecutive");
		let expected = expected_bits(Network::Bitcoin, next_height, &next, ancestor).unwrap();
		assert_eq!(expected, next.bits, "the computed retarget is the one the network made");
		assert_ne!(next.bits, last.bits, "a boundary where the difficulty actually changed");
		// And the header passes the checks that need only these two ancestors.
		assert!(next.validate_pow(next.target()).is_ok());
	}

	#[test]
	fn mainnet_retarget_matches_the_real_bits_at_32256() {
		assert_retarget(30240, MAINNET_30240, MAINNET_32255, MAINNET_32256);
	}

	#[test]
	fn mainnet_retarget_matches_the_real_bits_at_866880() {
		assert_retarget(864864, MAINNET_864864, MAINNET_866879, MAINNET_866880);
	}

	#[test]
	fn mainnet_between_retargets_the_target_is_the_parents() {
		let parent = header(MAINNET_866880);
		let held: BTreeMap<u32, Header> = [(866880, parent)].into_iter().collect();
		let mut next = parent;
		next.prev_blockhash = parent.block_hash();
		// A late timestamp buys nothing on mainnet: there is no minimum-difficulty rule.
		next.time = parent.time + 3600;
		assert_eq!(
			expected_bits(Network::Bitcoin, 866881, &next, |h| held.get(&h).copied()),
			Ok(parent.bits)
		);
	}

	#[test]
	fn a_retarget_without_the_period_start_is_a_missing_ancestor() {
		let last = header(MAINNET_866879);
		let next = header(MAINNET_866880);
		let held: BTreeMap<u32, Header> = [(866879, last)].into_iter().collect();
		assert_eq!(
			expected_bits(Network::Bitcoin, 866880, &next, |h| held.get(&h).copied()),
			Err(HeaderCheck::MissingAncestor { height: 866880, needed: 864864 })
		);
	}

	fn synthetic(time: u32, bits: u32) -> Header {
		Header {
			version: bitcoin::block::Version::TWO,
			prev_blockhash: BlockHash::all_zeros(),
			merkle_root: bitcoin::TxMerkleNode::all_zeros(),
			time,
			bits: CompactTarget::from_consensus(bits),
			nonce: 0,
		}
	}

	#[test]
	fn testnet_minimum_difficulty_blocks_follow_cores_rule() {
		const LIMIT: u32 = 0x1d00ffff;
		const REAL: u32 = 0x1c0fffff;
		// Period starting at 4032: 4032 real, 4033 real, 4034 a min-difficulty exception.
		let held: BTreeMap<u32, Header> = [
			(4032, synthetic(1_000_000, REAL)),
			(4033, synthetic(1_000_600, REAL)),
			(4034, synthetic(1_002_000, LIMIT)),
		]
		.into_iter()
		.collect();
		let ancestor = |h: u32| held.get(&h).copied();

		// More than twenty minutes after the parent: the limit.
		let late = synthetic(1_002_000 + 1_201, LIMIT);
		assert_eq!(
			expected_bits(Network::Testnet, 4035, &late, ancestor),
			Ok(CompactTarget::from_consensus(LIMIT))
		);
		// Otherwise the last non-exception target in the period, walking back over 4034.
		let prompt = synthetic(1_002_000 + 600, REAL);
		assert_eq!(
			expected_bits(Network::Testnet, 4035, &prompt, ancestor),
			Ok(CompactTarget::from_consensus(REAL))
		);
	}

	#[test]
	fn regtest_never_retargets() {
		const REGTEST: u32 = 0x207fffff;
		let held: BTreeMap<u32, Header> =
			[(0, synthetic(1, REGTEST)), (2015, synthetic(2, REGTEST))].into_iter().collect();
		let at_boundary = synthetic(3, REGTEST);
		assert_eq!(
			expected_bits(Network::Regtest, 2016, &at_boundary, |h| held.get(&h).copied()),
			Ok(CompactTarget::from_consensus(REGTEST))
		);
	}

	#[test]
	fn median_time_past_is_the_median_of_the_eleven_below() {
		let held: BTreeMap<u32, Header> =
			(0..20u32).map(|h| (h, synthetic(1000 + h * 10, 0x207fffff))).collect();
		// 9..=19 -> times 1090..=1190, median 1140.
		assert_eq!(median_time_past(20, |h| held.get(&h).copied()), Some(1140));
		// Near genesis fewer are held and the median of those counts.
		assert_eq!(median_time_past(1, |h| held.get(&h).copied()), Some(1000));
		assert_eq!(median_time_past(0, |h| held.get(&h).copied()), None);
	}
}
