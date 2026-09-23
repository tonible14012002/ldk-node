// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Wallet birthday resolution for a filter-driven chain source.
//!
//! A fresh CBF wallet has no server to ask "which block was the tip when this wallet was
//! created", and scanning every filter from genesis costs hours on a small device. Instead a
//! configured birthday height is rounded *down* to the nearest checkpoint compiled into the
//! crate, and the wallet, `ChannelManager` and sweeper are seeded there. Rounding down can only
//! extend the scanned range, never shrink it.

use bip157::HashCheckpoint;
use bitcoin::Network;

use lightning::chain::BestBlock;

use crate::logger::{log_info, LdkLogger, Logger};

/// Returns the highest checkpoint compiled into the `bip157` crate strictly below
/// `first_scan_height`, or `None` when the wallet should root at genesis.
///
/// Strictly below, because everything downstream — the initial BDK checkpoint, the listeners'
/// best block, kyoto's `ChainState::Checkpoint` — treats the anchor as already applied, and
/// scanning begins at the block after it. An anchor *at* `first_scan_height` would silently
/// skip that block's filters, losing a transaction confirmed exactly there.
///
/// Only compiled-in constants are used: CBF has no chain backend at build time, and consulting
/// a third-party tip oracle would reintroduce exactly the dependency this chain source removes.
/// Mainnet ships three such anchors — 481,823 (one block before SegWit activation), 709,631 (one
/// block before taproot activation) and 965,999 (see [`anchor_965_999`]); all other networks
/// resolve to `None`.
pub(crate) fn birthday_checkpoint(
	network: Network, first_scan_height: u32,
) -> Option<HashCheckpoint> {
	if network != Network::Bitcoin {
		return None;
	}
	mainnet_anchors()
		.into_iter()
		.map(|(cp, _)| cp)
		.filter(|cp| cp.height < first_scan_height)
		.max_by_key(|cp| cp.height)
}

/// Mainnet block 965,999 (mined 2026-09-08), the newest compiled birthday anchor: a wallet
/// born at block 966,000 or later scans nothing older than that, instead of falling through to
/// the taproot anchor and ~256,000 blocks of filters. The hash was cross-checked against three
/// independent explorers (mempool.space, blockstream.info, blockcypher.com) on 2026-09-09,
/// about 100 blocks below the tip, so no reorg can reach it. Add a newer entry to
/// [`mainnet_anchors`] when a later birthday is wanted; never edit an existing one — wallets
/// already anchored on it would latch divergence at the next start.
fn anchor_965_999() -> HashCheckpoint {
	let hash = "00000000000000000000dbb4d1e55ad22ed5b5a7d81d4c0fe992fceb8a5302d0"
		.parse::<bitcoin::BlockHash>()
		.expect("compiled block hash");
	HashCheckpoint::new(965_999, hash)
}

/// Every compiled mainnet birthday anchor, ascending, with the provenance label the startup
/// log prints beside it.
fn mainnet_anchors() -> [(HashCheckpoint, &'static str); 3] {
	[
		(HashCheckpoint::segwit_activation(), "bip157 segwit_activation constant"),
		(HashCheckpoint::taproot_activation(), "bip157 taproot_activation constant"),
		(anchor_965_999(), "ldk-node block 965,999 constant"),
	]
}

/// Resolves a configured wallet birthday height into the block the builder seeds a fresh
/// wallet at, logging the anchor and its provenance.
///
/// The returned block seeds the initial BDK checkpoint of a wallet whose persisted chain state
/// is still rooted at genesis, the best block of a freshly created `ChannelManager` and
/// sweeper, and — through them — kyoto's resume checkpoint and the block applicator's
/// `next_height`. A wallet with a persisted block is never rewound, but absent Lightning
/// components are still initialized from it.
// Wired by T9: the builder seeds a fresh wallet, ChannelManager and sweeper from it.
#[allow(dead_code)]
pub(crate) fn resolve_birthday(
	logger: &Logger, network: Network, wallet_birthday_height: Option<u32>,
) -> Option<BestBlock> {
	let requested = wallet_birthday_height?;
	match birthday_checkpoint(network, requested) {
		Some(cp) => {
			let provenance = mainnet_anchors()
				.into_iter()
				.find(|(anchor, _)| *anchor == cp)
				.map(|(_, label)| label)
				.unwrap_or("compiled anchor");
			log_info!(
				logger,
				"CBF wallet birthday: requested height {} resolved to compiled checkpoint at \
				 height {} (hash {}, {}); scanning starts at height {}. Applied only while the \
				 wallet's persisted chain state is still rooted at genesis.",
				requested,
				cp.height,
				cp.hash,
				provenance,
				cp.height + 1,
			);
			Some(BestBlock::new(cp.hash, cp.height))
		},
		None => {
			log_info!(
				logger,
				"CBF wallet birthday: no compiled checkpoint strictly below requested height {} \
				 on {}; a fresh wallet will scan from genesis.",
				requested,
				network,
			);
			None
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_logger() -> Logger {
		Logger::new_log_facade()
	}

	#[test]
	fn birthday_anchors_strictly_below_the_first_scan_height() {
		let newest = anchor_965_999();
		let taproot = HashCheckpoint::taproot_activation();
		let segwit = HashCheckpoint::segwit_activation();

		assert_eq!(birthday_checkpoint(Network::Bitcoin, u32::MAX), Some(newest));
		// A wallet born at block 966,000 anchors one block below it and scans from 966,000.
		assert_eq!(birthday_checkpoint(Network::Bitcoin, 966_000), Some(newest));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, newest.height + 1), Some(newest));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, newest.height), Some(taproot));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, 900_000), Some(taproot));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, taproot.height + 1), Some(taproot));
		// Scanning starts strictly after the anchor, so a first transaction exactly at a
		// compiled anchor height must fall through to the next-lower anchor or that block's
		// filters would never be checked.
		assert_eq!(birthday_checkpoint(Network::Bitcoin, taproot.height), Some(segwit));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, segwit.height + 1), Some(segwit));
		assert_eq!(birthday_checkpoint(Network::Bitcoin, segwit.height), None);
		assert_eq!(birthday_checkpoint(Network::Bitcoin, 0), None);
	}

	#[test]
	fn birthday_is_mainnet_only() {
		for network in [Network::Testnet, Network::Signet, Network::Regtest] {
			assert_eq!(birthday_checkpoint(network, u32::MAX), None);
		}
	}

	#[test]
	fn newest_anchor_is_block_965_999_with_its_published_hash() {
		let newest = anchor_965_999();
		assert_eq!(newest.height, 965_999);
		assert_eq!(
			newest.hash.to_string(),
			"00000000000000000000dbb4d1e55ad22ed5b5a7d81d4c0fe992fceb8a5302d0"
		);
	}

	#[test]
	fn mainnet_anchors_are_distinct_and_ascend() {
		let anchors = mainnet_anchors();
		for pair in anchors.windows(2) {
			assert!(pair[0].0.height < pair[1].0.height, "anchors must ascend: {:?}", anchors);
			assert_ne!(pair[0].0.hash, pair[1].0.hash);
		}
	}

	#[test]
	fn resolve_birthday_anchors_a_966_000_birthday_at_block_965_999() {
		let logger = test_logger();
		let anchor =
			resolve_birthday(&logger, Network::Bitcoin, Some(966_000)).expect("a mainnet anchor");
		assert_eq!(anchor.height, 965_999);
		assert_eq!(anchor.block_hash, anchor_965_999().hash);
		// `None` and non-mainnet networks still root a fresh wallet at genesis.
		assert!(resolve_birthday(&logger, Network::Bitcoin, None).is_none());
		assert!(resolve_birthday(&logger, Network::Regtest, Some(966_000)).is_none());
	}
}
