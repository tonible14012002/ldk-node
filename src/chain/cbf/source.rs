// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The **filter source** port: where a compact-block-filter node gets raw
//! BIP157/158 consensus data from.
//!
//! This is kept apart from [`ChainDataProvider`] on purpose. A
//! `ChainDataProvider` hands back *indexed answers* — "this transaction is
//! confirmed", "here is your wallet update" — that the asking node has no way
//! to check and must trust. A `FilterSource` hands back *raw consensus data*
//! — headers, filter headers, filters, blocks — that the consuming CBF engine
//! verifies itself: proof of work, the filter-header chain, the merkle root.
//! A lying source can withhold data, but it cannot make a verifying client
//! accept a chain that is not one.
//!
//! One trait, several implementations (a symmetric port):
//!
//! ```text
//!   BitcoindRpcSource   a Pro node reads its own bitcoind      (this crate)
//!   NodeFilterSource    a hybrid node asks a Pro node over the  (the embedding app)
//!                       Node network, which answers through
//!                       Node::chain_serve_headers & co.
//!   kyoto               the Bitcoin P2P network                 (the `cbf` feature)
//! ```
//!
//! The module is compiled without the `cbf` feature: a Pro node serves raw
//! data from its RPC source without following the chain by filters itself.
//!
//! The wire conversions an app needs to implement a network-backed source are
//! re-exported here, next to the trait they serve.
//!
//! [`ChainDataProvider`]: crate::chain::provider::ChainDataProvider

use std::fmt;

use async_trait::async_trait;

use bitcoin::block::Header;
use bitcoin::{Block, BlockHash};

pub use bdk_chain::BlockId;
pub use bitcoin::bip158::{BlockFilter, FilterHeader};

pub use crate::chain::provider::{
	BLOCK_CHUNK_BYTES, MAX_FILTERS_PER_REQUEST, MAX_FILTER_HEADERS_PER_REQUEST,
	MAX_HEADERS_PER_REQUEST,
};
pub use crate::chain::wire_convert::{
	block_chunk_count, block_chunk_to_wire, chain_tip_from_wire, chain_tip_to_wire,
	filter_headers_from_wire, filter_headers_to_wire, filters_from_wire, filters_to_wire,
	headers_from_wire, headers_to_wire, BlockChunkAssembler,
};

use crate::chain::provider::ChainProviderError;

/// The filter headers for a span of blocks, as BIP157's `cfheaders` carries
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterHeaders {
	/// The filter header of the block *below* the first one in `headers` —
	/// all zeros when the span starts at genesis. What the first of
	/// `headers` commits to, so the span can be checked against a chain the
	/// client already holds.
	pub previous: FilterHeader,
	/// One filter header per block, ascending by height, ending at the
	/// requested stop block.
	pub headers: Vec<FilterHeader>,
}

/// One block's basic filter, with the block it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedFilter {
	/// Height of the block.
	pub height: u32,
	/// Hash of the block. Part of the filter's SipHash key, so a filter is
	/// meaningless without it.
	pub block_hash: BlockHash,
	/// The BIP158 basic filter, as `getblockfilter` and `cfilter` carry it.
	pub filter: BlockFilter,
}

/// Why a [`FilterSource`] call did not produce data.
///
/// As with [`ChainProviderError`], the distinction is load-bearing: "I could
/// not get it" must never be mistaken for "it does not exist".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
	/// The source could not answer right now: unreachable, timed out, not
	/// ready, or lacking the index the call needs. Nothing is learned about
	/// the chain; try again later or elsewhere.
	Unavailable {
		/// What went wrong, for logs.
		reason: String,
		/// `true` when the call ran out of time rather than failing outright.
		timed_out: bool,
	},
	/// The source answered with data that failed verification or could not
	/// be parsed. A source that does this repeatedly is lying or broken.
	Invalid(String),
	/// The source was reached and says the thing asked for is not there — a
	/// height above its tip, or a block hash that is not on its best chain.
	NotFound(String),
}

impl SourceError {
	/// An [`SourceError::Unavailable`] that did not time out.
	pub fn unavailable(reason: impl Into<String>) -> Self {
		Self::Unavailable { reason: reason.into(), timed_out: false }
	}
}

impl fmt::Display for SourceError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Unavailable { reason, timed_out: true } => {
				write!(f, "filter source timed out: {}", reason)
			},
			Self::Unavailable { reason, timed_out: false } => {
				write!(f, "filter source unavailable: {}", reason)
			},
			Self::Invalid(e) => write!(f, "filter source sent invalid data: {}", e),
			Self::NotFound(e) => write!(f, "filter source does not have it: {}", e),
		}
	}
}

impl std::error::Error for SourceError {}

/// A wire reply that failed to decode is invalid data; a provider that could
/// not be reached, or refused, is an unavailable source.
impl From<ChainProviderError> for SourceError {
	fn from(e: ChainProviderError) -> Self {
		match e {
			ChainProviderError::Unreachable(reason) => SourceError::unavailable(reason),
			ChainProviderError::Refused(reason) => {
				SourceError::unavailable(format!("refused: {}", reason))
			},
			ChainProviderError::Malformed(_) | ChainProviderError::VersionMismatch { .. } => {
				SourceError::Invalid(e.to_string())
			},
		}
	}
}

/// A source of raw BIP157/158 chain data.
///
/// # Contract
///
/// * **Raw, not interpreted.** Every value returned is consensus data the
///   caller can check. Implementations may verify what they relay, but the
///   consumer never relies on it.
/// * **Ranges are anchored by hash.** [`FilterSource::filter_headers`] and
///   [`FilterSource::filters`] cover `start_height..=height(stop_hash)` on the
///   chain ending at `stop_hash`. A stop hash the source does not have on its
///   best chain is [`SourceError::NotFound`] — the usual sign that the caller
///   raced a reorg and should re-read the tip.
/// * **Bounded.** A serving implementation may refuse spans larger than
///   [`MAX_HEADERS_PER_REQUEST`], [`MAX_FILTER_HEADERS_PER_REQUEST`] or
///   [`MAX_FILTERS_PER_REQUEST`]; callers page.
/// * **Prefixes.** [`FilterSource::filter_headers`] and
///   [`FilterSource::filters`] may answer a non-empty *prefix* of the span —
///   the first blocks of it, from `start_height` — when the whole would be
///   too large for one reply; callers continue from where it ended. An empty
///   answer is invalid.
/// * **Errors are cheap; silence is not.** Implementations apply their own
///   timeouts.
/// * **Idempotent.** Every call may be retried.
#[async_trait]
pub trait FilterSource: Send + Sync {
	/// Identifies the source in logs.
	fn name(&self) -> &'static str;

	/// The source's best block.
	async fn tip(&self) -> Result<BlockId, SourceError>;

	/// Up to `count` consecutive best-chain headers starting at
	/// `from_height`, ascending. Fewer than `count` when the tip is reached
	/// first; [`SourceError::NotFound`] when `from_height` is above the tip.
	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError>;

	/// Filter headers for `start_height..=height(stop_hash)` — or a
	/// non-empty prefix of that span — with the one below the span.
	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError>;

	/// Basic filters for `start_height..=height(stop_hash)` — or a non-empty
	/// prefix of that span — ascending.
	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError>;

	/// A full block by hash.
	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError>;
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::hashes::Hash;

	/// Bitcoin Core renders filter headers the way it renders block hashes —
	/// byte-reversed — and `FilterHeader`'s `FromStr`/`Display` must agree,
	/// or every header parsed from `getblockfilter` would be wrong. BIP158's
	/// first test vector (testnet genesis) pins it.
	#[test]
	fn filter_header_display_order_matches_core() {
		let filter = BlockFilter::new(&[0x01, 0x9d, 0xfc, 0xa8]);
		let header = filter.filter_header(&FilterHeader::all_zeros());
		let core: FilterHeader =
			"21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750".parse().unwrap();
		assert_eq!(header, core);
	}

	#[test]
	fn provider_errors_fold_into_source_errors() {
		assert!(matches!(
			SourceError::from(ChainProviderError::Unreachable("x".into())),
			SourceError::Unavailable { timed_out: false, .. }
		));
		assert!(matches!(
			SourceError::from(ChainProviderError::Refused("x".into())),
			SourceError::Unavailable { .. }
		));
		assert!(matches!(
			SourceError::from(ChainProviderError::Malformed("x".into())),
			SourceError::Invalid(_)
		));
		assert!(matches!(
			SourceError::from(ChainProviderError::VersionMismatch { expected: 1, got: 2 }),
			SourceError::Invalid(_)
		));
	}
}
