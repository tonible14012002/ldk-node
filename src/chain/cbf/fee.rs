// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Fee maths for a filter-driven chain source.
//!
//! A CBF node sees no mempool, so the only fee signal it has is what already confirmed: the
//! coinbase of a block pays out its subsidy plus every fee the block collected, so
//! `(coinbase outputs - subsidy) / weight` is that block's average fee rate. The applicator
//! records the rate of every block it downloads anyway into the [`BlockFeeCache`], keyed by
//! height and tagged with the hash, so a later reader can tell a block that was reorged out
//! from one that is still canonical. The FEE adapter that turns the window into per-target
//! estimates is T8's; the cache and the maths live here because the applicator feeds them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bitcoin::constants::SUBSIDY_HALVING_INTERVAL;
use bitcoin::{Amount, Block, BlockHash, FeeRate};

use crate::chain::cbf::REORG_SAFETY_BLOCKS;
use crate::fee_estimator::{get_num_block_defaults_for_target, ConfirmationTarget};

/// How many recent blocks the fee cache keeps: twice the reorg-safety walk-back, so a reorg
/// that rewinds the resume checkpoint still leaves a full window of canonical samples.
pub(crate) const BLOCK_FEE_CACHE_CAPACITY: usize = REORG_SAFETY_BLOCKS as usize * 2;

/// Number of most recent blocks whose coinbase-derived fee rates feed the native CBF estimator.
pub(crate) const FEE_WINDOW_BLOCKS: u32 = BLOCK_FEE_CACHE_CAPACITY as u32;

/// Lower bound for native CBF fee estimates (1 sat/vB), matching the floor used by the Esplora
/// and Electrum fee sources. Coinbase-derived rates are frequently zero on regtest/signet.
pub(crate) const CBF_MIN_FEERATE_SAT_PER_KWU: u64 = 250;

/// Recent per-block coinbase-derived fee rates, keyed by height so a reader can window on the
/// tip, evict stale entries, and detect reorged-out blocks (a height whose cached hash no longer
/// matches the canonical chain). Shared between the applicator, which fills it, and the FEE
/// adapter, which reads it.
pub(crate) type BlockFeeCache = Arc<Mutex<BTreeMap<u32, (BlockHash, FeeRate)>>>;

/// A fresh, empty cache.
pub(crate) fn new_block_fee_cache() -> BlockFeeCache {
	Arc::new(Mutex::new(BTreeMap::new()))
}

/// Records one block's fee rate and evicts the oldest entries beyond
/// [`BLOCK_FEE_CACHE_CAPACITY`], so a bulk sync that downloads many matched blocks between two
/// fee refreshes cannot grow the cache without bound.
pub(crate) fn record_block_fee(cache: &BlockFeeCache, height: u32, hash: BlockHash, rate: FeeRate) {
	let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
	cache.insert(height, (hash, rate));
	while cache.len() > BLOCK_FEE_CACHE_CAPACITY {
		cache.pop_first();
	}
}

/// Block subsidy at the given height (approximate on regtest).
pub(crate) fn block_subsidy(height: u32) -> Amount {
	let halvings = height / SUBSIDY_HALVING_INTERVAL;
	if halvings >= 64 {
		return Amount::ZERO;
	}
	Amount::from_sat((Amount::ONE_BTC.to_sat() * 50) >> halvings)
}

/// Average fee rate of a block, derived from its coinbase: `(coinbase output total - subsidy) /
/// weight`. Lets us compute the fee rate of a block we already hold without a re-download.
pub(crate) fn coinbase_fee_rate(block: &Block, height: u32) -> FeeRate {
	let revenue: Amount = block
		.txdata
		.first()
		.map(|coinbase| coinbase.output.iter().map(|txout| txout.value).sum())
		.unwrap_or(Amount::ZERO);
	let block_fees = revenue.checked_sub(block_subsidy(height)).unwrap_or(Amount::ZERO);
	let fee_rate = block_fees.to_sat().checked_div(block.weight().to_kwu_floor()).unwrap_or(0);
	FeeRate::from_sat_per_kwu(fee_rate)
}

/// Maps a confirmation target to the percentile of the recent-block fee-rate window we read for it.
///
/// More urgent targets (shorter confirmation horizon) read a higher percentile; relaxed targets
/// read a lower one. This is a coarse stand-in for the per-horizon estimates a mempool-aware
/// backend would provide.
pub(crate) fn cbf_percentile_for_target(target: ConfirmationTarget) -> f64 {
	match get_num_block_defaults_for_target(target) {
		0..=2 => 90.0,
		3..=6 => 75.0,
		7..=12 => 50.0,
		13..=144 => 25.0,
		_ => 10.0,
	}
}

/// Returns the value at the given percentile of an ascending-sorted slice using nearest-rank.
/// Returns `0` for an empty slice.
pub(crate) fn percentile_of_sorted(sorted: &[u64], percentile: f64) -> u64 {
	if sorted.is_empty() {
		return 0;
	}
	let rank = ((percentile / 100.0) * sorted.len() as f64).ceil() as usize;
	let idx = rank.saturating_sub(1).min(sorted.len() - 1);
	sorted[idx]
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::block::{Header, Version};
	use bitcoin::hashes::Hash;
	use bitcoin::{
		absolute, transaction, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
	};
	use lightning::chain::chaininterface::ConfirmationTarget as LdkConfirmationTarget;

	/// A block whose only transaction is a coinbase paying `revenue`, padded past 1 kWU so the
	/// per-kWU division has something to divide by.
	fn block_with_coinbase_revenue(revenue: Amount) -> Block {
		let coinbase = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: revenue,
				script_pubkey: ScriptBuf::from_bytes(vec![0; 200]),
			}],
		};
		let header = Header {
			version: Version::TWO,
			prev_blockhash: BlockHash::all_zeros(),
			merkle_root: bitcoin::TxMerkleNode::all_zeros(),
			time: 0,
			bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
			nonce: 0,
		};
		Block { header, txdata: vec![coinbase] }
	}

	#[test]
	fn block_subsidy_halves_every_interval() {
		assert_eq!(block_subsidy(0), Amount::from_btc(50.0).unwrap());
		assert_eq!(block_subsidy(SUBSIDY_HALVING_INTERVAL - 1), Amount::from_btc(50.0).unwrap());
		assert_eq!(block_subsidy(SUBSIDY_HALVING_INTERVAL), Amount::from_btc(25.0).unwrap());
		// The fourth epoch, current at the time of writing: 3.125 BTC.
		assert_eq!(block_subsidy(840_000), Amount::from_sat(312_500_000));
		// Sixty-four halvings shift every bit out.
		assert_eq!(block_subsidy(64 * SUBSIDY_HALVING_INTERVAL), Amount::ZERO);
	}

	#[test]
	fn coinbase_fee_rate_subtracts_subsidy() {
		let height = 840_000;
		let fees = Amount::from_sat(5_000);
		let block = block_with_coinbase_revenue(block_subsidy(height) + fees);
		let kwu = block.weight().to_kwu_floor();
		assert!(kwu >= 1, "the fixture must exceed 1 kWU or the rate is vacuously zero");
		assert_eq!(coinbase_fee_rate(&block, height), FeeRate::from_sat_per_kwu(5_000 / kwu));

		// A coinbase paying exactly the subsidy collected no fees.
		let free = block_with_coinbase_revenue(block_subsidy(height));
		assert_eq!(coinbase_fee_rate(&free, height), FeeRate::ZERO);

		// A miner who under-claims the subsidy is not a negative fee rate.
		let under = block_with_coinbase_revenue(Amount::from_sat(1));
		assert_eq!(coinbase_fee_rate(&under, height), FeeRate::ZERO);

		// No coinbase at all — nothing to derive from.
		let empty = Block { header: block.header, txdata: Vec::new() };
		assert_eq!(coinbase_fee_rate(&empty, height), FeeRate::ZERO);
	}

	#[test]
	fn percentile_of_sorted_nearest_rank() {
		let sorted = [10, 20, 30, 40, 50];
		// Nearest rank: ceil(p/100 * n), one-indexed, clamped to the slice.
		assert_eq!(percentile_of_sorted(&sorted, 0.0), 10);
		assert_eq!(percentile_of_sorted(&sorted, 10.0), 10);
		assert_eq!(percentile_of_sorted(&sorted, 25.0), 20);
		assert_eq!(percentile_of_sorted(&sorted, 50.0), 30);
		assert_eq!(percentile_of_sorted(&sorted, 75.0), 40);
		assert_eq!(percentile_of_sorted(&sorted, 90.0), 50);
		assert_eq!(percentile_of_sorted(&sorted, 100.0), 50);
		assert_eq!(percentile_of_sorted(&[7], 50.0), 7);
		assert_eq!(percentile_of_sorted(&[], 50.0), 0);
	}

	#[test]
	fn urgent_targets_read_higher_percentiles() {
		let max_fee = ConfirmationTarget::Lightning(LdkConfirmationTarget::MaximumFeeEstimate);
		assert_eq!(cbf_percentile_for_target(max_fee), 90.0);
		assert_eq!(cbf_percentile_for_target(ConfirmationTarget::ChannelFunding), 75.0);
		let non_anchor = ConfirmationTarget::Lightning(LdkConfirmationTarget::NonAnchorChannelFee);
		assert_eq!(cbf_percentile_for_target(non_anchor), 50.0);
		let close_min = ConfirmationTarget::Lightning(LdkConfirmationTarget::ChannelCloseMinimum);
		assert_eq!(cbf_percentile_for_target(close_min), 25.0);
		let anchor = ConfirmationTarget::Lightning(LdkConfirmationTarget::AnchorChannelFee);
		assert_eq!(cbf_percentile_for_target(anchor), 10.0);
	}

	#[test]
	fn record_block_fee_keeps_only_the_newest_window() {
		let cache = new_block_fee_cache();
		let hash = BlockHash::all_zeros();
		for height in 0..(BLOCK_FEE_CACHE_CAPACITY as u32 + 5) {
			record_block_fee(&cache, height, hash, FeeRate::from_sat_per_kwu(height as u64));
		}
		let cache = cache.lock().unwrap();
		assert_eq!(cache.len(), BLOCK_FEE_CACHE_CAPACITY);
		assert_eq!(*cache.keys().next().unwrap(), 5, "the oldest heights were evicted");
		assert_eq!(
			*cache.keys().next_back().unwrap(),
			BLOCK_FEE_CACHE_CAPACITY as u32 + 4,
			"the newest height is kept"
		);
	}
}
