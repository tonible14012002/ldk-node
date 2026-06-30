// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use lightning::chain::chaininterface::ConfirmationTarget as LdkConfirmationTarget;
use lightning::chain::chaininterface::FeeEstimator as LdkFeeEstimator;
use lightning::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;

use bitcoin::FeeRate;

use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ConfirmationTarget {
	/// The default target for onchain payments.
	OnchainPayment,
	/// The target used for funding transactions.
	ChannelFunding,
	/// Targets used by LDK.
	Lightning(LdkConfirmationTarget),
}

pub(crate) trait FeeEstimator {
	fn estimate_fee_rate(&self, confirmation_target: ConfirmationTarget) -> FeeRate;
}

impl From<LdkConfirmationTarget> for ConfirmationTarget {
	fn from(value: LdkConfirmationTarget) -> Self {
		Self::Lightning(value)
	}
}

pub(crate) struct OnchainFeeEstimator {
	fee_rate_cache: RwLock<HashMap<ConfirmationTarget, FeeRate>>,
}

impl OnchainFeeEstimator {
	pub(crate) fn new() -> Self {
		let fee_rate_cache = RwLock::new(HashMap::new());
		Self { fee_rate_cache }
	}

	// Updates the fee rate cache and returns if the new values changed.
	pub(crate) fn set_fee_rate_cache(
		&self, fee_rate_cache_update: HashMap<ConfirmationTarget, FeeRate>,
	) -> bool {
		let mut locked_fee_rate_cache = self.fee_rate_cache.write().unwrap();
		if fee_rate_cache_update != *locked_fee_rate_cache {
			*locked_fee_rate_cache = fee_rate_cache_update;
			true
		} else {
			false
		}
	}
}

impl FeeEstimator for OnchainFeeEstimator {
	fn estimate_fee_rate(&self, confirmation_target: ConfirmationTarget) -> FeeRate {
		let locked_fee_rate_cache = self.fee_rate_cache.read().unwrap();

		let fallback_sats_kwu = get_fallback_rate_for_target(confirmation_target);

		// We'll fall back on this, if we really don't have any other information.
		let fallback_rate = FeeRate::from_sat_per_kwu(fallback_sats_kwu as u64);

		let estimate = *locked_fee_rate_cache.get(&confirmation_target).unwrap_or(&fallback_rate);

		// Currently we assume every transaction needs to at least be relayable, which is why we
		// enforce a lower bound of `FEERATE_FLOOR_SATS_PER_KW`.
		FeeRate::from_sat_per_kwu(estimate.to_sat_per_kwu().max(FEERATE_FLOOR_SATS_PER_KW as u64))
	}
}

impl LdkFeeEstimator for OnchainFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, confirmation_target: LdkConfirmationTarget) -> u32 {
		self.estimate_fee_rate(confirmation_target.into())
			.to_sat_per_kwu()
			.try_into()
			.unwrap_or_else(|_| get_fallback_rate_for_ldk_target(confirmation_target))
	}
}

pub(crate) fn get_num_block_defaults_for_target(target: ConfirmationTarget) -> usize {
	match target {
		ConfirmationTarget::OnchainPayment => 6,
		// Funding txs target ~3 blocks (mempool's "fast" tier) so they confirm
		// promptly. The prior 12-block target resolved to a fee low enough that
		// funding txs could sit unconfirmed for hours during normal congestion,
		// stalling channels in `sync` (never reaching `channel_ready`).
		ConfirmationTarget::ChannelFunding => 3,
		ConfirmationTarget::Lightning(ldk_target) => match ldk_target {
			LdkConfirmationTarget::MaximumFeeEstimate => 1,
			LdkConfirmationTarget::UrgentOnChainSweep => 6,
			LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee => 1008,
			LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => 144,
			LdkConfirmationTarget::AnchorChannelFee => 1008,
			LdkConfirmationTarget::NonAnchorChannelFee => 12,
			LdkConfirmationTarget::ChannelCloseMinimum => 144,
			LdkConfirmationTarget::OutputSpendingFee => 12,
		},
	}
}

pub(crate) fn get_fallback_rate_for_target(target: ConfirmationTarget) -> u32 {
	match target {
		ConfirmationTarget::OnchainPayment => 5000,
		ConfirmationTarget::ChannelFunding => 1000,
		ConfirmationTarget::Lightning(ldk_target) => get_fallback_rate_for_ldk_target(ldk_target),
	}
}

pub(crate) fn get_fallback_rate_for_ldk_target(target: LdkConfirmationTarget) -> u32 {
	match target {
		LdkConfirmationTarget::MaximumFeeEstimate => 8000,
		LdkConfirmationTarget::UrgentOnChainSweep => 5000,
		LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee => FEERATE_FLOOR_SATS_PER_KW,
		LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => FEERATE_FLOOR_SATS_PER_KW,
		LdkConfirmationTarget::AnchorChannelFee => 500,
		LdkConfirmationTarget::NonAnchorChannelFee => 1000,
		LdkConfirmationTarget::ChannelCloseMinimum => 500,
		LdkConfirmationTarget::OutputSpendingFee => 1000,
	}
}

pub(crate) fn get_all_conf_targets() -> [ConfirmationTarget; 10] {
	[
		ConfirmationTarget::OnchainPayment,
		ConfirmationTarget::ChannelFunding,
		LdkConfirmationTarget::MaximumFeeEstimate.into(),
		LdkConfirmationTarget::UrgentOnChainSweep.into(),
		LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee.into(),
		LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee.into(),
		LdkConfirmationTarget::AnchorChannelFee.into(),
		LdkConfirmationTarget::NonAnchorChannelFee.into(),
		LdkConfirmationTarget::ChannelCloseMinimum.into(),
		LdkConfirmationTarget::OutputSpendingFee.into(),
	]
}

pub(crate) fn apply_post_estimation_adjustments(
	target: ConfirmationTarget, estimated_rate: FeeRate,
) -> FeeRate {
	match target {
		ConfirmationTarget::Lightning(
			LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
		) => {
			let slightly_less_than_background = estimated_rate
				.to_sat_per_kwu()
				.saturating_sub(250)
				.max(FEERATE_FLOOR_SATS_PER_KW as u64);
			FeeRate::from_sat_per_kwu(slightly_less_than_background)
		},
		_ => estimated_rate,
	}
}

/// Public fee-priority selector for on-chain swap transactions (Peerswap
/// native primitives, B-series).
///
/// This is the **public** surface used by swap code to ask for a fee rate
/// without exposing the crate-internal [`ConfirmationTarget`] enum. Each
/// variant maps onto an existing internal target via [`From`], so no new
/// `ConfirmationTarget` variant is introduced and every existing exhaustive
/// match is left untouched.
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum SwapFeeTarget {
	/// Fee target for broadcasting a swap funding (HTLC opening) transaction.
	///
	/// Maps to [`ConfirmationTarget::ChannelFunding`] so the funding output
	/// confirms promptly (~3 blocks) and the swap can proceed without stalling.
	Funding,
	/// Fee target for time-sensitive claim/sweep transactions.
	///
	/// A swap claim is bounded by an on-chain timelock, so it must confirm
	/// urgently. Maps to [`LdkConfirmationTarget::UrgentOnChainSweep`].
	Claim,
	/// Fee target for refund / cooperative-spend transactions.
	///
	/// Less time-critical than a [`SwapFeeTarget::Claim`]; maps to the standard
	/// [`ConfirmationTarget::OnchainPayment`] priority.
	Refund,
}

#[cfg(feature = "swaps")]
impl From<SwapFeeTarget> for ConfirmationTarget {
	fn from(value: SwapFeeTarget) -> Self {
		match value {
			SwapFeeTarget::Funding => ConfirmationTarget::ChannelFunding,
			SwapFeeTarget::Claim => {
				ConfirmationTarget::Lightning(LdkConfirmationTarget::UrgentOnChainSweep)
			},
			SwapFeeTarget::Refund => ConfirmationTarget::OnchainPayment,
		}
	}
}

/// Provenance of a swap feerate estimate (Peerswap native primitive B6 /
/// plan FIX-B).
///
/// Lets a swap caller distinguish a live estimate sourced from the chain
/// backend from a static fallback/relay-floor value, so it can refuse to fund
/// (fail-closed) on an estimate it does not trust.
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapFeerateSource {
	/// A live estimate sourced from the chain backend's fee-rate cache.
	Native,
	/// No live estimate was available; a per-target fallback rate (or the
	/// `FEERATE_FLOOR_SATS_PER_KW` relay floor) was used instead.
	Static,
}

/// A swap feerate estimate carrying its [`SwapFeerateSource`] provenance
/// (Peerswap native primitive B6 / plan FIX-B).
///
/// This is intentionally NOT a bare `u64`/[`FeeRate`]: swap funding decisions
/// are fail-closed, so the consumer must be able to tell a live estimate from a
/// fallback/floor before committing funds.
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeerateQuote {
	/// The estimated feerate in satoshis per virtual byte (rounded up so the
	/// transaction is never under-funded relative to the estimate).
	pub sat_vb: u64,
	/// Whether `sat_vb` came from a live estimate or a static fallback/floor.
	pub source: SwapFeerateSource,
}

#[cfg(feature = "swaps")]
impl OnchainFeeEstimator {
	/// Estimate the on-chain fee rate for a swap transaction at the requested
	/// [`SwapFeeTarget`] priority.
	///
	/// Thin wrapper over [`FeeEstimator::estimate_fee_rate`] that maps the
	/// public [`SwapFeeTarget`] onto the internal [`ConfirmationTarget`]. The
	/// returned [`FeeRate`] is subject to the same `FEERATE_FLOOR_SATS_PER_KW`
	/// lower bound as every other estimate, and falls back to the per-target
	/// fallback rate when the cache is empty.
	pub(crate) fn estimate_swap_fee_rate(&self, target: SwapFeeTarget) -> FeeRate {
		self.estimate_fee_rate(target.into())
	}

	/// Source-bearing swap feerate estimate (B6 / FIX-B).
	///
	/// Returns the estimate in sat/vB together with its [`SwapFeerateSource`]:
	/// [`SwapFeerateSource::Native`] when a live cached estimate exists for the
	/// mapped target, [`SwapFeerateSource::Static`] when the per-target
	/// fallback / relay floor had to be used (cache empty). Callers MUST treat
	/// a `Static` quote as untrusted for fail-closed funding decisions.
	pub(crate) fn estimate_swap_feerate_quote(&self, target: SwapFeeTarget) -> FeerateQuote {
		let conf_target: ConfirmationTarget = target.into();
		let source = if self.fee_rate_cache.read().unwrap().contains_key(&conf_target) {
			SwapFeerateSource::Native
		} else {
			SwapFeerateSource::Static
		};
		let rate = self.estimate_fee_rate(conf_target);
		FeerateQuote { sat_vb: rate.to_sat_per_vb_ceil(), source }
	}
}

#[cfg(all(test, feature = "swaps"))]
mod swap_b6_tests {
	use super::*;

	// An empty cache must yield a `Static` quote (fallback/floor), never a
	// `Native` one — the fail-closed default for swap funding decisions.
	#[test]
	fn empty_cache_quote_is_static() {
		let estimator = OnchainFeeEstimator::new();
		for target in [SwapFeeTarget::Funding, SwapFeeTarget::Claim, SwapFeeTarget::Refund] {
			let quote = estimator.estimate_swap_feerate_quote(target);
			assert_eq!(quote.source, SwapFeerateSource::Static);
			// The fallback is always at least the relay floor, so sat/vB is > 0.
			assert!(quote.sat_vb > 0);
		}
	}

	// A live cached estimate for the mapped target must yield a `Native` quote
	// whose sat/vB reflects the cached rate (here well above the relay floor).
	#[test]
	fn cached_estimate_quote_is_native() {
		let estimator = OnchainFeeEstimator::new();
		let target = SwapFeeTarget::Funding;
		let conf_target: ConfirmationTarget = target.into();
		// 2500 sat/kwu == 10 sat/vB, comfortably above FEERATE_FLOOR_SATS_PER_KW.
		let mut update = HashMap::new();
		update.insert(conf_target, FeeRate::from_sat_per_kwu(2500));
		estimator.set_fee_rate_cache(update);

		let quote = estimator.estimate_swap_feerate_quote(target);
		assert_eq!(quote.source, SwapFeerateSource::Native);
		assert_eq!(quote.sat_vb, 10);
	}

	// A target absent from a populated cache still fails closed to `Static`.
	#[test]
	fn missing_target_in_populated_cache_is_static() {
		let estimator = OnchainFeeEstimator::new();
		let mut update = HashMap::new();
		update.insert(
			Into::<ConfirmationTarget>::into(SwapFeeTarget::Funding),
			FeeRate::from_sat_per_kwu(2500),
		);
		estimator.set_fee_rate_cache(update);

		let quote = estimator.estimate_swap_feerate_quote(SwapFeeTarget::Claim);
		assert_eq!(quote.source, SwapFeerateSource::Static);
	}
}
