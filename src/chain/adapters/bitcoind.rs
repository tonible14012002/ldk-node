// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! bitcoind-backed chain ability adapters.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::{FeeRate, Network, Transaction};

use lightning::chain::chaininterface::ConfirmationTarget as LdkConfirmationTarget;
use lightning::util::ser::Writeable;

use lightning_block_sync::gossip::UtxoSource;
use lightning_block_sync::poll::ValidatedBlockHeader;

use crate::chain::bitcoind::{BitcoindClient, FeeRateEstimationMode};
use crate::chain::seam::{BroadcastAdapter, FeeAdapter, FeeUpdate, LookupAdapter};
use crate::config::{Config, FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS, TX_BROADCAST_TIMEOUT_SECS};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
	ConfirmationTarget,
};
use crate::logger::{log_bytes, log_error, log_trace, LdkLogger, Logger};
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};
#[cfg(feature = "swaps")]
use lightning_block_sync::BlockSource;

use async_trait::async_trait;

/// Fee estimates from a bitcoind RPC/REST endpoint.
///
/// Unlike the other backends this picks the estimation *mode* per
/// [`ConfirmationTarget`], not per block count, which is why the adapter
/// contract is target-shaped rather than block-count-shaped.
pub(crate) struct BitcoindChainAdapter {
	api_client: Arc<BitcoindClient>,
	/// Cached best-chain tip, shared with the block-polling engine that
	/// maintains it. Used only as a fail-soft fallback for deriving a height.
	latest_chain_tip: Arc<RwLock<Option<ValidatedBlockHeader>>>,
	config: Arc<Config>,
	logger: Arc<Logger>,
}

impl BitcoindChainAdapter {
	pub(crate) fn new(
		api_client: Arc<BitcoindClient>,
		latest_chain_tip: Arc<RwLock<Option<ValidatedBlockHeader>>>, config: Arc<Config>,
		logger: Arc<Logger>,
	) -> Self {
		Self { api_client, latest_chain_tip, config, logger }
	}
}

#[async_trait]
impl FeeAdapter for BitcoindChainAdapter {
	fn name(&self) -> &'static str {
		"bitcoind"
	}

	async fn fee_rate_update(&self) -> Result<FeeUpdate, Error> {
		macro_rules! get_fee_rate_update {
			($estimation_fut: expr) => {{
				let update_res = tokio::time::timeout(
					Duration::from_secs(FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS),
					$estimation_fut,
				)
				.await
				.map_err(|e| {
					log_error!(self.logger, "Updating fee rate estimates timed out: {}", e);
					Error::FeerateEstimationUpdateTimeout
				})?;
				update_res
			}};
		}
		let confirmation_targets = get_all_conf_targets();

		let mut new_fee_rate_cache = HashMap::with_capacity(10);
		for target in confirmation_targets {
			let fee_rate_update_res = match target {
				ConfirmationTarget::Lightning(
					LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
				) => {
					let estimation_fut = self.api_client.get_mempool_minimum_fee_rate();
					get_fee_rate_update!(estimation_fut)
				},
				ConfirmationTarget::Lightning(LdkConfirmationTarget::MaximumFeeEstimate) => {
					let num_blocks = get_num_block_defaults_for_target(target);
					let estimation_mode = FeeRateEstimationMode::Conservative;
					let estimation_fut =
						self.api_client.get_fee_estimate_for_target(num_blocks, estimation_mode);
					get_fee_rate_update!(estimation_fut)
				},
				ConfirmationTarget::Lightning(LdkConfirmationTarget::UrgentOnChainSweep) => {
					let num_blocks = get_num_block_defaults_for_target(target);
					let estimation_mode = FeeRateEstimationMode::Conservative;
					let estimation_fut =
						self.api_client.get_fee_estimate_for_target(num_blocks, estimation_mode);
					get_fee_rate_update!(estimation_fut)
				},
				_ => {
					// Otherwise, we default to economical block-target estimate.
					let num_blocks = get_num_block_defaults_for_target(target);
					let estimation_mode = FeeRateEstimationMode::Economical;
					let estimation_fut =
						self.api_client.get_fee_estimate_for_target(num_blocks, estimation_mode);
					get_fee_rate_update!(estimation_fut)
				},
			};

			let fee_rate = match (fee_rate_update_res, self.config.network) {
				(Ok(rate), _) => rate,
				(Err(e), Network::Bitcoin) => {
					// Strictly fail on mainnet.
					log_error!(self.logger, "Failed to retrieve fee rate estimates: {}", e);
					return Err(Error::FeerateEstimationUpdateFailed);
				},
				(Err(e), n) if n == Network::Regtest || n == Network::Signet => {
					// On regtest/signet we just fall back to the usual 1 sat/vb == 250
					// sat/kwu default.
					log_error!(
						self.logger,
						"Failed to retrieve fee rate estimates: {}. Falling back to default of 1 sat/vb.",
						e,
					);
					FeeRate::from_sat_per_kwu(250)
				},
				(Err(e), _) => {
					// On testnet `estimatesmartfee` can be unreliable so we just skip in
					// case of a failure, which will have us falling back to defaults.
					log_error!(
						self.logger,
						"Failed to retrieve fee rate estimates: {}. Falling back to defaults.",
						e,
					);
					// NOTE: pre-seam this was a bare `return Ok(())`, which left BOTH the
					// fee-rate cache and the metrics timestamp untouched. `Skip` preserves
					// exactly that.
					return Ok(FeeUpdate::Skip);
				},
			};

			// LDK 0.0.118 introduced changes to the `ConfirmationTarget` semantics that
			// require some post-estimation adjustments to the fee rates, which we do here.
			let adjusted_fee_rate = apply_post_estimation_adjustments(target, fee_rate);

			new_fee_rate_cache.insert(target, adjusted_fee_rate);

			log_trace!(
				self.logger,
				"Fee rate estimation updated for {:?}: {} sats/kwu",
				target,
				adjusted_fee_rate.to_sat_per_kwu(),
			);
		}

		// bitcoind refreshes often enough that logging every completion is spammy,
		// so the completion line is emitted only when the cache actually changed.
		Ok(FeeUpdate::Apply { cache: new_fee_rate_cache, log_unchanged: false })
	}
}

#[async_trait]
impl LookupAdapter for BitcoindChainAdapter {
	fn name(&self) -> &'static str {
		"bitcoind"
	}

	#[cfg(feature = "swaps")]
	async fn tx_status(&self, txid: Txid, _script_pubkey: Option<&ScriptBuf>) -> RawTxObservation {
		match self.api_client.swap_tx_confirmations(&txid).await {
			Ok(Some(0)) => RawTxObservation::InMempool,
			Ok(Some(confirmations)) => {
				// `getrawtransaction` returns the depth but not the height; derive
				// it as `tip - (confs - 1)`. B5 LOW-2: read a FRESH best-chain tip
				// (`get_best_block`) rather than the cached `latest_chain_tip`,
				// which can lag the real tip and yield a height that is too low —
				// and thus a CSV/claim deadline armed slightly EARLY. A fresh (or
				// even a one-block-stale-newer) tip can only err on the LATE/safe
				// side. Fail-soft on the HEIGHT ONLY: the depth is already
				// authoritative, so on a tip-read error we fall back to the cached
				// tip rather than failing the whole query closed.
				let tip_height = match self.api_client.get_best_block().await {
					Ok((_, Some(h))) => Some(h),
					Ok((_, None)) => {
						self.latest_chain_tip.read().unwrap().as_ref().map(|tip| tip.height)
					},
					Err(e) => {
						log_error!(
							self.logger,
							"swap_query_tx: Bitcoind fresh-tip read failed for {} ({:?}); falling back to cached tip for height",
							txid,
							e
						);
						self.latest_chain_tip.read().unwrap().as_ref().map(|tip| tip.height)
					},
				};
				let height = tip_height.map(|t| t.saturating_sub(confirmations.saturating_sub(1)));
				RawTxObservation::Confirmed { height, confirmations }
			},
			Ok(None) => RawTxObservation::NotFound,
			Err(e) => {
				log_error!(self.logger, "swap_query_tx: Bitcoind query failed for {}: {}", txid, e);
				RawTxObservation::Unreachable
			},
		}
	}

	/// bitcoind is the only backend that can answer `gettxout`, so it is the
	/// only one that can verify BOLT-7 channel announcements.
	fn utxo_source(&self) -> Option<Arc<dyn UtxoSource>> {
		Some(self.api_client.utxo_source())
	}
}

#[async_trait]
impl BroadcastAdapter for BitcoindChainAdapter {
	fn name(&self) -> &'static str {
		"bitcoind"
	}

	// While it's a bit unclear when we'd be able to lean on Bitcoin Core >v28
	// features, we should eventually switch to use `submitpackage` via the
	// `rust-bitcoind-json-rpc` crate rather than just broadcasting individual
	// transactions.
	async fn broadcast_tx(&self, tx: &Transaction) {
		let txid = tx.compute_txid();
		let timeout_fut = tokio::time::timeout(
			Duration::from_secs(TX_BROADCAST_TIMEOUT_SECS),
			self.api_client.broadcast_transaction(tx),
		);
		match timeout_fut.await {
			Ok(res) => match res {
				Ok(id) => {
					debug_assert_eq!(id, txid);
					log_trace!(self.logger, "Successfully broadcast transaction {}", txid);
				},
				Err(e) => {
					log_error!(self.logger, "Failed to broadcast transaction {}: {}", txid, e);
					log_trace!(
						self.logger,
						"Failed broadcast transaction bytes: {}",
						log_bytes!(tx.encode())
					);
				},
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to broadcast transaction due to timeout {}: {}",
					txid,
					e
				);
				log_trace!(
					self.logger,
					"Failed broadcast transaction bytes: {}",
					log_bytes!(tx.encode())
				);
			},
		}
	}
}
