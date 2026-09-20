// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! bitcoind-backed chain ability adapters.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{FeeRate, Network, Transaction};

use lightning::chain::chaininterface::ConfirmationTarget as LdkConfirmationTarget;
use lightning::util::ser::Writeable;

use crate::chain::bitcoind::{BitcoindClient, FeeRateEstimationMode};
use crate::chain::seam::{BroadcastAdapter, FeeAdapter, FeeUpdate};
use crate::config::{Config, FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS, TX_BROADCAST_TIMEOUT_SECS};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
	ConfirmationTarget,
};
use crate::logger::{log_bytes, log_error, log_trace, LdkLogger, Logger};
use crate::Error;

use async_trait::async_trait;

/// Fee estimates from a bitcoind RPC/REST endpoint.
///
/// Unlike the other backends this picks the estimation *mode* per
/// [`ConfirmationTarget`], not per block count, which is why the adapter
/// contract is target-shaped rather than block-count-shaped.
pub(crate) struct BitcoindFeeAdapter {
	api_client: Arc<BitcoindClient>,
	config: Arc<Config>,
	logger: Arc<Logger>,
}

impl BitcoindFeeAdapter {
	pub(crate) fn new(
		api_client: Arc<BitcoindClient>, config: Arc<Config>, logger: Arc<Logger>,
	) -> Self {
		Self { api_client, config, logger }
	}
}

#[async_trait]
impl FeeAdapter for BitcoindFeeAdapter {
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
impl BroadcastAdapter for BitcoindFeeAdapter {
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
