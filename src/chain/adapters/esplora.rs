// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Esplora-backed chain ability adapters.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{FeeRate, Network, Transaction};

use esplora_client::AsyncClient as EsploraAsyncClient;

use lightning::util::ser::Writeable;

use lightning_block_sync::gossip::UtxoSource;

use crate::chain::seam::{BroadcastAdapter, FeeAdapter, FeeUpdate, LookupAdapter};
use crate::config::{Config, FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS, TX_BROADCAST_TIMEOUT_SECS};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
};
use crate::logger::{log_bytes, log_error, log_trace, LdkLogger, Logger};
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

/// Fee estimates from an Esplora server's `/fee-estimates` endpoint.
pub(crate) struct EsploraChainAdapter {
	client: EsploraAsyncClient,
	config: Arc<Config>,
	logger: Arc<Logger>,
}

impl EsploraChainAdapter {
	pub(crate) fn new(
		client: EsploraAsyncClient, config: Arc<Config>, logger: Arc<Logger>,
	) -> Self {
		Self { client, config, logger }
	}
}

#[async_trait]
impl FeeAdapter for EsploraChainAdapter {
	fn name(&self) -> &'static str {
		"esplora"
	}

	async fn fee_rate_update(&self) -> Result<FeeUpdate, Error> {
		let estimates = tokio::time::timeout(
			Duration::from_secs(FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS),
			self.client.get_fee_estimates(),
		)
		.await
		.map_err(|e| {
			log_error!(self.logger, "Updating fee rate estimates timed out: {}", e);
			Error::FeerateEstimationUpdateTimeout
		})?
		.map_err(|e| {
			log_error!(self.logger, "Failed to retrieve fee rate estimates: {}", e);
			Error::FeerateEstimationUpdateFailed
		})?;

		if estimates.is_empty() && self.config.network == Network::Bitcoin {
			// Ensure we fail if we didn't receive any estimates.
			log_error!(
				self.logger,
				"Failed to retrieve fee rate estimates: empty fee estimates are dissallowed on Mainnet.",
			);
			return Err(Error::FeerateEstimationUpdateFailed);
		}

		let confirmation_targets = get_all_conf_targets();

		let mut new_fee_rate_cache = HashMap::with_capacity(10);
		for target in confirmation_targets {
			let num_blocks = get_num_block_defaults_for_target(target);

			// Convert the retrieved fee rate and fall back to 1 sat/vb if we fail or it
			// yields less than that. This is mostly necessary to continue on
			// `signet`/`regtest` where we might not get estimates (or bogus values).
			let converted_estimate_sat_vb =
				esplora_client::convert_fee_rate(num_blocks, estimates.clone())
					.map_or(1.0, |converted| converted.max(1.0));

			let fee_rate = FeeRate::from_sat_per_kwu((converted_estimate_sat_vb * 250.0) as u64);

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

		Ok(FeeUpdate::Apply { cache: new_fee_rate_cache, log_unchanged: true })
	}
}

#[async_trait]
impl LookupAdapter for EsploraChainAdapter {
	fn name(&self) -> &'static str {
		"esplora"
	}

	#[cfg(feature = "swaps")]
	async fn tx_status(&self, txid: Txid, _script_pubkey: Option<&ScriptBuf>) -> RawTxObservation {
		let status = match self.client.get_tx_status(&txid).await {
			Ok(status) => status,
			Err(esplora_client::Error::HttpResponse { status: 404, .. }) => {
				// Definitive "not in the chain or mempool" answer.
				return RawTxObservation::NotFound;
			},
			Err(e) => {
				log_error!(
					self.logger,
					"swap_query_tx: Esplora status query failed for {}: {}",
					txid,
					e
				);
				return RawTxObservation::Unreachable;
			},
		};
		if !status.confirmed {
			return RawTxObservation::InMempool;
		}
		let height = match status.block_height {
			Some(height) => height,
			None => {
				log_error!(
					self.logger,
					"swap_query_tx: Esplora reported a confirmed tx {} without a block height",
					txid
				);
				return RawTxObservation::Unreachable;
			},
		};
		// B5 LOW-2: the confirming-block height and the tip come from two
		// separate Esplora calls; a block/reorg in the gap can make them
		// inconsistent. Detect the one observable inconsistency — a tip BELOW
		// the tx's confirming block (impossible on a single consistent chain)
		// — and FAIL CLOSED (treat as unverifiable) rather than reporting a
		// bogus `1`-confirmation from the saturating arithmetic. The benign
		// gap (tip one block ahead of the status snapshot) only over-counts
		// confirmations by ≤1, which errs on the safe/late side for deadlines.
		match self.client.get_height().await {
			Ok(tip_height) if tip_height >= height => {
				let confirmations = tip_height.saturating_sub(height).saturating_add(1);
				RawTxObservation::Confirmed { height: Some(height), confirmations }
			},
			Ok(tip_height) => {
				log_error!(
					self.logger,
					"swap_query_tx: Esplora tip {} below confirming-block height {} for {} (reorg/race); failing closed",
					tip_height,
					height,
					txid
				);
				RawTxObservation::Unreachable
			},
			Err(e) => {
				log_error!(self.logger, "swap_query_tx: Esplora tip query failed: {}", e);
				RawTxObservation::Unreachable
			},
		}
	}

	/// Esplora exposes no UTXO-set lookup, so channel announcements cannot be
	/// verified against one. Pre-seam this was the `_ => None` arm of
	/// `as_utxo_source`; it is now an explicit declaration by the adapter.
	fn utxo_source(&self) -> Option<Arc<dyn UtxoSource>> {
		None
	}
}

#[async_trait]
impl BroadcastAdapter for EsploraChainAdapter {
	fn name(&self) -> &'static str {
		"esplora"
	}

	async fn broadcast_tx(&self, tx: &Transaction) {
		let txid = tx.compute_txid();
		let timeout_fut = tokio::time::timeout(
			Duration::from_secs(TX_BROADCAST_TIMEOUT_SECS),
			self.client.broadcast(tx),
		);
		match timeout_fut.await {
			Ok(res) => match res {
				Ok(()) => {
					log_trace!(self.logger, "Successfully broadcast transaction {}", txid);
				},
				Err(e) => match e {
					esplora_client::Error::HttpResponse { status, message } => {
						if status == 400 {
							// Log 400 at lesser level, as this often just means bitcoind already knows the
							// transaction.
							// FIXME: We can further differentiate here based on the error
							// message which will be available with rust-esplora-client 0.7 and
							// later.
							log_trace!(
								self.logger,
								"Failed to broadcast due to HTTP connection error: {}",
								message
							);
						} else {
							log_error!(
								self.logger,
								"Failed to broadcast due to HTTP connection error: {} - {}",
								status,
								message
							);
						}
						log_trace!(
							self.logger,
							"Failed broadcast transaction bytes: {}",
							log_bytes!(tx.encode())
						);
					},
					_ => {
						log_error!(self.logger, "Failed to broadcast transaction {}: {}", txid, e);
						log_trace!(
							self.logger,
							"Failed broadcast transaction bytes: {}",
							log_bytes!(tx.encode())
						);
					},
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
