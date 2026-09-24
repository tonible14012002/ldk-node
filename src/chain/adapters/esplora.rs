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

use crate::chain::adapters::classify_relayed_sendrawtransaction;
use crate::chain::seam::{
	ActionResult, BroadcastAction, BroadcastRejection, ChainActionError, FeeAction, FeeUpdate,
	PackageOutcomes, TxBroadcastOutcome, ADAPTER_BUDGET_MARGIN, PER_TX_BROADCAST_BUDGET,
};
use crate::config::{Config, FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS, TX_BROADCAST_TIMEOUT_SECS};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
};
use crate::logger::{log_bytes, log_error, log_trace, LdkLogger, Logger};
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::seam::{Anchored, TxStatusAction};
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use crate::chain::DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

/// esplora-client's `DEFAULT_MAX_RETRIES` (0.12.3, `lib.rs`): every GET goes
/// through `AsyncClient::get_with_retry`, which re-sends a request whose
/// response was 429, 500 or 503 (`RETRYABLE_ERROR_CODES`) up to this many
/// times. A transport error, the client timeout included, is not retried. The
/// builder in `chain::layer` leaves this at the default. Mirrored here because
/// the crate keeps it private.
#[cfg(feature = "swaps")]
const ESPLORA_MAX_RETRIES: u64 = 6;
/// esplora-client's `BASE_BACKOFF_MILLIS`: the sleep before the first retry,
/// doubled before each further one.
#[cfg(feature = "swaps")]
const ESPLORA_BASE_BACKOFF_MILLIS: u64 = 256;

/// The backoff `get_with_retry` sleeps through when every retry is used:
/// 256 ms × (1 + 2 + … + 2^(retries-1)) = 256 ms × (2^retries − 1).
#[cfg(feature = "swaps")]
const ESPLORA_BACKOFF_TOTAL_MILLIS: u64 =
	ESPLORA_BASE_BACKOFF_MILLIS * ((1 << ESPLORA_MAX_RETRIES) - 1);

/// What one Esplora GET can take before the client gives up on its own: each
/// of the `MAX_RETRIES + 1` attempts is bounded by the reqwest client timeout
/// (`DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS`, a server that takes the whole
/// timeout to answer 503 is retried), plus the backoff between them.
/// 7 × 10 s + 16.128 s.
#[cfg(feature = "swaps")]
const ESPLORA_GET_BOUND_MILLIS: u64 =
	(ESPLORA_MAX_RETRIES + 1) * DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS * 1_000
		+ ESPLORA_BACKOFF_TOTAL_MILLIS;

/// TX_STATUS budget: pre-seam `swap_query_tx` made two GETs (status, then tip
/// height) with no bound of its own, each on the retrying path, so twice
/// [`ESPLORA_GET_BOUND_MILLIS`] plus the margin lets the client's own timeout,
/// and its log line, fire first even when the server is limping through 503s.
#[cfg(feature = "swaps")]
const ESPLORA_TX_STATUS_BUDGET: Duration =
	Duration::from_millis(2 * ESPLORA_GET_BOUND_MILLIS + ADAPTER_BUDGET_MARGIN.as_millis() as u64);

/// An `Unavailable` for a failed Esplora call, `timed_out` when the HTTP
/// client's own timeout is what failed it.
#[cfg(feature = "swaps")]
fn unavailable_from(what: &str, e: &esplora_client::Error) -> ChainActionError {
	let reason = format!("{}: {}", what, e);
	match e {
		esplora_client::Error::Reqwest(inner) if inner.is_timeout() => {
			ChainActionError::timed_out(reason)
		},
		_ => ChainActionError::unavailable(reason),
	}
}

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

	/// The pre-chain fee fetch, unchanged: its own wire timeout, its own
	/// mainnet policy, its own per-target conversion.
	async fn fetch_fee_rate_update(&self) -> Result<FeeUpdate, Error> {
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
impl FeeAction for EsploraChainAdapter {
	fn name(&self) -> &'static str {
		"esplora"
	}

	/// Pre-seam timing preserved: the fetch bounds itself at
	/// `FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS`; the margin lets that timeout, and
	/// its error log, fire before the seam's. `/fee-estimates` is on the
	/// client's retrying GET path (up to 6 retries with backoff on 429/500/503),
	/// but the fetch's own timeout cuts that path short, so it does not widen
	/// this budget.
	fn budget(&self) -> Option<Duration> {
		Some(Duration::from_secs(FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS) + ADAPTER_BUDGET_MARGIN)
	}

	async fn fee_rate_update(&self) -> ActionResult<FeeUpdate> {
		self.fetch_fee_rate_update().await.map_err(ChainActionError::from)
	}
}

/// Esplora reports the tip as a bare height, never as a height/hash pair, so
/// no observation it produces can be anchored: `tip` is always `None`.
#[cfg(feature = "swaps")]
#[async_trait]
impl TxStatusAction for EsploraChainAdapter {
	fn name(&self) -> &'static str {
		"esplora"
	}

	fn budget(&self) -> Option<Duration> {
		Some(ESPLORA_TX_STATUS_BUDGET)
	}

	async fn tx_status(
		&self, txid: Txid, _script_pubkey: Option<&ScriptBuf>,
	) -> ActionResult<Anchored<RawTxObservation>> {
		let unanchored = |value| Ok(Anchored { value, tip: None });

		let status = match self.client.get_tx_status(&txid).await {
			Ok(status) => status,
			Err(esplora_client::Error::HttpResponse { status: 404, .. }) => {
				// Definitive "not in the chain or mempool" answer.
				return unanchored(RawTxObservation::NotFound);
			},
			Err(e) => {
				log_error!(
					self.logger,
					"swap_query_tx: Esplora status query failed for {}: {}",
					txid,
					e
				);
				return Err(unavailable_from("status query failed", &e));
			},
		};
		if !status.confirmed {
			return unanchored(RawTxObservation::InMempool);
		}
		let height = match status.block_height {
			Some(height) => height,
			None => {
				log_error!(
					self.logger,
					"swap_query_tx: Esplora reported a confirmed tx {} without a block height",
					txid
				);
				return Err(ChainActionError::unavailable("confirmed without a block height"));
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
				unanchored(RawTxObservation::Confirmed { height: Some(height), confirmations })
			},
			Ok(tip_height) => {
				log_error!(
					self.logger,
					"swap_query_tx: Esplora tip {} below confirming-block height {} for {} (reorg/race); failing closed",
					tip_height,
					height,
					txid
				);
				Err(ChainActionError::unavailable(format!(
					"tip {} below confirming-block height {}",
					tip_height, height
				)))
			},
			Err(e) => {
				log_error!(self.logger, "swap_query_tx: Esplora tip query failed: {}", e);
				Err(unavailable_from("tip query failed", &e))
			},
		}
	}
}

#[async_trait]
impl BroadcastAction for EsploraChainAdapter {
	fn name(&self) -> &'static str {
		"esplora"
	}

	/// Pre-seam timing preserved: each transaction is sent under its own
	/// `TX_BROADCAST_TIMEOUT_SECS`, so the HTTP client's timeout and its error
	/// log fire before the seam's. `POST /tx` is not on the client's retrying
	/// path (`post_request_bytes` sends once), so one client timeout is all a
	/// send can take even without the per-transaction bound.
	fn budget(&self) -> Option<Duration> {
		Some(PER_TX_BROADCAST_BUDGET)
	}

	/// One send per transaction, exactly as pre-seam — a later transaction is
	/// still sent after an earlier one failed — then the package is answered
	/// for as a whole.
	async fn broadcast_package(
		&self, txs: &[Transaction],
	) -> ActionResult<PackageOutcomes, BroadcastRejection> {
		let mut outcomes = Vec::with_capacity(txs.len());
		for tx in txs {
			outcomes.push((tx.compute_txid(), self.broadcast_tx(tx).await));
		}
		Ok(outcomes)
	}
}

impl EsploraChainAdapter {
	/// The pre-seam per-transaction send and its log levels. electrs answers
	/// every `sendrawtransaction` failure with HTTP 400 and relays bitcoind's
	/// error in the body (`sendrawtransaction RPC error: {"code":..,
	/// "message":..}`), so a 400 is classified by the shared verdict table: a
	/// verdict is logged at trace, the layer's tail logs what it does about it.
	/// A 400 whose body is not that relay says nothing about the transaction
	/// and is `Unavailable`, like every other status and every transport
	/// failure — timed out when the client's own timeout or ours is what
	/// failed it.
	async fn broadcast_tx(&self, tx: &Transaction) -> TxBroadcastOutcome {
		let txid = tx.compute_txid();
		let timeout_fut = tokio::time::timeout(
			Duration::from_secs(TX_BROADCAST_TIMEOUT_SECS),
			self.client.broadcast(tx),
		);
		match timeout_fut.await {
			Ok(res) => match res {
				Ok(()) => {
					log_trace!(self.logger, "Successfully broadcast transaction {}", txid);
					TxBroadcastOutcome::Accepted
				},
				Err(e) => match e {
					esplora_client::Error::HttpResponse { status: 400, message } => {
						let outcome = match classify_relayed_sendrawtransaction(&message) {
							Some(outcome) => {
								log_trace!(
									self.logger,
									"Esplora relayed bitcoind's verdict on transaction {}: {}",
									txid,
									message
								);
								outcome
							},
							None => {
								log_error!(
									self.logger,
									"Failed to broadcast transaction {} due to HTTP 400 with an unrecognised body: {}",
									txid,
									message
								);
								TxBroadcastOutcome::Unavailable {
									reason: format!("HTTP 400: {}", message),
									timed_out: false,
								}
							},
						};
						log_trace!(
							self.logger,
							"Failed broadcast transaction bytes: {}",
							log_bytes!(tx.encode())
						);
						outcome
					},
					esplora_client::Error::HttpResponse { status, message } => {
						log_error!(
							self.logger,
							"Failed to broadcast due to HTTP connection error: {} - {}",
							status,
							message
						);
						log_trace!(
							self.logger,
							"Failed broadcast transaction bytes: {}",
							log_bytes!(tx.encode())
						);
						TxBroadcastOutcome::Unavailable {
							reason: format!("HTTP {}: {}", status, message),
							timed_out: false,
						}
					},
					_ => {
						log_error!(self.logger, "Failed to broadcast transaction {}: {}", txid, e);
						log_trace!(
							self.logger,
							"Failed broadcast transaction bytes: {}",
							log_bytes!(tx.encode())
						);
						let timed_out = matches!(
							&e,
							esplora_client::Error::Reqwest(inner) if inner.is_timeout()
						);
						TxBroadcastOutcome::Unavailable { reason: e.to_string(), timed_out }
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
				TxBroadcastOutcome::Unavailable { reason: e.to_string(), timed_out: true }
			},
		}
	}
}

#[cfg(all(test, feature = "swaps"))]
mod tests {
	use super::*;

	/// The retry arithmetic the TX_STATUS budget rests on, spelled out.
	#[test]
	fn tx_status_budget_covers_the_clients_retrying_get_path() {
		// 256 ms × (1 + 2 + 4 + 8 + 16 + 32).
		assert_eq!(ESPLORA_BACKOFF_TOTAL_MILLIS, 16_128);
		// 7 attempts × 10 s client timeout + the backoff.
		assert_eq!(ESPLORA_GET_BOUND_MILLIS, 7 * 10_000 + 16_128);
		// Two GETs plus the 1 s margin.
		assert_eq!(ESPLORA_TX_STATUS_BUDGET, Duration::from_millis(2 * 86_128 + 1_000));
		assert!(
			ESPLORA_TX_STATUS_BUDGET
				> Duration::from_secs(
					2 * (ESPLORA_MAX_RETRIES + 1) * DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS
				)
		);
	}
}
