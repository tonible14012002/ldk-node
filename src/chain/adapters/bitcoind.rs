// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! bitcoind-backed chain ability adapters.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::{FeeRate, Network, Transaction};

use bdk_chain::BlockId;

use lightning::chain::chaininterface::ConfirmationTarget as LdkConfirmationTarget;
use lightning::util::ser::Writeable;

use lightning_block_sync::gossip::UtxoSource;
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::rpc::RpcError;

use crate::chain::adapters::classify_sendrawtransaction;
use crate::chain::bitcoind::{BitcoindClient, FeeRateEstimationMode};
use crate::chain::seam::{
	package_result, ActionResult, Anchored, BroadcastAction, BroadcastRejection, ChainActionError,
	FeeAction, FeeUpdate, MempoolAction, MempoolAnswer, MempoolQuery, MempoolScope,
	TxBroadcastOutcome, UtxoCapability, UtxoVerification, ADAPTER_BUDGET_MARGIN,
	PER_TX_BROADCAST_BUDGET,
};
use crate::config::{Config, FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS, TX_BROADCAST_TIMEOUT_SECS};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
	ConfirmationTarget,
};
use crate::logger::{log_bytes, log_error, log_trace, LdkLogger, Logger};
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::seam::TxStatusAction;
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};
#[cfg(feature = "swaps")]
use lightning_block_sync::BlockSource;

use async_trait::async_trait;

/// `lightning_block_sync::http`'s `TCP_STREAM_TIMEOUT`: the connect timeout,
/// and the read/write timeout it sets on the socket. Mirrored here because the
/// crate keeps it private (lightning-block-sync 0.1.0, `http.rs`).
const BITCOIND_TCP_STREAM_TIMEOUT_SECS: u64 = 5;
/// `lightning_block_sync::http`'s `TCP_STREAM_RESPONSE_TIMEOUT`: how long the
/// crate means to let Bitcoin Core sit on a request before answering its
/// first byte (a UTXO cache flush on a slow device). It is applied as
/// `RESPONSE / STREAM` extra read attempts on the status line, so the wait it
/// grants is one stream timeout more than its face value.
const BITCOIND_TCP_STREAM_RESPONSE_TIMEOUT_SECS: u64 = 300;
/// `HttpClient::send_request_with_retry` sends once and, on any error,
/// reconnects and sends once more: two attempts per call.
const BITCOIND_HTTP_ATTEMPTS: u64 = 2;
/// The pause the crate takes between those two attempts.
const BITCOIND_HTTP_RETRY_SLEEP_MILLIS: u64 = 100;

/// What one bitcoind RPC/REST call is allowed to take, in the crate's own
/// terms: per attempt a connect, a request write and the wait for the status
/// line (`RESPONSE / STREAM + 1` reads of one stream timeout each), for two
/// attempts, plus the retry pause. 2 × (5 + 5 + 305) s + 0.1 s.
///
/// What it does not cover, stated so nobody reads it as a hard ceiling: the
/// header and body reads after the status line are each one stream timeout
/// but the crate does not bound their number; and on the `tokio` path this
/// crate runs, the socket is handed to tokio non-blocking, so the crate's
/// read/write timeouts never fire at all — only the connect timeout and the
/// single retry are real. This budget is therefore the first bound the read
/// has ever had, sized to the allowance the crate designed for a slow but
/// alive Bitcoin Core so the seam never cuts one off.
const BITCOIND_HTTP_CALL_BOUND_MILLIS: u64 = BITCOIND_HTTP_ATTEMPTS
	* 1_000
	* (BITCOIND_TCP_STREAM_TIMEOUT_SECS
		+ BITCOIND_TCP_STREAM_TIMEOUT_SECS
		+ (BITCOIND_TCP_STREAM_RESPONSE_TIMEOUT_SECS / BITCOIND_TCP_STREAM_TIMEOUT_SECS + 1)
			* BITCOIND_TCP_STREAM_TIMEOUT_SECS)
	+ BITCOIND_HTTP_RETRY_SLEEP_MILLIS;

/// TX_STATUS budget: pre-seam `swap_query_tx` had no bound of its own and
/// makes two calls (`getrawtransaction`, then a fresh best-block read), so
/// twice [`BITCOIND_HTTP_CALL_BOUND_MILLIS`] plus the margin.
#[cfg(feature = "swaps")]
const BITCOIND_TX_STATUS_BUDGET: Duration = Duration::from_millis(
	2 * BITCOIND_HTTP_CALL_BOUND_MILLIS + ADAPTER_BUDGET_MARGIN.as_millis() as u64,
);

/// MEMPOOL budget. The poll is `1 + n + m` calls — one `getrawmempool`, one
/// `getmempoolentry` per entry not yet in the client's entry cache, one
/// `getrawtransaction` per transaction to emit that is not in its
/// transaction cache — and pre-seam it ran unbounded, because `n` and `m` are
/// the size of the mempool on the first poll after start and the arrivals
/// since the last poll thereafter: there is no honest count to multiply the
/// per-call bound by. The seam requires a bound, so the crate's own per-call
/// allowance ([`BITCOIND_HTTP_CALL_BOUND_MILLIS`], ten and a half minutes) is
/// granted to the poll as a whole, plus the margin. Against a local Core each
/// call is milliseconds, so this covers a poll of many thousands of calls; a
/// poll that still overruns it is resumed, not restarted, by the next tick,
/// because both client caches keep everything fetched before the cut and the
/// watermark that would have marked it emitted was never advanced.
const BITCOIND_MEMPOOL_BUDGET: Duration = Duration::from_millis(
	BITCOIND_HTTP_CALL_BOUND_MILLIS + ADAPTER_BUDGET_MARGIN.as_millis() as u64,
);

/// Whether an I/O error is the HTTP client's own timeout. A blocking socket
/// with a read timeout reports it as `TimedOut` on some platforms and as
/// `WouldBlock` on others (Unix); `lightning_block_sync` surfaces both.
fn is_timeout(e: &std::io::Error) -> bool {
	matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
}

/// Classify a failed `sendrawtransaction`.
///
/// A transport failure or a timeout is `Unavailable`, because nothing is
/// known about the transaction from it; an RPC error goes through the shared
/// [`classify_sendrawtransaction`] verdict table.
fn classify_broadcast_error(e: &std::io::Error) -> TxBroadcastOutcome {
	if is_timeout(e) {
		return TxBroadcastOutcome::Unavailable { reason: e.to_string(), timed_out: true };
	}
	let Some(rpc_error) = e.get_ref().and_then(|inner| inner.downcast_ref::<RpcError>()) else {
		return TxBroadcastOutcome::Unavailable { reason: e.to_string(), timed_out: false };
	};
	classify_sendrawtransaction(rpc_error.code, &rpc_error.message)
}

/// Fee estimates from a bitcoind RPC/REST endpoint.
///
/// Unlike the other backends this picks the estimation *mode* per
/// [`ConfirmationTarget`], not per block count, which is why the adapter
/// contract is target-shaped rather than block-count-shaped.
pub(crate) struct BitcoindChainAdapter {
	api_client: Arc<BitcoindClient>,
	/// Cached best-chain tip, shared with the block-polling engine that
	/// maintains it: the tip the engine has polled up to, which is what a
	/// MEMPOOL answer is anchored to, and TX_STATUS's fail-soft fallback for
	/// deriving a height.
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

	/// The tip the block-polling engine has synced the listeners to, if it
	/// has synced them at all yet.
	fn cached_tip(&self) -> Option<BlockId> {
		self.latest_chain_tip
			.read()
			.unwrap()
			.as_ref()
			.map(|tip| BlockId { height: tip.height, hash: tip.header.block_hash() })
	}

	/// The pre-chain fee fetch, unchanged: one RPC per target, each under its
	/// own wire timeout, with the per-network failure policy.
	async fn fetch_fee_rate_update(&self) -> Result<FeeUpdate, Error> {
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
impl FeeAction for BitcoindChainAdapter {
	fn name(&self) -> &'static str {
		"bitcoind"
	}

	/// Pre-seam timing preserved: one RPC per confirmation target, each under
	/// `FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS`, run sequentially — so the whole
	/// fetch may legitimately take `targets × timeout` before the adapter's own
	/// per-target timeout (and its error log) fires.
	fn budget(&self) -> Option<Duration> {
		let per_target = Duration::from_secs(FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS);
		let targets = get_all_conf_targets().len() as u32;
		Some(per_target * targets + ADAPTER_BUDGET_MARGIN)
	}

	async fn fee_rate_update(&self) -> ActionResult<FeeUpdate> {
		self.fetch_fee_rate_update().await.map_err(ChainActionError::from)
	}
}

#[cfg(feature = "swaps")]
#[async_trait]
impl TxStatusAction for BitcoindChainAdapter {
	fn name(&self) -> &'static str {
		"bitcoind"
	}

	fn budget(&self) -> Option<Duration> {
		Some(BITCOIND_TX_STATUS_BUDGET)
	}

	/// A confirmed observation is anchored to the tip its height was derived
	/// against — bitcoind is the one backend that reports the tip as a
	/// height/hash pair. Mempool and not-found answers consult no tip and
	/// carry none.
	async fn tx_status(
		&self, txid: Txid, _script_pubkey: Option<&ScriptBuf>,
	) -> ActionResult<Anchored<RawTxObservation>> {
		match self.api_client.swap_tx_confirmations(&txid).await {
			Ok(Some(0)) => Ok(Anchored { value: RawTxObservation::InMempool, tip: None }),
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
				let tip = match self.api_client.get_best_block().await {
					Ok((hash, Some(height))) => Some(BlockId { height, hash }),
					Ok((_, None)) => self.cached_tip(),
					Err(e) => {
						log_error!(
							self.logger,
							"swap_query_tx: Bitcoind fresh-tip read failed for {} ({:?}); falling back to cached tip for height",
							txid,
							e
						);
						self.cached_tip()
					},
				};
				let height = tip.map(|t| t.height.saturating_sub(confirmations.saturating_sub(1)));
				Ok(Anchored { value: RawTxObservation::Confirmed { height, confirmations }, tip })
			},
			Ok(None) => Ok(Anchored { value: RawTxObservation::NotFound, tip: None }),
			Err(e) => {
				log_error!(self.logger, "swap_query_tx: Bitcoind query failed for {}: {}", txid, e);
				let reason = format!("query failed: {}", e);
				Err(if is_timeout(&e) {
					ChainActionError::timed_out(reason)
				} else {
					ChainActionError::unavailable(reason)
				})
			},
		}
	}
}

/// bitcoind is the only backend with a mempool of its own to poll.
#[async_trait]
impl MempoolAction for BitcoindChainAdapter {
	fn name(&self) -> &'static str {
		"bitcoind"
	}

	fn budget(&self) -> Option<Duration> {
		Some(BITCOIND_MEMPOOL_BUDGET)
	}

	/// `Incremental` is the pre-seam poll, unchanged: the client's emit-once
	/// walk of its mempool caches, which over-answers — every relevant *and*
	/// irrelevant new transaction, the query's scripts unread — because the
	/// asking wallet keeps what is its own on apply, exactly as it did when
	/// the engine called the client directly. `Complete` is the snapshot the
	/// serving path asks for, filtered by the query and leaving the poll's
	/// watermark alone.
	///
	/// Either answer is anchored to the tip the engine has synced up to: the
	/// engine polls the tip immediately before it asks, so that is the tip
	/// the mempool was read against. `None` only before the first sync.
	async fn mempool(&self, query: &MempoolQuery) -> ActionResult<Anchored<MempoolAnswer>> {
		let tip = self.cached_tip();
		let value = match query.scope {
			MempoolScope::Incremental { best_processed_height } => {
				let (unconfirmed, evicted) = self
					.api_client
					.get_updated_mempool_transactions(
						best_processed_height,
						query.known_unconfirmed.clone(),
					)
					.await
					.map_err(mempool_poll_error)?;
				MempoolAnswer { unconfirmed, evicted }
			},
			MempoolScope::Complete => {
				let unconfirmed = self
					.api_client
					.get_mempool_snapshot(|tx| query.is_relevant(tx))
					.await
					.map_err(mempool_poll_error)?;
				let now =
					SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
				let evicted = self
					.api_client
					.txids_missing_from_mempool(&query.known_unconfirmed)
					.await
					.into_iter()
					.map(|txid| (txid, now))
					.collect();
				MempoolAnswer { unconfirmed, evicted }
			},
		};
		Ok(Anchored { value, tip })
	}
}

/// A failed mempool poll is never a verdict on anything: `Unavailable`,
/// `timed_out` when the client's own timeout is why. The reason keeps the
/// error's full `Debug` form, which is what the engine logged pre-seam.
fn mempool_poll_error(e: std::io::Error) -> ChainActionError {
	let reason = format!("{:?}", e);
	if is_timeout(&e) {
		ChainActionError::timed_out(reason)
	} else {
		ChainActionError::unavailable(reason)
	}
}

/// bitcoind is the only backend that can answer `gettxout`, so it is the only
/// one that can verify BOLT-7 channel announcements — and it fetches the
/// output, so the verification is [`UtxoVerification::Full`].
impl UtxoCapability for BitcoindChainAdapter {
	fn name(&self) -> &'static str {
		"bitcoind"
	}

	fn utxo_source(&self) -> Option<(Arc<dyn UtxoSource>, UtxoVerification)> {
		Some((self.api_client.utxo_source(), UtxoVerification::Full))
	}
}

#[async_trait]
impl BroadcastAction for BitcoindChainAdapter {
	fn name(&self) -> &'static str {
		"bitcoind"
	}

	/// Pre-seam timing preserved: each transaction is sent under its own
	/// `TX_BROADCAST_TIMEOUT_SECS`, so that timeout and its error log fire
	/// before the seam's.
	fn budget(&self) -> Option<Duration> {
		Some(PER_TX_BROADCAST_BUDGET)
	}

	// While it's a bit unclear when we'd be able to lean on Bitcoin Core >v28
	// features, we should eventually switch to use `submitpackage` via the
	// `rust-bitcoind-json-rpc` crate rather than just broadcasting individual
	// transactions.
	async fn broadcast_package(&self, txs: &[Transaction]) -> ActionResult<(), BroadcastRejection> {
		let mut outcomes = Vec::with_capacity(txs.len());
		for tx in txs {
			outcomes.push((tx.compute_txid(), self.broadcast_tx(tx).await));
		}
		package_result(outcomes)
	}
}

impl BitcoindChainAdapter {
	/// The pre-seam per-transaction send and its log levels, with the RPC
	/// error classified by [`classify_broadcast_error`]. A verdict is logged
	/// at trace here, not error: the layer's tail logs each rejection with
	/// its reason once it has decided what to do about it.
	async fn broadcast_tx(&self, tx: &Transaction) -> TxBroadcastOutcome {
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
					TxBroadcastOutcome::Accepted
				},
				Err(e) => {
					let outcome = classify_broadcast_error(&e);
					match &outcome {
						TxBroadcastOutcome::AlreadyKnown => {
							log_trace!(
								self.logger,
								"Transaction {} is already known to bitcoind: {}",
								txid,
								e
							);
						},
						TxBroadcastOutcome::Rejected(reason) => {
							log_trace!(
								self.logger,
								"bitcoind rejected transaction {}: {}",
								txid,
								reason
							);
						},
						_ => {
							log_error!(
								self.logger,
								"Failed to broadcast transaction {}: {}",
								txid,
								e
							);
						},
					}
					log_trace!(
						self.logger,
						"Failed broadcast transaction bytes: {}",
						log_bytes!(tx.encode())
					);
					outcome
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

#[cfg(test)]
mod tests {
	use super::*;

	use std::io::{Error as IoError, ErrorKind};

	/// Both spellings of a socket read timeout are the client's own timeout.
	#[test]
	fn read_timeouts_of_either_kind_are_timed_out() {
		for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
			let e = IoError::new(kind, "read timed out");
			assert!(is_timeout(&e), "{:?}", kind);
			assert_eq!(
				classify_broadcast_error(&e),
				TxBroadcastOutcome::Unavailable { reason: e.to_string(), timed_out: true }
			);
		}
		let e = IoError::new(ErrorKind::ConnectionRefused, "refused");
		assert!(!is_timeout(&e));
		assert_eq!(
			classify_broadcast_error(&e),
			TxBroadcastOutcome::Unavailable { reason: e.to_string(), timed_out: false }
		);
	}

	/// An RPC error reaches the shared verdict table through the `io::Error`
	/// wrapper `lightning_block_sync` puts around it.
	#[test]
	fn rpc_errors_go_through_the_shared_verdict_table() {
		let wrap = |code: i64, message: &str| {
			IoError::new(ErrorKind::Other, RpcError { code, message: message.to_string() })
		};
		assert_eq!(
			classify_broadcast_error(&wrap(-27, "Transaction already in block chain")),
			TxBroadcastOutcome::AlreadyKnown
		);
		assert_eq!(
			classify_broadcast_error(&wrap(-26, "txn-already-known")),
			TxBroadcastOutcome::AlreadyKnown
		);
		assert_eq!(
			classify_broadcast_error(&wrap(-26, "txn-mempool-conflict")),
			TxBroadcastOutcome::Rejected("txn-mempool-conflict (-26)".into())
		);
		assert_eq!(
			classify_broadcast_error(&wrap(-25, "Missing inputs")),
			TxBroadcastOutcome::Rejected("Missing inputs (-25)".into())
		);
		assert!(matches!(
			classify_broadcast_error(&wrap(-25, "Fee exceeds maximum configured by user")),
			TxBroadcastOutcome::Unavailable { timed_out: false, .. }
		));
		assert!(matches!(
			classify_broadcast_error(&wrap(-8, "Invalid parameter")),
			TxBroadcastOutcome::Unavailable { timed_out: false, .. }
		));
	}

	/// The HTTP client's own allowance the budgets rest on.
	#[test]
	fn call_bound_covers_the_clients_two_attempts() {
		// Per attempt: 5 s connect + 5 s write + 61 reads × 5 s for the status
		// line; two attempts; 100 ms between them.
		assert_eq!(BITCOIND_HTTP_CALL_BOUND_MILLIS, 2 * (5_000 + 5_000 + 61 * 5_000) + 100);
		assert_eq!(BITCOIND_HTTP_CALL_BOUND_MILLIS, 630_100);
		// The whole poll gets one call's allowance plus the 1 s margin.
		assert_eq!(BITCOIND_MEMPOOL_BUDGET, Duration::from_millis(630_100 + 1_000));
		// Never below what the crate itself designed for a slow Bitcoin Core:
		// twice the response timeout per call.
		assert!(
			BITCOIND_MEMPOOL_BUDGET
				> Duration::from_secs(2 * BITCOIND_TCP_STREAM_RESPONSE_TIMEOUT_SECS)
		);
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn tx_status_budget_covers_two_calls() {
		// Two calls plus the 1 s margin.
		assert_eq!(BITCOIND_TX_STATUS_BUDGET, Duration::from_millis(2 * 630_100 + 1_000));
		assert!(
			BITCOIND_TX_STATUS_BUDGET
				> Duration::from_secs(2 * 2 * BITCOIND_TCP_STREAM_RESPONSE_TIMEOUT_SECS)
		);
	}
}
