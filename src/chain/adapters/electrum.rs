// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Electrum-backed chain ability adapters.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::Transaction;

use crate::chain::electrum::{
	ElectrumRuntimeClient, ELECTRUM_CLIENT_NUM_RETRIES, ELECTRUM_CLIENT_TIMEOUT_SECS,
	ELECTRUM_MEMPOOL_VIEW_TIMEOUT_SECS,
};
use crate::chain::seam::{
	ActionResult, Anchored, BroadcastAction, BroadcastRejection, ChainActionError, FeeAction,
	FeeUpdate, MempoolAction, MempoolAnswer, MempoolQuery, MempoolScope, PackageOutcomes,
	ADAPTER_BUDGET_MARGIN, PER_TX_BROADCAST_BUDGET,
};
use crate::chain::ElectrumRuntimeStatus;
use crate::config::FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS;
use crate::logger::{log_trace, LdkLogger, Logger};
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::seam::TxStatusAction;
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use crate::logger::log_error;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

/// How many times electrum-client (0.23.1, `client.rs` `impl_inner_call!`)
/// sends one call: the first attempt plus one per configured retry, a
/// protocol error excepted (it is returned at once, never retried).
const ELECTRUM_CLIENT_ATTEMPTS: u64 = ELECTRUM_CLIENT_NUM_RETRIES as u64 + 1;
/// The socket operations one attempt is made of, each under its own
/// `ELECTRUM_CLIENT_TIMEOUT_SECS`: the client sets it as the connect timeout
/// (`connect_with_total_timeout`, shared across the resolved addresses), the
/// write timeout and the read timeout, separately. Connect, request write,
/// response read.
const ELECTRUM_SOCKET_OPS_PER_ATTEMPT: u64 = 3;
/// electrum-client's reconnect sleep: before rebuilding the connection for
/// retry `n` it sleeps `min(2^n, 30)` seconds, n counted from 1.
const ELECTRUM_RECONNECT_SLEEP_CAP_SECS: u64 = 30;

/// The reconnect sleeps of one call that uses every retry: 2 + 4 + 8 s for
/// the three the client is built with.
const fn electrum_reconnect_sleeps_secs(retries: u64) -> u64 {
	let mut total = 0;
	let mut n = 1;
	while n <= retries {
		let sleep = 1u64 << n;
		total += if sleep < ELECTRUM_RECONNECT_SLEEP_CAP_SECS {
			sleep
		} else {
			ELECTRUM_RECONNECT_SLEEP_CAP_SECS
		};
		n += 1;
	}
	total
}

/// What one Electrum call is allowed to take, in the client's own terms:
/// `ATTEMPTS × OPS × TIMEOUT` plus the reconnect sleeps. 4 × 3 × 20 s + 14 s.
///
/// What it covers, so nobody reads it as a hard ceiling: one connect, one
/// write and one read per attempt. A response that arrives across several
/// reads, or a TLS handshake's own reads and writes on reconnect, each get
/// the same per-operation timeout and are not counted here.
const ELECTRUM_CALL_BOUND_SECS: u64 = ELECTRUM_CLIENT_ATTEMPTS
	* ELECTRUM_SOCKET_OPS_PER_ATTEMPT
	* (ELECTRUM_CLIENT_TIMEOUT_SECS as u64)
	+ electrum_reconnect_sleeps_secs(ELECTRUM_CLIENT_NUM_RETRIES as u64);

/// MEMPOOL budget: the view's own [`ELECTRUM_MEMPOOL_VIEW_TIMEOUT_SECS`] plus
/// the margin, so the view's timeout and its log line fire first.
///
/// Not the client's worst case. A view is three steps — the tip, the script
/// histories, the unconfirmed transactions — and three times
/// [`ELECTRUM_CALL_BOUND_SECS`] is over twelve minutes, sized for a server
/// that is down and being reconnected to. A Pro node reads from a public
/// server, not a local index, and serves the view to a hybrid node whose own
/// provider call gives up after 20 s and asks again on its next tick; a view
/// that has not come back in a minute is not one anyone is still waiting for,
/// and holding the slot open for twelve would only stack up the next asks
/// behind it on the one shared client. The answer is assembled in full before
/// it is handed back, so a view cut short leaves nothing half-applied.
const ELECTRUM_MEMPOOL_BUDGET: Duration =
	Duration::from_secs(ELECTRUM_MEMPOOL_VIEW_TIMEOUT_SECS + ADAPTER_BUDGET_MARGIN.as_secs());

/// TX_STATUS budget: pre-seam `swap_query_tx` had no bound of its own and
/// makes two socket calls (script history, then headers subscribe), so twice
/// [`ELECTRUM_CALL_BOUND_SECS`] plus the margin lets the client's own error
/// fire first for anything the bound covers.
#[cfg(feature = "swaps")]
const ELECTRUM_TX_STATUS_BUDGET: Duration =
	Duration::from_secs(2 * ELECTRUM_CALL_BOUND_SECS + ADAPTER_BUDGET_MARGIN.as_secs());

/// Fee estimates from an Electrum server.
///
/// The Electrum client batches all confirmation targets into one call and owns
/// its own timeout and completeness policy, so this adapter is a thin shim over
/// it rather than a per-target loop.
pub(crate) struct ElectrumChainAdapter {
	runtime_status: Arc<RwLock<ElectrumRuntimeStatus>>,
	logger: Arc<Logger>,
}

impl ElectrumChainAdapter {
	pub(crate) fn new(
		runtime_status: Arc<RwLock<ElectrumRuntimeStatus>>, logger: Arc<Logger>,
	) -> Self {
		Self { runtime_status, logger }
	}

	/// The live client, if the chain source has been started.
	fn client(&self) -> Option<Arc<ElectrumRuntimeClient>> {
		self.runtime_status.read().unwrap().client().as_ref().map(Arc::clone)
	}

	/// The pre-chain fee fetch, unchanged: the client's own batched call,
	/// timeout and completeness policy. A chain source that is not started is
	/// a state every chain checks for, not a bug: the fetch fails and the
	/// chain moves on.
	async fn fetch_fee_rate_update(&self) -> Result<FeeUpdate, Error> {
		let Some(electrum_client) = self.client() else {
			return Err(Error::FeerateEstimationUpdateFailed);
		};

		let cache = electrum_client.get_fee_rate_cache_update().await?;

		Ok(FeeUpdate::Apply { cache, log_unchanged: true })
	}
}

#[async_trait]
impl FeeAction for ElectrumChainAdapter {
	fn name(&self) -> &'static str {
		"electrum"
	}

	/// Pre-seam timing preserved: the client's batched call bounds itself at
	/// `FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS`; the margin lets that timeout, and
	/// its error log, fire before the seam's.
	fn budget(&self) -> Option<Duration> {
		Some(Duration::from_secs(FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS) + ADAPTER_BUDGET_MARGIN)
	}

	async fn fee_rate_update(&self) -> ActionResult<FeeUpdate> {
		self.fetch_fee_rate_update().await.map_err(ChainActionError::from)
	}
}

/// The Electrum client answers from a script-hash history, and reads the
/// server's header tip in the same round trip set to count depth against; the
/// observation is anchored to that tip, so the serving path can hand its hash
/// on and a hybrid asker can check it against its own chain.
#[cfg(feature = "swaps")]
#[async_trait]
impl TxStatusAction for ElectrumChainAdapter {
	fn name(&self) -> &'static str {
		"electrum"
	}

	fn budget(&self) -> Option<Duration> {
		Some(ELECTRUM_TX_STATUS_BUDGET)
	}

	async fn tx_status(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> ActionResult<Anchored<RawTxObservation>> {
		let script_pubkey = match script_pubkey {
			Some(script_pubkey) => script_pubkey.clone(),
			None => {
				log_error!(
					self.logger,
					"swap_query_tx: Electrum backend requires a watched scriptPubKey for {} (register via watch_txid)",
					txid
				);
				return Err(ChainActionError::unavailable("no watched scriptPubKey for the txid"));
			},
		};
		let client = match self.client() {
			Some(client) => client,
			None => {
				log_error!(self.logger, "swap_query_tx: Electrum chain source not started");
				return Err(ChainActionError::unavailable("chain source not started"));
			},
		};
		let observed = client.swap_query_tx(txid, script_pubkey).await;
		match observed.value {
			// The client has already logged why. It folds every failure —
			// socket timeout included — into `Unreachable` without saying
			// which, so no timeout can be claimed here.
			RawTxObservation::Unreachable => {
				Err(ChainActionError::unavailable("Electrum query failed"))
			},
			_ => Ok(observed),
		}
	}
}

#[async_trait]
impl BroadcastAction for ElectrumChainAdapter {
	fn name(&self) -> &'static str {
		"electrum"
	}

	/// Pre-seam timing preserved: the client sends each transaction under its
	/// own `TX_BROADCAST_TIMEOUT_SECS`, so that timeout and its error log fire
	/// before the seam's.
	fn budget(&self) -> Option<Duration> {
		Some(PER_TX_BROADCAST_BUDGET)
	}

	/// Pre-seam this check sat before the drain loop and returned early from
	/// the whole pass. The layer still abandons the pass when no adapter is
	/// ready, and `process_broadcast_queue` runs once a second, so this is
	/// the same behaviour: skip this pass, try again on the next tick.
	async fn ready(&self) -> bool {
		self.client().is_some()
	}

	/// One send per transaction, exactly as pre-seam. The Electrum client owns
	/// its own timeout, logging and classification, and takes the transaction
	/// by value; the clone is the one cost of the shared by-reference slot
	/// contract. A server-side refusal arrives as a protocol error the client
	/// classifies best-effort: a relayed `sendrawtransaction` verdict it can
	/// read is answered as such, anything else is `Unavailable`.
	async fn broadcast_package(
		&self, txs: &[Transaction],
	) -> ActionResult<PackageOutcomes, BroadcastRejection> {
		let Some(client) = self.client() else {
			return Err(ChainActionError::unavailable("chain source not started"));
		};
		let mut outcomes = Vec::with_capacity(txs.len());
		for tx in txs {
			outcomes.push((tx.compute_txid(), client.broadcast(tx.clone()).await));
		}
		Ok(outcomes)
	}
}

/// The mempool as the Electrum server indexes it, by script, so an
/// Electrum-backed Pro node can lend its view to a node that follows the
/// chain by filters and sees no mempool of its own.
///
/// Answers [`MempoolScope::Complete`] only. The adapter keeps no memory of
/// what it answered whom, so an `Incremental` question would get the whole
/// view every tick and pay for it; the one engine over this adapter never
/// asks — its transaction sync carries the mempool itself — and a served
/// question is always `Complete`. Anchored to the server's header tip when
/// the view was taken, which a filter-following asker checks against its own
/// chain.
#[async_trait]
impl MempoolAction for ElectrumChainAdapter {
	fn name(&self) -> &'static str {
		"electrum"
	}

	fn budget(&self) -> Option<Duration> {
		Some(ELECTRUM_MEMPOOL_BUDGET)
	}

	async fn mempool(&self, query: &MempoolQuery) -> ActionResult<Anchored<MempoolAnswer>> {
		if let MempoolScope::Incremental { .. } = query.scope {
			return Err(ChainActionError::unavailable(
				"Electrum serves complete mempool views only; it keeps no memory of what it \
				 answered an incremental asker",
			));
		}
		let Some(client) = self.client() else {
			return Err(ChainActionError::unavailable("chain source not started"));
		};

		let view = client
			.mempool_view(query.scripts.clone(), query.known_unconfirmed.clone())
			.await
			.map_err(ChainActionError::from)?;
		log_trace!(
			self.logger,
			"Electrum mempool view for {} script(s): {} unconfirmed, {} evicted, at height {}",
			query.scripts.len(),
			view.unconfirmed.len(),
			view.evicted.len(),
			view.tip.height
		);

		// The server reports no first-seen time; the moment this node learned of
		// a transaction is the one that matters to whoever applies the answer.
		let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
		Ok(Anchored {
			value: MempoolAnswer {
				unconfirmed: view.unconfirmed.into_iter().map(|tx| (tx, now)).collect(),
				evicted: view.evicted.into_iter().map(|txid| (txid, now)).collect(),
			},
			tip: Some(view.tip),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The retry arithmetic the budgets rest on, spelled out.
	#[test]
	fn budgets_cover_the_clients_retry_and_reconnect_path() {
		// Sleeps of 2, 4 and 8 s before each of the three reconnects.
		assert_eq!(electrum_reconnect_sleeps_secs(3), 2 + 4 + 8);
		// The per-reconnect sleep caps at 30 s: 2 + 4 + 8 + 16 + 30 + 30.
		assert_eq!(electrum_reconnect_sleeps_secs(6), 2 + 4 + 8 + 16 + 30 + 30);
		assert_eq!(electrum_reconnect_sleeps_secs(0), 0);
		// 4 attempts × (connect + write + read) × 20 s + the sleeps.
		assert_eq!(ELECTRUM_CALL_BOUND_SECS, 4 * 3 * 20 + 14);
		// The view's own minute plus the 1 s margin — not the client's twelve-minute
		// worst case, which a public server must not be allowed to hold the slot for.
		assert_eq!(ELECTRUM_MEMPOOL_BUDGET, Duration::from_secs(60 + 1));
		// Two calls plus the 1 s margin.
		#[cfg(feature = "swaps")]
		assert_eq!(ELECTRUM_TX_STATUS_BUDGET, Duration::from_secs(2 * 254 + 1));
	}

	/// An incremental question is refused before the server is asked — with
	/// a reason that says so, distinct from "not started" — and a complete
	/// one over a chain source that has not started is unavailable, never an
	/// empty mempool.
	#[tokio::test]
	async fn electrum_mempool_answers_complete_questions_only() {
		let adapter = ElectrumChainAdapter::new(
			Arc::new(RwLock::new(ElectrumRuntimeStatus::new())),
			Arc::new(Logger::new_log_facade()),
		);
		let incremental = MempoolQuery {
			scripts: Vec::new(),
			known_unconfirmed: Vec::new(),
			scope: MempoolScope::Incremental { best_processed_height: 7 },
		};
		let complete = MempoolQuery { scope: MempoolScope::Complete, ..incremental.clone() };

		let err = adapter.mempool(&incremental).await.unwrap_err();
		assert!(
			matches!(&err, ChainActionError::Unavailable { reason, timed_out: false } if reason.contains("complete")),
			"{}",
			err
		);
		let err = adapter.mempool(&complete).await.unwrap_err();
		assert_eq!(err, ChainActionError::unavailable("chain source not started"));
	}
}
