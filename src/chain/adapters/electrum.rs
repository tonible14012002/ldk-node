// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Electrum-backed chain ability adapters.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::Transaction;

use crate::chain::electrum::ElectrumRuntimeClient;
use crate::chain::seam::{
	package_result, ActionResult, BroadcastAction, BroadcastRejection, ChainActionError, FeeAction,
	FeeUpdate, ADAPTER_BUDGET_MARGIN, PER_TX_BROADCAST_BUDGET,
};
use crate::chain::ElectrumRuntimeStatus;
use crate::config::FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS;
use crate::logger::Logger;
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::electrum::{ELECTRUM_CLIENT_NUM_RETRIES, ELECTRUM_CLIENT_TIMEOUT_SECS};
#[cfg(feature = "swaps")]
use crate::chain::seam::{Anchored, TxStatusAction};
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use crate::logger::{log_error, LdkLogger};
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

/// How many times electrum-client (0.23.1, `client.rs` `impl_inner_call!`)
/// sends one call: the first attempt plus one per configured retry, a
/// protocol error excepted (it is returned at once, never retried).
#[cfg(feature = "swaps")]
const ELECTRUM_CLIENT_ATTEMPTS: u64 = ELECTRUM_CLIENT_NUM_RETRIES as u64 + 1;
/// The socket operations one attempt is made of, each under its own
/// `ELECTRUM_CLIENT_TIMEOUT_SECS`: the client sets it as the connect timeout
/// (`connect_with_total_timeout`, shared across the resolved addresses), the
/// write timeout and the read timeout, separately. Connect, request write,
/// response read.
#[cfg(feature = "swaps")]
const ELECTRUM_SOCKET_OPS_PER_ATTEMPT: u64 = 3;
/// electrum-client's reconnect sleep: before rebuilding the connection for
/// retry `n` it sleeps `min(2^n, 30)` seconds, n counted from 1.
#[cfg(feature = "swaps")]
const ELECTRUM_RECONNECT_SLEEP_CAP_SECS: u64 = 30;

/// The reconnect sleeps of one call that uses every retry: 2 + 4 + 8 s for
/// the three the client is built with.
#[cfg(feature = "swaps")]
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
#[cfg(feature = "swaps")]
const ELECTRUM_CALL_BOUND_SECS: u64 = ELECTRUM_CLIENT_ATTEMPTS
	* ELECTRUM_SOCKET_OPS_PER_ATTEMPT
	* (ELECTRUM_CLIENT_TIMEOUT_SECS as u64)
	+ electrum_reconnect_sleeps_secs(ELECTRUM_CLIENT_NUM_RETRIES as u64);

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
	#[cfg_attr(not(feature = "swaps"), allow(dead_code))] // read by TX_STATUS only
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

/// The Electrum client answers from a script-hash history and reports the tip
/// as a bare height, so no observation it produces can be anchored: `tip` is
/// always `None`.
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
		match client.swap_query_tx(txid, script_pubkey).await {
			// The client has already logged why. It folds every failure —
			// socket timeout included — into `Unreachable` without saying
			// which, so no timeout can be claimed here.
			RawTxObservation::Unreachable => {
				Err(ChainActionError::unavailable("Electrum query failed"))
			},
			value => Ok(Anchored { value, tip: None }),
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
	async fn broadcast_package(&self, txs: &[Transaction]) -> ActionResult<(), BroadcastRejection> {
		let Some(client) = self.client() else {
			return Err(ChainActionError::unavailable("chain source not started"));
		};
		let mut outcomes = Vec::with_capacity(txs.len());
		for tx in txs {
			outcomes.push((tx.compute_txid(), client.broadcast(tx.clone()).await));
		}
		package_result(outcomes)
	}
}

#[cfg(all(test, feature = "swaps"))]
mod tests {
	use super::*;

	/// The retry arithmetic the TX_STATUS budget rests on, spelled out.
	#[test]
	fn tx_status_budget_covers_the_clients_retry_and_reconnect_path() {
		// Sleeps of 2, 4 and 8 s before each of the three reconnects.
		assert_eq!(electrum_reconnect_sleeps_secs(3), 2 + 4 + 8);
		// The per-reconnect sleep caps at 30 s: 2 + 4 + 8 + 16 + 30 + 30.
		assert_eq!(electrum_reconnect_sleeps_secs(6), 2 + 4 + 8 + 16 + 30 + 30);
		assert_eq!(electrum_reconnect_sleeps_secs(0), 0);
		// 4 attempts × (connect + write + read) × 20 s + the sleeps.
		assert_eq!(ELECTRUM_CALL_BOUND_SECS, 4 * 3 * 20 + 14);
		// Two calls plus the 1 s margin.
		assert_eq!(ELECTRUM_TX_STATUS_BUDGET, Duration::from_secs(2 * 254 + 1));
	}
}
