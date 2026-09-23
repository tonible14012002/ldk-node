// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Electrum-backed chain ability adapters.

use std::sync::{Arc, RwLock};

use bitcoin::Transaction;

use crate::chain::electrum::ElectrumRuntimeClient;
use crate::chain::seam::{ActionResult, BroadcastAdapter, ChainActionError, FeeAction, FeeUpdate};
use crate::chain::ElectrumRuntimeStatus;
use crate::logger::Logger;
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::seam::{Anchored, TxStatusAction};
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use crate::logger::{log_error, LdkLogger};
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

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
	/// timeout and completeness policy.
	async fn fetch_fee_rate_update(&self) -> Result<FeeUpdate, Error> {
		let electrum_client: Arc<ElectrumRuntimeClient> = if let Some(client) =
			self.runtime_status.read().unwrap().client().as_ref()
		{
			Arc::clone(client)
		} else {
			debug_assert!(false, "We should have started the chain source before updating fees");
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
				return Err(ChainActionError::Unavailable(
					"no watched scriptPubKey for the txid".to_string(),
				));
			},
		};
		let client = match self.client() {
			Some(client) => client,
			None => {
				log_error!(self.logger, "swap_query_tx: Electrum chain source not started");
				return Err(ChainActionError::Unavailable("chain source not started".to_string()));
			},
		};
		match client.swap_query_tx(txid, script_pubkey).await {
			// The client has already logged why.
			RawTxObservation::Unreachable => {
				Err(ChainActionError::Unavailable("Electrum query failed".to_string()))
			},
			value => Ok(Anchored { value, tip: None }),
		}
	}
}

#[async_trait]
impl BroadcastAdapter for ElectrumChainAdapter {
	fn name(&self) -> &'static str {
		"electrum"
	}

	/// Pre-seam this check sat before the drain loop and returned early from
	/// the whole pass. `process_broadcast_queue` runs once a second, so this is
	/// the same behaviour: skip this pass, try again on the next tick.
	async fn ready(&self) -> bool {
		if self.client().is_some() {
			return true;
		}
		debug_assert!(false, "We should have started the chain source before broadcasting");
		false
	}

	async fn broadcast_tx(&self, tx: &Transaction) {
		// The Electrum client owns its own timeout and logging, and takes the
		// transaction by value; the clone is the one cost of the shared
		// by-reference slot contract.
		if let Some(client) = self.client() {
			client.broadcast(tx.clone()).await;
		}
	}
}
