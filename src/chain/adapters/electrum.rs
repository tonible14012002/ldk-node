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
use crate::chain::seam::{BroadcastAdapter, FeeAdapter, FeeUpdate};
use crate::chain::ElectrumRuntimeStatus;
use crate::Error;

use async_trait::async_trait;

/// Fee estimates from an Electrum server.
///
/// The Electrum client batches all confirmation targets into one call and owns
/// its own timeout and completeness policy, so this adapter is a thin shim over
/// it rather than a per-target loop.
pub(crate) struct ElectrumFeeAdapter {
	runtime_status: Arc<RwLock<ElectrumRuntimeStatus>>,
}

impl ElectrumFeeAdapter {
	pub(crate) fn new(runtime_status: Arc<RwLock<ElectrumRuntimeStatus>>) -> Self {
		Self { runtime_status }
	}

	/// The live client, if the chain source has been started.
	fn client(&self) -> Option<Arc<ElectrumRuntimeClient>> {
		self.runtime_status.read().unwrap().client().as_ref().map(Arc::clone)
	}
}

#[async_trait]
impl FeeAdapter for ElectrumFeeAdapter {
	fn name(&self) -> &'static str {
		"electrum"
	}

	async fn fee_rate_update(&self) -> Result<FeeUpdate, Error> {
		let electrum_client: Arc<ElectrumRuntimeClient> =
			if let Some(client) = self.runtime_status.read().unwrap().client().as_ref() {
				Arc::clone(client)
			} else {
				debug_assert!(
					false,
					"We should have started the chain source before updating fees"
				);
				return Err(Error::FeerateEstimationUpdateFailed);
			};

		let cache = electrum_client.get_fee_rate_cache_update().await?;

		Ok(FeeUpdate::Apply { cache, log_unchanged: true })
	}
}

#[async_trait]
impl BroadcastAdapter for ElectrumFeeAdapter {
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
