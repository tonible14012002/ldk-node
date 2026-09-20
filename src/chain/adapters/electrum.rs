// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Electrum-backed chain ability adapters.

use std::sync::{Arc, RwLock};

use crate::chain::electrum::ElectrumRuntimeClient;
use crate::chain::seam::{FeeAdapter, FeeUpdate};
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
