// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Chain ability adapters for a node with no chain source of its own.
//!
//! All three slots are filled from a single [`ChainDataProvider`]: the node
//! asks another node and believes the answer. There is no verification step
//! here and that is the design — a Dependent node that could check the answer
//! would not need to ask.
//!
//! What it does *not* do is pretend. Every path below distinguishes "the
//! provider said no" from "I could not ask", because the second is not
//! evidence of anything.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::{FeeRate, Transaction};

use lightning_block_sync::gossip::UtxoSource;

use crate::chain::provider::{
	ChainDataProvider, ChainProviderError, WireBroadcastRequest, CHAIN_WIRE_VERSION,
};
use crate::chain::seam::{BroadcastAdapter, FeeAdapter, FeeUpdate, LookupAdapter};
use crate::chain::wire_convert::{check_version, tx_to_wire};
use crate::fee_estimator::{apply_post_estimation_adjustments, conf_target_from_wire_name};
use crate::logger::{log_error, log_trace, LdkLogger, Logger};
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::provider::WireTxStatusRequest;
#[cfg(feature = "swaps")]
use crate::chain::wire_convert::{script_to_wire, txid_to_wire};
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

/// Fills the FEE, LOOKUP and BROADCAST slots from a remote node.
pub(crate) struct DependentChainAdapter {
	provider: Arc<dyn ChainDataProvider>,
	logger: Arc<Logger>,
}

impl DependentChainAdapter {
	pub(crate) fn new(provider: Arc<dyn ChainDataProvider>, logger: Arc<Logger>) -> Self {
		Self { provider, logger }
	}
}

#[async_trait]
impl FeeAdapter for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	async fn fee_rate_update(&self) -> Result<FeeUpdate, Error> {
		let estimates = self.provider.fee_estimates().await.map_err(|e| {
			log_error!(self.logger, "Failed to retrieve fee rate estimates from provider: {}", e);
			match e {
				ChainProviderError::Unreachable(_) => Error::FeerateEstimationUpdateTimeout,
				_ => Error::FeerateEstimationUpdateFailed,
			}
		})?;

		check_version(estimates.version).map_err(|e| {
			log_error!(self.logger, "Rejecting fee rate estimates from provider: {}", e);
			Error::FeerateEstimationUpdateFailed
		})?;

		let mut new_fee_rate_cache = HashMap::with_capacity(estimates.targets.len());
		for entry in &estimates.targets {
			let Some(target) = conf_target_from_wire_name(&entry.target) else {
				// A target this build does not know. Skipping it is right —
				// guessing which local target it meant would silently apply
				// the wrong rate — but it must be visible.
				log_trace!(
					self.logger,
					"Ignoring unknown confirmation target '{}' from chain provider",
					entry.target
				);
				continue;
			};

			// The serving node has already applied its own per-target policy;
			// the post-estimation adjustments are this node's own floors and
			// caps, so they still belong here.
			let fee_rate = FeeRate::from_sat_per_kwu(entry.sat_per_kwu);
			new_fee_rate_cache.insert(target, apply_post_estimation_adjustments(target, fee_rate));
		}

		// An empty cache would leave every target at its hardcoded fallback
		// while looking like a successful update, so refuse it outright.
		if new_fee_rate_cache.is_empty() {
			log_error!(
				self.logger,
				"Chain provider returned no usable fee rate estimates; keeping the previous cache"
			);
			return Err(Error::FeerateEstimationUpdateFailed);
		}

		Ok(FeeUpdate::Apply { cache: new_fee_rate_cache, log_unchanged: false })
	}
}

#[async_trait]
impl BroadcastAdapter for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	async fn broadcast_tx(&self, tx: &Transaction) {
		let txid = tx.compute_txid();
		let req = WireBroadcastRequest { version: CHAIN_WIRE_VERSION, tx_hex: tx_to_wire(tx) };

		// Broadcast is lossy by contract: a failure here is logged and
		// dropped, never propagated. See `BroadcastAdapter`.
		match self.provider.broadcast(req).await {
			Ok(()) => {
				log_trace!(
					self.logger,
					"Chain provider accepted transaction {} for broadcast",
					txid
				);
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Chain provider failed to broadcast transaction {}: {}",
					txid,
					e
				);
			},
		}
	}
}

#[async_trait]
impl LookupAdapter for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	#[cfg(feature = "swaps")]
	async fn tx_status(&self, txid: Txid, script_pubkey: Option<&ScriptBuf>) -> RawTxObservation {
		let req = WireTxStatusRequest {
			version: CHAIN_WIRE_VERSION,
			txid: txid_to_wire(&txid),
			script_hex: script_pubkey.map(script_to_wire),
		};

		let resp = match self.provider.tx_status(req).await {
			Ok(resp) => resp,
			Err(e) => {
				// FAIL CLOSED (E6). No answer is not the same as "not
				// confirmed", and callers arm CSV deadlines off this.
				log_error!(
					self.logger,
					"swap_query_tx: chain provider could not answer for {}: {}",
					txid,
					e
				);
				return RawTxObservation::Unreachable;
			},
		};

		if check_version(resp.version).is_err() {
			log_error!(
				self.logger,
				"swap_query_tx: chain provider answered for {} with wire version {} (expected {}); failing closed",
				txid,
				resp.version,
				CHAIN_WIRE_VERSION
			);
			return RawTxObservation::Unreachable;
		}

		if !resp.confirmed {
			return if resp.in_mempool {
				RawTxObservation::InMempool
			} else {
				RawTxObservation::NotFound
			};
		}

		// Confirmed, so the answer must carry a height and a tip to derive
		// depth from. A confirmation without them is incoherent; treat it as
		// no answer rather than inventing a depth.
		let (Some(height), Some(tip_height)) = (resp.confirmation_height, resp.tip_height) else {
			log_error!(
				self.logger,
				"swap_query_tx: chain provider reported {} confirmed without a height/tip pair; failing closed",
				txid
			);
			return RawTxObservation::Unreachable;
		};

		if tip_height < height {
			// The same inconsistency the Esplora adapter guards against (B5
			// LOW-2): a tip below the confirming block cannot happen on one
			// consistent chain.
			log_error!(
				self.logger,
				"swap_query_tx: chain provider tip {} below confirming-block height {} for {} (reorg/race); failing closed",
				tip_height,
				height,
				txid
			);
			return RawTxObservation::Unreachable;
		}

		let confirmations = tip_height.saturating_sub(height).saturating_add(1);
		RawTxObservation::Confirmed { height: Some(height), confirmations }
	}

	/// A Dependent node cannot verify BOLT-7 channel announcements.
	///
	/// It could ask its provider to check the UTXO set, but an announcement
	/// "verified" by asking the same node that supplied it is not verified.
	/// Declaring `None` makes the node log, at startup, that its routing graph
	/// carries unchecked capacities — which is the honest position.
	fn utxo_source(&self) -> Option<Arc<dyn UtxoSource>> {
		None
	}
}
