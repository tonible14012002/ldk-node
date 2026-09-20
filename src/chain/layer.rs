// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The chain ability seam.
//!
//! [`ChainLayer`] is the single entry point the rest of the crate uses to reach
//! the Bitcoin chain. It exists so the three chain *abilities* — fee estimation,
//! lookup, and broadcast — can each be served by an independently chosen
//! adapter, instead of all three being implied by one closed "which chain source
//! is configured" enum.
//!
//! Phase 1 introduces the type and routes every caller through it while the
//! legacy [`ChainSource`] enum still does the work. Abilities then migrate out of
//! the enum one at a time; the enum is deleted once it is empty. Until then this
//! is deliberately pure indirection: **every method here must behave exactly as
//! the call it replaces.**

use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use lightning::chain::{Filter, WatchedOutput};

use bitcoin::{Script, ScriptBuf, Txid};

use lightning_block_sync::gossip::UtxoSource;

use crate::chain::seam::{BroadcastAdapter, FeeAdapter, FeeUpdate, LookupAdapter};
use crate::chain::ChainSource;
use crate::fee_estimator::OnchainFeeEstimator;
use crate::io::utils::write_node_metrics;
use crate::logger::{log_info, LdkLogger, Logger};
use crate::types::{Broadcaster, ChainMonitor, ChannelManager, DynStore, Sweeper};
use crate::{Error, NodeMetrics};

#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;

/// Which adapter is serving each slot.
pub(crate) struct ChainSlotAdapters {
	pub(crate) fee: &'static str,
	pub(crate) lookup: &'static str,
	pub(crate) broadcast: &'static str,
	/// Whether the lookup slot can verify BOLT-7 channel announcements.
	/// `false` means the routing graph carries unverified capacities.
	pub(crate) verifies_announcements: bool,
}

/// Everything a slot's shared tail needs once its adapter has answered.
pub(crate) struct SharedChainCtx {
	pub(crate) fee_estimator: Arc<OnchainFeeEstimator>,
	pub(crate) tx_broadcaster: Arc<Broadcaster>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) logger: Arc<Logger>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
}

/// The chain layer: the crate's single seam onto Bitcoin.
pub(crate) struct ChainLayer {
	/// SLOT 1 — fee estimation.
	fee: Arc<dyn FeeAdapter>,
	/// SLOT 2 — chain lookup.
	lookup: Arc<dyn LookupAdapter>,
	/// SLOT 3 — transaction broadcast.
	broadcast: Arc<dyn BroadcastAdapter>,
	/// State shared by every slot's tail. Held once, rather than duplicated
	/// into each chain-source variant as it was pre-seam.
	shared: SharedChainCtx,
	/// The pre-seam chain source. Shrinks to nothing as abilities are extracted
	/// into slots, and is removed entirely at the end of Phase 1.
	///
	/// Held behind the `Arc` the builder already constructs purely to keep the
	/// Phase 1 wiring diff minimal; it goes away with the field.
	legacy: Arc<ChainSource>,
}

impl ChainLayer {
	pub(crate) fn new(legacy: Arc<ChainSource>) -> Self {
		let (fee, lookup, broadcast) = legacy.seam_slots();
		let shared = legacy.shared_ctx();
		Self { fee, lookup, broadcast, shared, legacy }
	}

	/// Which adapter currently occupies each slot. For logs and diagnostics;
	/// nothing may branch on it.
	pub(crate) fn slot_adapters(&self) -> ChainSlotAdapters {
		ChainSlotAdapters {
			fee: self.fee.name(),
			lookup: self.lookup.name(),
			broadcast: self.broadcast.name(),
			verifies_announcements: self.lookup.utxo_source().is_some(),
		}
	}

	/// Start any runtime-dependent parts of the layer (currently Electrum only).
	pub(crate) fn start(&self, runtime: Arc<tokio::runtime::Runtime>) -> Result<(), Error> {
		self.legacy.start(runtime)
	}

	pub(crate) fn stop(&self) {
		self.legacy.stop()
	}

	/// The UTXO source used to verify BOLT-7 `channel_announcement`s, if the
	/// configured lookup can serve one. `None` means announcements are accepted
	/// unverified.
	pub(crate) fn as_utxo_source(&self) -> Option<Arc<dyn UtxoSource>> {
		self.lookup.utxo_source()
	}

	pub(crate) async fn continuously_sync_wallets(
		self: Arc<Self>, stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) {
		let legacy = Arc::clone(&self.legacy);
		legacy
			.continuously_sync_wallets(
				self,
				stop_sync_receiver,
				channel_manager,
				chain_monitor,
				output_sweeper,
			)
			.await
	}

	/// Refresh the fee-rate cache from SLOT 1.
	///
	/// The adapter produces the cache; the seam installs it and records that it
	/// happened. Both steps are skipped entirely when the adapter returns
	/// [`FeeUpdate::Skip`], which preserves the pre-seam bitcoind behaviour of
	/// leaving a stale-but-valid cache in place on a soft failure rather than
	/// advancing the metrics timestamp as though an update had landed.
	pub(crate) async fn update_fee_rate_estimates(&self) -> Result<(), Error> {
		let now = Instant::now();

		let (cache, log_unchanged) = match self.fee.fee_rate_update().await? {
			FeeUpdate::Skip => return Ok(()),
			FeeUpdate::Apply { cache, log_unchanged } => (cache, log_unchanged),
		};

		let changed = self.shared.fee_estimator.set_fee_rate_cache(cache);
		if changed || log_unchanged {
			log_info!(
				self.shared.logger,
				"Fee rate cache update finished in {}ms.",
				now.elapsed().as_millis()
			);
		}

		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		{
			let mut locked_node_metrics = self.shared.node_metrics.write().unwrap();
			locked_node_metrics.latest_fee_rate_cache_update_timestamp = unix_time_secs_opt;
			write_node_metrics(
				&*locked_node_metrics,
				Arc::clone(&self.shared.kv_store),
				Arc::clone(&self.shared.logger),
			)?;
		}

		Ok(())
	}

	/// Drain the broadcast queue through SLOT 3.
	///
	/// Called once a second. Failures are logged by the adapter and dropped —
	/// the queue carries no retry semantics, so an error here must never
	/// propagate.
	pub(crate) async fn process_broadcast_queue(&self) {
		if !self.broadcast.ready().await {
			return;
		}

		let mut receiver = self.shared.tx_broadcaster.get_broadcast_queue().await;
		while let Some(next_package) = receiver.recv().await {
			for tx in &next_package {
				self.broadcast.broadcast_tx(tx).await;
			}
		}
	}

	/// One full synchronous sync pass, as triggered by [`crate::Node::sync_wallets`].
	///
	/// The engine choice lives here rather than at the call site: a caller asks
	/// for "sync everything once" and must not need to know which sync
	/// architecture is in play. The per-engine call ORDER is load-bearing and is
	/// reproduced exactly from the pre-seam implementation — in particular the
	/// transaction-based engine syncs the Lightning wallet *before* the on-chain
	/// wallet.
	pub(crate) async fn sync_wallets_once(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		match &*self.legacy {
			ChainSource::Esplora { .. } | ChainSource::Electrum { .. } => {
				self.update_fee_rate_estimates().await?;
				self.legacy
					.sync_lightning_wallet(channel_manager, chain_monitor, output_sweeper)
					.await?;
				self.legacy.sync_onchain_wallet().await?;
			},
			ChainSource::Bitcoind { .. } => {
				self.update_fee_rate_estimates().await?;
				self.legacy
					.poll_and_update_listeners(channel_manager, chain_monitor, output_sweeper)
					.await?;
			},
		}
		Ok(())
	}

	/// Reorg-aware status of a watched transaction (Peerswap native primitive B5).
	#[cfg(feature = "swaps")]
	pub(crate) async fn swap_query_tx(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> RawTxObservation {
		self.lookup.tx_status(txid, script_pubkey).await
	}

	/// The shared on-chain fee estimator (Peerswap native primitive B6).
	#[cfg(feature = "swaps")]
	pub(crate) fn fee_estimator(&self) -> &Arc<OnchainFeeEstimator> {
		self.legacy.fee_estimator()
	}
}

impl Filter for ChainLayer {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.legacy.register_tx(txid, script_pubkey)
	}

	fn register_output(&self, output: WatchedOutput) {
		self.legacy.register_output(output)
	}
}
