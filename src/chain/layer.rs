// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The chain ability seam.
//!
//! [`ChainLayer`] is the single entry point the rest of the crate uses to reach
//! the Bitcoin chain. The three chain *abilities* — fee estimation, lookup and
//! broadcast — each occupy a slot that one adapter fills, and the wallet sync
//! engine is a separate explicit axis.
//!
//! Nothing outside slot construction branches on which backend is configured.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use lightning::chain::{Filter, WatchedOutput};

use bitcoin::{Script, ScriptBuf, Txid};

use lightning_block_sync::gossip::UtxoSource;
use lightning_transaction_sync::EsploraSyncClient;

use crate::chain::adapters::bitcoind::BitcoindChainAdapter;
use crate::chain::adapters::electrum::ElectrumChainAdapter;
use crate::chain::adapters::esplora::EsploraChainAdapter;
use crate::chain::bitcoind::{BitcoindClient, BoundedHeaderCache};
use crate::chain::engine::bitcoind::BitcoindSyncEngine;
use crate::chain::engine::electrum::ElectrumSyncEngine;
use crate::chain::engine::esplora::EsploraSyncEngine;
use crate::chain::engine::SyncEngine;
use crate::chain::seam::{BroadcastAdapter, FeeAdapter, FeeUpdate, LookupAdapter};
use crate::chain::{ElectrumRuntimeStatus, WalletSyncStatus, DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS};
use crate::config::{BitcoindRestClientConfig, Config, ElectrumSyncConfig, EsploraSyncConfig};
use crate::fee_estimator::OnchainFeeEstimator;
use crate::io::utils::write_node_metrics;
use crate::logger::{log_info, LdkLogger, Logger};
use crate::types::{Broadcaster, ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;

/// Which adapter is serving each slot.
pub(crate) struct ChainSlotAdapters {
	pub(crate) fee: &'static str,
	pub(crate) lookup: &'static str,
	pub(crate) broadcast: &'static str,
	pub(crate) engine: &'static str,
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
	/// Wallet synchronisation. A separate axis, not one of the slots.
	engine: Arc<dyn SyncEngine>,
	/// State shared by every slot's tail. Held once, rather than duplicated
	/// into each backend as it was pre-seam.
	shared: SharedChainCtx,
}

impl ChainLayer {
	fn new(
		fee: Arc<dyn FeeAdapter>, lookup: Arc<dyn LookupAdapter>,
		broadcast: Arc<dyn BroadcastAdapter>, engine: Arc<dyn SyncEngine>,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, logger: Arc<Logger>, node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		Self {
			fee,
			lookup,
			broadcast,
			engine,
			shared: SharedChainCtx {
				fee_estimator,
				tx_broadcaster,
				kv_store,
				logger,
				node_metrics,
			},
		}
	}

	pub(crate) fn new_esplora(
		server_url: String, sync_config: EsploraSyncConfig, onchain_wallet: Arc<Wallet>,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		// FIXME / TODO: We introduced this to make `bdk_esplora` work separately without updating
		// `lightning-transaction-sync`. We should revert this as part of of the upgrade to LDK 0.2.
		let mut client_builder_0_11 = esplora_client_0_11::Builder::new(&server_url);
		client_builder_0_11 = client_builder_0_11.timeout(DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS);
		let esplora_client_0_11 = client_builder_0_11.build_async().unwrap();
		let tx_sync =
			Arc::new(EsploraSyncClient::from_client(esplora_client_0_11, Arc::clone(&logger)));

		let mut client_builder = esplora_client::Builder::new(&server_url);
		client_builder = client_builder.timeout(DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS);
		let esplora_client = client_builder.build_async().unwrap();

		let adapter = Arc::new(EsploraChainAdapter::new(
			esplora_client.clone(),
			Arc::clone(&config),
			Arc::clone(&logger),
		));

		let engine = Arc::new(EsploraSyncEngine {
			sync_config,
			esplora_client,
			onchain_wallet,
			onchain_wallet_sync_status: Mutex::new(WalletSyncStatus::Completed),
			tx_sync,
			lightning_wallet_sync_status: Mutex::new(WalletSyncStatus::Completed),
			kv_store: Arc::clone(&kv_store),
			logger: Arc::clone(&logger),
			node_metrics: Arc::clone(&node_metrics),
		});

		Self::new(
			Arc::clone(&adapter) as Arc<dyn FeeAdapter>,
			Arc::clone(&adapter) as Arc<dyn LookupAdapter>,
			adapter as Arc<dyn BroadcastAdapter>,
			engine,
			fee_estimator,
			tx_broadcaster,
			kv_store,
			logger,
			node_metrics,
		)
	}

	pub(crate) fn new_electrum(
		server_url: String, sync_config: ElectrumSyncConfig, onchain_wallet: Arc<Wallet>,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		let electrum_runtime_status = Arc::new(RwLock::new(ElectrumRuntimeStatus::new()));

		let adapter = Arc::new(ElectrumChainAdapter::new(
			Arc::clone(&electrum_runtime_status),
			Arc::clone(&logger),
		));

		let engine = Arc::new(ElectrumSyncEngine {
			server_url,
			sync_config,
			electrum_runtime_status,
			onchain_wallet,
			onchain_wallet_sync_status: Mutex::new(WalletSyncStatus::Completed),
			lightning_wallet_sync_status: Mutex::new(WalletSyncStatus::Completed),
			kv_store: Arc::clone(&kv_store),
			config,
			logger: Arc::clone(&logger),
			node_metrics: Arc::clone(&node_metrics),
		});

		Self::new(
			Arc::clone(&adapter) as Arc<dyn FeeAdapter>,
			Arc::clone(&adapter) as Arc<dyn LookupAdapter>,
			adapter as Arc<dyn BroadcastAdapter>,
			engine,
			fee_estimator,
			tx_broadcaster,
			kv_store,
			logger,
			node_metrics,
		)
	}

	pub(crate) fn new_bitcoind_rpc(
		rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String,
		onchain_wallet: Arc<Wallet>, fee_estimator: Arc<OnchainFeeEstimator>,
		tx_broadcaster: Arc<Broadcaster>, kv_store: Arc<DynStore>, config: Arc<Config>,
		logger: Arc<Logger>, node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		let api_client =
			Arc::new(BitcoindClient::new_rpc(rpc_host, rpc_port, rpc_user, rpc_password));
		Self::from_bitcoind_client(
			api_client,
			onchain_wallet,
			fee_estimator,
			tx_broadcaster,
			kv_store,
			config,
			logger,
			node_metrics,
		)
	}

	pub(crate) fn new_bitcoind_rest(
		rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String,
		onchain_wallet: Arc<Wallet>, fee_estimator: Arc<OnchainFeeEstimator>,
		tx_broadcaster: Arc<Broadcaster>, kv_store: Arc<DynStore>, config: Arc<Config>,
		rest_client_config: BitcoindRestClientConfig, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		let api_client = Arc::new(BitcoindClient::new_rest(
			rest_client_config.rest_host,
			rest_client_config.rest_port,
			rpc_host,
			rpc_port,
			rpc_user,
			rpc_password,
		));
		Self::from_bitcoind_client(
			api_client,
			onchain_wallet,
			fee_estimator,
			tx_broadcaster,
			kv_store,
			config,
			logger,
			node_metrics,
		)
	}

	#[allow(clippy::too_many_arguments)]
	fn from_bitcoind_client(
		api_client: Arc<BitcoindClient>, onchain_wallet: Arc<Wallet>,
		fee_estimator: Arc<OnchainFeeEstimator>, tx_broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		let latest_chain_tip = Arc::new(RwLock::new(None));

		let adapter = Arc::new(BitcoindChainAdapter::new(
			Arc::clone(&api_client),
			Arc::clone(&latest_chain_tip),
			Arc::clone(&config),
			Arc::clone(&logger),
		));

		let engine = Arc::new(BitcoindSyncEngine {
			api_client,
			header_cache: tokio::sync::Mutex::new(BoundedHeaderCache::new()),
			latest_chain_tip,
			onchain_wallet,
			wallet_polling_status: Mutex::new(WalletSyncStatus::Completed),
			kv_store: Arc::clone(&kv_store),
			config,
			logger: Arc::clone(&logger),
			node_metrics: Arc::clone(&node_metrics),
		});

		Self::new(
			Arc::clone(&adapter) as Arc<dyn FeeAdapter>,
			Arc::clone(&adapter) as Arc<dyn LookupAdapter>,
			adapter as Arc<dyn BroadcastAdapter>,
			engine,
			fee_estimator,
			tx_broadcaster,
			kv_store,
			logger,
			node_metrics,
		)
	}

	/// Which adapter currently occupies each slot. For logs and diagnostics;
	/// nothing may branch on it.
	pub(crate) fn slot_adapters(&self) -> ChainSlotAdapters {
		ChainSlotAdapters {
			fee: self.fee.name(),
			lookup: self.lookup.name(),
			broadcast: self.broadcast.name(),
			engine: self.engine.name(),
			verifies_announcements: self.lookup.utxo_source().is_some(),
		}
	}

	/// Start any runtime-dependent part of the layer (currently Electrum only).
	pub(crate) fn start(&self, runtime: Arc<tokio::runtime::Runtime>) -> Result<(), Error> {
		self.engine.start(runtime)
	}

	pub(crate) fn stop(&self) {
		self.engine.stop()
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
		let engine = Arc::clone(&self.engine);
		engine
			.run_background(
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
	/// Fees first, then the engine — in both engine shapes, exactly as
	/// pre-seam. Which engine is running is the engine's own business; this
	/// does not branch on it.
	pub(crate) async fn sync_wallets_once(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		self.update_fee_rate_estimates().await?;
		self.engine.sync_once(channel_manager, chain_monitor, output_sweeper).await
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
		&self.shared.fee_estimator
	}
}

impl Filter for ChainLayer {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.engine.register_tx(txid, script_pubkey)
	}

	fn register_output(&self, output: WatchedOutput) {
		self.engine.register_output(output)
	}
}
