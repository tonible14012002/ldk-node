// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The transaction-based sync engine backed by Electrum.
//!
//! Same strategy as the Esplora engine — drives `Confirm` and needs `Filter`
//! registrations — but shares no code with it, because the Electrum client owns
//! its own runtime, batching and timeouts.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bitcoin::{Script, Txid};

use lightning::chain::{Confirm, WatchedOutput};

use bdk_wallet::Update as BdkUpdate;

use crate::chain::electrum::ElectrumRuntimeClient;
use crate::chain::engine::{run_tx_based_sync_loop, SyncEngine, TxBasedBackend};
use crate::chain::{
	periodically_archive_fully_resolved_monitors, ChainLayer, ElectrumRuntimeStatus,
	WalletSyncStatus,
};
use crate::config::{Config, ElectrumSyncConfig};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

use async_trait::async_trait;

pub(crate) struct ElectrumSyncEngine {
	pub(crate) server_url: String,
	pub(crate) sync_config: ElectrumSyncConfig,
	pub(crate) electrum_runtime_status: Arc<RwLock<ElectrumRuntimeStatus>>,
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) onchain_wallet_sync_status: Mutex<WalletSyncStatus>,
	pub(crate) lightning_wallet_sync_status: Mutex<WalletSyncStatus>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) config: Arc<Config>,
	pub(crate) logger: Arc<Logger>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
}

#[async_trait]
impl TxBasedBackend for ElectrumSyncEngine {
	async fn sync_onchain_wallet(&self) -> Result<(), Error> {
		let Self {
			electrum_runtime_status,
			onchain_wallet,
			onchain_wallet_sync_status,
			kv_store,
			logger,
			node_metrics,
			..
		} = self;
		let electrum_client: Arc<ElectrumRuntimeClient> =
			if let Some(client) = electrum_runtime_status.read().unwrap().client().as_ref() {
				Arc::clone(client)
			} else {
				debug_assert!(
					false,
					"We should have started the chain source before syncing the onchain wallet"
				);
				return Err(Error::FeerateEstimationUpdateFailed);
			};
		let receiver_res = {
			let mut status_lock = onchain_wallet_sync_status.lock().unwrap();
			status_lock.register_or_subscribe_pending_sync()
		};
		if let Some(mut sync_receiver) = receiver_res {
			log_info!(logger, "Sync in progress, skipping.");
			return sync_receiver.recv().await.map_err(|e| {
				debug_assert!(false, "Failed to receive wallet sync result: {:?}", e);
				log_error!(logger, "Failed to receive wallet sync result: {:?}", e);
				Error::WalletOperationFailed
			})?;
		}

		// If this is our first sync, do a full scan with the configured gap limit.
		// Otherwise just do an incremental sync.
		let incremental_sync =
			node_metrics.read().unwrap().latest_onchain_wallet_sync_timestamp.is_some();

		let apply_wallet_update =
			|update_res: Result<BdkUpdate, Error>, now: Instant| match update_res {
				Ok(update) => match onchain_wallet.apply_update(update) {
					Ok(()) => {
						log_info!(
							logger,
							"{} of on-chain wallet finished in {}ms.",
							if incremental_sync { "Incremental sync" } else { "Sync" },
							now.elapsed().as_millis()
						);
						let unix_time_secs_opt =
							SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
						{
							let mut locked_node_metrics = node_metrics.write().unwrap();
							locked_node_metrics.latest_onchain_wallet_sync_timestamp =
								unix_time_secs_opt;
							write_node_metrics(
								&*locked_node_metrics,
								Arc::clone(&kv_store),
								Arc::clone(&logger),
							)?;
						}
						Ok(())
					},
					Err(e) => Err(e),
				},
				Err(e) => Err(e),
			};

		let cached_txs = onchain_wallet.get_cached_txs();

		let res = if incremental_sync {
			let incremental_sync_request = onchain_wallet.get_incremental_sync_request();
			let incremental_sync_fut = electrum_client
				.get_incremental_sync_wallet_update(incremental_sync_request, cached_txs);

			let now = Instant::now();
			let update_res = incremental_sync_fut.await.map(|u| u.into());
			apply_wallet_update(update_res, now)
		} else {
			let full_scan_request = onchain_wallet.get_full_scan_request();
			let full_scan_fut =
				electrum_client.get_full_scan_wallet_update(full_scan_request, cached_txs);
			let now = Instant::now();
			let update_res = full_scan_fut.await.map(|u| u.into());
			apply_wallet_update(update_res, now)
		};

		onchain_wallet_sync_status.lock().unwrap().propagate_result_to_subscribers(res);

		res
	}

	async fn sync_lightning_wallet(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		let Self {
			electrum_runtime_status,
			lightning_wallet_sync_status,
			kv_store,
			logger,
			node_metrics,
			..
		} = self;
		let electrum_client: Arc<ElectrumRuntimeClient> =
			if let Some(client) = electrum_runtime_status.read().unwrap().client().as_ref() {
				Arc::clone(client)
			} else {
				debug_assert!(
					false,
					"We should have started the chain source before syncing the lightning wallet"
				);
				return Err(Error::TxSyncFailed);
			};

		let sync_cman = Arc::clone(&channel_manager);
		let sync_cmon = Arc::clone(&chain_monitor);
		let sync_sweeper = Arc::clone(&output_sweeper);
		let confirmables = vec![
			sync_cman as Arc<dyn Confirm + Sync + Send>,
			sync_cmon as Arc<dyn Confirm + Sync + Send>,
			sync_sweeper as Arc<dyn Confirm + Sync + Send>,
		];

		let receiver_res = {
			let mut status_lock = lightning_wallet_sync_status.lock().unwrap();
			status_lock.register_or_subscribe_pending_sync()
		};
		if let Some(mut sync_receiver) = receiver_res {
			log_info!(logger, "Sync in progress, skipping.");
			return sync_receiver.recv().await.map_err(|e| {
				debug_assert!(false, "Failed to receive wallet sync result: {:?}", e);
				log_error!(logger, "Failed to receive wallet sync result: {:?}", e);
				Error::TxSyncFailed
			})?;
		}

		let res = electrum_client.sync_confirmables(confirmables).await;

		if let Ok(_) = res {
			let unix_time_secs_opt =
				SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
			{
				let mut locked_node_metrics = node_metrics.write().unwrap();
				locked_node_metrics.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
				write_node_metrics(
					&*locked_node_metrics,
					Arc::clone(&kv_store),
					Arc::clone(&logger),
				)?;
			}

			periodically_archive_fully_resolved_monitors(
				Arc::clone(&channel_manager),
				Arc::clone(&chain_monitor),
				Arc::clone(&kv_store),
				Arc::clone(&logger),
				Arc::clone(&node_metrics),
			)?;
		}

		lightning_wallet_sync_status.lock().unwrap().propagate_result_to_subscribers(res);

		res
	}
}

#[async_trait]
impl SyncEngine for ElectrumSyncEngine {
	fn name(&self) -> &'static str {
		"electrum-tx-sync"
	}

	fn start(&self, runtime: Arc<tokio::runtime::Runtime>) -> Result<(), Error> {
		self.electrum_runtime_status.write().unwrap().start(
			self.server_url.clone(),
			Arc::clone(&runtime),
			Arc::clone(&self.config),
			Arc::clone(&self.logger),
		)
	}

	fn stop(&self) {
		self.electrum_runtime_status.write().unwrap().stop();
	}

	async fn sync_once(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		// ORDER IS LOAD-BEARING: Lightning wallet before on-chain wallet.
		self.sync_lightning_wallet(channel_manager, chain_monitor, output_sweeper).await?;
		self.sync_onchain_wallet().await?;
		Ok(())
	}

	async fn run_background(
		&self, layer: Arc<ChainLayer>, stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) {
		if let Some(background_sync_config) = self.sync_config.background_sync_config.as_ref() {
			run_tx_based_sync_loop(
				self,
				layer,
				stop_sync_receiver,
				channel_manager,
				chain_monitor,
				output_sweeper,
				background_sync_config,
				Arc::clone(&self.logger),
			)
			.await
		} else {
			// Background syncing is disabled
			log_info!(
				self.logger,
				"Background syncing is disabled. Manual syncing required for onchain wallet, lightning wallet, and fee rate updates.",
			);
		}
	}

	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.electrum_runtime_status.write().unwrap().register_tx(txid, script_pubkey)
	}

	fn register_output(&self, output: WatchedOutput) {
		self.electrum_runtime_status.write().unwrap().register_output(output)
	}
}
