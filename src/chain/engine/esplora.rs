// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The transaction-based sync engine backed by Esplora.
//!
//! Drives `Confirm` via `lightning-transaction-sync`, so it must be told which
//! transactions and outputs to watch — hence the `Filter` registrations.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::{Script, Txid};

use lightning::chain::{Confirm, Filter, WatchedOutput};

use lightning_transaction_sync::EsploraSyncClient;

use bdk_esplora::EsploraAsyncExt;

use esplora_client::AsyncClient as EsploraAsyncClient;

use crate::chain::engine::{run_tx_based_sync_loop, SyncEngine, TxBasedBackend};
use crate::chain::{periodically_archive_fully_resolved_monitors, ChainLayer, WalletSyncStatus};
use crate::config::{
	EsploraSyncConfig, BDK_CLIENT_CONCURRENCY, BDK_CLIENT_STOP_GAP, BDK_WALLET_SYNC_TIMEOUT_SECS,
	LDK_WALLET_SYNC_TIMEOUT_SECS,
};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

use async_trait::async_trait;

pub(crate) struct EsploraSyncEngine {
	pub(crate) sync_config: EsploraSyncConfig,
	pub(crate) esplora_client: EsploraAsyncClient,
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) onchain_wallet_sync_status: Mutex<WalletSyncStatus>,
	pub(crate) tx_sync: Arc<EsploraSyncClient<Arc<Logger>>>,
	pub(crate) lightning_wallet_sync_status: Mutex<WalletSyncStatus>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) logger: Arc<Logger>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
}

#[async_trait]
impl TxBasedBackend for EsploraSyncEngine {
	async fn sync_onchain_wallet(&self) -> Result<(), Error> {
		let Self {
			esplora_client,
			onchain_wallet,
			onchain_wallet_sync_status,
			kv_store,
			logger,
			node_metrics,
			..
		} = self;
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

		let res = {
			// If this is our first sync, do a full scan with the configured gap limit.
			// Otherwise just do an incremental sync.
			let incremental_sync =
				node_metrics.read().unwrap().latest_onchain_wallet_sync_timestamp.is_some();

			macro_rules! get_and_apply_wallet_update {
					($sync_future: expr) => {{
						let now = Instant::now();
						match $sync_future.await {
							Ok(res) => match res {
								Ok(update) => match onchain_wallet.apply_update(update) {
									Ok(()) => {
										log_info!(
											logger,
											"{} of on-chain wallet finished in {}ms.",
											if incremental_sync { "Incremental sync" } else { "Sync" },
											now.elapsed().as_millis()
											);
										let unix_time_secs_opt = SystemTime::now()
											.duration_since(UNIX_EPOCH)
											.ok()
											.map(|d| d.as_secs());
										{
											let mut locked_node_metrics = node_metrics.write().unwrap();
											locked_node_metrics.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
											write_node_metrics(&*locked_node_metrics, Arc::clone(&kv_store), Arc::clone(&logger))?;
										}
										Ok(())
									},
									Err(e) => Err(e),
								},
								Err(e) => match *e {
									esplora_client::Error::Reqwest(he) => {
										log_error!(
											logger,
											"{} of on-chain wallet failed due to HTTP connection error: {}",
											if incremental_sync { "Incremental sync" } else { "Sync" },
											he
											);
										Err(Error::WalletOperationFailed)
									},
									_ => {
										log_error!(
											logger,
											"{} of on-chain wallet failed due to Esplora error: {}",
											if incremental_sync { "Incremental sync" } else { "Sync" },
											e
										);
										Err(Error::WalletOperationFailed)
									},
								},
							},
							Err(e) => {
								log_error!(
									logger,
									"{} of on-chain wallet timed out: {}",
									if incremental_sync { "Incremental sync" } else { "Sync" },
									e
								);
								Err(Error::WalletOperationTimeout)
							},
						}
					}}
				}

			if incremental_sync {
				let sync_request = onchain_wallet.get_incremental_sync_request();
				let wallet_sync_timeout_fut = tokio::time::timeout(
					Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS),
					esplora_client.sync(sync_request, BDK_CLIENT_CONCURRENCY),
				);
				get_and_apply_wallet_update!(wallet_sync_timeout_fut)
			} else {
				let full_scan_request = onchain_wallet.get_full_scan_request();
				let wallet_sync_timeout_fut = tokio::time::timeout(
					Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS),
					esplora_client.full_scan(
						full_scan_request,
						BDK_CLIENT_STOP_GAP,
						BDK_CLIENT_CONCURRENCY,
					),
				);
				get_and_apply_wallet_update!(wallet_sync_timeout_fut)
			}
		};

		onchain_wallet_sync_status.lock().unwrap().propagate_result_to_subscribers(res);

		res
	}

	async fn sync_lightning_wallet(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		let Self { tx_sync, lightning_wallet_sync_status, kv_store, logger, node_metrics, .. } =
			self;
		let sync_cman = Arc::clone(&channel_manager);
		let sync_cmon = Arc::clone(&chain_monitor);
		let sync_sweeper = Arc::clone(&output_sweeper);
		let confirmables = vec![
			&*sync_cman as &(dyn Confirm + Sync + Send),
			&*sync_cmon as &(dyn Confirm + Sync + Send),
			&*sync_sweeper as &(dyn Confirm + Sync + Send),
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
				Error::WalletOperationFailed
			})?;
		}
		let res = {
			let timeout_fut = tokio::time::timeout(
				Duration::from_secs(LDK_WALLET_SYNC_TIMEOUT_SECS),
				tx_sync.sync(confirmables),
			);
			let now = Instant::now();
			match timeout_fut.await {
				Ok(res) => match res {
					Ok(()) => {
						log_info!(
							logger,
							"Sync of Lightning wallet finished in {}ms.",
							now.elapsed().as_millis()
						);

						let unix_time_secs_opt =
							SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
						{
							let mut locked_node_metrics = node_metrics.write().unwrap();
							locked_node_metrics.latest_lightning_wallet_sync_timestamp =
								unix_time_secs_opt;
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
						Ok(())
					},
					Err(e) => {
						log_error!(logger, "Sync of Lightning wallet failed: {}", e);
						Err(e.into())
					},
				},
				Err(e) => {
					log_error!(logger, "Lightning wallet sync timed out: {}", e);
					Err(Error::TxSyncTimeout)
				},
			}
		};

		lightning_wallet_sync_status.lock().unwrap().propagate_result_to_subscribers(res);

		res
	}
}

#[async_trait]
impl SyncEngine for EsploraSyncEngine {
	fn name(&self) -> &'static str {
		"esplora-tx-sync"
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
		self.tx_sync.register_tx(txid, script_pubkey)
	}

	fn register_output(&self, output: WatchedOutput) {
		self.tx_sync.register_output(output)
	}
}
