// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The block-polling sync engine (bitcoind).
//!
//! Drives `Listen` via `lightning-block-sync`: it downloads blocks, keeps a
//! bounded header cache and a cached best tip, and handles reorgs itself. It
//! registers nothing, because it sees every block regardless.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lightning::chain::Listen;

use lightning_block_sync::init::{synchronize_listeners, validate_best_block_header};
use lightning_block_sync::poll::{ChainPoller, ChainTip, ValidatedBlockHeader};
use lightning_block_sync::{BlockSourceErrorKind, SpvClient};

use crate::chain::bitcoind::{BitcoindClient, BoundedHeaderCache, ChainListener};
use crate::chain::engine::SyncEngine;
use crate::chain::{ChainLayer, WalletSyncStatus, CHAIN_POLLING_INTERVAL_SECS};
use crate::config::Config;
use crate::io::utils::write_node_metrics;
use crate::logger::{log_error, log_info, log_trace, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

use async_trait::async_trait;

pub(crate) struct BitcoindSyncEngine {
	pub(crate) api_client: Arc<BitcoindClient>,
	pub(crate) header_cache: tokio::sync::Mutex<BoundedHeaderCache>,
	pub(crate) latest_chain_tip: Arc<RwLock<Option<ValidatedBlockHeader>>>,
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) wallet_polling_status: Mutex<WalletSyncStatus>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) config: Arc<Config>,
	pub(crate) logger: Arc<Logger>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
}

#[async_trait]
impl SyncEngine for BitcoindSyncEngine {
	fn name(&self) -> &'static str {
		"bitcoind-block-poll"
	}

	async fn sync_once(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		let Self {
			api_client,
			header_cache,
			latest_chain_tip,
			onchain_wallet,
			wallet_polling_status,
			kv_store,
			config,
			logger,
			node_metrics,
			..
		} = self;
		let receiver_res = {
			let mut status_lock = wallet_polling_status.lock().unwrap();
			status_lock.register_or_subscribe_pending_sync()
		};

		if let Some(mut sync_receiver) = receiver_res {
			log_info!(logger, "Sync in progress, skipping.");
			return sync_receiver.recv().await.map_err(|e| {
				debug_assert!(false, "Failed to receive wallet polling result: {:?}", e);
				log_error!(logger, "Failed to receive wallet polling result: {:?}", e);
				Error::WalletOperationFailed
			})?;
		}

		let latest_chain_tip_opt = latest_chain_tip.read().unwrap().clone();
		let chain_tip = if let Some(tip) = latest_chain_tip_opt {
			tip
		} else {
			match validate_best_block_header(api_client.as_ref()).await {
				Ok(tip) => {
					*latest_chain_tip.write().unwrap() = Some(tip);
					tip
				},
				Err(e) => {
					log_error!(logger, "Failed to poll for chain data: {:?}", e);
					let res = Err(Error::TxSyncFailed);
					wallet_polling_status.lock().unwrap().propagate_result_to_subscribers(res);
					return res;
				},
			}
		};

		let mut locked_header_cache = header_cache.lock().await;
		let chain_poller = ChainPoller::new(Arc::clone(&api_client), config.network);
		let chain_listener = ChainListener {
			onchain_wallet: Arc::clone(&onchain_wallet),
			channel_manager: Arc::clone(&channel_manager),
			chain_monitor,
			output_sweeper,
		};
		let mut spv_client =
			SpvClient::new(chain_tip, chain_poller, &mut *locked_header_cache, &chain_listener);

		let now = SystemTime::now();
		match spv_client.poll_best_tip().await {
			Ok((ChainTip::Better(tip), true)) => {
				log_trace!(
					logger,
					"Finished polling best tip in {}ms",
					now.elapsed().unwrap().as_millis()
				);
				*latest_chain_tip.write().unwrap() = Some(tip);
			},
			Ok(_) => {},
			Err(e) => {
				log_error!(logger, "Failed to poll for chain data: {:?}", e);
				let res = Err(Error::TxSyncFailed);
				wallet_polling_status.lock().unwrap().propagate_result_to_subscribers(res);
				return res;
			},
		}

		let cur_height = channel_manager.current_best_block().height;

		let now = SystemTime::now();
		let unconfirmed_txids = onchain_wallet.get_unconfirmed_txids();
		match api_client.get_updated_mempool_transactions(cur_height, unconfirmed_txids).await {
			Ok((unconfirmed_txs, evicted_txids)) => {
				log_trace!(
					logger,
					"Finished polling mempool of size {} and {} evicted transactions in {}ms",
					unconfirmed_txs.len(),
					evicted_txids.len(),
					now.elapsed().unwrap().as_millis()
				);
				onchain_wallet.apply_mempool_txs(unconfirmed_txs, evicted_txids).unwrap_or_else(
					|e| {
						log_error!(logger, "Failed to apply mempool transactions: {:?}", e);
					},
				);
			},
			Err(e) => {
				log_error!(logger, "Failed to poll for mempool transactions: {:?}", e);
				let res = Err(Error::TxSyncFailed);
				wallet_polling_status.lock().unwrap().propagate_result_to_subscribers(res);
				return res;
			},
		}

		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		let mut locked_node_metrics = node_metrics.write().unwrap();
		locked_node_metrics.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
		locked_node_metrics.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;

		let write_res =
			write_node_metrics(&*locked_node_metrics, Arc::clone(&kv_store), Arc::clone(&logger));
		match write_res {
			Ok(()) => (),
			Err(e) => {
				log_error!(logger, "Failed to persist node metrics: {}", e);
				let res = Err(Error::PersistenceFailed);
				wallet_polling_status.lock().unwrap().propagate_result_to_subscribers(res);
				return res;
			},
		}

		let res = Ok(());
		wallet_polling_status.lock().unwrap().propagate_result_to_subscribers(res);
		res
	}

	async fn run_background(
		&self, layer: Arc<ChainLayer>, mut stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) {
		let Self {
			api_client,
			header_cache,
			latest_chain_tip,
			onchain_wallet,
			wallet_polling_status,
			kv_store,
			config,
			logger,
			node_metrics,
			..
		} = self;
		// First register for the wallet polling status to make sure `Node::sync_wallets` calls
		// wait on the result before proceeding.
		{
			let mut status_lock = wallet_polling_status.lock().unwrap();
			if status_lock.register_or_subscribe_pending_sync().is_some() {
				debug_assert!(false, "Sync already in progress. This should never happen.");
			}
		}

		log_info!(
			logger,
			"Starting initial synchronization of chain listeners. This might take a while..",
		);

		let mut backoff = CHAIN_POLLING_INTERVAL_SECS;
		const MAX_BACKOFF_SECS: u64 = 300;

		loop {
			let channel_manager_best_block_hash = channel_manager.current_best_block().block_hash;
			let sweeper_best_block_hash = output_sweeper.current_best_block().block_hash;
			let onchain_wallet_best_block_hash = onchain_wallet.current_best_block().block_hash;

			let mut chain_listeners = vec![
				(onchain_wallet_best_block_hash, &**onchain_wallet as &(dyn Listen + Send + Sync)),
				(channel_manager_best_block_hash, &*channel_manager as &(dyn Listen + Send + Sync)),
				(sweeper_best_block_hash, &*output_sweeper as &(dyn Listen + Send + Sync)),
			];

			// TODO: Eventually we might want to see if we can synchronize `ChannelMonitor`s
			// before giving them to `ChainMonitor` it the first place. However, this isn't
			// trivial as we load them on initialization (in the `Builder`) and only gain
			// network access during `start`. For now, we just make sure we get the worst known
			// block hash and sychronize them via `ChainMonitor`.
			if let Some(worst_channel_monitor_block_hash) = chain_monitor
				.list_monitors()
				.iter()
				.flat_map(|(txo, _)| chain_monitor.get_monitor(*txo))
				.map(|m| m.current_best_block())
				.min_by_key(|b| b.height)
				.map(|b| b.block_hash)
			{
				chain_listeners.push((
					worst_channel_monitor_block_hash,
					&*chain_monitor as &(dyn Listen + Send + Sync),
				));
			}

			let mut locked_header_cache = header_cache.lock().await;
			let now = SystemTime::now();
			match synchronize_listeners(
				api_client.as_ref(),
				config.network,
				&mut *locked_header_cache,
				chain_listeners.clone(),
			)
			.await
			{
				Ok(chain_tip) => {
					{
						log_info!(
							logger,
							"Finished synchronizing listeners in {}ms",
							now.elapsed().unwrap().as_millis()
						);
						*latest_chain_tip.write().unwrap() = Some(chain_tip);
						let unix_time_secs_opt =
							SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
						let mut locked_node_metrics = node_metrics.write().unwrap();
						locked_node_metrics.latest_lightning_wallet_sync_timestamp =
							unix_time_secs_opt;
						locked_node_metrics.latest_onchain_wallet_sync_timestamp =
							unix_time_secs_opt;
						write_node_metrics(
							&*locked_node_metrics,
							Arc::clone(&kv_store),
							Arc::clone(&logger),
						)
						.unwrap_or_else(|e| {
							log_error!(logger, "Failed to persist node metrics: {}", e);
						});
					}
					break;
				},

				Err(e) => {
					log_error!(logger, "Failed to synchronize chain listeners: {:?}", e);
					if e.kind() == BlockSourceErrorKind::Transient {
						log_info!(
								logger,
								"Transient error syncing chain listeners: {:?}. Retrying in {} seconds.",
								e,
								backoff
							);
						tokio::time::sleep(Duration::from_secs(backoff)).await;
						backoff = std::cmp::min(backoff * 2, MAX_BACKOFF_SECS);
					} else {
						log_error!(
								logger,
								"Persistent error syncing chain listeners: {:?}. Retrying in {} seconds.",
								e,
								MAX_BACKOFF_SECS
							);
						tokio::time::sleep(Duration::from_secs(MAX_BACKOFF_SECS)).await;
					}
				},
			}
		}

		// Now propagate the initial result to unblock waiting subscribers.
		wallet_polling_status.lock().unwrap().propagate_result_to_subscribers(Ok(()));

		let mut chain_polling_interval =
			tokio::time::interval(Duration::from_secs(CHAIN_POLLING_INTERVAL_SECS));
		chain_polling_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		let mut fee_rate_update_interval =
			tokio::time::interval(Duration::from_secs(CHAIN_POLLING_INTERVAL_SECS));
		// When starting up, we just blocked on updating, so skip the first tick.
		fee_rate_update_interval.reset();
		fee_rate_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		log_info!(logger, "Starting continuous polling for chain updates.");

		// Start the polling loop.
		loop {
			tokio::select! {
				_ = stop_sync_receiver.changed() => {
					log_trace!(
						logger,
						"Stopping polling for new chain data.",
					);
					return;
				}
				_ = chain_polling_interval.tick() => {
					let _ = self.sync_once(Arc::clone(&channel_manager), Arc::clone(&chain_monitor), Arc::clone(&output_sweeper)).await;
				}
				_ = fee_rate_update_interval.tick() => {
					let _ = layer.update_fee_rate_estimates().await;
				}
			}
		}
	}
}
