// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The sync engine for a node with no chain source of its own.
//!
//! Transaction-based in shape — it registers what it needs watched and drives
//! `Confirm` — so it reuses the shared background loop rather than growing a
//! third one. What differs is where the answers come from: a
//! [`ChainDataProvider`] instead of a local Esplora or Electrum client.
//!
//! # Two syncs, two shapes
//!
//! ```text
//!   on-chain (BDK)    drain the wallet's own SyncRequest -> ask -> apply
//!                     a first sync is a full scan, driven here in bounded
//!                     batches because the serving node cannot derive
//!
//!   lightning (LDK)   ask about everything Confirm still finds relevant,
//!                     plus everything Filter registered, then replay the
//!                     answer in LDK's required order
//! ```
//!
//! # Reorg handling
//!
//! The serving node holds no per-peer state. Reorg detection works because
//! each request carries what *this* node currently believes — the block hash
//! it last saw each transaction confirmed in — so the serving node can answer
//! with the difference. A transaction that moved blocks comes back in
//! `confirmed` with its new block; one that left the chain comes back in
//! `unconfirmed`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::{BlockHash, Script, Txid};

use lightning::chain::{Confirm, WatchedOutput};

use crate::chain::engine::{run_tx_based_sync_loop, SyncEngine, TxBasedBackend};
use crate::chain::provider::{
	ChainDataProvider, WireLightningSyncRequest, WireWatchedOutput, WireWatchedTx,
	CHAIN_WIRE_VERSION,
};
use crate::chain::wire_convert::{
	block_hash_from_wire, check_version, full_scan_request_batch_to_wire, header_from_wire,
	outpoint_to_wire, script_to_wire, sync_request_to_wire, tx_from_wire, txid_from_wire,
	txid_to_wire, wire_update_to_bdk,
};
use crate::chain::{ChainLayer, WalletSyncStatus};
use crate::config::{
	EsploraSyncConfig, BDK_CLIENT_STOP_GAP, BDK_WALLET_SYNC_TIMEOUT_SECS,
	LDK_WALLET_SYNC_TIMEOUT_SECS,
};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_error, log_info, log_trace, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

use async_trait::async_trait;

/// How many scripts one full-scan batch asks about.
///
/// A full scan derives without bound until `stop_gap` consecutive unused
/// addresses appear. The serving node holds none of this wallet's descriptors
/// and so cannot derive; the scan is therefore driven from here, a batch at a
/// time. The batch is a multiple of the gap limit so a typical wallet finishes
/// in one or two round trips.
const FULL_SCAN_BATCH_SPKS: u32 = 100;

/// Ceiling on full-scan batches, so a provider that keeps reporting activity
/// cannot hold a sync open forever.
const FULL_SCAN_MAX_BATCHES: usize = 50;

/// What `Filter` has asked to have watched.
#[derive(Default)]
struct WatchedSet {
	txids: HashSet<Txid>,
	outputs: Vec<WatchedOutput>,
}

pub(crate) struct DependentSyncEngine {
	pub(crate) provider: Arc<dyn ChainDataProvider>,
	pub(crate) sync_config: EsploraSyncConfig,
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) onchain_wallet_sync_status: Mutex<WalletSyncStatus>,
	pub(crate) lightning_wallet_sync_status: Mutex<WalletSyncStatus>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) logger: Arc<Logger>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
	watched: Mutex<WatchedSet>,
	/// The block each tracked transaction was last seen confirmed in. Sent
	/// with every request so the serving node can report only what changed.
	confirmed_in: Mutex<HashMap<Txid, BlockHash>>,
}

impl DependentSyncEngine {
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new(
		provider: Arc<dyn ChainDataProvider>, sync_config: EsploraSyncConfig,
		onchain_wallet: Arc<Wallet>, kv_store: Arc<DynStore>, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		Self {
			provider,
			sync_config,
			onchain_wallet,
			onchain_wallet_sync_status: Mutex::new(WalletSyncStatus::Completed),
			lightning_wallet_sync_status: Mutex::new(WalletSyncStatus::Completed),
			kv_store,
			logger,
			node_metrics,
			watched: Mutex::new(WatchedSet::default()),
			confirmed_in: Mutex::new(HashMap::new()),
		}
	}

	/// Ask the provider to advance the on-chain wallet, and apply the answer.
	async fn run_onchain_sync(&self) -> Result<(), Error> {
		// First sync is a full scan with the configured gap limit; after that,
		// incremental. Same rule as every other engine.
		let incremental_sync =
			self.node_metrics.read().unwrap().latest_onchain_wallet_sync_timestamp.is_some();

		let spk_map = self.onchain_wallet.revealed_spk_index();

		if incremental_sync {
			let request = sync_request_to_wire(self.onchain_wallet.get_incremental_sync_request());
			let wire_update = self.ask_wallet_sync(request).await?;
			let update = wire_update_to_bdk(&wire_update, &spk_map).map_err(|e| {
				log_error!(self.logger, "Chain provider returned an unusable update: {}", e);
				Error::WalletOperationFailed
			})?;
			return self.onchain_wallet.apply_update(update);
		}

		let mut full_scan = self.onchain_wallet.get_full_scan_request();
		for batch in 0..FULL_SCAN_MAX_BATCHES {
			let request = full_scan_request_batch_to_wire(
				&mut full_scan,
				FULL_SCAN_BATCH_SPKS,
				BDK_CLIENT_STOP_GAP as u32,
			);
			if request.spks.is_empty() {
				break;
			}

			let wire_update = self.ask_wallet_sync(request).await?;
			// Every batch is applied as it arrives rather than accumulated:
			// a later batch failing then leaves the wallet with the progress
			// already made instead of discarding all of it.
			let had_activity = !wire_update.txs.is_empty();
			let update = wire_update_to_bdk(&wire_update, &spk_map).map_err(|e| {
				log_error!(self.logger, "Chain provider returned an unusable update: {}", e);
				Error::WalletOperationFailed
			})?;
			self.onchain_wallet.apply_update(update)?;

			if !had_activity {
				// A batch with no activity at all satisfies the gap limit for
				// the scripts it covered.
				break;
			}

			if batch + 1 == FULL_SCAN_MAX_BATCHES {
				log_error!(
					self.logger,
					"Full scan stopped after {} batches with activity still appearing; \
					 the wallet may not be fully scanned",
					FULL_SCAN_MAX_BATCHES
				);
			}
		}

		Ok(())
	}

	async fn ask_wallet_sync(
		&self, request: crate::chain::provider::WireSyncRequest,
	) -> Result<crate::chain::provider::WireUpdate, Error> {
		let fut = tokio::time::timeout(
			Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS),
			self.provider.wallet_sync(request),
		);
		match fut.await {
			Ok(Ok(update)) => {
				check_version(update.version).map_err(|e| {
					log_error!(self.logger, "Rejecting wallet update from provider: {}", e);
					Error::WalletOperationFailed
				})?;
				Ok(update)
			},
			Ok(Err(e)) => {
				log_error!(self.logger, "Sync of on-chain wallet failed: {}", e);
				Err(Error::WalletOperationFailed)
			},
			Err(e) => {
				log_error!(self.logger, "Sync of on-chain wallet timed out: {}", e);
				Err(Error::WalletOperationTimeout)
			},
		}
	}
}

#[async_trait]
impl TxBasedBackend for DependentSyncEngine {
	async fn sync_onchain_wallet(&self) -> Result<(), Error> {
		let receiver_res = {
			let mut status_lock = self.onchain_wallet_sync_status.lock().unwrap();
			status_lock.register_or_subscribe_pending_sync()
		};
		if let Some(mut sync_receiver) = receiver_res {
			log_info!(self.logger, "Sync in progress, skipping.");
			return sync_receiver.recv().await.map_err(|e| {
				debug_assert!(false, "Failed to receive wallet sync result: {:?}", e);
				log_error!(self.logger, "Failed to receive wallet sync result: {:?}", e);
				Error::WalletOperationFailed
			})?;
		}

		let incremental_sync =
			self.node_metrics.read().unwrap().latest_onchain_wallet_sync_timestamp.is_some();
		let now = Instant::now();

		let res = match self.run_onchain_sync().await {
			Ok(()) => {
				log_info!(
					self.logger,
					"{} of on-chain wallet finished in {}ms.",
					if incremental_sync { "Incremental sync" } else { "Sync" },
					now.elapsed().as_millis()
				);
				let unix_time_secs_opt =
					SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
				let mut locked_node_metrics = self.node_metrics.write().unwrap();
				locked_node_metrics.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
				write_node_metrics(
					&*locked_node_metrics,
					Arc::clone(&self.kv_store),
					Arc::clone(&self.logger),
				)
			},
			Err(e) => Err(e),
		};

		self.onchain_wallet_sync_status.lock().unwrap().propagate_result_to_subscribers(res);

		res
	}

	async fn sync_lightning_wallet(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		let receiver_res = {
			let mut status_lock = self.lightning_wallet_sync_status.lock().unwrap();
			status_lock.register_or_subscribe_pending_sync()
		};
		if let Some(mut sync_receiver) = receiver_res {
			log_info!(self.logger, "Sync in progress, skipping.");
			return sync_receiver.recv().await.map_err(|e| {
				debug_assert!(false, "Failed to receive wallet sync result: {:?}", e);
				log_error!(self.logger, "Failed to receive wallet sync result: {:?}", e);
				Error::WalletOperationFailed
			})?;
		}

		let now = Instant::now();
		let confirmables: Vec<&(dyn Confirm + Sync + Send)> = vec![
			&*channel_manager as &(dyn Confirm + Sync + Send),
			&*chain_monitor as &(dyn Confirm + Sync + Send),
			&*output_sweeper as &(dyn Confirm + Sync + Send),
		];

		let res = self.run_lightning_sync(&confirmables).await;

		match res {
			Ok(()) => {
				log_info!(
					self.logger,
					"Sync of Lightning wallet finished in {}ms.",
					now.elapsed().as_millis()
				);
				let unix_time_secs_opt =
					SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
				let mut locked_node_metrics = self.node_metrics.write().unwrap();
				locked_node_metrics.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
				let _ = write_node_metrics(
					&*locked_node_metrics,
					Arc::clone(&self.kv_store),
					Arc::clone(&self.logger),
				);
			},
			Err(ref e) => {
				log_error!(self.logger, "Sync of Lightning wallet failed: {:?}", e);
			},
		}

		self.lightning_wallet_sync_status.lock().unwrap().propagate_result_to_subscribers(res);

		res
	}
}

impl DependentSyncEngine {
	/// Ask about everything being tracked and replay the answer into `Confirm`.
	async fn run_lightning_sync(
		&self, confirmables: &[&(dyn Confirm + Sync + Send)],
	) -> Result<(), Error> {
		// What LDK still considers relevant, plus anything `Filter`
		// registered that has never been seen. The block hash LDK carries is
		// authoritative — it is what a reorg has to be detected against.
		let mut tracked: HashMap<Txid, Option<BlockHash>> = HashMap::new();
		for confirmable in confirmables {
			for (txid, _height, block_hash) in confirmable.get_relevant_txids() {
				tracked.insert(txid, block_hash);
			}
		}

		let (registered_txids, outputs) = {
			let watched = self.watched.lock().unwrap();
			(watched.txids.clone(), watched.outputs.clone())
		};
		for txid in registered_txids {
			tracked.entry(txid).or_insert(None);
		}

		let request = WireLightningSyncRequest {
			version: CHAIN_WIRE_VERSION,
			txids: tracked
				.iter()
				.map(|(txid, block_hash)| WireWatchedTx {
					txid: txid_to_wire(txid),
					known_block_hash: block_hash.map(|h| h.to_string()),
				})
				.collect(),
			outputs: outputs
				.iter()
				.map(|o| WireWatchedOutput {
					outpoint: outpoint_to_wire(&o.outpoint.into_bitcoin_outpoint()),
					script_hex: script_to_wire(&o.script_pubkey),
					block_hash: o.block_hash.map(|h| h.to_string()),
				})
				.collect(),
		};

		let fut = tokio::time::timeout(
			Duration::from_secs(LDK_WALLET_SYNC_TIMEOUT_SECS),
			self.provider.lightning_sync(request),
		);
		let response = match fut.await {
			Ok(Ok(response)) => response,
			Ok(Err(e)) => {
				log_error!(self.logger, "Lightning sync failed: {}", e);
				return Err(Error::TxSyncFailed);
			},
			Err(e) => {
				log_error!(self.logger, "Lightning sync timed out: {}", e);
				return Err(Error::TxSyncTimeout);
			},
		};

		check_version(response.version).map_err(|e| {
			log_error!(self.logger, "Rejecting lightning sync response: {}", e);
			Error::TxSyncFailed
		})?;

		let malformed = |e: crate::chain::provider::ChainProviderError| {
			log_error!(self.logger, "Lightning sync response malformed: {}", e);
			Error::TxSyncFailed
		};

		// LDK's `Confirm` contract is order-sensitive: unconfirmations first,
		// then confirmations in ascending block height, then the new tip. Any
		// other order can leave a monitor believing a transaction is in a
		// block that no longer exists.
		for txid_hex in &response.unconfirmed {
			let txid = txid_from_wire(txid_hex).map_err(malformed)?;
			log_trace!(self.logger, "Transaction {} is no longer confirmed", txid);
			self.confirmed_in.lock().unwrap().remove(&txid);
			for confirmable in confirmables {
				confirmable.transaction_unconfirmed(&txid);
			}
		}

		let mut by_block: Vec<(u32, BlockHash, String, Vec<(usize, bitcoin::Transaction)>)> =
			Vec::new();
		for entry in &response.confirmed {
			let tx = tx_from_wire(&entry.tx_hex).map_err(malformed)?;
			let block_hash = block_hash_from_wire(&entry.block.hash).map_err(malformed)?;
			let height = entry.block.height;

			self.confirmed_in.lock().unwrap().insert(tx.compute_txid(), block_hash);

			match by_block.iter_mut().find(|(h, bh, _, _)| *h == height && *bh == block_hash) {
				Some((_, _, _, txs)) => txs.push((entry.pos_in_block as usize, tx)),
				None => by_block.push((
					height,
					block_hash,
					entry.header_hex.clone(),
					vec![(entry.pos_in_block as usize, tx)],
				)),
			}
		}
		by_block.sort_by_key(|(height, _, _, _)| *height);

		for (height, _block_hash, header_hex, mut txs) in by_block {
			let header = header_from_wire(&header_hex).map_err(malformed)?;
			// Within a block LDK wants them in position order.
			txs.sort_by_key(|(pos, _)| *pos);
			let txdata: Vec<(usize, &bitcoin::Transaction)> =
				txs.iter().map(|(pos, tx)| (*pos, tx)).collect();
			for confirmable in confirmables {
				confirmable.transactions_confirmed(&header, &txdata, height);
			}
		}

		let tip_header = header_from_wire(&response.tip_header_hex).map_err(malformed)?;
		for confirmable in confirmables {
			confirmable.best_block_updated(&tip_header, response.tip.height);
		}

		Ok(())
	}
}

#[async_trait]
impl SyncEngine for DependentSyncEngine {
	fn name(&self) -> &'static str {
		"dependent-tx-sync"
	}

	async fn sync_once(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		// Transaction-based order: Lightning first, then on-chain. Matches
		// the Esplora and Electrum engines.
		self.sync_lightning_wallet(channel_manager, chain_monitor, output_sweeper).await?;
		self.sync_onchain_wallet().await
	}

	async fn run_background(
		&self, layer: Arc<ChainLayer>, stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) {
		let Some(background_sync_config) = self.sync_config.background_sync_config.as_ref() else {
			log_info!(
				self.logger,
				"Background syncing is disabled. Manual syncing required for correct operation."
			);
			return;
		};

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
	}

	fn register_tx(&self, txid: &Txid, _script_pubkey: &Script) {
		self.watched.lock().unwrap().txids.insert(*txid);
	}

	fn register_output(&self, output: WatchedOutput) {
		self.watched.lock().unwrap().outputs.push(output);
	}
}
