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
//!
//! # Serving nodes that scan by block filter
//!
//! A Pro node over bitcoind has no script index; it answers by scanning block
//! filters from where this node left off ([`crate::chain::filter_scan`]). So
//! each request also says where that is — the wallet's checkpoint chain, the
//! Lightning sync's best block — and carries what a filter scan cannot work
//! out alone: the script each watched transaction is registered with, and the
//! wallet's outputs whose spends must be recognised. An index-backed server
//! ignores all three.
//!
//! Such a server caps what one answer scans, and says so: an answer that
//! stopped short of its tip carries that tip as `server_tip`. It is followed
//! at once by another request from where it ended, a bounded number of times
//! per sync; the next sync continues from wherever that left off.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::{BlockHash, Script, ScriptBuf, Txid};

use bdk_chain::BlockId;

use lightning::chain::{BestBlock, Confirm, WatchedOutput};

use crate::chain::engine::{run_tx_based_sync_loop, SyncEngine, TxBasedBackend};
use crate::chain::provider::{
	ChainDataProvider, WireLightningSyncRequest, WireSyncRequest, WireUpdate, WireWatchedOutput,
	WireWatchedTx, CHAIN_WIRE_VERSION,
};
use crate::chain::wire_convert::{
	block_hash_from_wire, block_id_from_wire, block_id_to_wire, check_version,
	full_scan_request_batch_to_wire, header_from_wire, outpoint_to_wire, script_to_wire,
	sync_request_to_wire, tx_from_wire, txid_from_wire, txid_to_wire, wire_update_to_bdk,
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

/// Rounds of on-chain sync one call makes at most, each continuing from
/// where a capped answer stopped.
const ONCHAIN_SYNC_MAX_ROUNDS: usize = 4;

/// Lightning sync passes one call makes at most: a pass is repeated when it
/// may have stopped short of the tip, or when replaying it registered
/// something new — which may have confirmed, or been spent, inside the very
/// blocks the pass covered.
const LIGHTNING_SYNC_MAX_PASSES: usize = 4;

/// How deep a spend of one of the wallet's outputs must be buried before the
/// output is no longer offered to the provider for spend recognition; see
/// [`crate::wallet::Wallet::outpoints_for_spend_watch`].
const SPEND_WATCH_REORG_DEPTH: u32 = 144;

/// Whether an answer that brought this node to `reached` stopped short of
/// the serving node's tip, which it then names.
fn stopped_short(server_tip: Option<&crate::chain::provider::WireBlockId>, reached: u32) -> bool {
	server_tip.is_some_and(|tip| tip.height > reached)
}

/// What `Filter` has asked to have watched.
#[derive(Default)]
struct WatchedSet {
	/// Each transaction with the script it was registered with.
	txids: HashMap<Txid, ScriptBuf>,
	outputs: Vec<WatchedOutput>,
}

impl WatchedSet {
	/// How many registrations there are, to tell whether a pass added any.
	fn len(&self) -> usize {
		self.txids.len() + self.outputs.len()
	}
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
	///
	/// Returns whether the wallet is known to have reached the provider's tip.
	/// A first sync that did not is not recorded as done, so the next one is
	/// a full scan again, from where this one stopped.
	async fn run_onchain_sync(&self) -> Result<bool, Error> {
		// First sync is a full scan with the configured gap limit; after that,
		// incremental. Same rule as every other engine.
		let incremental_sync =
			self.node_metrics.read().unwrap().latest_onchain_wallet_sync_timestamp.is_some();

		for _round in 0..ONCHAIN_SYNC_MAX_ROUNDS {
			let from = self.onchain_wallet.current_best_block().height;
			let server_tip = if incremental_sync {
				let spk_map = self.onchain_wallet.revealed_spk_index();
				let mut request =
					sync_request_to_wire(self.onchain_wallet.get_incremental_sync_request());
				request.owned_outpoints = self.owned_outpoints();
				let wire_update = self.ask_wallet_sync(request).await?;
				self.apply_wallet_update(&wire_update, &spk_map)?;
				wire_update.server_tip
			} else {
				self.run_full_scan().await?
			};
			let reached = self.onchain_wallet.current_best_block().height;
			if !stopped_short(server_tip.as_ref(), reached) {
				return Ok(true);
			}
			log_info!(
				self.logger,
				"On-chain sync advanced from height {} to {} of the provider's {}; continuing",
				from,
				reached,
				server_tip.map(|t| t.height).unwrap_or_default()
			);
		}
		Ok(false)
	}

	/// One full scan, driven here in bounded batches of scripts. Returns the
	/// provider's tip when an answer stopped short of it.
	async fn run_full_scan(&self) -> Result<Option<crate::chain::provider::WireBlockId>, Error> {
		let mut server_tip = None;
		let spk_map = self.onchain_wallet.revealed_spk_index();
		let mut full_scan = self.onchain_wallet.get_full_scan_request();
		for batch in 0..FULL_SCAN_MAX_BATCHES {
			let mut request = full_scan_request_batch_to_wire(
				&mut full_scan,
				FULL_SCAN_BATCH_SPKS,
				BDK_CLIENT_STOP_GAP as u32,
			);
			if request.spks.is_empty() {
				break;
			}
			request.owned_outpoints = self.owned_outpoints();

			let wire_update = self.ask_wallet_sync(request).await?;
			// Every batch is applied as it arrives rather than accumulated:
			// a later batch failing then leaves the wallet with the progress
			// already made instead of discarding all of it.
			let had_activity = !wire_update.txs.is_empty();
			self.apply_wallet_update(&wire_update, &spk_map)?;
			// Every batch scans the same blocks; any one capped means all were.
			server_tip = server_tip.or(wire_update.server_tip);

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
		Ok(server_tip)
	}

	/// The wallet's outputs whose spends a filter-scanning provider must
	/// recognise, in wire form.
	fn owned_outpoints(&self) -> Vec<crate::chain::provider::WireOutPoint> {
		self.onchain_wallet
			.outpoints_for_spend_watch(SPEND_WATCH_REORG_DEPTH)
			.iter()
			.map(outpoint_to_wire)
			.collect()
	}

	fn apply_wallet_update(
		&self, wire_update: &WireUpdate,
		spk_map: &HashMap<ScriptBuf, (bdk_wallet::KeychainKind, u32)>,
	) -> Result<(), Error> {
		let update = wire_update_to_bdk(wire_update, spk_map).map_err(|e| {
			log_error!(self.logger, "Chain provider returned an unusable update: {}", e);
			Error::WalletOperationFailed
		})?;
		self.onchain_wallet.apply_update(update)
	}

	async fn ask_wallet_sync(&self, request: WireSyncRequest) -> Result<WireUpdate, Error> {
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
			Ok(false) if !incremental_sync => {
				// Not recorded as done: the next sync scans on from here.
				log_info!(
					self.logger,
					"First sync of on-chain wallet reached height {} in {}ms and continues next time.",
					self.onchain_wallet.current_best_block().height,
					now.elapsed().as_millis()
				);
				Ok(())
			},
			Ok(_) => {
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

		let res =
			self.run_lightning_sync(&confirmables, channel_manager.current_best_block()).await;

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
	/// Bring `Confirm` up to the provider's tip from `best_block`, the block
	/// it has synced to; see the module docs for why that can take more than
	/// one pass.
	async fn run_lightning_sync(
		&self, confirmables: &[&(dyn Confirm + Sync + Send)], best_block: BestBlock,
	) -> Result<(), Error> {
		let mut scan_from = BlockId { height: best_block.height, hash: best_block.block_hash };
		for _pass in 0..LIGHTNING_SYNC_MAX_PASSES {
			let registered = self.watched.lock().unwrap().len();
			let (tip, server_tip) = self.lightning_sync_pass(confirmables, scan_from).await?;
			if self.watched.lock().unwrap().len() != registered {
				// Replaying the answer registered something: it may have
				// confirmed, or been spent, in the blocks just covered. Ask
				// about the same blocks again; what is already known is
				// skipped or replayed harmlessly.
				log_trace!(
					self.logger,
					"Lightning sync registered new items; covering the same blocks again"
				);
				continue;
			}
			if !stopped_short(server_tip.as_ref(), tip.height) {
				break;
			}
			scan_from = tip;
		}
		Ok(())
	}

	/// Ask about everything being tracked, from `scan_from`, and replay the
	/// answer into `Confirm`. Returns the tip the answer brought `Confirm` to,
	/// and the provider's own tip when that was short of it.
	async fn lightning_sync_pass(
		&self, confirmables: &[&(dyn Confirm + Sync + Send)], scan_from: BlockId,
	) -> Result<(BlockId, Option<crate::chain::provider::WireBlockId>), Error> {
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
		for txid in registered_txids.keys() {
			tracked.entry(*txid).or_insert(None);
		}

		let request = WireLightningSyncRequest {
			version: CHAIN_WIRE_VERSION,
			txids: tracked
				.iter()
				.map(|(txid, block_hash)| WireWatchedTx {
					txid: txid_to_wire(txid),
					known_block_hash: block_hash.map(|h| h.to_string()),
					script_hex: registered_txids.get(txid).map(script_to_wire),
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
			scan_from: Some(block_id_to_wire(&scan_from)),
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
		let tip = block_id_from_wire(&response.tip).map_err(malformed)?;
		if tip_header.block_hash() != tip.hash {
			return Err(malformed(crate::chain::provider::ChainProviderError::Malformed(
				"the tip header is not the tip's".to_string(),
			)));
		}
		for confirmable in confirmables {
			confirmable.best_block_updated(&tip_header, tip.height);
		}

		Ok((tip, response.server_tip))
	}
}

#[async_trait]
impl SyncEngine for DependentSyncEngine {
	fn name(&self) -> &'static str {
		"dependent-tx-sync"
	}

	fn onchain_wallet(&self) -> Option<&Arc<Wallet>> {
		Some(&self.onchain_wallet)
	}

	async fn sync_once(
		&self, _layer: &ChainLayer, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
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

	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.watched.lock().unwrap().txids.insert(*txid, script_pubkey.to_owned());
	}

	fn register_output(&self, output: WatchedOutput) {
		let mut watched = self.watched.lock().unwrap();
		if !watched.outputs.iter().any(|o| o.outpoint == output.outpoint) {
			watched.outputs.push(output);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::chain::provider::WireBlockId;
	use bitcoin::hashes::Hash;

	#[test]
	fn only_an_answer_naming_a_higher_tip_is_continued() {
		let tip = |height| WireBlockId { height, hash: String::new() };
		assert!(!stopped_short(None, 100), "an index-backed answer is complete");
		assert!(stopped_short(Some(&tip(5000)), 2116), "a capped scan is continued");
		assert!(!stopped_short(Some(&tip(2116)), 2116), "reached the named tip");
		assert!(!stopped_short(Some(&tip(2000)), 2116), "a stale name is no reason to ask again");
	}

	#[test]
	fn the_watched_set_counts_what_was_registered_once() {
		let mut set = WatchedSet::default();
		assert_eq!(set.len(), 0);
		set.txids.insert(Txid::from_byte_array([1; 32]), ScriptBuf::new());
		set.txids.insert(Txid::from_byte_array([1; 32]), ScriptBuf::new());
		assert_eq!(set.len(), 1);
	}
}
