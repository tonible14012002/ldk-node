// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The filter-driven sync engine: BIP157/158 compact block filters over P2P, via kyoto.
//!
//! A third strategy next to transaction-based and block-polling. Kyoto keeps a header chain
//! from trusted peers and streams every block's filter; the engine matches each filter against
//! the scripts the wallet and LDK watch, fetches only the blocks that match, and drives
//! `Listen` — through the gated [`ChainListener`] — from the [`BlockApplicator`]. Nothing is
//! polled and no server is asked: what this engine cannot see (a mempool, an arbitrary
//! transaction's status, a fee market) it does not pretend to, and the layer's slots borrow it
//! from a provider or an external fee source instead.
//!
//! Ported from DatPham's upstream `CbfChainSource` (`cycles-cbf-828`) onto LDK 0.1 and
//! bdk_wallet 2.x: reorgs are a descending list of headers rather than a `BlockLocator`, the
//! wallet APIs are synchronous, the runtime is the one [`SyncEngine::start`] hands over, and
//! the fee/broadcast hooks became slot adapters.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bip157::chain::BlockHeaderChanges;
use bip157::{
	Builder as KyotoBuilder, ChainState, Client, Event as KyotoEvent, HashCheckpoint, Info,
	Node as KyotoNode, Requester, TrustedPeer, Warning,
};

use bitcoin::block::Header;
use bitcoin::{Script, ScriptBuf, Txid};

use bdk_chain::BlockId;

use lightning::chain::WatchedOutput;

use tokio::sync::{mpsc, watch};

use crate::chain::bitcoind::ChainListener;
use crate::chain::cbf::applicator::{BlockApplicator, ChainOp, CBF_CHAIN_OP_QUEUE_DEPTH};
use crate::chain::cbf::birthday::resolve_birthday;
use crate::chain::cbf::fee::{new_block_fee_cache, BlockFeeCache};
use crate::chain::cbf::{
	mark_syncing, parse_trusted_peer, resume_checkpoint, simplify_sync_state, CbfSyncState,
	ResumeRefusal, WatchLedger,
};
use crate::chain::engine::SyncEngine;
use crate::chain::seam::{MempoolAnswer, MempoolQuery, MempoolScope};
use crate::chain::{CbfSyncStatus, ChainLayer, ElectrumRuntimeStatus};
use crate::config::{Config, DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_debug, log_error, log_info, log_trace, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

use async_trait::async_trait;

/// Peer response timeout passed to kyoto's `Builder::response_timeout`.
const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 30;

/// Maximum consecutive `node.run()` failures before the restart loop gives up.
const MAX_RESTART_RETRIES: u32 = 5;

/// Initial backoff delay between restart attempts; doubles each failure.
const INITIAL_BACKOFF_MS: u64 = 500;

/// Retry matched block downloads before surfacing a CBF sync failure.
const CBF_BLOCK_FETCH_RETRIES: u8 = 3;

/// Per-attempt timeout when downloading a matched block from a peer. Kyoto queues the request
/// and awaits a peer response with no timeout of its own, so a slow or unresponsive peer would
/// otherwise park the fetch forever. Kept short so a single request is bounded and can be
/// retried rather than stalling.
const CBF_BLOCK_FETCH_TIMEOUT_SECS: u64 = 10;

/// Bound on the header lookup [`SyncEngine::is_on_chain`] makes, for the same reason.
// Reached only through `is_on_chain`, whose first caller is the hybrid check (T10).
#[allow(dead_code)]
const CBF_HEADER_LOOKUP_TIMEOUT_SECS: u64 = 10;

/// Runtime status of the underlying kyoto node.
enum CbfRuntimeStatus {
	Started { requester: Requester },
	Stopped,
}

/// An Electrum server used for fee estimates only, started and stopped with the engine.
///
/// The FEE adapter over it lives in the layer's chain; the engine owns only the connection's
/// lifetime, because the adapter cannot: it has no runtime until [`SyncEngine::start`].
pub(crate) struct ExternalElectrum {
	pub(crate) server_url: String,
	pub(crate) status: Arc<RwLock<ElectrumRuntimeStatus>>,
}

/// Everything it takes to build — and, from the restart loop, rebuild — the kyoto node.
#[derive(Clone)]
struct KyotoParams {
	trusted_peers: Vec<TrustedPeer>,
	required_peers: u8,
	/// The compiled birthday anchor, if a birthday is configured; the resume floor.
	birthday: Option<HashCheckpoint>,
	config: Arc<Config>,
	logger: Arc<Logger>,
}

impl KyotoParams {
	fn build(&self, listener: &ChainListener) -> Result<(KyotoNode, Client), ResumeRefusal> {
		let checkpoint = resume_checkpoint(&self.logger, listener, self.birthday)?;

		let mut kyoto_builder = KyotoBuilder::new(self.config.network);
		let data_dir = PathBuf::from(&self.config.storage_dir_path).join("bip157_data");
		kyoto_builder = kyoto_builder.data_dir(data_dir);
		if !self.trusted_peers.is_empty() {
			kyoto_builder = kyoto_builder.add_peers(self.trusted_peers.iter().cloned());
		}
		kyoto_builder = kyoto_builder
			.required_peers(self.required_peers)
			.fetch_witness_data()
			.response_timeout(Duration::from_secs(DEFAULT_RESPONSE_TIMEOUT_SECS));

		log_debug!(
			self.logger,
			"CBF builder: resuming from checkpoint height={}, hash={}",
			checkpoint.height,
			checkpoint.hash,
		);
		kyoto_builder = kyoto_builder.chain_state(ChainState::Checkpoint(checkpoint));

		Ok(kyoto_builder.build())
	}
}

pub(crate) struct CbfSyncEngine {
	kyoto: KyotoParams,
	/// Scripts LDK asked to watch. The wallet's own are pulled from the wallet, not kept here,
	/// so nothing is tracked twice.
	registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
	/// Where watched transactions were seen confirmed, as the applicator saw them.
	watch_ledger: Arc<WatchLedger>,
	/// Coinbase-derived fee rates of the blocks the applicator downloaded.
	block_fee_cache: BlockFeeCache,
	/// Whether kyoto is running, and the live requester if so.
	runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	/// Where the engine is between "started" and "caught up".
	sync_state_tx: watch::Sender<CbfSyncState>,
	/// The runtime handed over by [`SyncEngine::start`]; the background tasks are spawned on it.
	runtime: Mutex<Option<Arc<tokio::runtime::Runtime>>>,
	external_electrum: Option<ExternalElectrum>,
	onchain_wallet: Arc<Wallet>,
	config: Arc<Config>,
	kv_store: Arc<DynStore>,
	node_metrics: Arc<RwLock<NodeMetrics>>,
	logger: Arc<Logger>,
}

impl CbfSyncEngine {
	/// Parses the trusted peers and resolves the birthday; nothing connects until
	/// [`SyncEngine::run_background`].
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new(
		peers: Vec<String>, required_peers: u8, wallet_birthday_height: Option<u32>,
		external_electrum: Option<ExternalElectrum>, onchain_wallet: Arc<Wallet>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Result<Self, Error> {
		let mut trusted_peers = Vec::with_capacity(peers.len());
		for peer_str in &peers {
			let parsed = parse_trusted_peer(peer_str).map_err(|e| {
				log_error!(logger, "Invalid CBF trusted peer '{}': {}", peer_str, e);
				e
			})?;
			trusted_peers.push(parsed.into_trusted_peer());
		}

		let birthday = resolve_birthday(&logger, config.network, wallet_birthday_height)
			.map(|best| HashCheckpoint::new(best.height, best.block_hash));

		let (sync_state_tx, _) =
			watch::channel(CbfSyncState::Active { applied_tip: None, synced_to_tip: false });

		Ok(Self {
			kyoto: KyotoParams {
				trusted_peers,
				required_peers,
				birthday,
				config: Arc::clone(&config),
				logger: Arc::clone(&logger),
			},
			registered_scripts: Arc::new(Mutex::new(HashSet::new())),
			watch_ledger: Arc::new(WatchLedger::new()),
			block_fee_cache: new_block_fee_cache(),
			runtime_status: Arc::new(Mutex::new(CbfRuntimeStatus::Stopped)),
			sync_state_tx,
			runtime: Mutex::new(None),
			external_electrum,
			onchain_wallet,
			config,
			kv_store,
			node_metrics,
			logger,
		})
	}

	/// Watch `txid`: its script joins the filter match set so the block it confirms in is
	/// fetched, and the ledger records where the applicator sees it.
	pub(crate) fn watch_tx(&self, txid: Txid, script_pubkey: ScriptBuf) {
		self.registered_scripts.lock().unwrap_or_else(|e| e.into_inner()).insert(script_pubkey);
		self.watch_ledger.watch(txid);
	}

	/// Builds kyoto, spawns the applicator and the kyoto loop on `runtime`, and publishes the
	/// starting sync state. A resume the engine refuses (see [`ResumeRefusal`]) is published as
	/// a failed sync and nothing is spawned: the node comes up, `wait_until_synced` errors, and
	/// the log says what to configure.
	fn launch(&self, runtime: Arc<tokio::runtime::Runtime>, listener: Arc<ChainListener>) {
		let (node, client) = match self.kyoto.build(&listener) {
			Ok(built) => built,
			Err(refusal) => {
				log_error!(self.logger, "CBF sync cannot start: {}", refusal);
				self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
				return;
			},
		};
		let Client { requester, info_rx, warn_rx, event_rx } = client;

		{
			let mut status = self.runtime_status.lock().unwrap_or_else(|e| e.into_inner());
			if matches!(*status, CbfRuntimeStatus::Started { .. }) {
				debug_assert!(false, "launch() called while the CBF engine is already running");
				let _ = requester.shutdown();
				return;
			}
			*status = CbfRuntimeStatus::Started { requester };
		}

		let (ops_tx, ops_rx) = mpsc::channel(CBF_CHAIN_OP_QUEUE_DEPTH);
		let best_block_height = listener.get_best_block().height;
		self.sync_state_tx.send_replace(CbfSyncState::Active {
			applied_tip: Some(best_block_height),
			synced_to_tip: false,
		});
		let applicator = BlockApplicator::new(
			Arc::clone(&listener),
			ops_rx,
			best_block_height + 1,
			self.sync_state_tx.clone(),
			Arc::clone(&self.block_fee_cache),
			Arc::clone(&self.watch_ledger),
			Arc::clone(&self.kv_store),
			Arc::clone(&self.node_metrics),
			Arc::clone(&self.logger),
		);
		runtime.spawn(applicator.run());

		log_info!(self.logger, "CBF chain source started.");

		let kyoto_loop = KyotoLoop {
			kyoto: self.kyoto.clone(),
			listener,
			registered_scripts: Arc::clone(&self.registered_scripts),
			runtime_status: Arc::clone(&self.runtime_status),
			sync_state_tx: self.sync_state_tx.clone(),
			ops_tx,
			logger: Arc::clone(&self.logger),
		};
		runtime.spawn(kyoto_loop.run(node, info_rx, warn_rx, event_rx));
	}

	/// Blocks until the applicator has applied every block through the tip kyoto reports, or
	/// the sync failed.
	///
	/// Waits on the sync state alone. Before [`SyncEngine::run_background`] has launched kyoto
	/// the state is the initial "syncing", so a caller that raced the launch waits for it
	/// rather than being told the engine is not running; only [`SyncEngine::stop`] and the
	/// restart loop giving up publish a failure.
	pub(crate) async fn wait_until_synced(&self) -> Result<(), Error> {
		let mut sync_state_rx = self.sync_state_tx.subscribe();

		// Wait for kyoto to report catching up to the network tip (a `FiltersSynced`-driven
		// `synced_to_tip`) and for the resulting blocks to be applied. We must not target a
		// locally-sampled chain tip: kyoto does not persist, so a freshly (re)started node's
		// local header chain sits at genesis until it syncs from peers, which would let this
		// return before any sync happens.
		loop {
			match *sync_state_rx.borrow() {
				CbfSyncState::Active { synced_to_tip, .. } => {
					if synced_to_tip {
						return Ok(());
					}
				},
				CbfSyncState::Failed(error) => return Err(error),
			}

			if let Err(e) = sync_state_rx.changed().await {
				debug_assert!(false, "Failed to receive CBF sync result: {:?}", e);
				log_error!(self.logger, "Failed to receive CBF sync result: {:?}", e);
				return Err(Error::TxSyncFailed);
			}
		}
	}

	/// The applied tip's height as the sync state knows it, for an incremental question.
	fn applied_tip_height(&self) -> u32 {
		match *self.sync_state_tx.borrow() {
			CbfSyncState::Active { applied_tip, .. } => applied_tip.unwrap_or(0),
			CbfSyncState::Failed(_) => 0,
		}
	}
}

// Wired by T8: the CBF adapters — coinbase-derived FEE, P2P BROADCAST, forward-only
// TX_STATUS and the existence-only UTXO source — read the engine through these.
#[allow(dead_code)]
impl CbfSyncEngine {
	/// The live kyoto requester, or `None` while kyoto is not running.
	pub(crate) fn requester(&self) -> Option<Requester> {
		match &*self.runtime_status.lock().unwrap_or_else(|e| e.into_inner()) {
			CbfRuntimeStatus::Started { requester } => Some(requester.clone()),
			CbfRuntimeStatus::Stopped => None,
		}
	}

	/// Coinbase-derived fee rates of the blocks the applicator downloaded, by height.
	pub(crate) fn block_fee_cache(&self) -> &BlockFeeCache {
		&self.block_fee_cache
	}

	/// The scripts LDK asked to watch, on top of the wallet's own.
	pub(crate) fn registered_scripts(&self) -> &Arc<Mutex<HashSet<ScriptBuf>>> {
		&self.registered_scripts
	}

	/// Where watched transactions were seen confirmed.
	pub(crate) fn watch_ledger(&self) -> &Arc<WatchLedger> {
		&self.watch_ledger
	}

	/// The block the applicator most recently applied, if any.
	pub(crate) fn applied_tip(&self) -> Option<BlockId> {
		self.watch_ledger.tip()
	}

	/// A simplified, externally-consumable snapshot of the sync state. Never blocks.
	pub(crate) fn sync_status(&self) -> CbfSyncStatus {
		simplify_sync_state(*self.sync_state_tx.borrow())
	}
}

#[async_trait]
impl SyncEngine for CbfSyncEngine {
	fn name(&self) -> &'static str {
		"cbf"
	}

	/// Keeps the runtime for [`Self::run_background`] to spawn on, and connects the external
	/// Electrum fee source if one is configured. Kyoto itself needs the listeners, which only
	/// `run_background` is handed.
	fn start(&self, runtime: Arc<tokio::runtime::Runtime>) -> Result<(), Error> {
		if let Some(external) = &self.external_electrum {
			let mut status = external.status.write().unwrap();
			if status.client().is_none() {
				status.start(
					external.server_url.clone(),
					Arc::clone(&runtime),
					Arc::clone(&self.config),
					Arc::clone(&self.logger),
				)?;
			}
		}
		*self.runtime.lock().unwrap_or_else(|e| e.into_inner()) = Some(runtime);
		Ok(())
	}

	fn stop(&self) {
		let requester = {
			let mut status = self.runtime_status.lock().unwrap_or_else(|e| e.into_inner());
			match std::mem::replace(&mut *status, CbfRuntimeStatus::Stopped) {
				CbfRuntimeStatus::Started { requester } => Some(requester),
				CbfRuntimeStatus::Stopped => None,
			}
		};
		if let Some(requester) = requester {
			if let Err(e) = requester.shutdown() {
				log_error!(self.logger, "Failed to shut down CBF node: {:?}", e);
			}
		}
		self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::NotRunning));
		if let Some(external) = &self.external_electrum {
			external.status.write().unwrap().stop();
		}
	}

	/// Wait for the filters to catch up, then borrow a mempool view if the layer has one to
	/// lend, then record the pass.
	///
	/// The mempool is supplementary: a filter-driven engine has none of its own, and a
	/// provider that cannot answer this pass does not make the pass fail — the chain is
	/// synced regardless. What it answers is applied as is; a hybrid node's reorg-consistency
	/// check on the answer's tip is T10's.
	async fn sync_once(
		&self, layer: &ChainLayer, _channel_manager: Arc<ChannelManager>,
		_chain_monitor: Arc<ChainMonitor>, _output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		self.wait_until_synced().await?;

		if layer.has_mempool_chain() {
			let mut scripts = self.onchain_wallet.list_watched_scripts();
			scripts.extend(
				self.registered_scripts.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned(),
			);
			let query = MempoolQuery {
				scripts,
				known_unconfirmed: self.onchain_wallet.get_unconfirmed_txids(),
				scope: MempoolScope::Incremental {
					best_processed_height: self.applied_tip_height(),
				},
			};
			let now = SystemTime::now();
			match layer.mempool(&query).await {
				Ok(answered) => {
					let MempoolAnswer { unconfirmed, evicted } = answered.value.value;
					log_trace!(
						self.logger,
						"Borrowed a mempool view of {} unconfirmed and {} evicted transactions \
						 via {} in {}ms",
						unconfirmed.len(),
						evicted.len(),
						answered.by,
						now.elapsed().unwrap_or_default().as_millis()
					);
					if let Err(e) = self.onchain_wallet.apply_mempool_txs(unconfirmed, evicted) {
						log_error!(self.logger, "Failed to apply mempool transactions: {:?}", e);
					}
				},
				Err(e) => {
					log_error!(
						self.logger,
						"Could not borrow a mempool view this pass; the filter sync is complete \
						 without it: {}",
						e
					);
				},
			}
		}

		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		let mut locked_node_metrics = self.node_metrics.write().unwrap();
		locked_node_metrics.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
		locked_node_metrics.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
		write_node_metrics(
			&*locked_node_metrics,
			Arc::clone(&self.kv_store),
			Arc::clone(&self.logger),
		)
		.map_err(|e| {
			log_error!(self.logger, "Failed to persist node metrics: {}", e);
			Error::PersistenceFailed
		})
	}

	/// Launches kyoto and the applicator, then keeps the fee cache fresh through the FEE slot
	/// until told to stop. Block application itself is event-driven and runs on the spawned
	/// tasks; this loop only owns the fee tick.
	async fn run_background(
		&self, layer: Arc<ChainLayer>, mut stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) {
		let runtime = self.runtime.lock().unwrap_or_else(|e| e.into_inner()).clone();
		let Some(runtime) = runtime else {
			log_error!(
				self.logger,
				"CBF sync cannot start: the engine was not started with a runtime."
			);
			self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::NotRunning));
			return;
		};

		// Snapshots the channel monitors before the first block is delivered; the resume height
		// `launch` derives is read from the same, still untouched, state.
		let listener = Arc::new(ChainListener::new_gated(
			Arc::clone(&self.onchain_wallet),
			channel_manager,
			chain_monitor,
			output_sweeper,
			Arc::clone(layer.tx_broadcaster()),
			Arc::clone(layer.fee_estimator()),
			Arc::clone(&self.logger),
		));
		self.launch(runtime, listener);

		let mut fee_rate_update_interval =
			tokio::time::interval(Duration::from_secs(DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS));
		// We primed the cache once on startup, so skip the immediate first tick.
		fee_rate_update_interval.reset();
		fee_rate_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		loop {
			tokio::select! {
				_ = stop_sync_receiver.changed() => {
					log_trace!(self.logger, "Stopping CBF fee-rate update loop.");
					return;
				}
				_ = fee_rate_update_interval.tick() => {
					let _ = layer.update_fee_rate_estimates().await;
				}
			}
		}
	}

	/// A filter-driven engine has no mempool view: the BROADCAST tail is the only way the
	/// wallet hears that the coins a just-sent transaction spent are gone.
	fn tracks_own_broadcasts(&self) -> bool {
		true
	}

	fn onchain_wallet(&self) -> Option<&Arc<Wallet>> {
		Some(&self.onchain_wallet)
	}

	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.watch_tx(*txid, script_pubkey.to_owned());
	}

	fn register_output(&self, output: WatchedOutput) {
		self.registered_scripts
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.insert(output.script_pubkey);
	}

	/// Asks kyoto for the header at the block's height and compares hashes. `None` while
	/// kyoto is not running, when the lookup fails or times out, and when the height is
	/// outside the header range kyoto holds (above its tip, or below the checkpoint it
	/// resumed from): an answer this engine cannot check is not one it refutes.
	async fn is_on_chain(&self, block: &BlockId) -> Option<bool> {
		let requester = self.requester()?;
		let lookup = tokio::time::timeout(
			Duration::from_secs(CBF_HEADER_LOOKUP_TIMEOUT_SECS),
			requester.get_header(block.height),
		)
		.await;
		match lookup {
			Ok(Ok(Some(header))) => Some(header.block_hash() == block.hash),
			Ok(Ok(None)) => None,
			Ok(Err(e)) => {
				log_debug!(
					self.logger,
					"CBF could not look up the header at height {}: {:?}",
					block.height,
					e
				);
				None
			},
			Err(_elapsed) => {
				log_debug!(
					self.logger,
					"CBF header lookup at height {} timed out after {}s",
					block.height,
					CBF_HEADER_LOOKUP_TIMEOUT_SECS
				);
				None
			},
		}
	}
}

/// The kyoto side of the engine: runs the node, restarts it on failure with exponential
/// backoff, and turns its events into [`ChainOp`]s for the applicator.
struct KyotoLoop {
	kyoto: KyotoParams,
	listener: Arc<ChainListener>,
	registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
	runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	sync_state_tx: watch::Sender<CbfSyncState>,
	ops_tx: mpsc::Sender<ChainOp>,
	logger: Arc<Logger>,
}

impl KyotoLoop {
	async fn run(
		self, node: KyotoNode, info_rx: mpsc::Receiver<Info>,
		warn_rx: mpsc::UnboundedReceiver<Warning>, event_rx: mpsc::UnboundedReceiver<KyotoEvent>,
	) {
		let mut current_node = node;
		let mut current_info_rx = info_rx;
		let mut current_warn_rx = warn_rx;
		let mut current_event_rx = event_rx;
		let mut retries = 0u32;
		let mut backoff_ms = INITIAL_BACKOFF_MS;

		loop {
			let info_handle =
				tokio::spawn(process_info_messages(current_info_rx, Arc::clone(&self.logger)));
			let warn_handle =
				tokio::spawn(process_warn_messages(current_warn_rx, Arc::clone(&self.logger)));
			let event_handle = tokio::spawn(process_kyoto_events(
				Arc::clone(&self.logger),
				current_event_rx,
				Arc::clone(&self.registered_scripts),
				Arc::clone(&self.runtime_status),
				self.ops_tx.clone(),
				Arc::clone(&self.listener.onchain_wallet),
				self.sync_state_tx.clone(),
			));

			match current_node.run().await {
				Ok(()) => {
					log_info!(self.logger, "CBF node shut down cleanly.");
					*self.runtime_status.lock().unwrap_or_else(|e| e.into_inner()) =
						CbfRuntimeStatus::Stopped;
					self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::NotRunning));
					break;
				},
				Err(e) => {
					retries += 1;
					if retries > MAX_RESTART_RETRIES {
						log_error!(
							self.logger,
							"CBF node failed {} times, giving up: {:?}",
							retries,
							e,
						);
						*self.runtime_status.lock().unwrap_or_else(|e| e.into_inner()) =
							CbfRuntimeStatus::Stopped;
						self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
						break;
					}
					log_error!(
						self.logger,
						"CBF node exited with error (attempt {}/{}): {:?}. Restarting in {}ms.",
						retries,
						MAX_RESTART_RETRIES,
						e,
						backoff_ms,
					);

					// Abort the old consumers before rebuilding.
					info_handle.abort();
					warn_handle.abort();
					event_handle.abort();

					tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
					backoff_ms = backoff_ms.saturating_mul(2);
					let (new_node, new_client) = match self.kyoto.build(&self.listener) {
						Ok(built) => built,
						Err(refusal) => {
							log_error!(self.logger, "CBF restart aborted: {}", refusal);
							*self.runtime_status.lock().unwrap_or_else(|e| e.into_inner()) =
								CbfRuntimeStatus::Stopped;
							self.sync_state_tx
								.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
							break;
						},
					};
					let Client {
						requester: new_requester,
						info_rx: new_info_rx,
						warn_rx: new_warn_rx,
						event_rx: new_event_rx,
					} = new_client;

					{
						let mut status =
							self.runtime_status.lock().unwrap_or_else(|e| e.into_inner());
						if matches!(*status, CbfRuntimeStatus::Stopped) {
							let _ = new_requester.shutdown();
							self.sync_state_tx
								.send_replace(CbfSyncState::Failed(Error::NotRunning));
							log_info!(
								self.logger,
								"CBF restart aborted: stop() called during backoff."
							);
							break;
						}
						*status = CbfRuntimeStatus::Started { requester: new_requester };
						self.sync_state_tx.send_replace(CbfSyncState::Active {
							applied_tip: Some(self.listener.get_best_block().height),
							synced_to_tip: false,
						});
					}

					current_node = new_node;
					current_info_rx = new_info_rx;
					current_warn_rx = new_warn_rx;
					current_event_rx = new_event_rx;
				},
			}
		}
	}
}

async fn process_info_messages(mut info_rx: mpsc::Receiver<Info>, logger: Arc<Logger>) {
	while let Some(info) = info_rx.recv().await {
		log_debug!(logger, "CBF node info: {}", info);
	}
}

async fn process_warn_messages(mut warn_rx: mpsc::UnboundedReceiver<Warning>, logger: Arc<Logger>) {
	while let Some(warning) = warn_rx.recv().await {
		log_debug!(logger, "CBF node warning: {}", warning);
	}
}

/// The scripts every filter is matched against: the wallet's watched set plus LDK's
/// registrations, copied once and refreshed only when either set grew.
///
/// Both sets only ever grow, so a size comparison is exact. Cloning the wallet's scripts per
/// filter — thousands of them, tens of thousands of filters on a catch-up — was the single
/// largest allocation in the event loop.
struct MatchSet {
	wallet_count: usize,
	registered_count: usize,
	scripts: Vec<ScriptBuf>,
}

impl MatchSet {
	fn new() -> Self {
		Self { wallet_count: usize::MAX, registered_count: usize::MAX, scripts: Vec::new() }
	}

	fn current(
		&mut self, onchain_wallet: &Wallet, registered_scripts: &Mutex<HashSet<ScriptBuf>>,
	) -> &[ScriptBuf] {
		let wallet_count = onchain_wallet.watched_script_count();
		let registered = registered_scripts.lock().unwrap_or_else(|e| e.into_inner());
		if wallet_count != self.wallet_count || registered.len() != self.registered_count {
			self.scripts = onchain_wallet.list_watched_scripts();
			self.scripts.extend(registered.iter().cloned());
			self.wallet_count = wallet_count;
			self.registered_count = registered.len();
		}
		&self.scripts
	}
}

async fn process_kyoto_events(
	logger: Arc<Logger>, mut event_rx: mpsc::UnboundedReceiver<KyotoEvent>,
	registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
	runtime_status: Arc<Mutex<CbfRuntimeStatus>>, ops_tx: mpsc::Sender<ChainOp>,
	onchain_wallet: Arc<Wallet>, sync_state_tx: watch::Sender<CbfSyncState>,
) {
	let mut match_set = MatchSet::new();
	while let Some(event) = event_rx.recv().await {
		match event {
			KyotoEvent::IndexedFilter(indexed_filter) => {
				// A new block's filter arrived, so we're behind by at least this block until it
				// is fetched (if matched) and applied. Flip this before the fetch, not after,
				// so a `sync_wallets` call issued in between doesn't return on a stale
				// `synced_to_tip` that predates this block.
				mark_syncing(&sync_state_tx);

				// Copy the requester out and release the lock before any `.await` below: this is a
				// `std::sync::Mutex`, so holding its guard across an await point would make this
				// future non-`Send` and it could not be spawned.
				let requester_opt = match &*runtime_status.lock().unwrap_or_else(|e| e.into_inner())
				{
					CbfRuntimeStatus::Started { requester } => Some(requester.clone()),
					CbfRuntimeStatus::Stopped => None,
				};
				let requester = match requester_opt {
					Some(requester) => requester,
					None => {
						let _ = ops_tx.send(ChainOp::Failed { error: Error::NotRunning }).await;
						return;
					},
				};

				let block_hash = indexed_filter.block_hash();
				let matched = {
					let scripts = match_set.current(&onchain_wallet, &registered_scripts);
					indexed_filter.contains_any(scripts.iter())
				};

				let chop: ChainOp = if matched {
					let mut attempt = 0;
					let block = loop {
						attempt += 1;
						let handle = match requester.request_block(block_hash) {
							Ok(handle) => handle,
							Err(_) => {
								log_error!(
									logger,
									"Failed to obtain receiver for matched CBF block {}; node is stopped",
									block_hash
								);
								let _ =
									ops_tx.send(ChainOp::Failed { error: Error::NotRunning }).await;
								return;
							},
						};

						// Bound the download so an unresponsive peer can't park the fetch forever,
						// then flatten the three error layers (timeout / receiver dropped / fetch
						// error) into a single reason so the retry-or-fail decision is written once.
						let fetched = tokio::time::timeout(
							Duration::from_secs(CBF_BLOCK_FETCH_TIMEOUT_SECS),
							handle,
						)
						.await
						.map_err(|_| format!("timed out after {}s", CBF_BLOCK_FETCH_TIMEOUT_SECS))
						.and_then(|recv| recv.map_err(|_| "receiver was dropped".to_string()))
						.and_then(|fetch| fetch.map_err(|e| format!("failed: {:?}", e)));

						match fetched {
							Ok(block) => break block,
							Err(reason) if attempt < CBF_BLOCK_FETCH_RETRIES => {
								log_debug!(
									logger,
									"CBF block fetch for {} {} on attempt {}; retrying",
									block_hash,
									reason,
									attempt
								);
							},
							Err(reason) => {
								log_error!(
									logger,
									"CBF block fetch for {} {} after {} attempts; giving up",
									block_hash,
									reason,
									CBF_BLOCK_FETCH_RETRIES
								);
								let _ = ops_tx
									.send(ChainOp::Failed { error: Error::TxSyncFailed })
									.await;
								return;
							},
						}
					};
					ChainOp::ConnectFull { block }
				} else {
					ChainOp::ConnectFiltered {
						header: indexed_filter.header(),
						height: indexed_filter.height(),
					}
				};
				if let Err(e) = ops_tx.send(chop).await {
					log_debug!(logger, "ops_rx gone: {}", e);
				}
			},
			KyotoEvent::FiltersSynced(sync_update) => {
				// Because application of blocks is async, the fact that kyoto synced up to the
				// tip does NOT mean that we caught everything up, that's why we send a ChainOp,
				// only processing of which means we processed all blocks up to the tip.
				log_info!(logger, "Kyoto synced up to the tip {}", sync_update.tip().height);
				let _ = ops_tx.send(ChainOp::Synced { tip_height: sync_update.tip().height }).await;
			},
			KyotoEvent::ChainUpdate(BlockHeaderChanges::Connected(indexed_header)) => {
				log_debug!(logger, "Kyoto connected header at height {}", indexed_header.height);
			},
			KyotoEvent::ChainUpdate(BlockHeaderChanges::Reorganized {
				reorganized,
				accepted: _,
			}) => {
				// Rewind to the fork point, tip first; kyoto re-delivers the new chain's
				// filters afterwards.
				let mut headers: Vec<(Header, u32)> =
					reorganized.iter().map(|h| (h.header, h.height)).collect();
				headers.sort_by(|a, b| b.1.cmp(&a.1));
				headers.dedup_by_key(|(_, height)| *height);
				if !headers.is_empty() {
					let _ = ops_tx.send(ChainOp::Disconnect { headers }).await;
				}
			},
			KyotoEvent::ChainUpdate(BlockHeaderChanges::ForkAdded(fork)) => {
				log_debug!(logger, "Kyoto added fork header at height {}", fork.height);
			},
		}
	}
}
