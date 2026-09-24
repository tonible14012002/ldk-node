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
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bip157::chain::BlockHeaderChanges;
use bip157::{
	Builder as KyotoBuilder, ChainState, Client, Event as KyotoEvent, HashCheckpoint, Info,
	Node as KyotoNode, NodeError, Requester, TrustedPeer, Warning,
};

use bitcoin::block::Header;
use bitcoin::{BlockHash, Script, ScriptBuf, Txid};

use bdk_chain::BlockId;

use lightning::chain::WatchedOutput;

use tokio::sync::{mpsc, watch, Semaphore};

use crate::chain::bitcoind::ChainListener;
use crate::chain::cbf::applicator::{
	BlockApplicator, ChainFanout, ChainOp, CBF_CHAIN_OP_QUEUE_DEPTH, CBF_FULL_BLOCK_PERMITS,
};
use crate::chain::cbf::birthday::resolve_birthday;
use crate::chain::cbf::fee::{new_block_fee_cache, BlockFeeCache};
use crate::chain::cbf::fee_sampler::{
	BlockFetch, FeeBlockSource, FeeSampler, SampleFailure, CBF_FEE_SAMPLE_INTERVAL,
};
use crate::chain::cbf::source::FilterSource;
use crate::chain::cbf::source_sync::{
	lock_headers, new_shared_header_chain, HeaderChain, SharedHeaderChain, SourceFeeSource,
	SourceSync, SourceSyncEnd, SourceTuning, WatchedScripts,
};
use crate::chain::cbf::{
	mark_syncing, parse_trusted_peer, resume_checkpoint, simplify_sync_state, CbfSyncState,
	ResumeRefusal, WatchLedger, CBF_BLOCK_FETCH_TIMEOUT_SECS, CBF_HEADER_LOOKUP_TIMEOUT_SECS,
};
use crate::chain::engine::SyncEngine;
use crate::chain::seam::{ActionResult, MempoolQuery, MempoolScope};
use crate::chain::{BorrowedMempool, MempoolEvictions};
use crate::chain::{CbfSyncStatus, ChainLayer, ElectrumRuntimeStatus};
use crate::config::{
	BackgroundSyncConfig, CbfSource, Config, BDK_WALLET_SYNC_TIMEOUT_SECS,
	DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS, WALLET_SYNC_INTERVAL_MINIMUM_SECS,
};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_debug, log_error, log_info, log_trace, log_warn, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

use async_trait::async_trait;

/// Peer response timeout passed to kyoto's `Builder::response_timeout`.
const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 30;

/// Maximum consecutive unexpected failed runs — the event stream closing under a running node,
/// or the event loop ending for a reason the network does not explain — before the restart
/// loop gives up. Reset once a run catches up to the tip. A run that fails on the network (no
/// reachable peers, peers not serving blocks) never counts: see [`RestartPolicy`].
const MAX_RESTART_RETRIES: u32 = 5;

/// Initial backoff delay between restart attempts; doubles each failure up to
/// [`CBF_MAX_BACKOFF_MS`], and starts over after a peer handshake or a caught-up run.
pub(crate) const INITIAL_BACKOFF_MS: u64 = 500;

/// The longest the restart loop waits between two attempts. Five minutes: a node waiting on a
/// network that is down keeps trying, without hammering DNS seeds or a Pi's radio.
pub(crate) const CBF_MAX_BACKOFF_MS: u64 = 300_000;

/// While the node waits for peers, how often the wait is reported at warn; every retry in
/// between is logged at debug only.
pub(crate) const CBF_PEER_WAIT_REPORT_INTERVAL: Duration = Duration::from_secs(600);

/// Retry matched block downloads before giving up on the node and rebuilding it.
const CBF_BLOCK_FETCH_RETRIES: u8 = 3;

/// How long the restart loop waits for a node it asked to shut down before dropping it. A node
/// takes the shutdown on its next loop iteration, so this is only ever reached by one wedged
/// in a peer handshake or a database write.
const CBF_NODE_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// How long a foreground pass waits for the filters to catch up before it gives up with
/// [`Error::WalletOperationTimeout`]. The on-chain wallet-sync bound every other engine uses:
/// [`crate::Node::sync_wallets`] holds the node's runtime lock across the pass, so an unbounded
/// wait — kyoto with no peers, or a long catch-up — would leave `Node::stop` waiting on that
/// lock for as long.
const CBF_SYNC_WAIT_TIMEOUT: Duration = Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS);

/// How often the background loop retries the fee refresh while no refresh has filled the cache
/// since startup. The boot refresh runs before kyoto is up, so on a node whose only fee source
/// is its own blocks it cannot succeed; waiting out the regular ten-minute tick would leave the
/// node on hardcoded fallbacks — and `Node::chain_freshness` stale — for that long.
const CBF_FEE_RECOVERY_RETRY: Duration = Duration::from_secs(15);

/// [`CbfSyncEngine::active_source`]: kyoto feeds the applicator.
const ACTIVE_P2P: u8 = 0;
/// [`CbfSyncEngine::active_source`]: the node filter source feeds the applicator.
const ACTIVE_NODE: u8 = 1;

/// A running node-source sync: which launch it belongs to, and how to stop it.
struct SourceRun {
	generation: u64,
	stop_tx: watch::Sender<bool>,
}

/// Runtime status of the underlying kyoto node.
enum CbfRuntimeStatus {
	Started {
		requester: Requester,
		/// Which [`CbfSyncEngine::launch`] this node belongs to. The restart loop writes the
		/// status only while it still carries its own generation: after a `stop()` and a fresh
		/// `start()` the status belongs to the new launch, and the old loop's exit — which
		/// arrives whenever kyoto gets round to the shutdown — must not clobber it.
		generation: u64,
	},
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

		let data_dir = PathBuf::from(&self.config.storage_dir_path).join("bip157_data");
		let mut kyoto_builder =
			kyoto_builder(self.config.network, data_dir, &self.trusted_peers, self.required_peers);

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

/// Kyoto as the engine configures it, short of the resume checkpoint.
fn kyoto_builder(
	network: bitcoin::Network, data_dir: PathBuf, trusted_peers: &[TrustedPeer], required_peers: u8,
) -> KyotoBuilder {
	let mut kyoto_builder = KyotoBuilder::new(network).data_dir(data_dir);
	if !trusted_peers.is_empty() {
		kyoto_builder = kyoto_builder.add_peers(trusted_peers.iter().cloned());
	}
	kyoto_builder
		.required_peers(required_peers)
		.fetch_witness_data()
		.response_timeout(Duration::from_secs(DEFAULT_RESPONSE_TIMEOUT_SECS))
}

pub(crate) struct CbfSyncEngine {
	kyoto: KyotoParams,
	/// Where the chain data comes from; see [`CbfSource`].
	source_mode: CbfSource,
	/// The node filter source, kept only when `source_mode` uses it.
	filter_source: Option<Arc<dyn FilterSource>>,
	/// The header chain the node-source sync verified; read by its fee source and
	/// `is_on_chain`. Empty while kyoto runs.
	source_headers: SharedHeaderChain,
	/// Which source feeds the applicator now: [`ACTIVE_P2P`] or [`ACTIVE_NODE`]. Moves from
	/// node to P2P once, when `node,p2p` falls back.
	active_source: Arc<AtomicU8>,
	/// The node-source sync, while one runs.
	source_run: Arc<Mutex<Option<SourceRun>>>,
	/// Scripts LDK asked to watch. The wallet's own are pulled from the wallet, not kept here,
	/// so nothing is tracked twice.
	registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
	/// Where watched transactions were seen confirmed, as the applicator saw them.
	watch_ledger: Arc<WatchLedger>,
	/// Coinbase-derived fee rates of the blocks the applicator downloaded.
	block_fee_cache: BlockFeeCache,
	/// The [`CBF_FULL_BLOCK_PERMITS`] bound on full blocks held in memory at once: the
	/// applicator's matched blocks and the FEE adapter's samples share it.
	full_block_permits: Arc<Semaphore>,
	/// Whether kyoto is running, and the live requester if so.
	runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	/// Counts [`Self::launch`] calls; each stamps its generation into the runtime status.
	launch_generation: AtomicU64,
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
		source_mode: CbfSource, filter_source: Option<Arc<dyn FilterSource>>,
		external_electrum: Option<ExternalElectrum>, onchain_wallet: Arc<Wallet>,
		kv_store: Arc<DynStore>, config: Arc<Config>, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Result<Self, Error> {
		let filter_source = match (source_mode.uses_node_source(), filter_source) {
			(true, Some(source)) => Some(source),
			(true, None) => {
				log_error!(
					logger,
					"CBF source {:?} needs a filter source, and none was given \
					 (NodeBuilder::set_cbf_filter_source).",
					source_mode
				);
				return Err(Error::ConnectionFailed);
			},
			(false, Some(source)) => {
				log_info!(
					logger,
					"A CBF filter source ('{}') is set, but the CBF source is P2P; ignoring it.",
					source.name()
				);
				None
			},
			(false, None) => None,
		};

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
			source_mode,
			filter_source,
			source_headers: new_shared_header_chain(),
			active_source: Arc::new(AtomicU8::new(if source_mode.uses_node_source() {
				ACTIVE_NODE
			} else {
				ACTIVE_P2P
			})),
			source_run: Arc::new(Mutex::new(None)),
			registered_scripts: Arc::new(Mutex::new(HashSet::new())),
			watch_ledger: Arc::new(WatchLedger::new()),
			block_fee_cache: new_block_fee_cache(),
			full_block_permits: Arc::new(Semaphore::new(CBF_FULL_BLOCK_PERMITS)),
			runtime_status: Arc::new(Mutex::new(CbfRuntimeStatus::Stopped)),
			launch_generation: AtomicU64::new(0),
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

	/// Adds `script_pubkey` to the filter match set, so every block paying or spending it is
	/// fetched.
	fn match_script(&self, script_pubkey: ScriptBuf) {
		self.registered_scripts.lock().unwrap_or_else(|e| e.into_inner()).insert(script_pubkey);
	}

	/// Builds kyoto, spawns the applicator and the kyoto loop on `runtime`, and publishes the
	/// starting sync state. A resume the engine refuses (see [`ResumeRefusal`]) is published as
	/// a failed sync and nothing is spawned: the node comes up, `wait_until_synced` errors, and
	/// the log says what to configure.
	fn launch(&self, runtime: Arc<tokio::runtime::Runtime>, listener: Arc<ChainListener>) {
		if self.source_mode.uses_node_source() {
			let anchor = match resume_checkpoint(&self.logger, &listener, self.kyoto.birthday) {
				Ok(checkpoint) => BlockId { height: checkpoint.height, hash: checkpoint.hash },
				Err(refusal) => {
					log_error!(self.logger, "CBF sync cannot start: {}", refusal);
					self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
					return;
				},
			};
			let best_block_height = listener.get_best_block().height;
			let fallback =
				(self.source_mode == CbfSource::NodeThenP2p).then(|| Arc::clone(&listener));
			self.launch_source(runtime.handle(), listener, anchor, best_block_height, fallback);
			return;
		}

		let (node, client) = match self.kyoto.build(&listener) {
			Ok(built) => built,
			Err(refusal) => {
				log_error!(self.logger, "CBF sync cannot start: {}", refusal);
				self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
				return;
			},
		};
		let Client { requester, info_rx, warn_rx, event_rx } = client;

		let generation = self.launch_generation.fetch_add(1, Ordering::AcqRel) + 1;
		{
			let mut status = self.runtime_status.lock().unwrap_or_else(|e| e.into_inner());
			if matches!(*status, CbfRuntimeStatus::Started { .. }) {
				debug_assert!(false, "launch() called while the CBF engine is already running");
				let _ = requester.shutdown();
				return;
			}
			*status = CbfRuntimeStatus::Started { requester, generation };
		}

		let (ops_tx, ops_rx) = mpsc::channel(CBF_CHAIN_OP_QUEUE_DEPTH);
		let full_block_permits = Arc::clone(&self.full_block_permits);
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

		log_info!(self.logger, "CBF chain source started: filters from the P2P network (kyoto).");

		let kyoto_loop = KyotoLoop {
			kyoto: self.kyoto.clone(),
			generation,
			listener,
			registered_scripts: Arc::clone(&self.registered_scripts),
			runtime_status: Arc::clone(&self.runtime_status),
			sync_state_tx: self.sync_state_tx.clone(),
			ops_tx,
			full_block_permits,
			logger: Arc::clone(&self.logger),
		};
		runtime.spawn(kyoto_loop.run(node, info_rx, warn_rx, event_rx));
	}

	/// Starts the applicator over `fanout` and the sync loop over the node filter source,
	/// resuming from `anchor`. Kyoto is not built: no Bitcoin P2P connection is opened. With
	/// `fallback_listener` (`node,p2p`) the loop hands over to kyoto, on the same applicator,
	/// once the source has stayed unavailable too long.
	///
	/// Generic over the fan-out so it can be driven without a `ChannelManager`.
	fn launch_source<F: ChainFanout + 'static>(
		&self, handle: &tokio::runtime::Handle, fanout: Arc<F>, anchor: BlockId,
		best_block_height: u32, fallback_listener: Option<Arc<ChainListener>>,
	) {
		let Some(source) = self.filter_source.clone() else {
			debug_assert!(false, "a node-source launch without a filter source");
			log_error!(self.logger, "CBF sync cannot start: no filter source.");
			self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
			return;
		};
		let generation = self.launch_generation.fetch_add(1, Ordering::AcqRel) + 1;
		let (stop_tx, stop_rx) = watch::channel(false);
		{
			// Lock order: `source_run`, then `runtime_status` — as in the fallback.
			let mut run = self.source_run.lock().unwrap_or_else(|e| e.into_inner());
			let kyoto_running = matches!(
				*self.runtime_status.lock().unwrap_or_else(|e| e.into_inner()),
				CbfRuntimeStatus::Started { .. }
			);
			if run.is_some() || kyoto_running {
				debug_assert!(false, "launch() called while the CBF engine is already running");
				return;
			}
			*run = Some(SourceRun { generation, stop_tx });
		}
		*lock_headers(&self.source_headers) = HeaderChain::default();
		self.active_source.store(ACTIVE_NODE, Ordering::Release);

		let (ops_tx, ops_rx) = mpsc::channel(CBF_CHAIN_OP_QUEUE_DEPTH);
		self.sync_state_tx.send_replace(CbfSyncState::Active {
			applied_tip: Some(best_block_height),
			synced_to_tip: false,
		});
		let applicator = BlockApplicator::new(
			fanout,
			ops_rx,
			best_block_height + 1,
			self.sync_state_tx.clone(),
			Arc::clone(&self.block_fee_cache),
			Arc::clone(&self.watch_ledger),
			Arc::clone(&self.kv_store),
			Arc::clone(&self.node_metrics),
			Arc::clone(&self.logger),
		);
		handle.spawn(applicator.run());

		let fall_back = self.source_mode == CbfSource::NodeThenP2p;
		let sync = SourceSync::new(
			Arc::clone(&source),
			self.config.network,
			anchor,
			Arc::clone(&self.source_headers),
			Arc::new(EngineScripts {
				wallet: Arc::clone(&self.onchain_wallet),
				registered: Arc::clone(&self.registered_scripts),
			}),
			ops_tx.clone(),
			self.sync_state_tx.clone(),
			Arc::clone(&self.full_block_permits),
			stop_rx,
			SourceTuning::production(fall_back),
			Arc::clone(&self.logger),
		);
		log_info!(
			self.logger,
			"CBF chain source started: filters from the node source '{}'{}; no Bitcoin P2P connection.",
			source.name(),
			if fall_back { ", falling back to P2P if it stays unavailable" } else { "" }
		);

		let fallback = fallback_listener.filter(|_| fall_back).map(|listener| KyotoFallback {
			kyoto: self.kyoto.clone(),
			generation,
			listener,
			registered_scripts: Arc::clone(&self.registered_scripts),
			runtime_status: Arc::clone(&self.runtime_status),
			sync_state_tx: self.sync_state_tx.clone(),
			ops_tx,
			full_block_permits: Arc::clone(&self.full_block_permits),
			source_run: Arc::clone(&self.source_run),
			active_source: Arc::clone(&self.active_source),
			logger: Arc::clone(&self.logger),
		});
		let source_run = Arc::clone(&self.source_run);
		let logger = Arc::clone(&self.logger);
		let spawn_handle = handle.clone();
		handle.spawn(async move {
			match sync.run().await {
				SourceSyncEnd::FallBack => {
					if let Some(fallback) = fallback {
						fallback.start(&spawn_handle);
						return;
					}
					log_error!(logger, "CBF node source asked for a P2P fallback it has not got.");
				},
				SourceSyncEnd::Stopped => log_debug!(logger, "CBF node-source sync stopped."),
				SourceSyncEnd::ApplicatorGone => {
					log_debug!(logger, "CBF node-source sync ended: the applicator halted.")
				},
				// Logged, and published as failed, by the loop.
				SourceSyncEnd::Failed(_) => {},
			}
			let mut run = source_run.lock().unwrap_or_else(|e| e.into_inner());
			if run.as_ref().is_some_and(|r| r.generation == generation) {
				*run = None;
			}
		});
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

	/// [`Self::wait_until_synced`], given up after `bound` with
	/// [`Error::WalletOperationTimeout`].
	async fn wait_until_synced_within(&self, bound: Duration) -> Result<(), Error> {
		match tokio::time::timeout(bound, self.wait_until_synced()).await {
			Ok(synced) => synced,
			Err(_elapsed) => {
				log_error!(
					self.logger,
					"CBF sync did not catch up to the tip within {}s; giving up on this pass.",
					bound.as_secs()
				);
				Err(Error::WalletOperationTimeout)
			},
		}
	}

	/// Whether kyoto has caught up to the network tip and every block up to it is applied.
	fn is_synced(&self) -> bool {
		matches!(*self.sync_state_tx.borrow(), CbfSyncState::Active { synced_to_tip: true, .. })
	}

	/// The applied tip's height as the sync state knows it, for an incremental question.
	fn applied_tip_height(&self) -> u32 {
		match *self.sync_state_tx.borrow() {
			CbfSyncState::Active { applied_tip, .. } => applied_tip.unwrap_or(0),
			CbfSyncState::Failed(_) => 0,
		}
	}

	/// Borrow a mempool view from the layer's MEMPOOL chain for everything this node watches —
	/// the wallet's scripts and LDK's — and apply it to the on-chain wallet.
	///
	/// The layer refuses an answer anchored to a tip this engine does not consider best, keeps
	/// fresh own broadcasts from being evicted on a borrowed word, and stamps the answer on
	/// this node's clock ([`ChainLayer::borrow_mempool`]). Evictions are applied only as
	/// `evictions` says; see [`Self::mempool_borrow_due`].
	async fn borrow_mempool(
		&self, layer: &ChainLayer, evictions: MempoolEvictions,
	) -> ActionResult<BorrowedMempool> {
		let mut scripts = self.onchain_wallet.list_watched_scripts();
		scripts.extend(
			self.registered_scripts.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned(),
		);
		let query = MempoolQuery {
			scripts,
			known_unconfirmed: self.onchain_wallet.get_unconfirmed_txids(),
			scope: MempoolScope::Incremental { best_processed_height: self.applied_tip_height() },
		};
		let started = std::time::Instant::now();
		let borrowed = layer.borrow_mempool(&query, evictions).await?;
		log_trace!(
			self.logger,
			"Borrowed a mempool view of {} unconfirmed and {} evicted transactions via {} in {}ms",
			borrowed.unconfirmed,
			borrowed.evicted,
			borrowed.by,
			started.elapsed().as_millis()
		);
		Ok(borrowed)
	}

	/// Whether the background loop borrows a mempool view on this tick, and with which
	/// evictions: `None` when there is no chain to borrow from.
	///
	/// A node catching up — kyoto still syncing, or waiting for peers after a cold boot whose
	/// network came up late — borrows too. Gating the borrow on being synced stopped it for
	/// exactly as long as the node was behind, which is when an incoming payment is most worth
	/// seeing. The answer is still tip-checked: one anchored off this node's chain is refused,
	/// and one above its applied tip cannot be placed and is accepted, as on a synced node.
	///
	/// What waits for the sync is the evictions. A view taken above the applied tip does not
	/// have the transactions that confirmed in the blocks between; the wallet's known
	/// unconfirmed ones among them would read as evicted, their inputs as spendable again and
	/// the payments as gone from the balance, until the blocks arrive. So a node behind the tip
	/// applies the unconfirmed half only ([`MempoolEvictions::Withhold`]) — nothing in it needs
	/// a block of ours — and a synced node applies both.
	fn mempool_borrow_due(&self, layer: &ChainLayer) -> Option<MempoolEvictions> {
		mempool_borrow_plan(layer.has_mempool_chain(), self.is_synced())
	}

	/// Which evictions a borrow taken now may apply: all of them only once synced.
	fn mempool_evictions(&self) -> MempoolEvictions {
		mempool_evictions_when(self.is_synced())
	}
}

/// [`CbfSyncEngine::mempool_borrow_due`], on its two inputs.
fn mempool_borrow_plan(has_mempool_chain: bool, synced: bool) -> Option<MempoolEvictions> {
	has_mempool_chain.then(|| mempool_evictions_when(synced))
}

/// [`CbfSyncEngine::mempool_evictions`], on whether the engine is synced.
fn mempool_evictions_when(synced: bool) -> MempoolEvictions {
	if synced {
		MempoolEvictions::Apply
	} else {
		MempoolEvictions::Withhold
	}
}

/// The background fee tick's cadence. The regular interval once a refresh has filled the cache;
/// until then — the boot refresh ran before kyoto was up and found nothing — a short retry, so
/// the estimates recover within seconds of the first blocks being reachable rather than on the
/// first regular tick ten minutes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeeCadence {
	recovering: bool,
}

impl FeeCadence {
	fn new(cache_filled: bool) -> Self {
		Self { recovering: !cache_filled }
	}

	/// When the first tick is due.
	fn first_delay(&self) -> Duration {
		if self.recovering {
			CBF_FEE_RECOVERY_RETRY
		} else {
			Duration::from_secs(DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS)
		}
	}

	/// A tick ran and succeeded (`ok`) or not: the delay to the next one, if it is not the
	/// regular interval.
	fn after(&mut self, ok: bool) -> Option<Duration> {
		if ok {
			self.recovering = false;
		}
		self.recovering.then_some(CBF_FEE_RECOVERY_RETRY)
	}
}

/// Kyoto as a [`FeeBlockSource`]: the live requester of whichever node the restart loop runs,
/// the engine's sync state, and the shared full-block permits.
pub(crate) struct KyotoFeeSource {
	runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	sync_state_rx: watch::Receiver<CbfSyncState>,
	full_block_permits: Arc<Semaphore>,
}

impl KyotoFeeSource {
	fn requester(&self) -> Result<Requester, SampleFailure> {
		match &*self.runtime_status.lock().unwrap_or_else(|e| e.into_inner()) {
			CbfRuntimeStatus::Started { requester, .. } => Ok(requester.clone()),
			CbfRuntimeStatus::Stopped => Err(SampleFailure::NodeGone),
		}
	}
}

#[async_trait]
impl FeeBlockSource for KyotoFeeSource {
	async fn tip_height(&self) -> Result<u32, SampleFailure> {
		let requester = self.requester()?;
		match tokio::time::timeout(
			Duration::from_secs(CBF_HEADER_LOOKUP_TIMEOUT_SECS),
			requester.chain_tip(),
		)
		.await
		{
			Ok(Ok(tip)) => Ok(tip.height),
			Ok(Err(_)) => Err(SampleFailure::NodeGone),
			Err(_elapsed) => Err(SampleFailure::LookupTimedOut),
		}
	}

	async fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SampleFailure> {
		let requester = self.requester()?;
		match tokio::time::timeout(
			Duration::from_secs(CBF_HEADER_LOOKUP_TIMEOUT_SECS),
			requester.get_header(height),
		)
		.await
		{
			Ok(Ok(header)) => Ok(header.map(|indexed| indexed.header.block_hash())),
			Ok(Err(_)) => Err(SampleFailure::NodeGone),
			Err(_elapsed) => Err(SampleFailure::LookupTimedOut),
		}
	}

	fn can_fetch(&self) -> bool {
		matches!(*self.sync_state_rx.borrow(), CbfSyncState::Active { synced_to_tip: true, .. })
	}

	/// Takes a full-block permit without waiting — the applicator's matched blocks come
	/// first — and holds it until the download is dropped, so a sample kept across passes
	/// still counts against the bound.
	fn request_block(&self, hash: BlockHash) -> Result<BlockFetch, SampleFailure> {
		let permit = Arc::clone(&self.full_block_permits)
			.try_acquire_owned()
			.map_err(|_| SampleFailure::NoPermit)?;
		let receiver =
			self.requester()?.request_block(hash).map_err(|_| SampleFailure::NodeGone)?;
		Ok(Box::pin(async move {
			let _permit = permit;
			match receiver.await {
				Ok(Ok(indexed)) => Ok((indexed.height, indexed.block)),
				Ok(Err(e)) => Err(SampleFailure::FetchFailed(e.to_string())),
				// The node that took the request was shut down or rebuilt.
				Err(_) => Err(SampleFailure::NodeGone),
			}
		}))
	}
}

/// The chain as the fee sampler and the FEE adapter read it, from whichever source feeds the
/// applicator now: kyoto's header chain and peers, or the node source's verified header chain
/// and blocks.
pub(crate) struct CbfFeeSource {
	kyoto: KyotoFeeSource,
	node: Option<SourceFeeSource>,
	active_source: Arc<AtomicU8>,
}

impl CbfFeeSource {
	fn node(&self) -> Option<&SourceFeeSource> {
		self.node.as_ref().filter(|_| self.active_source.load(Ordering::Acquire) == ACTIVE_NODE)
	}
}

#[async_trait]
impl FeeBlockSource for CbfFeeSource {
	async fn tip_height(&self) -> Result<u32, SampleFailure> {
		match self.node() {
			Some(node) => node.tip_height().await,
			None => self.kyoto.tip_height().await,
		}
	}

	async fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SampleFailure> {
		match self.node() {
			Some(node) => node.block_hash_at(height).await,
			None => self.kyoto.block_hash_at(height).await,
		}
	}

	fn can_fetch(&self) -> bool {
		match self.node() {
			Some(node) => node.can_fetch(),
			None => self.kyoto.can_fetch(),
		}
	}

	fn request_block(&self, hash: BlockHash) -> Result<BlockFetch, SampleFailure> {
		match self.node() {
			Some(node) => node.request_block(hash),
			None => self.kyoto.request_block(hash),
		}
	}
}

/// The scripts the node-source sync matches filters against: the wallet's and LDK's, as the
/// kyoto event loop's `MatchSet` reads them.
struct EngineScripts {
	wallet: Arc<Wallet>,
	registered: Arc<Mutex<HashSet<ScriptBuf>>>,
}

impl WatchedScripts for EngineScripts {
	fn counts(&self) -> (usize, usize) {
		let registered = self.registered.lock().unwrap_or_else(|e| e.into_inner()).len();
		(self.wallet.watched_script_count(), registered)
	}

	fn scripts(&self) -> Vec<ScriptBuf> {
		let mut scripts = self.wallet.list_watched_scripts();
		scripts.extend(self.registered.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned());
		scripts
	}
}

/// Keeps the block-fee cache warm until `stop` fires; see [`FeeSampler`]. A pass is raced
/// against the stop, so shutting down never waits out a block download.
async fn run_fee_sampler(
	mut sampler: FeeSampler<CbfFeeSource>, mut stop: tokio::sync::watch::Receiver<()>,
) {
	let mut tick = tokio::time::interval(CBF_FEE_SAMPLE_INTERVAL);
	tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		tokio::select! {
			_ = stop.changed() => return,
			_ = tick.tick() => {},
		}
		tokio::select! {
			_ = stop.changed() => return,
			_ = sampler.pass_logged() => {},
		}
	}
}

/// The interval on which the background loop borrows a mempool view: the on-chain wallet sync
/// interval every other engine polls its chain source on. [`crate::config::CbfConfig`] carries
/// no background-sync configuration, so this is the default one, floored like everywhere else.
fn mempool_borrow_interval() -> Duration {
	Duration::from_secs(
		BackgroundSyncConfig::default()
			.onchain_wallet_sync_interval_secs
			.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS),
	)
}

// The CBF adapters — coinbase-derived FEE, P2P BROADCAST, forward-only TX_STATUS and the
// existence-only UTXO source — read the engine through these.
impl CbfSyncEngine {
	/// The live kyoto requester, or `None` while kyoto is not running.
	pub(crate) fn requester(&self) -> Option<Requester> {
		match &*self.runtime_status.lock().unwrap_or_else(|e| e.into_inner()) {
			CbfRuntimeStatus::Started { requester, .. } => Some(requester.clone()),
			CbfRuntimeStatus::Stopped => None,
		}
	}

	/// Coinbase-derived fee rates of the blocks the applicator downloaded, by height.
	pub(crate) fn block_fee_cache(&self) -> &BlockFeeCache {
		&self.block_fee_cache
	}

	/// The chain as the fee sampler and the FEE adapter read it — kyoto's header chain or the
	/// node source's verified one, whichever feeds the applicator — and block downloads under
	/// one of the full-block permits.
	pub(crate) fn fee_source(&self) -> CbfFeeSource {
		CbfFeeSource {
			kyoto: KyotoFeeSource {
				runtime_status: Arc::clone(&self.runtime_status),
				sync_state_rx: self.sync_state_tx.subscribe(),
				full_block_permits: Arc::clone(&self.full_block_permits),
			},
			node: self.filter_source.as_ref().map(|source| {
				SourceFeeSource::new(
					Arc::clone(source),
					Arc::clone(&self.source_headers),
					self.sync_state_tx.subscribe(),
					Arc::clone(&self.full_block_permits),
				)
			}),
			active_source: Arc::clone(&self.active_source),
		}
	}

	/// Whether the node filter source, rather than kyoto, feeds the applicator now.
	fn node_source_active(&self) -> bool {
		self.filter_source.is_some() && self.active_source.load(Ordering::Acquire) == ACTIVE_NODE
	}

	/// Where watched transactions were seen confirmed, and the block the applicator most
	/// recently applied. Read by the TX_STATUS adapter, which exists with `swaps`.
	#[cfg_attr(not(feature = "swaps"), allow(dead_code))]
	pub(crate) fn watch_ledger(&self) -> &Arc<WatchLedger> {
		&self.watch_ledger
	}

	/// A simplified, externally-consumable snapshot of the sync state. Never blocks.
	pub(crate) fn sync_status(&self) -> CbfSyncStatus {
		simplify_sync_state(*self.sync_state_tx.borrow())
	}
}

#[async_trait]
impl SyncEngine for CbfSyncEngine {
	/// `"cbf"` for the P2P-only source, as before; `"cbf(node)"` or `"cbf(p2p)"` for the
	/// node sources, by which one feeds the applicator now.
	fn name(&self) -> &'static str {
		match self.source_mode {
			CbfSource::P2p => "cbf",
			_ if self.node_source_active() => "cbf(node)",
			_ => "cbf(p2p)",
		}
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
		// The node-source sync first: a `node,p2p` fallback checks it under the same lock
		// before it starts kyoto, so once it is taken no kyoto can start behind this stop.
		let source_run = self.source_run.lock().unwrap_or_else(|e| e.into_inner()).take();
		if let Some(run) = source_run {
			let _ = run.stop_tx.send(true);
		}
		let requester = {
			let mut status = self.runtime_status.lock().unwrap_or_else(|e| e.into_inner());
			match std::mem::replace(&mut *status, CbfRuntimeStatus::Stopped) {
				CbfRuntimeStatus::Started { requester, .. } => Some(requester),
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

	/// Wait — bounded by [`CBF_SYNC_WAIT_TIMEOUT`] — for the filters to catch up, then borrow a
	/// mempool view if the layer has one to lend, then record the pass.
	///
	/// The mempool is supplementary: a filter-driven engine has none of its own, and a
	/// provider that cannot answer this pass does not make the pass fail — the chain is
	/// synced regardless. The background loop borrows on its own cadence too; this pass asks
	/// again so a caller of `sync_wallets` sees the mempool as of now.
	async fn sync_once(
		&self, layer: &ChainLayer, _channel_manager: Arc<ChannelManager>,
		_chain_monitor: Arc<ChainMonitor>, _output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		self.wait_until_synced_within(CBF_SYNC_WAIT_TIMEOUT).await?;

		if layer.has_mempool_chain() {
			// Just waited for the sync, but a block may have landed since: ask again.
			if let Err(e) = self.borrow_mempool(layer, self.mempool_evictions()).await {
				log_error!(
					self.logger,
					"Could not borrow a mempool view this pass; the filter sync is complete \
					 without it: {}",
					e
				);
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

	/// Launches kyoto and the applicator, then, until told to stop, keeps the fee cache fresh
	/// through the FEE slot and — when the MEMPOOL chain has an adapter, synced or not — borrows
	/// a mempool view on the on-chain wallet sync interval. Block application itself is
	/// event-driven and runs on the spawned tasks; this loop owns only the two ticks.
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
		self.launch(Arc::clone(&runtime), listener);

		// Samples the fee window's blocks in its own task: a block download takes seconds
		// to minutes on one mainnet peer, and must hold up neither tick below.
		let sampler = FeeSampler::new(
			self.fee_source(),
			Arc::clone(&self.block_fee_cache),
			Arc::clone(&self.logger),
		);
		runtime.spawn(run_fee_sampler(sampler, stop_sync_receiver.clone()));

		let mut fee_rate_update_interval =
			tokio::time::interval(Duration::from_secs(DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS));
		fee_rate_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		// The boot refresh ran before kyoto was launched. If it filled the cache, the first
		// regular tick is ten minutes out; if it did not, retry shortly until one does.
		let mut fee_cadence = FeeCadence::new(layer.fee_estimator().has_estimates());
		fee_rate_update_interval.reset_after(fee_cadence.first_delay());

		// The Dependent tier saw incoming unconfirmed payments and evictions on its own; a
		// hybrid node must too, without waiting for someone to call `sync_wallets`.
		let mut mempool_interval = tokio::time::interval(mempool_borrow_interval());
		mempool_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

		// The fee refresh runs as its own task, one at a time: its chain may fall through to a
		// provider that takes its whole budget, and the mempool tick must not wait on that.
		let mut fee_refresh: Option<tokio::task::JoinHandle<bool>> = None;

		loop {
			tokio::select! {
				_ = stop_sync_receiver.changed() => {
					log_trace!(self.logger, "Stopping CBF background loop.");
					if let Some(refresh) = fee_refresh.take() {
						refresh.abort();
					}
					return;
				}
				_ = fee_rate_update_interval.tick(), if fee_refresh.is_none() => {
					let layer = Arc::clone(&layer);
					let logger = Arc::clone(&self.logger);
					fee_refresh = Some(runtime.spawn(async move {
						let refreshed = layer.update_fee_rate_estimates().await;
						if let Err(e) = &refreshed {
							log_debug!(
								logger,
								"CBF fee-rate refresh failed this tick; the cached rates stand: {}",
								e
							);
						}
						refreshed.is_ok()
					}));
				}
				finished = async { fee_refresh.as_mut().expect("guarded").await }, if fee_refresh.is_some() => {
					fee_refresh = None;
					// A refresh that panicked or was cancelled did not fill the cache.
					let ok = finished.unwrap_or(false);
					if let Some(retry) = fee_cadence.after(ok) {
						fee_rate_update_interval.reset_after(retry);
					}
				}
				_ = mempool_interval.tick() => {
					let Some(evictions) = self.mempool_borrow_due(&layer) else {
						continue;
					};
					// A borrow runs up to its chain's budget; a stop must not wait it out.
					tokio::select! {
						_ = stop_sync_receiver.changed() => {
							log_trace!(self.logger, "Stopping CBF background loop mid-borrow.");
							return;
						}
						borrowed = self.borrow_mempool(&layer, evictions) => {
							// Every tick asks again, so one that cannot answer is not news.
							if let Err(e) = borrowed {
								log_debug!(
									self.logger,
									"CBF background mempool borrow failed this tick: {}",
									e
								);
							}
						}
					}
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

	fn cbf_sync_status(&self) -> Option<CbfSyncStatus> {
		Some(self.sync_status())
	}

	/// The script joins the match set, and the ledger holds LDK's registration apart from any
	/// swap's, letting it go once buried.
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.match_script(script_pubkey.to_owned());
		self.watch_ledger.watch_ldk(*txid);
	}

	fn register_output(&self, output: WatchedOutput) {
		self.registered_scripts
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.insert(output.script_pubkey);
	}

	/// A swap watch is a `Filter` registration and a ledger entry in one: the script joins the
	/// match set so the confirming block is fetched, and the ledger records where the
	/// applicator sees the transaction, which is the only place the TX_STATUS adapter over this
	/// engine can answer from.
	#[cfg(feature = "swaps")]
	fn watch_tx(&self, txid: Txid, script_pubkey: ScriptBuf) {
		self.match_script(script_pubkey);
		self.watch_ledger.watch_swap(txid);
	}

	/// The script stays in the match set — a set that only grows, and a script LDK may still
	/// watch for its own reasons — and the ledger drops the swap's watch, keeping LDK's if
	/// LDK registered the same transaction.
	#[cfg(feature = "swaps")]
	fn unwatch_tx(&self, txid: &Txid) {
		self.watch_ledger.unwatch_swap(txid);
	}

	/// Asks kyoto for the header at the block's height and compares hashes. `None` while
	/// kyoto is not running, when the lookup fails or times out, and when the height is
	/// outside the header range kyoto holds (above its tip, or below the checkpoint it
	/// resumed from): an answer this engine cannot check is not one it refutes.
	async fn is_on_chain(&self, block: &BlockId) -> Option<bool> {
		if self.node_source_active() {
			// The verified header chain; a height outside it is not one this engine refutes.
			let held = lock_headers(&self.source_headers).hash(block.height);
			return held.map(|hash| hash == block.hash);
		}
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

/// What a `node,p2p` engine needs to start kyoto on the applicator the node source fed, once
/// that source has stayed unavailable too long.
struct KyotoFallback {
	kyoto: KyotoParams,
	generation: u64,
	listener: Arc<ChainListener>,
	registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
	runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	sync_state_tx: watch::Sender<CbfSyncState>,
	ops_tx: mpsc::Sender<ChainOp>,
	full_block_permits: Arc<Semaphore>,
	source_run: Arc<Mutex<Option<SourceRun>>>,
	active_source: Arc<AtomicU8>,
	logger: Arc<Logger>,
}

impl KyotoFallback {
	/// Builds kyoto — re-anchored on the listeners, so the blocks the node source already
	/// applied are skipped by the applicator — and runs it under the node source's launch
	/// generation. Nothing starts if `stop()` took the run first.
	fn start(self, handle: &tokio::runtime::Handle) {
		let mut run = self.source_run.lock().unwrap_or_else(|e| e.into_inner());
		if !run.as_ref().is_some_and(|r| r.generation == self.generation) {
			log_info!(self.logger, "CBF P2P fallback aborted: the engine was stopped.");
			return;
		}
		let (node, client) = match self.kyoto.build(&self.listener) {
			Ok(built) => built,
			Err(refusal) => {
				*run = None;
				drop(run);
				log_error!(self.logger, "CBF P2P fallback cannot start: {}", refusal);
				self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
				return;
			},
		};
		let Client { requester, info_rx, warn_rx, event_rx } = client;
		*self.runtime_status.lock().unwrap_or_else(|e| e.into_inner()) =
			CbfRuntimeStatus::Started { requester, generation: self.generation };
		*run = None;
		drop(run);
		self.active_source.store(ACTIVE_P2P, Ordering::Release);
		log_warn!(
			self.logger,
			"CBF fell back to the P2P network (kyoto) for the rest of this run: the node source stayed unavailable."
		);

		let kyoto_loop = KyotoLoop {
			kyoto: self.kyoto,
			generation: self.generation,
			listener: self.listener,
			registered_scripts: self.registered_scripts,
			runtime_status: self.runtime_status,
			sync_state_tx: self.sync_state_tx,
			ops_tx: self.ops_tx,
			full_block_permits: self.full_block_permits,
			logger: self.logger,
		};
		handle.spawn(kyoto_loop.run(node, info_rx, warn_rx, event_rx));
	}
}

/// The kyoto side of the engine: runs the node, restarts it on failure with exponential
/// backoff, and turns its events into [`ChainOp`]s for the applicator.
struct KyotoLoop {
	kyoto: KyotoParams,
	/// The launch this loop belongs to; see [`CbfRuntimeStatus::Started`].
	generation: u64,
	listener: Arc<ChainListener>,
	registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
	runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	sync_state_tx: watch::Sender<CbfSyncState>,
	ops_tx: mpsc::Sender<ChainOp>,
	/// The [`CBF_FULL_BLOCK_PERMITS`] bound; shared by every node this loop runs, since a
	/// permit lives in its op until the applicator drops it, whichever node fetched the block.
	full_block_permits: Arc<Semaphore>,
	logger: Arc<Logger>,
}

/// How one run of the kyoto node ended, as the restart loop judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunEnd {
	/// `node.run()` returned `Ok`: it was asked to shut down.
	Shutdown,
	/// `node.run()` returned [`NodeError::NoReachablePeers`]: kyoto tried every peer it knew and
	/// reached none. Environmental — the network is down (a Pi whose Wi-Fi or DHCP came up late
	/// after a cold boot), DNS seeds are unreachable, or the trusted peers are offline — and it
	/// clears by itself once the network does.
	NoPeers,
	/// The event loop gave up on the node because a matched block could not be fetched after
	/// every retry: the peers stopped answering, timed out, or dropped the request. Environmental
	/// like [`RunEnd::NoPeers`]: a rebuilt node on healthier peers fetches the block.
	PeersUnresponsive,
	/// The node's event stream ended while `node.run()` was still going. Nothing in the network
	/// explains it.
	NodeFailed,
	/// The event task ended for any other reason — its requester was gone, the block permits
	/// were closed, or the task panicked — while the node itself kept running. Before this was
	/// a distinct end the failure was reported and the node left running: a permanent stall,
	/// since nothing else ever restarted it.
	EventLoopFailed,
	/// The applicator halted on a divergence. Nothing can take blocks until the node process is
	/// restarted, so there is nothing to rebuild kyoto for.
	ApplicatorGone,
}

impl RunEnd {
	/// Whether the run ended on the network rather than on the node: such an end is retried for
	/// as long as it takes and never spends the failure budget.
	fn is_environmental(self) -> bool {
		matches!(self, RunEnd::NoPeers | RunEnd::PeersUnresponsive)
	}
}

/// How the restart loop reports a restart it is about to wait out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartReport {
	/// The node started waiting on the network just now, or has been waiting another
	/// [`CBF_PEER_WAIT_REPORT_INTERVAL`]: one warning.
	WaitingWarn,
	/// Still waiting on the network, reported recently: debug only.
	WaitingQuiet,
	/// An unexpected failure, counted against the budget: an error.
	Failure,
}

/// What the restart loop does once a run has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartDecision {
	/// Rebuild the node after this delay, reported as `report` says.
	Restart { backoff: Duration, report: RestartReport },
	/// The budget of consecutive unexpected failures is spent: publish a failed sync.
	GiveUp,
	/// Nothing to restart: the node was stopped on purpose, or a restart cannot help.
	Stop,
}

/// When to restart the node, and when to give up on it.
///
/// Two kinds of failed run. One that ended on the network ([`RunEnd::is_environmental`]) is
/// retried forever: a Pi that booted before its Wi-Fi saw six `NoReachablePeers` in sixteen
/// seconds, and a budget sized for node failures gave up for good on a network that came up a
/// minute later — the node stayed behind, its channel monitors unfed, until someone restarted
/// the process. Its backoff doubles to [`CBF_MAX_BACKOFF_MS`] and it is reported once, then
/// once per [`CBF_PEER_WAIT_REPORT_INTERVAL`] while it lasts. Every other failure spends the
/// budget of [`MAX_RESTART_RETRIES`] consecutive runs; only that budget running out gives up.
///
/// Kept apart from the loop that acts on it so the decisions that matter can be checked
/// without a node.
struct RestartPolicy {
	/// Consecutive unexpected failures; the budget.
	retries: u32,
	backoff_ms: u64,
	/// Since when the node has been failing on the network, while it is.
	waiting_since: Option<Instant>,
	/// When the wait was last reported at warn.
	last_wait_report: Option<Instant>,
}

impl RestartPolicy {
	fn new() -> Self {
		Self {
			retries: 0,
			backoff_ms: INITIAL_BACKOFF_MS,
			waiting_since: None,
			last_wait_report: None,
		}
	}

	/// The run that just ended caught up to the tip at least once: it was a healthy node that
	/// failed later, not a failed restart, so the budget and the backoff start over.
	fn note_progress(&mut self) {
		self.retries = 0;
		self.note_connected();
	}

	/// The run that just ended completed a peer handshake: the network is back, so the next
	/// failure is retried promptly and a later wait is reported afresh. How long the node
	/// waited, if it was waiting.
	///
	/// The failure budget is left alone: a handshake proves the network, not the node, and a
	/// node that handshakes and then fails the same unexpected way every run must still give up.
	fn note_connected(&mut self) -> Option<Duration> {
		self.backoff_ms = INITIAL_BACKOFF_MS;
		self.last_wait_report = None;
		self.waiting_since.take().map(|since| since.elapsed())
	}

	fn next_backoff(&mut self) -> Duration {
		let backoff = Duration::from_millis(self.backoff_ms);
		self.backoff_ms = self.backoff_ms.saturating_mul(2).min(CBF_MAX_BACKOFF_MS);
		backoff
	}

	fn decide(&mut self, end: RunEnd, now: Instant) -> RestartDecision {
		match end {
			RunEnd::Shutdown | RunEnd::ApplicatorGone => RestartDecision::Stop,
			RunEnd::NoPeers | RunEnd::PeersUnresponsive => {
				debug_assert!(end.is_environmental());
				self.waiting_since.get_or_insert(now);
				let report = match self.last_wait_report {
					Some(last)
						if now.saturating_duration_since(last) < CBF_PEER_WAIT_REPORT_INTERVAL =>
					{
						RestartReport::WaitingQuiet
					},
					_ => {
						self.last_wait_report = Some(now);
						RestartReport::WaitingWarn
					},
				};
				RestartDecision::Restart { backoff: self.next_backoff(), report }
			},
			RunEnd::NodeFailed | RunEnd::EventLoopFailed => {
				self.retries += 1;
				if self.retries > MAX_RESTART_RETRIES {
					return RestartDecision::GiveUp;
				}
				RestartDecision::Restart {
					backoff: self.next_backoff(),
					report: RestartReport::Failure,
				}
			},
		}
	}

	/// How many runs in a row have failed unexpectedly.
	fn failures(&self) -> u32 {
		self.retries
	}

	/// How long the node has been failing on the network, while it is.
	fn waiting_for(&self, now: Instant) -> Option<Duration> {
		self.waiting_since.map(|since| now.saturating_duration_since(since))
	}
}

/// What a run that ended on the network ran into, for the wait log.
fn run_end_reason(end: RunEnd) -> &'static str {
	match end {
		RunEnd::NoPeers => "no reachable peers",
		RunEnd::PeersUnresponsive => "peers did not serve a matched block",
		RunEnd::Shutdown => "shut down",
		RunEnd::NodeFailed => "event stream ended",
		RunEnd::EventLoopFailed => "event loop failed",
		RunEnd::ApplicatorGone => "applicator halted",
	}
}

/// Which side of a run finished first.
enum Turn {
	Node(Result<(), NodeError>),
	Events(Result<EventLoopEnd, tokio::task::JoinError>),
}

/// A node with the receivers its client came with.
type NodeRun = (
	KyotoNode,
	mpsc::Receiver<Info>,
	mpsc::UnboundedReceiver<Warning>,
	mpsc::UnboundedReceiver<KyotoEvent>,
);

impl KyotoLoop {
	async fn run(
		self, node: KyotoNode, info_rx: mpsc::Receiver<Info>,
		warn_rx: mpsc::UnboundedReceiver<Warning>, event_rx: mpsc::UnboundedReceiver<KyotoEvent>,
	) {
		let mut current: NodeRun = (node, info_rx, warn_rx, event_rx);
		let mut policy = RestartPolicy::new();
		// Set by the event loop on `FiltersSynced`, read once per run end.
		let synced_this_run = Arc::new(AtomicBool::new(false));
		// Set by the info consumer on a peer handshake, read once per run end.
		let connected_this_run = Arc::new(AtomicBool::new(false));

		loop {
			let (node, info_rx, warn_rx, event_rx) = current;
			let info_handle = tokio::spawn(process_info_messages(
				info_rx,
				Arc::clone(&connected_this_run),
				Arc::clone(&self.logger),
			));
			let warn_handle =
				tokio::spawn(process_warn_messages(warn_rx, Arc::clone(&self.logger)));
			let mut event_handle =
				tokio::spawn(self.event_loop(Arc::clone(&synced_this_run)).run(event_rx));
			let mut node_run = Box::pin(node.run());

			// The node and its event consumer are raced: either one ending ends the run. Before,
			// only the node was awaited, so an event loop that gave up left the node running —
			// healthy as far as `run()` could tell — and nothing ever restarted it.
			let turn = tokio::select! {
				biased;
				result = &mut node_run => Turn::Node(result),
				joined = &mut event_handle => Turn::Events(joined),
			};
			let end = match turn {
				Turn::Node(Ok(())) => {
					log_info!(self.logger, "CBF node shut down cleanly.");
					event_handle.abort();
					RunEnd::Shutdown
				},
				Turn::Node(Err(e)) => {
					// Matched exhaustively so a kyoto upgrade that adds a failure has to be
					// classified here: environmental ends are retried forever, and reported by
					// the restart decision below at a rate that suits a network that is down.
					let end = match e {
						NodeError::NoReachablePeers => RunEnd::NoPeers,
					};
					log_debug!(self.logger, "CBF node exited with error: {}", e);
					event_handle.abort();
					end
				},
				Turn::Events(joined) => {
					let end = match joined {
						Ok(EventLoopEnd::ApplicatorGone) => RunEnd::ApplicatorGone,
						Ok(EventLoopEnd::PeersUnresponsive) => RunEnd::PeersUnresponsive,
						Ok(EventLoopEnd::Failed(e)) => {
							log_error!(self.logger, "CBF event loop gave up on the node: {}", e);
							RunEnd::EventLoopFailed
						},
						Ok(EventLoopEnd::EventsClosed) => {
							log_error!(
								self.logger,
								"CBF event stream ended while the node was still running."
							);
							RunEnd::NodeFailed
						},
						Err(e) => {
							log_error!(
								self.logger,
								"CBF event loop task ended abnormally: {:?}",
								e
							);
							RunEnd::EventLoopFailed
						},
					};
					// The node is still running with nobody consuming it: stop it before deciding
					// anything, so a rebuild never has two nodes on one data directory.
					self.stop_node(node_run).await;
					end
				},
			};
			info_handle.abort();
			warn_handle.abort();

			let connected = connected_this_run.swap(false, Ordering::AcqRel);
			if synced_this_run.swap(false, Ordering::AcqRel) {
				policy.note_progress();
			} else if connected {
				if let Some(waited) = policy.note_connected() {
					log_info!(
						self.logger,
						"CBF reached peers again after waiting {}s.",
						waited.as_secs()
					);
				}
			}
			let now = Instant::now();
			match policy.decide(end, now) {
				RestartDecision::Stop => {
					// A `stop()` settled the status and state itself, and a halted applicator
					// published its failure; this only lands for an exit nobody asked for.
					let error = match end {
						RunEnd::ApplicatorGone => Error::TxSyncFailed,
						_ => Error::NotRunning,
					};
					self.settle(CbfSyncState::Failed(error));
					break;
				},
				RestartDecision::GiveUp => {
					log_error!(
						self.logger,
						"CBF node failed {} times in a row without catching up; giving up.",
						policy.failures()
					);
					self.settle(CbfSyncState::Failed(Error::TxSyncFailed));
					break;
				},
				RestartDecision::Restart { backoff, report } => {
					match report {
						RestartReport::WaitingWarn => log_warn!(
							self.logger,
							"CBF waiting for peers: {}; waiting {}s so far, next retry in {}s.",
							run_end_reason(end),
							policy.waiting_for(now).unwrap_or_default().as_secs(),
							backoff.as_secs().max(1)
						),
						RestartReport::WaitingQuiet => log_debug!(
							self.logger,
							"CBF still waiting for peers: {}; next retry in {}ms.",
							run_end_reason(end),
							backoff.as_millis()
						),
						RestartReport::Failure => log_error!(
							self.logger,
							"Restarting the CBF node in {}ms (attempt {}/{}).",
							backoff.as_millis(),
							policy.failures(),
							MAX_RESTART_RETRIES,
						),
					}
					// Between two runs the node is catching up, not caught up: a run that had
					// synced and then lost its peers must not read `Synced` through a backoff of
					// up to five minutes.
					self.publish_catching_up();
					tokio::time::sleep(backoff).await;
					match self.rebuild() {
						Some(next) => current = next,
						None => break,
					}
				},
			}
		}
	}

	/// The consumer of one node's events.
	fn event_loop(&self, synced: Arc<AtomicBool>) -> EventLoop {
		EventLoop {
			generation: self.generation,
			registered_scripts: Arc::clone(&self.registered_scripts),
			runtime_status: Arc::clone(&self.runtime_status),
			ops_tx: self.ops_tx.clone(),
			onchain_wallet: Arc::clone(&self.listener.onchain_wallet),
			sync_state_tx: self.sync_state_tx.clone(),
			full_block_permits: Arc::clone(&self.full_block_permits),
			synced,
			logger: Arc::clone(&self.logger),
		}
	}

	/// This launch's requester, or `None` once `stop()` took it or a later launch replaced it.
	fn own_requester(&self) -> Option<Requester> {
		own_requester(&self.runtime_status, self.generation)
	}

	/// Asks the running node to shut down and waits, bounded, for its `run()` to return. A node
	/// that does not stop in time is dropped: its future is cancelled, and its peer tasks end as
	/// the channels they report into close.
	async fn stop_node(&self, node_run: impl Future<Output = Result<(), NodeError>>) {
		if let Some(requester) = self.own_requester() {
			if requester.shutdown().is_err() {
				log_debug!(self.logger, "CBF node was already gone when asked to shut down.");
			}
		}
		match tokio::time::timeout(Duration::from_secs(CBF_NODE_SHUTDOWN_TIMEOUT_SECS), node_run)
			.await
		{
			Ok(Ok(())) => log_debug!(self.logger, "CBF node shut down for a rebuild."),
			Ok(Err(e)) => log_debug!(
				self.logger,
				"CBF node exited with error while shutting down for a rebuild: {:?}",
				e
			),
			Err(_elapsed) => log_warn!(
				self.logger,
				"CBF node did not shut down within {}s; dropping it.",
				CBF_NODE_SHUTDOWN_TIMEOUT_SECS
			),
		}
	}

	/// Publishes that the node is behind — `Syncing`, never `Failed` — while this launch still
	/// owns the runtime status; after a `stop()` or a newer launch the state is not ours.
	fn publish_catching_up(&self) {
		publish_catching_up(&self.runtime_status, self.generation, &self.sync_state_tx);
	}

	/// Marks kyoto stopped and publishes `state` — unless the runtime status no longer belongs
	/// to this launch. A `stop()` since has settled both already, and a `stop()` followed by a
	/// fresh `start()` owns them: a late write from this loop would clobber the new node's
	/// `Started` and fail the sync it is running.
	fn settle(&self, state: CbfSyncState) {
		let mut status = self.runtime_status.lock().unwrap_or_else(|e| e.into_inner());
		let owned = matches!(
			&*status,
			CbfRuntimeStatus::Started { generation, .. } if *generation == self.generation
		);
		if !owned {
			log_debug!(
				self.logger,
				"CBF launch {} ended after the runtime status moved on; leaving it alone.",
				self.generation
			);
			return;
		}
		*status = CbfRuntimeStatus::Stopped;
		drop(status);
		self.sync_state_tx.send_replace(state);
	}

	/// Builds the next node, re-anchored on the listeners' current state, and hands its
	/// requester to the runtime status. `None` when the launch no longer owns the runtime or
	/// the resume is refused; the latter settles the sync state as failed.
	fn rebuild(&self) -> Option<NodeRun> {
		if self.own_requester().is_none() {
			log_info!(self.logger, "CBF restart aborted: stop() was called during the backoff.");
			return None;
		}
		let (node, client) = match self.kyoto.build(&self.listener) {
			Ok(built) => built,
			Err(refusal) => {
				log_error!(self.logger, "CBF restart aborted: {}", refusal);
				self.settle(CbfSyncState::Failed(Error::TxSyncFailed));
				return None;
			},
		};
		let Client { requester, info_rx, warn_rx, event_rx } = client;

		{
			let mut status = self.runtime_status.lock().unwrap_or_else(|e| e.into_inner());
			let owned = matches!(
				&*status,
				CbfRuntimeStatus::Started { generation, .. } if *generation == self.generation
			);
			if !owned {
				drop(status);
				let _ = requester.shutdown();
				log_info!(
					self.logger,
					"CBF restart aborted: stop() was called while the node was being rebuilt."
				);
				return None;
			}
			*status = CbfRuntimeStatus::Started { requester, generation: self.generation };
		}
		self.sync_state_tx.send_replace(CbfSyncState::Active {
			applied_tip: Some(self.listener.get_best_block().height),
			synced_to_tip: false,
		});
		Some((node, info_rx, warn_rx, event_rx))
	}
}

/// [`KyotoLoop::publish_catching_up`] for launch `generation`. The status lock is held across
/// the publish so a concurrent `stop()` cannot slip its `Failed` in between and be overwritten.
fn publish_catching_up(
	runtime_status: &Mutex<CbfRuntimeStatus>, generation: u64,
	sync_state_tx: &watch::Sender<CbfSyncState>,
) {
	let status = runtime_status.lock().unwrap_or_else(|e| e.into_inner());
	let owned = matches!(
		&*status,
		CbfRuntimeStatus::Started { generation: owner, .. } if *owner == generation
	);
	if owned {
		mark_syncing(sync_state_tx);
	}
}

/// The requester of launch `generation`, if the runtime status still belongs to it. Copied
/// out under the lock so no caller holds a `std::sync::Mutex` guard across an `.await`.
fn own_requester(runtime_status: &Mutex<CbfRuntimeStatus>, generation: u64) -> Option<Requester> {
	match &*runtime_status.lock().unwrap_or_else(|e| e.into_inner()) {
		CbfRuntimeStatus::Started { requester, generation: owner } if *owner == generation => {
			Some(requester.clone())
		},
		_ => None,
	}
}

/// Kyoto reports progress on every filter batch and a handshake per peer. On a device whose
/// log is the only window into "syncing" versus "no peers", one line per peer and one per ten
/// percent of a catch-up is the signal without the noise.
///
/// Raises `connected` on every handshake, for the restart loop's backoff.
async fn process_info_messages(
	mut info_rx: mpsc::Receiver<Info>, connected: Arc<AtomicBool>, logger: Arc<Logger>,
) {
	let mut handshakes = 0usize;
	// Progress restarts from zero on every batch after the first, and the `FiltersSynced` line
	// already marks each of those; only a rising decile is worth a line.
	let mut last_decile: Option<u32> = None;
	while let Some(info) = info_rx.recv().await {
		match info {
			Info::SuccessfulHandshake => {
				connected.store(true, Ordering::Release);
				handshakes += 1;
				log_info!(logger, "CBF peer connected ({} handshakes this run).", handshakes);
			},
			Info::ConnectionsMet => log_info!(logger, "CBF required peer connections met."),
			Info::Progress(progress) => {
				let percent = progress.percentage_complete().clamp(0.0, 100.0);
				let decile = percent as u32 / 10;
				let rising = match last_decile {
					Some(last) => decile > last,
					None => true,
				};
				if rising {
					last_decile = Some(decile);
					log_info!(
						logger,
						"CBF filter sync {:.0}% complete; header chain at height {}.",
						percent,
						progress.chain_height()
					);
				}
			},
			Info::BlockReceived(hash) => log_debug!(logger, "CBF received block {}", hash),
		}
	}
}

/// Kyoto's warnings, at the level each one deserves: a peer problem the node handles itself is
/// operator information, a rejected broadcast or a peer without filters is a warning, and a
/// sync error nobody expected is an error.
async fn process_warn_messages(mut warn_rx: mpsc::UnboundedReceiver<Warning>, logger: Arc<Logger>) {
	// `NeedConnections` is re-sent on every iteration of kyoto's 10ms loop for as long as the
	// node is under-connected; it is logged when the counts change and dropped otherwise.
	let mut last_need: Option<(usize, usize)> = None;
	while let Some(warning) = warn_rx.recv().await {
		match &warning {
			Warning::NeedConnections { connected, required } => {
				if last_need != Some((*connected, *required)) {
					last_need = Some((*connected, *required));
					log_info!(
						logger,
						"CBF node is looking for peers: {} connected, {} required.",
						connected,
						required
					);
				}
			},
			Warning::CouldNotConnect | Warning::PeerTimedOut | Warning::PotentialStaleTip => {
				log_info!(logger, "CBF node: {}", warning)
			},
			Warning::TransactionRejected { .. } | Warning::NoCompactFilters => {
				log_warn!(logger, "CBF node: {}", warning)
			},
			Warning::UnexpectedSyncError { .. } => log_error!(logger, "CBF node: {}", warning),
			Warning::UnsolicitedMessage | Warning::EvaluatingFork | Warning::ChannelDropped => {
				log_debug!(logger, "CBF node: {}", warning)
			},
		}
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

/// Why the event loop stopped consuming kyoto's events.
enum EventLoopEnd {
	/// Kyoto dropped its event sender: the node is gone.
	EventsClosed,
	/// The applicator is gone: it halted on a divergence, and nothing can take blocks.
	ApplicatorGone,
	/// A matched block could not be fetched after every retry: the peers timed out, dropped the
	/// request, or would not serve it. A rebuilt node, on whichever peers it reaches, retries.
	PeersUnresponsive,
	/// The loop cannot go on with this node: the requester was gone, or the block permits were
	/// closed.
	Failed(Error),
}

/// One node's consumer of kyoto's events, turning them into [`ChainOp`]s for the applicator.
struct EventLoop {
	generation: u64,
	registered_scripts: Arc<Mutex<HashSet<ScriptBuf>>>,
	runtime_status: Arc<Mutex<CbfRuntimeStatus>>,
	ops_tx: mpsc::Sender<ChainOp>,
	onchain_wallet: Arc<Wallet>,
	sync_state_tx: watch::Sender<CbfSyncState>,
	full_block_permits: Arc<Semaphore>,
	/// Raised on `FiltersSynced`, for the restart loop's failure budget.
	synced: Arc<AtomicBool>,
	logger: Arc<Logger>,
}

impl EventLoop {
	async fn run(self, mut event_rx: mpsc::UnboundedReceiver<KyotoEvent>) -> EventLoopEnd {
		let mut match_set = MatchSet::new();
		while let Some(event) = event_rx.recv().await {
			match event {
				KyotoEvent::IndexedFilter(indexed_filter) => {
					// A new block's filter arrived, so we're behind by at least this block until it
					// is fetched (if matched) and applied. Flip this before the fetch, not after,
					// so a `sync_wallets` call issued in between doesn't return on a stale
					// `synced_to_tip` that predates this block.
					mark_syncing(&self.sync_state_tx);

					let block_hash = indexed_filter.block_hash();
					let matched = {
						let scripts =
							match_set.current(&self.onchain_wallet, &self.registered_scripts);
						indexed_filter.contains_any(scripts.iter())
					};

					let op = if matched {
						match self.fetch_full_block(block_hash).await {
							Ok(op) => op,
							Err(end) => return end,
						}
					} else {
						ChainOp::ConnectFiltered {
							header: indexed_filter.header(),
							height: indexed_filter.height(),
						}
					};
					if self.ops_tx.send(op).await.is_err() {
						return EventLoopEnd::ApplicatorGone;
					}
				},
				KyotoEvent::FiltersSynced(sync_update) => {
					// Because application of blocks is async, the fact that kyoto synced up to the
					// tip does NOT mean that we caught everything up, that's why we send a ChainOp,
					// only processing of which means we processed all blocks up to the tip.
					log_info!(
						self.logger,
						"Kyoto synced up to the tip {}",
						sync_update.tip().height
					);
					self.synced.store(true, Ordering::Release);
					let synced = ChainOp::Synced { tip_height: sync_update.tip().height };
					if self.ops_tx.send(synced).await.is_err() {
						return EventLoopEnd::ApplicatorGone;
					}
				},
				KyotoEvent::ChainUpdate(BlockHeaderChanges::Connected(indexed_header)) => {
					log_debug!(
						self.logger,
						"Kyoto connected header at height {}",
						indexed_header.height
					);
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
					if !headers.is_empty()
						&& self.ops_tx.send(ChainOp::Disconnect { headers }).await.is_err()
					{
						return EventLoopEnd::ApplicatorGone;
					}
				},
				KyotoEvent::ChainUpdate(BlockHeaderChanges::ForkAdded(fork)) => {
					log_debug!(self.logger, "Kyoto added fork header at height {}", fork.height);
				},
			}
		}
		EventLoopEnd::EventsClosed
	}

	/// Fetches a matched block under one of the [`CBF_FULL_BLOCK_PERMITS`], retrying a bounded
	/// number of times. The permit is taken before the request so the bound covers the block
	/// while it downloads, and rides in the op until the applicator drops it.
	async fn fetch_full_block(&self, block_hash: BlockHash) -> Result<ChainOp, EventLoopEnd> {
		let permit = match Arc::clone(&self.full_block_permits).acquire_owned().await {
			Ok(permit) => permit,
			Err(_closed) => {
				log_error!(self.logger, "CBF full-block permits were closed; cannot fetch blocks.");
				return Err(EventLoopEnd::Failed(Error::TxSyncFailed));
			},
		};
		let Some(requester) = own_requester(&self.runtime_status, self.generation) else {
			return Err(EventLoopEnd::Failed(Error::NotRunning));
		};

		let mut attempt = 0;
		loop {
			attempt += 1;
			let handle = match requester.request_block(block_hash) {
				Ok(handle) => handle,
				Err(_) => {
					log_error!(
						self.logger,
						"Failed to obtain receiver for matched CBF block {}; node is stopped",
						block_hash
					);
					return Err(EventLoopEnd::Failed(Error::NotRunning));
				},
			};

			// Bound the download so an unresponsive peer can't park the fetch forever, then
			// flatten the three error layers (timeout / receiver dropped / fetch error) into a
			// single reason so the retry-or-fail decision is written once.
			let fetched =
				tokio::time::timeout(Duration::from_secs(CBF_BLOCK_FETCH_TIMEOUT_SECS), handle)
					.await
					.map_err(|_| format!("timed out after {}s", CBF_BLOCK_FETCH_TIMEOUT_SECS))
					.and_then(|recv| recv.map_err(|_| "receiver was dropped".to_string()))
					.and_then(|fetch| fetch.map_err(|e| format!("failed: {:?}", e)));

			match fetched {
				Ok(block) => return Ok(ChainOp::ConnectFull { block, permit }),
				Err(reason) if attempt < CBF_BLOCK_FETCH_RETRIES => {
					log_debug!(
						self.logger,
						"CBF block fetch for {} {} on attempt {}; retrying",
						block_hash,
						reason,
						attempt
					);
				},
				Err(reason) => {
					log_warn!(
						self.logger,
						"CBF block fetch for {} {} after {} attempts; giving up on this node",
						block_hash,
						reason,
						CBF_BLOCK_FETCH_RETRIES
					);
					return Err(EventLoopEnd::PeersUnresponsive);
				},
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn restart_backoff(decision: RestartDecision) -> Duration {
		match decision {
			RestartDecision::Restart { backoff, .. } => backoff,
			other => panic!("expected a restart, got {:?}", other),
		}
	}

	#[test]
	fn an_event_loop_failure_restarts_the_node_like_a_node_failure() {
		// The give-up that used to be a permanent stall: the event task reports it, the node is
		// still running, and the policy treats it as one failed run — backoff, rebuild.
		let now = Instant::now();
		let mut policy = RestartPolicy::new();
		assert_eq!(
			policy.decide(RunEnd::EventLoopFailed, now),
			RestartDecision::Restart {
				backoff: Duration::from_millis(INITIAL_BACKOFF_MS),
				report: RestartReport::Failure,
			}
		);
		assert_eq!(
			policy.decide(RunEnd::NodeFailed, now),
			RestartDecision::Restart {
				backoff: Duration::from_millis(2 * INITIAL_BACKOFF_MS),
				report: RestartReport::Failure,
			},
			"the two kinds of failure share one budget and one backoff"
		);
		assert_eq!(policy.failures(), 2);
	}

	#[test]
	fn an_unexpected_failure_still_gives_up_once_the_budget_is_spent() {
		let now = Instant::now();
		let mut policy = RestartPolicy::new();
		for attempt in 1..=MAX_RESTART_RETRIES {
			let expected = Duration::from_millis(INITIAL_BACKOFF_MS << (attempt - 1));
			assert_eq!(
				restart_backoff(policy.decide(RunEnd::EventLoopFailed, now)),
				expected,
				"attempt {} restarts",
				attempt
			);
		}
		assert_eq!(policy.decide(RunEnd::NodeFailed, now), RestartDecision::GiveUp);

		// A run that reached `FiltersSynced` was a healthy node that failed later; the budget
		// starts over rather than counting a week-old restart against it.
		policy.note_progress();
		assert_eq!(policy.failures(), 0);
		assert_eq!(
			restart_backoff(policy.decide(RunEnd::NodeFailed, now)),
			Duration::from_millis(INITIAL_BACKOFF_MS)
		);
	}

	/// The Pi that booted before its Wi-Fi: `NoReachablePeers` run after run. The policy never
	/// gives up on it, the backoff stops growing at the cap, and the failure budget is untouched.
	#[test]
	fn no_reachable_peers_is_retried_forever_on_a_capped_backoff() {
		let now = Instant::now();
		let mut policy = RestartPolicy::new();
		let mut last = Duration::ZERO;
		for run in 0..200 {
			let end = if run % 7 == 3 { RunEnd::PeersUnresponsive } else { RunEnd::NoPeers };
			let backoff = restart_backoff(policy.decide(end, now));
			assert!(backoff >= last, "the backoff never shrinks while waiting");
			assert!(backoff <= Duration::from_millis(CBF_MAX_BACKOFF_MS));
			last = backoff;
		}
		assert_eq!(last, Duration::from_millis(CBF_MAX_BACKOFF_MS), "capped at five minutes");
		assert_eq!(policy.failures(), 0, "waiting on the network spends no budget");

		// Unexpected failures in between still count, and still run out.
		for _ in 0..MAX_RESTART_RETRIES {
			restart_backoff(policy.decide(RunEnd::NodeFailed, now));
			restart_backoff(policy.decide(RunEnd::NoPeers, now));
		}
		assert_eq!(policy.decide(RunEnd::NodeFailed, now), RestartDecision::GiveUp);
	}

	/// Warned once when the wait starts, then once per report interval; debug in between.
	#[test]
	fn a_wait_for_peers_is_reported_once_then_once_per_interval() {
		let start = Instant::now();
		let mut policy = RestartPolicy::new();
		let report =
			|policy: &mut RestartPolicy, at: Instant| match policy.decide(RunEnd::NoPeers, at) {
				RestartDecision::Restart { report, .. } => report,
				other => panic!("expected a restart, got {:?}", other),
			};
		assert_eq!(report(&mut policy, start), RestartReport::WaitingWarn);
		for secs in [1, 5, 60, 599] {
			assert_eq!(
				report(&mut policy, start + Duration::from_secs(secs)),
				RestartReport::WaitingQuiet
			);
		}
		let later = start + CBF_PEER_WAIT_REPORT_INTERVAL;
		assert_eq!(report(&mut policy, later), RestartReport::WaitingWarn);
		assert_eq!(policy.waiting_for(later), Some(CBF_PEER_WAIT_REPORT_INTERVAL));
		assert_eq!(
			report(&mut policy, later + Duration::from_secs(1)),
			RestartReport::WaitingQuiet
		);
	}

	/// A handshake means the network is back: the backoff and the wait start over, so the next
	/// outage is retried promptly and warned about afresh. The failure budget is not refilled —
	/// only a run that caught up does that.
	#[test]
	fn a_handshake_resets_the_backoff_and_the_wait_but_not_the_budget() {
		let now = Instant::now();
		let mut policy = RestartPolicy::new();
		restart_backoff(policy.decide(RunEnd::NodeFailed, now));
		for _ in 0..20 {
			restart_backoff(policy.decide(RunEnd::NoPeers, now));
		}
		assert!(policy.waiting_for(now).is_some());

		assert!(policy.note_connected().is_some(), "it was waiting");
		assert_eq!(policy.waiting_for(now), None);
		assert_eq!(policy.note_connected(), None, "and is not any more");
		assert_eq!(policy.failures(), 1, "a handshake proves the network, not the node");
		assert_eq!(
			policy.decide(RunEnd::NoPeers, now),
			RestartDecision::Restart {
				backoff: Duration::from_millis(INITIAL_BACKOFF_MS),
				report: RestartReport::WaitingWarn,
			}
		);

		// A run that caught up resets everything.
		for _ in 0..20 {
			restart_backoff(policy.decide(RunEnd::NoPeers, now));
		}
		policy.note_progress();
		assert_eq!(policy.failures(), 0);
		assert_eq!(policy.waiting_for(now), None);
		assert_eq!(
			restart_backoff(policy.decide(RunEnd::PeersUnresponsive, now)),
			Duration::from_millis(INITIAL_BACKOFF_MS)
		);
	}

	#[test]
	fn only_the_network_ends_are_environmental() {
		assert!(RunEnd::NoPeers.is_environmental());
		assert!(RunEnd::PeersUnresponsive.is_environmental());
		for end in
			[RunEnd::Shutdown, RunEnd::NodeFailed, RunEnd::EventLoopFailed, RunEnd::ApplicatorGone]
		{
			assert!(!end.is_environmental(), "{:?}", end);
		}
	}

	/// Between two runs — waiting out the backoff for peers — the status reads `Syncing`, never
	/// `Synced` from before the outage and never `Failed`; and a launch that no longer owns the
	/// status leaves it alone.
	#[test]
	fn a_node_waiting_for_peers_reads_syncing() {
		let data_dir = std::env::temp_dir().join(format!(
			"ldk-node-cbf-status-{}-{}",
			std::process::id(),
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
		));
		let (_node, client) =
			KyotoBuilder::new(bitcoin::Network::Regtest).data_dir(data_dir.clone()).build();
		let runtime_status =
			Mutex::new(CbfRuntimeStatus::Started { requester: client.requester, generation: 1 });
		let (sync_state_tx, _rx) =
			watch::channel(CbfSyncState::Active { applied_tip: Some(100), synced_to_tip: true });

		publish_catching_up(&runtime_status, 2, &sync_state_tx);
		assert_eq!(
			simplify_sync_state(*sync_state_tx.borrow()),
			CbfSyncStatus::Synced,
			"a stale launch does not touch the new one's status"
		);

		publish_catching_up(&runtime_status, 1, &sync_state_tx);
		assert_eq!(simplify_sync_state(*sync_state_tx.borrow()), CbfSyncStatus::Syncing);
		assert!(matches!(
			*sync_state_tx.borrow(),
			CbfSyncState::Active { applied_tip: Some(100), synced_to_tip: false }
		));

		// After a `stop()` the failure it published stands.
		*runtime_status.lock().unwrap() = CbfRuntimeStatus::Stopped;
		sync_state_tx.send_replace(CbfSyncState::Failed(Error::NotRunning));
		publish_catching_up(&runtime_status, 1, &sync_state_tx);
		assert_eq!(simplify_sync_state(*sync_state_tx.borrow()), CbfSyncStatus::Failed);
		let _ = std::fs::remove_dir_all(data_dir);
	}

	/// The mempool is borrowed whenever there is a chain to borrow from; the evictions wait for
	/// the sync, the unconfirmed half does not.
	#[test]
	fn the_mempool_is_borrowed_while_catching_up_without_its_evictions() {
		assert_eq!(mempool_borrow_plan(false, false), None);
		assert_eq!(mempool_borrow_plan(false, true), None);
		assert_eq!(mempool_borrow_plan(true, false), Some(MempoolEvictions::Withhold));
		assert_eq!(mempool_borrow_plan(true, true), Some(MempoolEvictions::Apply));
	}

	fn unlaunched_engine() -> CbfSyncEngine {
		engine_with(CbfSource::P2p, None, Config::default().storage_dir_path)
	}

	fn engine_with(
		source_mode: CbfSource, filter_source: Option<Arc<dyn FilterSource>>,
		storage_dir_path: String,
	) -> CbfSyncEngine {
		use lightning::util::test_utils::TestStore;

		use crate::chain::test_wallet::fresh_regtest_wallet;
		use crate::fee_estimator::OnchainFeeEstimator;
		use crate::tx_broadcaster::TransactionBroadcaster;

		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_regtest_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		let config = Arc::new(Config {
			network: bitcoin::Network::Regtest,
			storage_dir_path,
			..Config::default()
		});
		CbfSyncEngine::new(
			Vec::new(),
			1,
			None,
			source_mode,
			filter_source,
			None,
			wallet,
			kv_store,
			config,
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		)
		.expect("an engine that connects to nothing")
	}

	/// A fan-out whose one listener takes every block in order.
	#[derive(Default)]
	struct AcceptingFanout {
		tip: Mutex<u32>,
	}

	impl ChainFanout for AcceptingFanout {
		fn connect_block(&self, block: &bitcoin::Block, height: u32) {
			self.connect_filtered(&block.header, height)
		}
		fn connect_filtered(&self, _header: &Header, height: u32) {
			let mut tip = self.tip.lock().unwrap();
			assert_eq!(*tip + 1, height, "blocks arrive in order");
			*tip = height;
		}
		fn disconnect(&self, _header: &Header, height: u32) {
			*self.tip.lock().unwrap() = height - 1;
		}
		fn take_divergence(&self) -> Option<String> {
			None
		}
		fn record_stranded_listeners(&self, _tip_height: u32) -> bool {
			false
		}
		fn set_bulk_chain_persistence(&self, _enabled: bool) {}
		fn flush_chain_persistence(&self) -> Result<(), Error> {
			Ok(())
		}
	}

	/// `node` mode syncs to the source's tip through the real applicator and never builds
	/// kyoto: no requester, no kyoto data directory, and the header, fee and `is_on_chain`
	/// readers answer from the verified chain.
	#[tokio::test]
	async fn node_source_mode_syncs_without_ever_building_kyoto() {
		use crate::chain::cbf::source_sync::test_support::FakeSource;

		let dir = std::env::temp_dir().join(format!(
			"ldk-node-cbf-node-mode-{}-{:?}",
			std::process::id(),
			Instant::now()
		));
		let _ = std::fs::remove_dir_all(&dir);
		let source = Arc::new(FakeSource::new(30, &[]));
		let engine = engine_with(
			CbfSource::Node,
			Some(Arc::clone(&source) as Arc<dyn FilterSource>),
			dir.to_string_lossy().into_owned(),
		);
		assert_eq!(SyncEngine::name(&engine), "cbf(node)");

		let fanout = Arc::new(AcceptingFanout::default());
		*fanout.tip.lock().unwrap() = 10;
		let anchor = BlockId { height: 10, hash: source.block_at(10).block_hash() };
		engine.launch_source(
			&tokio::runtime::Handle::current(),
			Arc::clone(&fanout),
			anchor,
			10,
			None,
		);

		engine
			.wait_until_synced_within(Duration::from_secs(20))
			.await
			.expect("synced from the node source");
		assert_eq!(*fanout.tip.lock().unwrap(), 29);
		assert_eq!(engine.sync_status(), CbfSyncStatus::Synced);

		assert!(engine.requester().is_none(), "kyoto was never started");
		assert!(matches!(*engine.runtime_status.lock().unwrap(), CbfRuntimeStatus::Stopped));
		assert!(!dir.join("bip157_data").exists(), "kyoto never touched its data directory");
		assert_eq!(
			engine
				.is_on_chain(&BlockId { height: 20, hash: source.block_at(20).block_hash() })
				.await,
			Some(true)
		);
		assert_eq!(engine.fee_source().tip_height().await, Ok(29));

		engine.stop();
		assert!(engine.source_run.lock().unwrap().is_none(), "stop() took the running sync");
		assert_eq!(engine.sync_status(), CbfSyncStatus::Failed, "a stopped engine is not synced");
		let _ = std::fs::remove_dir_all(&dir);
	}

	/// A foreground pass that can never catch up — kyoto not launched, no peers — gives up
	/// with a timeout instead of holding the caller (and `Node::stop`) forever; one that is
	/// caught up returns at once, and one that failed says so.
	#[tokio::test]
	async fn the_foreground_wait_for_the_filters_is_bounded() {
		let engine = unlaunched_engine();
		let started = std::time::Instant::now();
		assert_eq!(
			engine.wait_until_synced_within(Duration::from_millis(50)).await,
			Err(Error::WalletOperationTimeout)
		);
		assert!(started.elapsed() < Duration::from_secs(5));
		assert!(!engine.is_synced());

		engine
			.sync_state_tx
			.send_replace(CbfSyncState::Active { applied_tip: Some(100), synced_to_tip: true });
		assert!(engine.is_synced(), "a borrow may apply evictions only now");
		assert_eq!(engine.mempool_evictions(), MempoolEvictions::Apply);
		assert_eq!(engine.wait_until_synced_within(Duration::from_millis(50)).await, Ok(()));

		engine.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
		assert!(!engine.is_synced());
		assert_eq!(
			engine.wait_until_synced_within(Duration::from_millis(50)).await,
			Err(Error::TxSyncFailed)
		);
		assert_eq!(CBF_SYNC_WAIT_TIMEOUT, Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS));
	}

	#[test]
	fn a_failed_boot_fee_refresh_is_retried_shortly_until_one_succeeds() {
		let regular = Duration::from_secs(DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS);

		// The boot refresh filled the cache: the regular cadence from the start.
		let mut filled = FeeCadence::new(true);
		assert_eq!(filled.first_delay(), regular);
		assert_eq!(filled.after(false), None, "a later failure waits for the regular tick");

		// It did not: retry shortly, keep retrying while it fails, then settle.
		let mut empty = FeeCadence::new(false);
		assert_eq!(empty.first_delay(), CBF_FEE_RECOVERY_RETRY);
		assert!(CBF_FEE_RECOVERY_RETRY < regular);
		assert_eq!(empty.after(false), Some(CBF_FEE_RECOVERY_RETRY));
		assert_eq!(empty.after(false), Some(CBF_FEE_RECOVERY_RETRY));
		assert_eq!(empty.after(true), None);
		assert_eq!(empty.after(false), None, "recovered: failures wait for the regular tick");
	}

	#[test]
	fn the_mempool_is_borrowed_on_the_onchain_wallet_sync_interval() {
		let expected = BackgroundSyncConfig::default()
			.onchain_wallet_sync_interval_secs
			.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS);
		assert_eq!(mempool_borrow_interval(), Duration::from_secs(expected));
		assert!(
			mempool_borrow_interval() >= Duration::from_secs(WALLET_SYNC_INTERVAL_MINIMUM_SECS)
		);
	}

	#[test]
	fn a_shutdown_or_a_halted_applicator_is_never_restarted() {
		let now = Instant::now();
		let mut policy = RestartPolicy::new();
		assert_eq!(policy.decide(RunEnd::Shutdown, now), RestartDecision::Stop);
		assert_eq!(policy.decide(RunEnd::ApplicatorGone, now), RestartDecision::Stop);
		assert_eq!(policy.failures(), 0, "neither counts against the failure budget");
	}

	/// Live mainnet probe of the fee sampler, through the engine's own kyoto settings and
	/// [`KyotoFeeSource`]: resumes seven blocks below the tip like a node restarted at its
	/// wallet's tip, waits for the filters, then runs sampler passes on their real bounds and
	/// prints each pass's summary and the resulting estimates. Needs the network; ignored by
	/// default. Run with:
	///
	/// `cargo test --features cbf --lib cbf_fee_sampler_mainnet_probe -- --ignored --nocapture`
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	#[ignore = "needs mainnet P2P and mempool.space; run by hand"]
	async fn cbf_fee_sampler_mainnet_probe() {
		use std::str::FromStr;

		use crate::chain::adapters::cbf::fee_cache_from_samples;
		use crate::chain::cbf::fee::FEE_WINDOW_BLOCKS;
		use crate::chain::cbf::fee_sampler::{canonical_window, window_samples, MIN_FEE_SAMPLES};
		use crate::chain::cbf::REORG_SAFETY_BLOCKS;

		const PROBE_BOUND: Duration = Duration::from_secs(9 * 60);
		let started = std::time::Instant::now();
		let curl = |url: &str| {
			let out = std::process::Command::new("curl").args(["-sf", url]).output().unwrap();
			String::from_utf8(out.stdout).unwrap().trim().to_string()
		};
		let tip: u32 = curl("https://mempool.space/api/blocks/tip/height").parse().unwrap();
		let height = tip - REORG_SAFETY_BLOCKS;
		let hash = BlockHash::from_str(&curl(&format!(
			"https://mempool.space/api/block-height/{}",
			height
		)))
		.unwrap();
		println!("probe: network tip {}, resuming kyoto at {} {}", tip, height, hash);

		let data_dir = std::env::temp_dir().join(format!("cbf-fee-probe-{}", std::process::id()));
		let (node, client) = kyoto_builder(bitcoin::Network::Bitcoin, data_dir.clone(), &[], 1)
			.chain_state(ChainState::Checkpoint(HashCheckpoint::new(height, hash)))
			.build();
		let Client { requester, info_rx, warn_rx: _warn_rx, mut event_rx } = client;
		tokio::spawn(node.run());
		drop(info_rx);

		let (sync_state_tx, sync_state_rx) =
			watch::channel(CbfSyncState::Active { applied_tip: None, synced_to_tip: false });
		let synced = tokio::time::timeout(Duration::from_secs(180), async {
			while let Some(event) = event_rx.recv().await {
				if let KyotoEvent::FiltersSynced(update) = event {
					return Some(update.tip().height);
				}
			}
			None
		})
		.await
		.expect("kyoto synced within 3 minutes")
		.expect("kyoto kept running");
		println!("probe: kyoto synced to {} after {:.1}s", synced, started.elapsed().as_secs_f32());
		sync_state_tx
			.send_replace(CbfSyncState::Active { applied_tip: Some(synced), synced_to_tip: true });
		tokio::spawn(async move { while event_rx.recv().await.is_some() {} });

		let source = KyotoFeeSource {
			runtime_status: Arc::new(Mutex::new(CbfRuntimeStatus::Started {
				requester: requester.clone(),
				generation: 1,
			})),
			sync_state_rx,
			full_block_permits: Arc::new(Semaphore::new(CBF_FULL_BLOCK_PERMITS)),
		};
		let cache = new_block_fee_cache();
		let logger = Arc::new(Logger::new_log_facade());
		let mut sampler = FeeSampler::new(
			KyotoFeeSource {
				runtime_status: Arc::clone(&source.runtime_status),
				sync_state_rx: source.sync_state_rx.clone(),
				full_block_permits: Arc::clone(&source.full_block_permits),
			},
			Arc::clone(&cache),
			logger,
		);

		let mut answered_after = None;
		let mut pass_no = 0;
		while started.elapsed() < PROBE_BOUND {
			pass_no += 1;
			let report = sampler.pass().await;
			println!(
				"probe: pass {} at {:.1}s — {}",
				pass_no,
				started.elapsed().as_secs_f32(),
				report
			);
			let (_, canonical) = canonical_window(&source).await.unwrap();
			let samples = window_samples(&cache.lock().unwrap(), &canonical);
			if samples.len() >= MIN_FEE_SAMPLES && answered_after.is_none() {
				answered_after = Some(started.elapsed());
			}
			if samples.len() == canonical.len() {
				break;
			}
			tokio::time::sleep(Duration::from_secs(5)).await;
		}

		let (_, canonical) = canonical_window(&source).await.unwrap();
		for (height, (hash, rate)) in cache.lock().unwrap().iter() {
			println!(
				"probe: sample h={} {} {} sat/vB ({} sat/kwu)",
				height,
				hash,
				rate.to_sat_per_vb_floor(),
				rate.to_sat_per_kwu()
			);
		}
		let samples = window_samples(&cache.lock().unwrap(), &canonical);
		println!(
			"probe: {} of {} window heights held by kyoto sampled (window {}); first answer after \
			 {:?}",
			samples.len(),
			canonical.len(),
			FEE_WINDOW_BLOCKS,
			answered_after
		);
		if let Some(estimates) = fee_cache_from_samples(&samples) {
			let mut estimates: Vec<_> = estimates.into_iter().collect();
			estimates.sort_by_key(|(_, rate)| rate.to_sat_per_kwu());
			for (target, rate) in estimates {
				println!("probe: estimate {:?} = {} sat/kwu", target, rate.to_sat_per_kwu());
			}
		}
		let _ = requester.shutdown();
		let _ = std::fs::remove_dir_all(data_dir);
		assert!(samples.len() >= MIN_FEE_SAMPLES, "the sampler landed too few mainnet samples");
	}
}
