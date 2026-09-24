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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
	BlockApplicator, ChainOp, CBF_CHAIN_OP_QUEUE_DEPTH, CBF_FULL_BLOCK_PERMITS,
};
use crate::chain::cbf::birthday::resolve_birthday;
use crate::chain::cbf::fee::{new_block_fee_cache, BlockFeeCache};
use crate::chain::cbf::fee_sampler::{
	BlockFetch, FeeBlockSource, FeeSampler, SampleFailure, CBF_FEE_SAMPLE_INTERVAL,
};
use crate::chain::cbf::{
	mark_syncing, parse_trusted_peer, resume_checkpoint, simplify_sync_state, CbfSyncState,
	ResumeRefusal, WatchLedger, CBF_BLOCK_FETCH_TIMEOUT_SECS, CBF_HEADER_LOOKUP_TIMEOUT_SECS,
};
use crate::chain::engine::SyncEngine;
use crate::chain::seam::{ActionResult, MempoolQuery, MempoolScope};
use crate::chain::BorrowedMempool;
use crate::chain::{CbfSyncStatus, ChainLayer, ElectrumRuntimeStatus};
use crate::config::{
	BackgroundSyncConfig, Config, BDK_WALLET_SYNC_TIMEOUT_SECS,
	DEFAULT_FEE_RATE_CACHE_UPDATE_INTERVAL_SECS, WALLET_SYNC_INTERVAL_MINIMUM_SECS,
};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_debug, log_error, log_info, log_trace, log_warn, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

use async_trait::async_trait;

/// Peer response timeout passed to kyoto's `Builder::response_timeout`.
const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 30;

/// Maximum consecutive failed runs — `node.run()` erroring, or the event loop giving up on the
/// node — before the restart loop gives up. Reset once a run catches up to the tip.
const MAX_RESTART_RETRIES: u32 = 5;

/// Initial backoff delay between restart attempts; doubles each failure.
const INITIAL_BACKOFF_MS: u64 = 500;

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

		log_info!(self.logger, "CBF chain source started.");

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
	/// this node's clock ([`ChainLayer::borrow_mempool`]).
	async fn borrow_mempool(&self, layer: &ChainLayer) -> ActionResult<BorrowedMempool> {
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
		let borrowed = layer.borrow_mempool(&query).await?;
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

	/// Whether the background loop borrows a mempool view on this tick: only once synced — a
	/// view taken while the filters are still catching up would be anchored above what the
	/// wallet has applied, and an eviction would outrun the block that confirmed it — and only
	/// when there is a chain to borrow from.
	fn mempool_borrow_due(&self, layer: &ChainLayer) -> bool {
		layer.has_mempool_chain() && self.is_synced()
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

/// Keeps the block-fee cache warm until `stop` fires; see [`FeeSampler`]. A pass is raced
/// against the stop, so shutting down never waits out a block download.
async fn run_fee_sampler(
	mut sampler: FeeSampler<KyotoFeeSource>, mut stop: tokio::sync::watch::Receiver<()>,
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

	/// The chain as the fee sampler and the FEE adapter read it: kyoto's header chain, and
	/// block downloads under one of the full-block permits.
	pub(crate) fn fee_source(&self) -> KyotoFeeSource {
		KyotoFeeSource {
			runtime_status: Arc::clone(&self.runtime_status),
			sync_state_rx: self.sync_state_tx.subscribe(),
			full_block_permits: Arc::clone(&self.full_block_permits),
		}
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
			if let Err(e) = self.borrow_mempool(layer).await {
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
	/// through the FEE slot and — once synced, when the MEMPOOL chain has an adapter — borrows
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
					if !self.mempool_borrow_due(&layer) {
						continue;
					}
					// A borrow runs up to its chain's budget; a stop must not wait it out.
					tokio::select! {
						_ = stop_sync_receiver.changed() => {
							log_trace!(self.logger, "Stopping CBF background loop mid-borrow.");
							return;
						}
						borrowed = self.borrow_mempool(&layer) => {
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
	/// `node.run()` returned an error, or its event stream ended under a running node.
	NodeFailed,
	/// The event task gave up on this node — a matched block could not be fetched after every
	/// retry, or the requester was gone — while the node itself kept running. Before this was
	/// a distinct end the failure was reported and the node left running: a permanent stall,
	/// since nothing else ever restarted it.
	EventLoopFailed,
	/// The applicator halted on a divergence. Nothing can take blocks until the node process is
	/// restarted, so there is nothing to rebuild kyoto for.
	ApplicatorGone,
}

/// What the restart loop does once a run has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartDecision {
	/// Rebuild the node after this delay.
	Restart { backoff: Duration },
	/// The budget of consecutive failures is spent: publish a failed sync.
	GiveUp,
	/// Nothing to restart: the node was stopped on purpose, or a restart cannot help.
	Stop,
}

/// The restart budget: how many runs in a row may fail before the engine gives up, and how long
/// to wait before each attempt.
///
/// Kept apart from the loop that acts on it so the decision that matters — an event-loop
/// failure rebuilds the node exactly like a node failure, and a run that caught up refills the
/// budget — can be checked without a node.
struct RestartPolicy {
	retries: u32,
	backoff_ms: u64,
}

impl RestartPolicy {
	fn new() -> Self {
		Self { retries: 0, backoff_ms: INITIAL_BACKOFF_MS }
	}

	/// The run that just ended caught up to the tip at least once: it was a healthy node that
	/// failed later, not a failed restart, so the budget starts over.
	fn note_progress(&mut self) {
		self.retries = 0;
		self.backoff_ms = INITIAL_BACKOFF_MS;
	}

	fn decide(&mut self, end: RunEnd) -> RestartDecision {
		match end {
			RunEnd::Shutdown | RunEnd::ApplicatorGone => RestartDecision::Stop,
			RunEnd::NodeFailed | RunEnd::EventLoopFailed => {
				self.retries += 1;
				if self.retries > MAX_RESTART_RETRIES {
					return RestartDecision::GiveUp;
				}
				let backoff = Duration::from_millis(self.backoff_ms);
				self.backoff_ms = self.backoff_ms.saturating_mul(2);
				RestartDecision::Restart { backoff }
			},
		}
	}

	/// How many runs in a row have failed.
	fn failures(&self) -> u32 {
		self.retries
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

		loop {
			let (node, info_rx, warn_rx, event_rx) = current;
			let info_handle =
				tokio::spawn(process_info_messages(info_rx, Arc::clone(&self.logger)));
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
					log_error!(self.logger, "CBF node exited with error: {:?}", e);
					event_handle.abort();
					RunEnd::NodeFailed
				},
				Turn::Events(joined) => {
					let end = match joined {
						Ok(EventLoopEnd::ApplicatorGone) => RunEnd::ApplicatorGone,
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

			if synced_this_run.swap(false, Ordering::AcqRel) {
				policy.note_progress();
			}
			match policy.decide(end) {
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
				RestartDecision::Restart { backoff } => {
					log_error!(
						self.logger,
						"Restarting the CBF node in {}ms (attempt {}/{}).",
						backoff.as_millis(),
						policy.failures(),
						MAX_RESTART_RETRIES,
					);
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
async fn process_info_messages(mut info_rx: mpsc::Receiver<Info>, logger: Arc<Logger>) {
	let mut handshakes = 0usize;
	// Progress restarts from zero on every batch after the first, and the `FiltersSynced` line
	// already marks each of those; only a rising decile is worth a line.
	let mut last_decile: Option<u32> = None;
	while let Some(info) = info_rx.recv().await {
		match info {
			Info::SuccessfulHandshake => {
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
	/// The loop cannot go on with this node: the requester was gone, or a matched block could
	/// not be fetched after every retry.
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
					log_error!(
						self.logger,
						"CBF block fetch for {} {} after {} attempts; giving up on this node",
						block_hash,
						reason,
						CBF_BLOCK_FETCH_RETRIES
					);
					return Err(EventLoopEnd::Failed(Error::TxSyncFailed));
				},
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_event_loop_failure_restarts_the_node_like_a_node_failure() {
		// The give-up that used to be a permanent stall: the event task reports it, the node is
		// still running, and the policy treats it as one failed run — backoff, rebuild.
		let mut policy = RestartPolicy::new();
		assert_eq!(
			policy.decide(RunEnd::EventLoopFailed),
			RestartDecision::Restart { backoff: Duration::from_millis(INITIAL_BACKOFF_MS) }
		);
		assert_eq!(
			policy.decide(RunEnd::NodeFailed),
			RestartDecision::Restart { backoff: Duration::from_millis(2 * INITIAL_BACKOFF_MS) },
			"the two kinds of failure share one budget and one backoff"
		);
		assert_eq!(policy.failures(), 2);
	}

	#[test]
	fn the_budget_is_spent_after_max_retries_and_refilled_by_a_run_that_caught_up() {
		let mut policy = RestartPolicy::new();
		for attempt in 1..=MAX_RESTART_RETRIES {
			let expected = Duration::from_millis(INITIAL_BACKOFF_MS << (attempt - 1));
			assert_eq!(
				policy.decide(RunEnd::EventLoopFailed),
				RestartDecision::Restart { backoff: expected },
				"attempt {} restarts",
				attempt
			);
		}
		assert_eq!(policy.decide(RunEnd::NodeFailed), RestartDecision::GiveUp);

		// A run that reached `FiltersSynced` was a healthy node that failed later; the budget
		// starts over rather than counting a week-old restart against it.
		policy.note_progress();
		assert_eq!(policy.failures(), 0);
		assert_eq!(
			policy.decide(RunEnd::NodeFailed),
			RestartDecision::Restart { backoff: Duration::from_millis(INITIAL_BACKOFF_MS) }
		);
	}

	fn unlaunched_engine() -> CbfSyncEngine {
		use lightning::util::test_utils::TestStore;

		use crate::chain::test_wallet::fresh_regtest_wallet;
		use crate::fee_estimator::OnchainFeeEstimator;
		use crate::tx_broadcaster::TransactionBroadcaster;

		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_regtest_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		let config = Arc::new(Config { network: bitcoin::Network::Regtest, ..Config::default() });
		CbfSyncEngine::new(
			Vec::new(),
			1,
			None,
			None,
			wallet,
			kv_store,
			config,
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		)
		.expect("an engine that connects to nothing")
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
		assert!(engine.is_synced(), "the background borrow is due only now");
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
		let mut policy = RestartPolicy::new();
		assert_eq!(policy.decide(RunEnd::Shutdown), RestartDecision::Stop);
		assert_eq!(policy.decide(RunEnd::ApplicatorGone), RestartDecision::Stop);
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
