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
//!
//! # Serving Dependent nodes
//!
//! A Pro node over bitcoind computes a Dependent node's wallet and Lightning
//! syncs for it by scanning bitcoind's BIP158 block filters from where the
//! Dependent node left off ([`crate::chain::filter_scan`]), and adds what is
//! unconfirmed from bitcoind's mempool. That needs `-blockfilterindex=1`;
//! without it both serves refuse as unsupported.
//!
//! Each served scan runs under [`SCAN_SERVE_TIMEOUT`], at most
//! [`SCAN_SERVE_CONCURRENCY`] at a time, and stops reading filters after
//! [`SCAN_FILTER_BUDGET`] or [`FILTER_SCAN_MAX_BLOCKS`] blocks, answering for
//! what it read. The `chain.wallet_sync` and `chain.lightning_sync` routes
//! have no serve timeout of their own at the host, so the host's default
//! peer-invocation timeout (10 s) bounds them; the asking app waits 20 s per
//! call. The deadline sits under the 10 s.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, Txid};

use lightning::chain::Listen;

use lightning_block_sync::init::{synchronize_listeners, validate_best_block_header};
use lightning_block_sync::poll::{ChainPoller, ChainTip, ValidatedBlockHeader};
use lightning_block_sync::{
	AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, BlockSourceErrorKind,
	SpvClient,
};

use crate::chain::adapters::bitcoind_raw::{BitcoindRpcSource, SourceReadiness};
use crate::chain::bitcoind::{BitcoindClient, BoundedHeaderCache, ChainListener};
use crate::chain::engine::SyncEngine;
use crate::chain::filter_scan::{
	scan_lightning, scan_wallet, LightningScan, ScanError, ScanLimits, WalletScan, WatchedTxScan,
	FILTER_SCAN_MAX_BLOCKS,
};
use crate::chain::provider::{
	ChainProviderError, WireAnchor, WireConfirmedTx, WireLightningSyncRequest,
	WireLightningSyncResponse, WireSeenAt, WireSyncRequest, WireUpdate, CHAIN_WIRE_VERSION,
};
use crate::chain::seam::{MempoolAnswer, MempoolQuery, MempoolScope};
use crate::chain::wire_convert::{
	block_hash_from_wire, block_id_from_wire, block_id_to_wire, check_version, header_to_wire,
	outpoint_from_wire, script_from_wire, tx_to_wire, txid_from_wire, txid_to_wire,
};
use crate::chain::target::{SyncTarget, TargetId};
use crate::chain::{ChainLayer, CHAIN_POLLING_INTERVAL_SECS};
use crate::config::Config;
use crate::io::utils::write_node_metrics;
use crate::logger::{log_debug, log_error, log_info, log_trace, log_warn, LdkLogger, Logger};
use crate::Error;

use async_trait::async_trait;

pub(crate) struct BitcoindSyncEngine {
	pub(crate) api_client: Arc<BitcoindClient>,
	pub(crate) header_cache: tokio::sync::Mutex<BoundedHeaderCache>,
	pub(crate) latest_chain_tip: Arc<RwLock<Option<ValidatedBlockHeader>>>,
	pub(crate) config: Arc<Config>,
	pub(crate) logger: Arc<Logger>,
	/// Answers Dependent nodes' syncs; `None` when its RPC client could not
	/// be set up, and the serves then refuse.
	pub(crate) scan_server: Option<Arc<DependentScanServer>>,
	/// The targets the polling loop delivers blocks to: those synchronised up
	/// to `latest_chain_tip`. A target registered after the initial
	/// synchronisation is caught up to that tip — and only that tip — before
	/// it joins, so the next poll hands it exactly the blocks it has not seen.
	/// See [`PinnedTipSource`].
	joined: Mutex<HashSet<TargetId>>,
}

impl BitcoindSyncEngine {
	pub(crate) fn new(
		api_client: Arc<BitcoindClient>,
		latest_chain_tip: Arc<RwLock<Option<ValidatedBlockHeader>>>, config: Arc<Config>,
		logger: Arc<Logger>, scan_server: Option<Arc<DependentScanServer>>,
	) -> Self {
		Self {
			api_client,
			header_cache: tokio::sync::Mutex::new(BoundedHeaderCache::new()),
			latest_chain_tip,
			config,
			logger,
			scan_server,
			joined: Mutex::new(HashSet::new()),
		}
	}

	/// This target's listeners with the block each last saw, in the shape
	/// `synchronize_listeners` takes.
	fn chain_listeners_of(target: &SyncTarget) -> Vec<(BlockHash, &(dyn Listen + Send + Sync))> {
		let mut chain_listeners = vec![
			(
				target.onchain_wallet.current_best_block().block_hash,
				&*target.onchain_wallet as &(dyn Listen + Send + Sync),
			),
			(
				target.channel_manager.current_best_block().block_hash,
				&*target.channel_manager as &(dyn Listen + Send + Sync),
			),
			(
				target.output_sweeper.current_best_block().block_hash,
				&*target.output_sweeper as &(dyn Listen + Send + Sync),
			),
		];

		// TODO: Eventually we might want to see if we can synchronize `ChannelMonitor`s
		// before giving them to `ChainMonitor` it the first place. However, this isn't
		// trivial as we load them on initialization (in the `Builder`) and only gain
		// network access during `start`. For now, we just make sure we get the worst known
		// block hash and sychronize them via `ChainMonitor`.
		if let Some(worst_channel_monitor_block_hash) = target
			.chain_monitor
			.list_monitors()
			.iter()
			.flat_map(|(txo, _)| target.chain_monitor.get_monitor(*txo))
			.map(|m| m.current_best_block())
			.min_by_key(|b| b.height)
			.map(|b| b.block_hash)
		{
			chain_listeners.push((
				worst_channel_monitor_block_hash,
				&*target.chain_monitor as &(dyn Listen + Send + Sync),
			));
		}
		chain_listeners
	}

	/// The ungated fan-out for one target; see [`ChainListener::new`].
	fn listener_of(&self, layer: &ChainLayer, target: &SyncTarget) -> ChainListener {
		ChainListener::new(
			Arc::clone(&target.onchain_wallet),
			Arc::clone(&target.channel_manager),
			Arc::clone(&target.chain_monitor),
			Arc::clone(&target.output_sweeper),
			Arc::clone(layer.tx_broadcaster()),
			Arc::clone(layer.fee_estimator()),
			Arc::clone(&self.logger),
		)
	}

	/// Stamp a completed pass into `targets`' metrics.
	fn record_pass(&self, targets: &[Arc<SyncTarget>]) -> Result<(), Error> {
		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		for target in targets {
			let mut locked_node_metrics =
				target.node_metrics.write().unwrap_or_else(|e| e.into_inner());
			locked_node_metrics.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
			locked_node_metrics.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
			write_node_metrics(
				&*locked_node_metrics,
				Arc::clone(&target.kv_store),
				Arc::clone(&self.logger),
			)
			.map_err(|e| {
				log_error!(self.logger, "Failed to persist node metrics: {}", e);
				Error::PersistenceFailed
			})?;
		}
		Ok(())
	}

	/// One poll: catch up any target that joined since the last one, deliver
	/// the new blocks to every joined target, then the mempool. The header
	/// cache lock serialises passes, so two callers — the loop and a
	/// foreground `sync_wallets` — never poll from the same cached tip twice.
	async fn poll_pass(&self, layer: &ChainLayer) -> Result<(), Error> {
		let Self { api_client, header_cache, latest_chain_tip, config, logger, .. } = self;

		let mut locked_header_cache = header_cache.lock().await;

		let latest_chain_tip_opt = *latest_chain_tip.read().unwrap_or_else(|e| e.into_inner());
		let chain_tip = if let Some(tip) = latest_chain_tip_opt {
			tip
		} else {
			match validate_best_block_header(api_client.as_ref()).await {
				Ok(tip) => {
					*latest_chain_tip.write().unwrap_or_else(|e| e.into_inner()) = Some(tip);
					tip
				},
				Err(e) => {
					log_error!(logger, "Failed to poll for chain data: {:?}", e);
					return Err(Error::TxSyncFailed);
				},
			}
		};

		// A target registered after the loop started is brought up to the cached tip
		// — not the source's — from wherever its own listeners stand, so the poll below
		// hands it exactly the blocks past that tip, once, like everyone else.
		let targets = layer.targets().snapshot();
		let mut joined_targets = Vec::with_capacity(targets.len());
		for target in &targets {
			if self.joined.lock().unwrap_or_else(|e| e.into_inner()).contains(&target.id) {
				joined_targets.push(Arc::clone(target));
				continue;
			}
			let pinned = PinnedTipSource { inner: api_client.as_ref(), tip: chain_tip };
			let now = SystemTime::now();
			match synchronize_listeners(
				&pinned,
				config.network,
				&mut *locked_header_cache,
				Self::chain_listeners_of(target),
			)
			.await
			{
				Ok(_) => {
					log_info!(
						logger,
						"Finished synchronizing listeners of {} to height {} in {}ms",
						target.label,
						chain_tip.height,
						now.elapsed().unwrap_or_default().as_millis()
					);
					self.joined.lock().unwrap_or_else(|e| e.into_inner()).insert(target.id);
					joined_targets.push(Arc::clone(target));
				},
				Err(e) => {
					log_error!(
						logger,
						"Failed to synchronize chain listeners of {}: {:?}; retrying next poll",
						target.label,
						e
					);
				},
			}
		}

		let listeners: Vec<ChainListener> =
			joined_targets.iter().map(|t| self.listener_of(layer, t)).collect();
		let fanout = FanoutListener { listeners: &listeners };
		let chain_poller = ChainPoller::new(Arc::clone(api_client), config.network);
		let mut spv_client =
			SpvClient::new(chain_tip, chain_poller, &mut *locked_header_cache, &fanout);

		let now = SystemTime::now();
		match spv_client.poll_best_tip().await {
			Ok((ChainTip::Better(tip), true)) => {
				log_trace!(
					logger,
					"Finished polling best tip in {}ms",
					now.elapsed().unwrap_or_default().as_millis()
				);
				*latest_chain_tip.write().unwrap_or_else(|e| e.into_inner()) = Some(tip);
			},
			Ok(_) => {},
			Err(e) => {
				log_error!(logger, "Failed to poll for chain data: {:?}", e);
				return Err(Error::TxSyncFailed);
			},
		}

		if joined_targets.is_empty() {
			return Ok(());
		}

		// One mempool poll for every wallet: the adapter answers the whole mempool
		// regardless, and each wallet keeps what is its own on apply. The evictions are
		// the union's absences; each wallet is handed only those of its own unconfirmed
		// transactions.
		let cur_height = joined_targets
			.iter()
			.map(|t| t.channel_manager.current_best_block().height)
			.min()
			.unwrap_or(0);
		let per_target_unconfirmed: Vec<Vec<Txid>> =
			joined_targets.iter().map(|t| t.onchain_wallet.get_unconfirmed_txids()).collect();
		let known_unconfirmed: Vec<Txid> = {
			let mut all: Vec<Txid> = per_target_unconfirmed.iter().flatten().copied().collect();
			all.sort_unstable();
			all.dedup();
			all
		};

		let now = SystemTime::now();
		let query = MempoolQuery {
			// A block-polling engine has no script list to send and needs
			// none: its adapter answers the whole mempool and the wallet
			// keeps what is its own on apply, as it always has.
			scripts: Vec::new(),
			known_unconfirmed,
			scope: MempoolScope::Incremental { best_processed_height: cur_height },
		};
		match layer.mempool(&query).await {
			Ok(answered) => {
				let MempoolAnswer { unconfirmed: unconfirmed_txs, evicted: evicted_txids } =
					answered.value.value;
				log_trace!(
					logger,
					"Finished polling mempool of size {} and {} evicted transactions in {}ms",
					unconfirmed_txs.len(),
					evicted_txids.len(),
					now.elapsed().unwrap_or_default().as_millis()
				);
				for (target, own_unconfirmed) in joined_targets.iter().zip(per_target_unconfirmed)
				{
					let own_evicted: Vec<(Txid, u64)> = evicted_txids
						.iter()
						.filter(|(txid, _)| own_unconfirmed.contains(txid))
						.cloned()
						.collect();
					target
						.onchain_wallet
						.apply_mempool_txs(unconfirmed_txs.clone(), own_evicted)
						.unwrap_or_else(|e| {
							log_error!(logger, "Failed to apply mempool transactions: {:?}", e);
						});
				}
			},
			Err(e) => {
				log_error!(logger, "Failed to poll for mempool transactions: {}", e);
				return Err(Error::TxSyncFailed);
			},
		}

		self.record_pass(&joined_targets)
	}

	/// A background tick: one poll, answered to every target whose latch is
	/// free. A target whose latch a foreground pass holds gets its answer from
	/// that pass; when every target is held, this tick waits for one of them
	/// rather than polling behind it — the single-wallet "sync in progress"
	/// behaviour.
	async fn background_tick(&self, layer: &ChainLayer) -> Result<(), Error> {
		let targets = layer.targets().snapshot();
		let mut held = Vec::with_capacity(targets.len());
		let mut busy = None;
		for target in &targets {
			let receiver_res = target
				.onchain_wallet_sync_status
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.register_or_subscribe_pending_sync();
			match receiver_res {
				None => held.push(Arc::clone(target)),
				Some(receiver) => busy = busy.or(Some(receiver)),
			}
		}
		if held.is_empty() {
			if let Some(mut sync_receiver) = busy {
				log_info!(self.logger, "Sync in progress, skipping.");
				return sync_receiver.recv().await.map_err(|e| {
					debug_assert!(false, "Failed to receive wallet polling result: {:?}", e);
					log_error!(self.logger, "Failed to receive wallet polling result: {:?}", e);
					Error::WalletOperationFailed
				})?;
			}
			// No targets at all: keep the cached tip moving so a node that
			// registers later starts from a fresh one.
			return self.poll_pass(layer).await;
		}
		let res = self.poll_pass(layer).await;
		for target in &held {
			target
				.onchain_wallet_sync_status
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.propagate_result_to_subscribers(res);
		}
		res
	}
}

/// `Listen` over every joined target at once, so one poll delivers each new
/// block to all of them in registration order.
struct FanoutListener<'a> {
	listeners: &'a [ChainListener],
}

impl Listen for FanoutListener<'_> {
	fn filtered_block_connected(
		&self, header: &bitcoin::block::Header,
		txdata: &lightning::chain::transaction::TransactionData, height: u32,
	) {
		for listener in self.listeners {
			listener.filtered_block_connected(header, txdata, height);
		}
	}

	fn block_connected(&self, block: &bitcoin::Block, height: u32) {
		for listener in self.listeners {
			listener.block_connected(block, height);
		}
	}

	fn block_disconnected(&self, header: &bitcoin::block::Header, height: u32) {
		for listener in self.listeners {
			listener.block_disconnected(header, height);
		}
	}
}

/// The chain source with its best block pinned at `tip`.
///
/// `synchronize_listeners` syncs to whatever its source calls best. A target
/// that joins a running loop must be synced to the loop's *cached* tip, not
/// the source's: the next poll connects every block from the cached tip to
/// the source's, and a target already past the cached tip would be handed
/// blocks it has — which a `ChannelManager` refuses, loudly. Pinning the best
/// block makes the catch-up stop exactly where the poll resumes.
struct PinnedTipSource<'a> {
	inner: &'a BitcoindClient,
	tip: ValidatedBlockHeader,
}

impl BlockSource for PinnedTipSource<'_> {
	fn get_header<'a>(
		&'a self, header_hash: &'a BlockHash, height_hint: Option<u32>,
	) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		self.inner.get_header(header_hash, height_hint)
	}

	fn get_block<'a>(&'a self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, BlockData> {
		self.inner.get_block(header_hash)
	}

	fn get_best_block(&self) -> AsyncBlockSourceResult<'_, (BlockHash, Option<u32>)> {
		let tip = self.tip;
		Box::pin(async move { Ok((tip.header.block_hash(), Some(tip.height))) })
	}
}

/// Served scans running at once; the rest wait their turn.
pub(crate) const SCAN_SERVE_CONCURRENCY: usize = 2;
/// Deadline of one served wallet or Lightning sync, readiness read and turn
/// included: under the host's 10 s default serve timeout for these routes.
pub(crate) const SCAN_SERVE_TIMEOUT: Duration = Duration::from_secs(8);
/// Time one served scan spends reading filters at most before it answers for
/// what it has read, leaving the rest of the deadline for the blocks that
/// matched and the mempool.
pub(crate) const SCAN_FILTER_BUDGET: Duration = Duration::from_secs(4);
/// How long a readiness read (`getindexinfo`, `getblockchaininfo`) is reused.
const SCAN_READINESS_TTL: Duration = Duration::from_secs(30);
/// Mempool snapshots one wallet serve takes at most: a second is needed only
/// when the first found a payment whose output an unconfirmed child spends.
const MEMPOOL_PASSES: usize = 3;

/// Serves Dependent nodes' wallet and Lightning syncs from this node's
/// bitcoind: its RPC for filters and blocks, and the engine's client for the
/// mempool. See the module docs.
pub(crate) struct DependentScanServer {
	source: BitcoindRpcSource,
	permits: tokio::sync::Semaphore,
	limits: ScanLimits,
	timeout: Duration,
	readiness: Mutex<Option<(Instant, SourceReadiness)>>,
	logger: Arc<Logger>,
}

impl DependentScanServer {
	pub(crate) fn new(source: BitcoindRpcSource, logger: Arc<Logger>) -> Self {
		Self {
			source,
			permits: tokio::sync::Semaphore::new(SCAN_SERVE_CONCURRENCY),
			limits: ScanLimits {
				max_blocks: FILTER_SCAN_MAX_BLOCKS,
				filter_budget: SCAN_FILTER_BUDGET,
			},
			timeout: SCAN_SERVE_TIMEOUT,
			readiness: Mutex::new(None),
			logger,
		}
	}

	/// What `getindexinfo` / `getblockchaininfo` said, re-read at most every
	/// [`SCAN_READINESS_TTL`].
	async fn readiness(&self) -> SourceReadiness {
		if let Some((at, cached)) = self.readiness.lock().unwrap().as_ref() {
			if at.elapsed() < SCAN_READINESS_TTL {
				return cached.clone();
			}
		}
		let fresh = self.source.read_readiness().await;
		*self.readiness.lock().unwrap() = Some((Instant::now(), fresh.clone()));
		fresh
	}

	/// Run one serve under the deadline: refuse when bitcoind cannot scan,
	/// then take a turn and scan.
	async fn serve<T>(
		&self, what: &str, serve: impl Future<Output = Result<T, Error>>,
	) -> Result<T, Error> {
		let served = async {
			let readiness = self.readiness().await;
			if readiness.has_filter_index == Some(false) {
				log_warn!(
					self.logger,
					"Refusing a Dependent node's {}: this node's bitcoind runs without -blockfilterindex=1",
					what
				);
				return Err(Error::ChainServeUnsupported);
			}
			if let Some(reason) = readiness.not_ready_reason() {
				log_info!(
					self.logger,
					"Refusing a Dependent node's {}: not ready: {}",
					what,
					reason
				);
				return Err(Error::ChainServeFailed);
			}
			let _turn = self.permits.acquire().await.map_err(|_| Error::ChainServeFailed)?;
			serve.await
		};
		match tokio::time::timeout(self.timeout, served).await {
			Ok(result) => result,
			Err(_elapsed) => {
				log_warn!(
					self.logger,
					"A Dependent node's {} was dropped: not served within {}s",
					what,
					self.timeout.as_secs()
				);
				Err(Error::ChainServeFailed)
			},
		}
	}

	fn scan_failed(&self, what: &str, e: ScanError) -> Error {
		match e {
			ScanError::NoFilterIndex(_) => {
				log_warn!(
					self.logger,
					"Refusing a Dependent node's {}: this node's bitcoind has no block filter index ({})",
					what,
					e
				);
				Error::ChainServeUnsupported
			},
			ScanError::Pruned { .. } => {
				log_error!(self.logger, "Cannot serve a Dependent node's {}: {}", what, e);
				Error::ChainServeFailed
			},
			ScanError::Source(_) => {
				log_warn!(self.logger, "Serving a Dependent node's {} failed: {}", what, e);
				Error::ChainServeFailed
			},
			ScanError::Refused(_) => {
				log_info!(self.logger, "Refusing a Dependent node's {}: {}", what, e);
				Error::ChainServeFailed
			},
		}
	}

	fn malformed(&self, what: &str, e: ChainProviderError) -> Error {
		log_error!(self.logger, "Refusing a malformed {} request: {}", what, e);
		Error::ChainServeFailed
	}
}

/// A wire wallet sync request as a scan.
fn wallet_scan_from_wire(req: &WireSyncRequest) -> Result<WalletScan, ChainProviderError> {
	check_version(req.version)?;
	Ok(WalletScan {
		chain: req.chain_tip.iter().map(block_id_from_wire).collect::<Result<_, _>>()?,
		spks: req.spks.iter().map(|s| script_from_wire(s)).collect::<Result<_, _>>()?,
		txids: req.txids.iter().map(|t| txid_from_wire(t)).collect::<Result<_, _>>()?,
		owned: req
			.outpoints
			.iter()
			.chain(req.owned_outpoints.iter())
			.map(outpoint_from_wire)
			.collect::<Result<_, _>>()?,
	})
}

/// A wire Lightning sync request as a scan.
fn lightning_scan_from_wire(
	req: &WireLightningSyncRequest,
) -> Result<LightningScan, ChainProviderError> {
	check_version(req.version)?;
	let mut txs = Vec::with_capacity(req.txids.len());
	for w in &req.txids {
		txs.push(WatchedTxScan {
			txid: txid_from_wire(&w.txid)?,
			known: w.known_block_hash.as_deref().map(block_hash_from_wire).transpose()?,
			script: w.script_hex.as_deref().map(script_from_wire).transpose()?,
		});
	}
	let mut outputs = Vec::with_capacity(req.outputs.len());
	for o in &req.outputs {
		outputs.push((outpoint_from_wire(&o.outpoint)?, script_from_wire(&o.script_hex)?));
	}
	Ok(LightningScan {
		txs,
		outputs,
		scan_from: req.scan_from.as_ref().map(block_id_from_wire).transpose()?,
	})
}

impl BitcoindSyncEngine {
	fn scan_server(&self, what: &str) -> Result<&DependentScanServer, Error> {
		match self.scan_server.as_deref() {
			Some(server) => Ok(server),
			None => {
				log_warn!(
					self.logger,
					"Refusing a Dependent node's {}: this node has no RPC client to scan with",
					what
				);
				Err(Error::ChainServeUnsupported)
			},
		}
	}

	/// The asker's unconfirmed transactions, from bitcoind's mempool: those
	/// paying its scripts, spending its outputs — what it sent, what the
	/// scan found, and what an earlier snapshot found paying it — or asked
	/// about by id. `confirmed` are left out.
	async fn wallet_mempool(
		&self, spks: &HashSet<ScriptBuf>, txids: &HashSet<Txid>, mut owned: HashSet<OutPoint>,
		confirmed: &HashSet<Txid>,
	) -> Result<Vec<Transaction>, Error> {
		let mut picked: HashMap<Txid, Transaction> = HashMap::new();
		for _ in 0..MEMPOOL_PASSES {
			let owned_now = owned.clone();
			let snapshot = self
				.api_client
				.get_mempool_snapshot(|tx| {
					tx.output.iter().any(|o| spks.contains(&o.script_pubkey))
						|| tx.input.iter().any(|i| owned_now.contains(&i.previous_output))
						|| txids.contains(&tx.compute_txid())
				})
				.await
				.map_err(|e| {
					log_warn!(
						self.logger,
						"Serving a Dependent node's wallet sync: mempool read failed: {}",
						e
					);
					Error::ChainServeFailed
				})?;
			let mut grew = false;
			for (tx, _first_seen) in snapshot {
				let txid = tx.compute_txid();
				if confirmed.contains(&txid) {
					continue;
				}
				for (vout, out) in tx.output.iter().enumerate() {
					if spks.contains(&out.script_pubkey) {
						grew |= owned.insert(OutPoint { txid, vout: vout as u32 });
					}
				}
				picked.insert(txid, tx);
			}
			if !grew {
				break;
			}
		}
		Ok(picked.into_values().collect())
	}
}

#[async_trait]
impl SyncEngine for BitcoindSyncEngine {
	fn name(&self) -> &'static str {
		"bitcoind-block-poll"
	}

	/// The MEMPOOL chain is this node's own bitcoind.
	fn serves_mempool(&self) -> bool {
		true
	}

	/// Every slot is filled from this node's own bitcoind: a real chain
	/// source, so other nodes may be served from it.
	fn serves_peers(&self) -> bool {
		true
	}

	/// A filter scan from the asker's latest checkpoint on this node's best
	/// chain, plus what bitcoind's mempool holds for it; see the module docs.
	/// Shaped like the Electrum serve: full transactions, anchors at their
	/// blocks' header times, the asker's `start_time` as the first-seen time
	/// of what is unconfirmed, and a checkpoint chain that extends — or, over
	/// a reorg, displaces — the asker's own. No floating txouts: the value of
	/// an arbitrary spent output is not available without `-txindex`.
	async fn serve_wallet_sync(&self, req: &WireSyncRequest) -> Result<WireUpdate, Error> {
		const WHAT: &str = "wallet sync";
		let server = self.scan_server(WHAT)?;
		let scan = wallet_scan_from_wire(req).map_err(|e| server.malformed(WHAT, e))?;
		let asked = (scan.spks.len(), scan.chain.last().map(|b| b.height));
		server
			.serve(WHAT, async {
				let spks: HashSet<ScriptBuf> = scan.spks.iter().cloned().collect();
				let txids = scan.txids.clone();
				let scanned = scan_wallet(&server.source, scan, &server.limits)
					.await
					.map_err(|e| server.scan_failed(WHAT, e))?;
				let confirmed: HashSet<Txid> =
					scanned.found.iter().map(|f| f.tx.compute_txid()).collect();
				let unconfirmed =
					self.wallet_mempool(&spks, &txids, scanned.owned.clone(), &confirmed).await?;

				let last = scanned.checkpoints.last().copied();
				log_debug!(
					self.logger,
					"Served a wallet sync of {} scripts from height {:?}: scanned {} blocks to {:?} (tip {}), {} confirmed, {} unconfirmed",
					asked.0,
					asked.1,
					scanned.blocks_scanned,
					last.map(|b| b.height),
					scanned.tip.height,
					scanned.found.len(),
					unconfirmed.len()
				);

				let mut txs = Vec::with_capacity(scanned.found.len() + unconfirmed.len());
				let mut anchors = Vec::with_capacity(scanned.found.len());
				for found in &scanned.found {
					txs.push(tx_to_wire(&found.tx));
					anchors.push(WireAnchor {
						txid: txid_to_wire(&found.tx.compute_txid()),
						block: block_id_to_wire(&found.block),
						confirmation_time: found.header.time as u64,
					});
				}
				let mut seen_ats = Vec::with_capacity(unconfirmed.len());
				for tx in &unconfirmed {
					txs.push(tx_to_wire(tx));
					seen_ats.push(WireSeenAt {
						txid: txid_to_wire(&tx.compute_txid()),
						seen_at: req.start_time,
					});
				}
				Ok(WireUpdate {
					version: CHAIN_WIRE_VERSION,
					txs,
					txouts: Vec::new(),
					anchors,
					seen_ats,
					checkpoints: scanned.checkpoints.iter().map(block_id_to_wire).collect(),
					server_tip: last
						.filter(|last| last.height < scanned.tip.height)
						.map(|_| block_id_to_wire(&scanned.tip)),
				})
			})
			.await
	}

	/// A filter scan for the watched transactions and outputs from the block
	/// the asker has synced to; see the module docs. Same answer as the
	/// Electrum serve: a watched transaction newly confirmed (or moved) with
	/// its block, header and position; every spend of a watched output in
	/// the blocks scanned; a watched transaction the asker believed confirmed
	/// in a block no longer on the best chain, and not found again, as
	/// unconfirmed. A scan cut short reports the last block it scanned as
	/// the tip.
	async fn serve_lightning_sync(
		&self, req: &WireLightningSyncRequest,
	) -> Result<WireLightningSyncResponse, Error> {
		const WHAT: &str = "lightning sync";
		let server = self.scan_server(WHAT)?;
		let scan = lightning_scan_from_wire(req).map_err(|e| server.malformed(WHAT, e))?;
		let asked = (scan.txs.len(), scan.outputs.len(), scan.scan_from.map(|b| b.height));
		server
			.serve(WHAT, async {
				let scanned = scan_lightning(&server.source, scan, &server.limits)
					.await
					.map_err(|e| server.scan_failed(WHAT, e))?;
				if scanned.unscannable > 0 {
					log_debug!(
						self.logger,
						"A Dependent node's lightning sync watches {} transactions without a script; a filter scan cannot find them",
						scanned.unscannable
					);
				}
				log_debug!(
					self.logger,
					"Served a lightning sync of {} transactions and {} outputs from height {:?}: scanned {} blocks to {}, {} confirmed, {} unconfirmed",
					asked.0,
					asked.1,
					asked.2,
					scanned.blocks_scanned,
					scanned.tip.height,
					scanned.confirmed.len(),
					scanned.unconfirmed.len()
				);
				Ok(WireLightningSyncResponse {
					version: CHAIN_WIRE_VERSION,
					tip: block_id_to_wire(&scanned.tip),
					tip_header_hex: header_to_wire(&scanned.tip_header),
					confirmed: scanned
						.confirmed
						.iter()
						.map(|found| WireConfirmedTx {
							tx_hex: tx_to_wire(&found.tx),
							block: block_id_to_wire(&found.block),
							pos_in_block: found.pos,
							header_hex: header_to_wire(&found.header),
						})
						.collect(),
					unconfirmed: scanned.unconfirmed.iter().map(txid_to_wire).collect(),
					server_tip: (scanned.tip != scanned.source_tip)
						.then(|| block_id_to_wire(&scanned.source_tip)),
				})
			})
			.await
	}

	/// Poll the tip, then the mempool, then record the pass — in that order,
	/// as pre-seam. The mempool comes through the layer's MEMPOOL chain now;
	/// what it answers is applied exactly where, and how, the client's own
	/// poll result was. The poll is one for every joined target; `target` is
	/// the one answered here, through its own latch.
	async fn sync_once(&self, layer: &ChainLayer, target: &Arc<SyncTarget>) -> Result<(), Error> {
		let receiver_res = {
			let mut status_lock =
				target.onchain_wallet_sync_status.lock().unwrap_or_else(|e| e.into_inner());
			status_lock.register_or_subscribe_pending_sync()
		};

		if let Some(mut sync_receiver) = receiver_res {
			log_info!(self.logger, "Sync in progress, skipping.");
			return sync_receiver.recv().await.map_err(|e| {
				debug_assert!(false, "Failed to receive wallet polling result: {:?}", e);
				log_error!(self.logger, "Failed to receive wallet polling result: {:?}", e);
				Error::WalletOperationFailed
			})?;
		}

		let res = self.poll_pass(layer).await;
		target
			.onchain_wallet_sync_status
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.propagate_result_to_subscribers(res);
		res
	}

	async fn run_background(
		&self, layer: Arc<ChainLayer>, mut stop_sync_receiver: tokio::sync::watch::Receiver<()>,
	) {
		let Self { api_client, header_cache, latest_chain_tip, config, logger, .. } = self;
		// First register for the wallet polling status to make sure `Node::sync_wallets` calls
		// wait on the result before proceeding.
		let initial_targets = layer.targets().snapshot();
		for target in &initial_targets {
			let mut status_lock =
				target.onchain_wallet_sync_status.lock().unwrap_or_else(|e| e.into_inner());
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
			// Every target's listeners in one call, each from the block it last saw:
			// `synchronize_listeners` brings each to the same tip on its own.
			let chain_listeners: Vec<(BlockHash, &(dyn Listen + Send + Sync))> =
				initial_targets.iter().flat_map(|target| Self::chain_listeners_of(target)).collect();

			let mut locked_header_cache = header_cache.lock().await;
			let now = SystemTime::now();
			match synchronize_listeners(
				api_client.as_ref(),
				config.network,
				&mut *locked_header_cache,
				chain_listeners,
			)
			.await
			{
				Ok(chain_tip) => {
					{
						log_info!(
							logger,
							"Finished synchronizing listeners in {}ms",
							now.elapsed().unwrap_or_default().as_millis()
						);
						*latest_chain_tip.write().unwrap_or_else(|e| e.into_inner()) =
							Some(chain_tip);
						{
							let mut joined = self.joined.lock().unwrap_or_else(|e| e.into_inner());
							joined.extend(initial_targets.iter().map(|t| t.id));
						}
						if let Err(e) = self.record_pass(&initial_targets) {
							log_error!(logger, "Failed to persist node metrics: {}", e);
						}
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
		for target in &initial_targets {
			target
				.onchain_wallet_sync_status
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.propagate_result_to_subscribers(Ok(()));
		}

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
					if self.background_tick(&layer).await.is_ok() {
						layer.reap_dead_fundings();
					}
				}
				_ = fee_rate_update_interval.tick() => {
					let _ = layer.update_fee_rate_estimates().await;
				}
			}
		}
	}

	fn target_unregistered(&self, id: TargetId) {
		self.joined.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
	}
}
