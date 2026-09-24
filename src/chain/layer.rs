// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The chain ability seam.
//!
//! [`ChainLayer`] is the single entry point the rest of the crate uses to reach
//! the Bitcoin chain. Each chain *ability* occupies a slot: FEE, BROADCAST,
//! TX_STATUS, MEMPOOL and SCRIPT_HISTORY are ordered adapter chains
//! ([`ActionChain`]), and UTXO is a capability declared once at startup. The
//! wallet sync engine is a separate explicit axis.
//!
//! Nothing outside slot construction branches on which backend is configured.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bdk_chain::BlockId;

use lightning::chain::{Filter, WatchedOutput};

use bitcoin::{Script, Transaction, Txid};

use lightning_block_sync::gossip::UtxoSource;
use lightning_transaction_sync::EsploraSyncClient;

use crate::chain::adapters::bitcoind::BitcoindChainAdapter;
use crate::chain::adapters::dependent::DependentChainAdapter;
use crate::chain::adapters::electrum::ElectrumChainAdapter;
use crate::chain::adapters::esplora::EsploraChainAdapter;
use crate::chain::bitcoind::{BitcoindClient, BoundedHeaderCache};
use crate::chain::engine::bitcoind::BitcoindSyncEngine;
use crate::chain::engine::dependent::DependentSyncEngine;
use crate::chain::engine::electrum::ElectrumSyncEngine;
use crate::chain::engine::esplora::EsploraSyncEngine;
use crate::chain::engine::SyncEngine;
use crate::chain::provider::{
	ChainDataProvider, WireFeeEstimates, WireFeeTarget, WireLightningSyncRequest,
	WireLightningSyncResponse, WireMempoolRequest, WireMempoolResponse, WireSyncRequest,
	WireUpdate, CHAIN_WIRE_VERSION,
};
use crate::chain::seam::{
	accepted_txids, package_result, ActionChain, ActionResult, Anchored, Answered, BroadcastAction,
	BroadcastRejection, ChainActionError, FeeAction, FeeUpdate, MempoolAction, MempoolAnswer,
	MempoolQuery, ScriptHistoryAction, SlotAdapter, UtxoCapability, UtxoVerification,
	BROADCAST_BUDGET, FEE_BUDGET, MAX_MEMPOOL_QUERY_ITEMS, MEMPOOL_BUDGET, SCRIPT_HISTORY_BUDGET,
};
use crate::chain::wire_convert::{mempool_answer_to_wire, wire_to_mempool_query};
use crate::chain::{
	CbfSyncStatus, ChainSlotAdapterStatus, ChainSlotStatus, ChainUtxoStatus, ChainUtxoVerification,
	ElectrumRuntimeStatus, WalletSyncStatus, DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS,
};
use crate::config::{BitcoindRestClientConfig, Config, ElectrumSyncConfig, EsploraSyncConfig};
use crate::fee_estimator::{
	conf_target_wire_name, get_all_conf_targets, FeeEstimator, OnchainFeeEstimator,
};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_debug, log_error, log_info, log_trace, log_warn, LdkLogger, Logger};
use crate::types::{Broadcaster, ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{Error, NodeMetrics};

#[cfg(all(feature = "cbf", feature = "swaps"))]
use crate::chain::adapters::cbf::CbfWatchTxStatus;
#[cfg(feature = "cbf")]
use crate::chain::adapters::cbf::{CbfDerivedFee, CbfP2pBroadcast, CbfUtxoSource};
#[cfg(feature = "cbf")]
use crate::chain::engine::cbf::{CbfSyncEngine, ExternalElectrum};
#[cfg(feature = "cbf")]
use crate::config::{CbfConfig, CbfExternalFee};

#[cfg(feature = "swaps")]
use crate::chain::provider::WireTxStatusResponse;
#[cfg(feature = "swaps")]
use crate::chain::seam::{TxStatusAction, TX_STATUS_BUDGET};
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::ScriptBuf;

/// Which adapters serve each slot, in chain order.
///
/// For logs and diagnostics; nothing may branch on it.
pub(crate) struct ChainSlotAdapters {
	pub(crate) fee: Vec<&'static str>,
	#[cfg(feature = "swaps")]
	pub(crate) tx_status: Vec<&'static str>,
	pub(crate) broadcast: Vec<&'static str>,
	/// Empty for an engine that carries unconfirmed transactions in its own
	/// sync and never asks the slot.
	pub(crate) mempool: Vec<&'static str>,
	/// Empty for every engine that scans its own chain source; filled only
	/// on a hybrid node.
	pub(crate) script_history: Vec<&'static str>,
	/// The adapter verifying BOLT-7 channel announcements and how far it
	/// checks them. `None` means the routing graph carries unverified
	/// capacities.
	pub(crate) utxo: Option<(&'static str, UtxoVerification)>,
	pub(crate) engine: &'static str,
}

impl fmt::Display for ChainSlotAdapters {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "fee=[{}]", self.fee.join(","))?;
		#[cfg(feature = "swaps")]
		write!(f, " tx_status=[{}]", self.tx_status.join(","))?;
		write!(f, " broadcast=[{}]", self.broadcast.join(","))?;
		write!(f, " mempool=[{}]", self.mempool.join(","))?;
		write!(f, " script_history=[{}]", self.script_history.join(","))?;
		match self.utxo {
			Some((name, verification)) => write!(f, " utxo={}({})", name, verification.as_str())?,
			None => write!(f, " utxo=none")?,
		}
		write!(f, " (sync engine: {})", self.engine)
	}
}

/// The per-ability slots of a [`ChainLayer`].
pub(crate) struct ChainSlots {
	/// FEE — fee-rate estimation.
	pub(crate) fee: ActionChain<dyn FeeAction>,
	/// TX_STATUS — reorg-aware status of an arbitrary transaction.
	#[cfg(feature = "swaps")]
	pub(crate) tx_status: ActionChain<dyn TxStatusAction>,
	/// BROADCAST — transaction broadcast.
	pub(crate) broadcast: ActionChain<dyn BroadcastAction>,
	/// MEMPOOL — unconfirmed transactions and evictions. Empty for an engine
	/// whose own sync carries them; an empty chain is never run by such an
	/// engine, so it costs nothing and logs nothing.
	pub(crate) mempool: ActionChain<dyn MempoolAction>,
	/// SCRIPT_HISTORY — the wide wallet scan run elsewhere. Empty for every
	/// engine that scans its own chain source; a hybrid node fills it from
	/// its provider.
	pub(crate) script_history: ActionChain<dyn ScriptHistoryAction>,
	/// UTXO — verification of BOLT-7 channel announcements, if any adapter can.
	pub(crate) utxo: Option<Arc<dyn UtxoCapability>>,
}

/// What the BROADCAST tail tells the on-chain wallet: transactions now on the
/// network, and transactions the network refused, each with the time.
type Unconfirmed = Vec<(Transaction, u64)>;
type Evicted = Vec<(Txid, u64)>;

/// What [`ChainLayer::borrow_mempool`] applied, and who answered.
#[cfg(feature = "cbf")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BorrowedMempool {
	pub(crate) by: &'static str,
	pub(crate) unconfirmed: usize,
	pub(crate) evicted: usize,
}

/// A borrowed mempool answer, every time in it replaced by `now` on this
/// node's clock.
///
/// The wallet orders a transaction's last sighting against its eviction to
/// decide whether it is still unconfirmed. Evictions are stamped locally —
/// the wire carries none — so a sighting stamped on the provider's clock
/// would be compared across two clocks: a provider running behind would have
/// a transaction that re-entered its mempool stay evicted here, one running
/// ahead would pin a stale sighting over a later local eviction. Both are
/// stamped with the moment this node learned of them instead.
#[cfg(feature = "cbf")]
pub(crate) fn stamp_locally(answer: MempoolAnswer, now: u64) -> (Unconfirmed, Evicted) {
	(
		answer.unconfirmed.into_iter().map(|(tx, _)| (tx, now)).collect(),
		answer.evicted.into_iter().map(|(txid, _)| (txid, now)).collect(),
	)
}

/// One package's run through the BROADCAST chain: the chain's verdict, and
/// every transaction some adapter reported as on the network along the way.
struct BroadcastRun {
	outcome: Result<Answered<()>, ChainActionError<BroadcastRejection>>,
	accepted: HashSet<Txid>,
}

/// Everything a slot's shared tail needs once its adapter has answered.
pub(crate) struct SharedChainCtx {
	pub(crate) fee_estimator: Arc<OnchainFeeEstimator>,
	pub(crate) tx_broadcaster: Arc<Broadcaster>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) logger: Arc<Logger>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
}

/// How long a transaction this node itself broadcast is shielded from a
/// borrowed mempool answer's eviction.
///
/// Ten minutes — one block interval. A package handed to the node's own
/// peers over P2P reaches a well-connected mempool within seconds, but the
/// provider a hybrid node borrows its mempool view from may answer from a
/// poll taken before the relay arrived, or from an `Incremental` memory that
/// has not seen it yet; an eviction applied then would hand the inputs back
/// to the on-chain wallet and offer them to a second spend. Within one block
/// interval a transaction that did reach the network has either shown up in
/// every well-connected mempool or been confirmed — and a confirmation the
/// filters show makes the eviction moot. After it, an absence is a real
/// signal — dropped, or replaced — and the inputs should be released.
pub(crate) const OWN_BROADCAST_EVICTION_GRACE: Duration = Duration::from_secs(10 * 60);

/// Bound on the transactions [`RecentOwnBroadcasts`] remembers. Own broadcasts
/// are rare — a channel open, a sweep, a payment — so the bound is never
/// reached in practice; it exists so nothing can grow the memory without limit.
const OWN_BROADCAST_MEMORY_CAP: usize = 1024;

/// The transactions this node itself put on the network within the last
/// [`OWN_BROADCAST_EVICTION_GRACE`], recorded by the BROADCAST tail for the
/// MEMPOOL tail to shield from a borrowed answer's eviction.
///
/// Pruned by age on every access, and by count past the cap, oldest first.
#[derive(Default)]
pub(crate) struct RecentOwnBroadcasts {
	sent_at: HashMap<Txid, Instant>,
}

impl RecentOwnBroadcasts {
	/// This node put `txid` on the network at `now`.
	fn record(&mut self, txid: Txid, now: Instant) {
		self.prune(now);
		self.sent_at.insert(txid, now);
		if self.sent_at.len() > OWN_BROADCAST_MEMORY_CAP {
			let excess = self.sent_at.len() - OWN_BROADCAST_MEMORY_CAP;
			let mut by_age: Vec<(Instant, Txid)> =
				self.sent_at.iter().map(|(txid, at)| (*at, *txid)).collect();
			by_age.sort_unstable();
			for (_, txid) in by_age.into_iter().take(excess) {
				self.sent_at.remove(&txid);
			}
		}
	}

	/// Whether this node put `txid` on the network within the grace period
	/// before `now`.
	fn is_recent(&mut self, txid: &Txid, now: Instant) -> bool {
		self.prune(now);
		self.sent_at.contains_key(txid)
	}

	fn prune(&mut self, now: Instant) {
		self.sent_at
			.retain(|_, at| now.saturating_duration_since(*at) <= OWN_BROADCAST_EVICTION_GRACE);
	}

	#[cfg(test)]
	fn len(&self) -> usize {
		self.sent_at.len()
	}
}

/// The chain layer: the crate's single seam onto Bitcoin.
pub(crate) struct ChainLayer {
	slots: ChainSlots,
	/// Wallet synchronisation. A separate axis, not one of the slots.
	engine: Arc<dyn SyncEngine>,
	/// State shared by every slot's tail. Held once, rather than duplicated
	/// into each backend as it was pre-seam.
	shared: SharedChainCtx,
	/// What the BROADCAST tail put on the network recently, for the MEMPOOL
	/// tail; see [`OWN_BROADCAST_EVICTION_GRACE`].
	recent_own_broadcasts: Mutex<RecentOwnBroadcasts>,
	/// The last provider tip the engine could not place on its chain, so
	/// accepting an unverifiable answer is logged once per tip rather than
	/// once per pass.
	last_unverifiable_tip: Mutex<Option<BlockId>>,
}

impl ChainLayer {
	fn new(
		slots: ChainSlots, engine: Arc<dyn SyncEngine>, fee_estimator: Arc<OnchainFeeEstimator>,
		tx_broadcaster: Arc<Broadcaster>, kv_store: Arc<DynStore>, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		Self {
			slots,
			engine,
			shared: SharedChainCtx {
				fee_estimator,
				tx_broadcaster,
				kv_store,
				logger,
				node_metrics,
			},
			recent_own_broadcasts: Mutex::new(RecentOwnBroadcasts::default()),
			last_unverifiable_tip: Mutex::new(None),
		}
	}

	/// Slots for a backend whose single adapter fills every action slot on
	/// its own — the shape of every chain source today.
	///
	/// MEMPOOL is passed separately because only a block-polling backend
	/// has one to fill; the others carry unconfirmed transactions in their
	/// own sync and leave the chain empty. SCRIPT_HISTORY is empty for all
	/// of them: each scans its own chain source.
	fn slots_for_single_adapter<A>(
		adapter: Arc<A>, mempool: Vec<Arc<dyn MempoolAction>>,
		utxo: Option<Arc<dyn UtxoCapability>>, logger: &Arc<Logger>,
	) -> ChainSlots
	where
		A: SlotAdapters + 'static,
	{
		ChainSlots {
			fee: ActionChain::new(
				"fee",
				FEE_BUDGET,
				vec![Arc::clone(&adapter) as Arc<dyn FeeAction>],
				Arc::clone(logger),
			),
			#[cfg(feature = "swaps")]
			tx_status: ActionChain::new(
				"tx_status",
				TX_STATUS_BUDGET,
				vec![Arc::clone(&adapter) as Arc<dyn TxStatusAction>],
				Arc::clone(logger),
			),
			broadcast: ActionChain::new(
				"broadcast",
				BROADCAST_BUDGET,
				vec![adapter as Arc<dyn BroadcastAction>],
				Arc::clone(logger),
			),
			mempool: ActionChain::new("mempool", MEMPOOL_BUDGET, mempool, Arc::clone(logger)),
			script_history: ActionChain::new(
				"script_history",
				SCRIPT_HISTORY_BUDGET,
				Vec::new(),
				Arc::clone(logger),
			),
			utxo,
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

		// Esplora exposes no UTXO-set lookup, so channel announcements cannot
		// be verified against one. Its sync carries the mempool itself.
		let slots = Self::slots_for_single_adapter(adapter, Vec::new(), None, &logger);

		Self::new(slots, engine, fee_estimator, tx_broadcaster, kv_store, logger, node_metrics)
	}

	/// A node with no chain source of its own: every slot is filled from one
	/// remote provider.
	///
	/// This is the Dependent tier. Nothing about the transport reaches this
	/// crate — `provider` is supplied by the embedding application, which owns
	/// the peer connection, and this constructor only decides which slots it
	/// occupies.
	pub(crate) fn new_dependent(
		provider: Arc<dyn ChainDataProvider>, sync_config: EsploraSyncConfig,
		onchain_wallet: Arc<Wallet>, fee_estimator: Arc<OnchainFeeEstimator>,
		tx_broadcaster: Arc<Broadcaster>, kv_store: Arc<DynStore>, logger: Arc<Logger>,
		node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Self {
		let adapter =
			Arc::new(DependentChainAdapter::new(Arc::clone(&provider), Arc::clone(&logger)));

		let engine = Arc::new(DependentSyncEngine::new(
			provider,
			sync_config,
			onchain_wallet,
			Arc::clone(&kv_store),
			Arc::clone(&logger),
			Arc::clone(&node_metrics),
		));

		// A Dependent node cannot verify BOLT-7 channel announcements; see the
		// adapter module docs for why it does not ask its provider to. Its
		// sync carries the mempool itself, through the provider's wallet sync.
		let slots = Self::slots_for_single_adapter(adapter, Vec::new(), None, &logger);

		Self::new(slots, engine, fee_estimator, tx_broadcaster, kv_store, logger, node_metrics)
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

		// Electrum exposes no UTXO-set lookup, so channel announcements cannot
		// be verified against one. Its sync carries the mempool itself, so the
		// MEMPOOL chain is never run for this node — it is filled so the node
		// can *serve* mempool views to one that follows the chain by filters
		// and has none: the server indexes the mempool by script, which is the
		// shape of the question.
		let mempool = vec![Arc::clone(&adapter) as Arc<dyn MempoolAction>];
		let slots = Self::slots_for_single_adapter(adapter, mempool, None, &logger);

		Self::new(slots, engine, fee_estimator, tx_broadcaster, kv_store, logger, node_metrics)
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

		let mempool = vec![Arc::clone(&adapter) as Arc<dyn MempoolAction>];
		let utxo = Some(Arc::clone(&adapter) as Arc<dyn UtxoCapability>);
		let slots = Self::slots_for_single_adapter(adapter, mempool, utxo, &logger);

		Self::new(slots, engine, fee_estimator, tx_broadcaster, kv_store, logger, node_metrics)
	}

	/// A node following the chain by compact block filters over P2P, borrowing
	/// what filters cannot show it from an external fee source and, on a
	/// hybrid node, from a provider, and falling back to what the filters and
	/// the node's own peers can give.
	///
	/// The chains, in order:
	///
	/// A hybrid node runs on its own abilities first: in every slot where the
	/// filter node has an adapter, that adapter leads and the provider is the
	/// fallback, asked only when the node's own adapter cannot answer.
	///
	/// * FEE = [external fee, if configured; coinbase-derived; provider, if
	///   any]. An external fee server is an explicit operator choice and stays
	///   first. The coinbase-derived rates are `Unavailable` while kyoto is not
	///   running — the boot refresh runs before it is launched — and while the
	///   window holds no sample, so the provider answers until the filter node
	///   has a fee market of its own; the background loop retries a failed
	///   refresh on its short recovery cadence. Once samples exist the
	///   after-the-fact rates of recent blocks answer, however thin the window.
	/// * BROADCAST = [P2P; provider, if any]. The node's own peers take the
	///   package. An announced package ends the chain, pulled or not
	///   (`AlreadyKnown` for one no peer asked for); the provider is asked only
	///   when kyoto refused the handoff or is not running. The trade-off: P2P
	///   relay gives no accept/reject verdict, so a transaction the network
	///   refuses is not evicted at once — it is found out late, when the
	///   borrowed mempool view no longer holds it after the own-broadcast grace
	///   window, and only then are its inputs released.
	/// * TX_STATUS = [forward-only watch; provider, if any]. What this node saw
	///   confirm itself outranks what it is told, and costs nothing to ask.
	/// * MEMPOOL = [provider, if any], SCRIPT_HISTORY = [provider, if any]:
	///   nothing a filter node can fill itself.
	/// * UTXO = the existence-only source over the filters when
	///   `cbf_config.utxo_source` asks for it; none otherwise.
	///
	/// `wallet_birthday_height` floors the resume checkpoint here; the builder
	/// seeds a fresh wallet, `ChannelManager` and sweeper at the same anchor.
	/// `fallback` is the provider a hybrid node borrows from, set through
	/// [`crate::Builder::set_chain_provider_fallback`].
	#[cfg(feature = "cbf")]
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new_cbf(
		peers: Vec<String>, cbf_config: CbfConfig, fallback: Option<Arc<dyn ChainDataProvider>>,
		onchain_wallet: Arc<Wallet>, fee_estimator: Arc<OnchainFeeEstimator>,
		tx_broadcaster: Arc<Broadcaster>, kv_store: Arc<DynStore>, config: Arc<Config>,
		logger: Arc<Logger>, node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Result<Self, Error> {
		let mut fee: Vec<Arc<dyn FeeAction>> = Vec::new();
		let mut external_electrum = None;
		match cbf_config.external_fee {
			Some(CbfExternalFee::Esplora(server_url)) => {
				let mut client_builder = esplora_client::Builder::new(&server_url);
				client_builder = client_builder.timeout(DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS);
				let esplora_client = client_builder.build_async().map_err(|e| {
					log_error!(logger, "Failed to build the external Esplora fee client: {}", e);
					Error::ConnectionFailed
				})?;
				fee.push(Arc::new(EsploraChainAdapter::new(
					esplora_client,
					Arc::clone(&config),
					Arc::clone(&logger),
				)));
			},
			Some(CbfExternalFee::Electrum(server_url)) => {
				let status = Arc::new(RwLock::new(ElectrumRuntimeStatus::new()));
				fee.push(Arc::new(ElectrumChainAdapter::new(
					Arc::clone(&status),
					Arc::clone(&logger),
				)));
				external_electrum = Some(ExternalElectrum { server_url, status });
			},
			None => {},
		}

		let engine = Arc::new(CbfSyncEngine::new(
			peers,
			cbf_config.required_peers,
			cbf_config.wallet_birthday_height,
			external_electrum,
			onchain_wallet,
			Arc::clone(&kv_store),
			config,
			Arc::clone(&logger),
			Arc::clone(&node_metrics),
		)?);

		let provider = fallback
			.map(|provider| Arc::new(DependentChainAdapter::new(provider, Arc::clone(&logger))));
		fee.push(Arc::new(CbfDerivedFee::new(Arc::clone(&engine), Arc::clone(&logger))));
		if let Some(provider) = &provider {
			fee.push(Arc::clone(provider) as Arc<dyn FeeAction>);
		}

		let mut broadcast: Vec<Arc<dyn BroadcastAction>> =
			vec![Arc::new(CbfP2pBroadcast::new(Arc::clone(&engine), Arc::clone(&logger)))];
		broadcast.extend(provider.iter().map(|p| Arc::clone(p) as Arc<dyn BroadcastAction>));

		#[cfg(feature = "swaps")]
		let tx_status: Vec<Arc<dyn TxStatusAction>> = {
			let watch: Arc<dyn TxStatusAction> =
				Arc::new(CbfWatchTxStatus::new(Arc::clone(engine.watch_ledger())));
			std::iter::once(watch)
				.chain(provider.iter().map(|p| Arc::clone(p) as Arc<dyn TxStatusAction>))
				.collect()
		};

		let mempool: Vec<Arc<dyn MempoolAction>> =
			provider.iter().map(|p| Arc::clone(p) as Arc<dyn MempoolAction>).collect();
		let script_history: Vec<Arc<dyn ScriptHistoryAction>> =
			provider.iter().map(|p| Arc::clone(p) as Arc<dyn ScriptHistoryAction>).collect();

		let utxo: Option<Arc<dyn UtxoCapability>> = cbf_config.utxo_source.then(|| {
			Arc::new(CbfUtxoSource::new(Arc::clone(&engine), Arc::clone(&logger)))
				as Arc<dyn UtxoCapability>
		});

		let slots = ChainSlots {
			fee: ActionChain::new("fee", FEE_BUDGET, fee, Arc::clone(&logger)),
			#[cfg(feature = "swaps")]
			tx_status: ActionChain::new(
				"tx_status",
				TX_STATUS_BUDGET,
				tx_status,
				Arc::clone(&logger),
			),
			broadcast: ActionChain::new(
				"broadcast",
				BROADCAST_BUDGET,
				broadcast,
				Arc::clone(&logger),
			),
			mempool: ActionChain::new("mempool", MEMPOOL_BUDGET, mempool, Arc::clone(&logger)),
			script_history: ActionChain::new(
				"script_history",
				SCRIPT_HISTORY_BUDGET,
				script_history,
				Arc::clone(&logger),
			),
			utxo,
		};

		Ok(Self::new(slots, engine, fee_estimator, tx_broadcaster, kv_store, logger, node_metrics))
	}

	/// Which adapters currently occupy each slot. For logs and diagnostics;
	/// nothing may branch on it.
	pub(crate) fn slot_adapters(&self) -> ChainSlotAdapters {
		ChainSlotAdapters {
			fee: self.slots.fee.names(),
			#[cfg(feature = "swaps")]
			tx_status: self.slots.tx_status.names(),
			broadcast: self.slots.broadcast.names(),
			mempool: self.slots.mempool.names(),
			script_history: self.slots.script_history.names(),
			utxo: self
				.slots
				.utxo
				.as_ref()
				.and_then(|u| u.utxo_source().map(|(_, verification)| (u.name(), verification))),
			engine: self.engine.name(),
		}
	}

	/// The public form of [`ChainLayer::slot_adapters`], with each slot's most
	/// recent answerer — see [`crate::Node::chain_slot_adapters`].
	pub(crate) fn slot_status(&self) -> ChainSlotStatus {
		fn slot<A: ?Sized + Send + Sync + SlotAdapter>(
			chain: &ActionChain<A>,
		) -> ChainSlotAdapterStatus {
			ChainSlotAdapterStatus {
				adapters: chain.names().into_iter().map(str::to_string).collect(),
				last_answered: chain.last_answered().map(str::to_string),
			}
		}

		ChainSlotStatus {
			engine: self.engine.name().to_string(),
			fee: slot(&self.slots.fee),
			broadcast: slot(&self.slots.broadcast),
			#[cfg(feature = "swaps")]
			tx_status: slot(&self.slots.tx_status),
			#[cfg(not(feature = "swaps"))]
			tx_status: ChainSlotAdapterStatus::default(),
			mempool: slot(&self.slots.mempool),
			script_history: slot(&self.slots.script_history),
			utxo: self.slots.utxo.as_ref().and_then(|u| {
				u.utxo_source().map(|(_, verification)| ChainUtxoStatus {
					adapter: u.name().to_string(),
					verification: match verification {
						UtxoVerification::Full => ChainUtxoVerification::Full,
						UtxoVerification::ExistenceOnly => ChainUtxoVerification::ExistenceOnly,
					},
				})
			}),
		}
	}

	/// The compact-block-filter sync status; `None` unless the engine follows
	/// the chain by filters. See [`crate::Node::cbf_sync_status`].
	pub(crate) fn cbf_sync_status(&self) -> Option<CbfSyncStatus> {
		self.engine.cbf_sync_status()
	}

	/// Start any runtime-dependent part of the layer (currently Electrum only).
	pub(crate) fn start(&self, runtime: Arc<tokio::runtime::Runtime>) -> Result<(), Error> {
		self.engine.start(runtime)
	}

	pub(crate) fn stop(&self) {
		self.engine.stop()
	}

	/// The UTXO source used to verify BOLT-7 `channel_announcement`s, if any
	/// adapter can serve one. `None` means announcements are accepted
	/// unverified.
	pub(crate) fn as_utxo_source(&self) -> Option<Arc<dyn UtxoSource>> {
		self.slots.utxo.as_ref().and_then(|u| u.utxo_source()).map(|(source, _)| source)
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

	/// Refresh the fee-rate cache from the FEE chain.
	///
	/// The chain produces the cache; the seam installs it and records that it
	/// happened. Both steps are skipped entirely when the answering adapter
	/// returns [`FeeUpdate::Skip`], which preserves the pre-seam bitcoind
	/// behaviour of leaving a stale-but-valid cache in place on a soft failure
	/// rather than advancing the metrics timestamp as though an update had
	/// landed.
	///
	/// An exhausted chain is reported as the same two errors callers saw from
	/// the single adapters: [`Error::FeerateEstimationUpdateTimeout`] when a
	/// timeout is why, [`Error::FeerateEstimationUpdateFailed`] otherwise.
	pub(crate) async fn update_fee_rate_estimates(&self) -> Result<(), Error> {
		let now = Instant::now();

		let update = match self.slots.fee.run(|a| async move { a.fee_rate_update().await }).await {
			Ok(answered) => answered.value,
			Err(ChainActionError::Unavailable { timed_out, .. }) => {
				return Err(if timed_out {
					Error::FeerateEstimationUpdateTimeout
				} else {
					Error::FeerateEstimationUpdateFailed
				});
			},
			Err(ChainActionError::Rejected(reason)) => {
				log_error!(self.shared.logger, "Fee rate estimates rejected: {}", reason);
				return Err(Error::FeerateEstimationUpdateFailed);
			},
		};

		let (cache, log_unchanged) = match update {
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

	/// Drain the broadcast queue through the BROADCAST chain.
	///
	/// Called once a second. When no adapter in the chain is ready the pass is
	/// abandoned before anything is pulled from the queue, so the packages
	/// wait for the next tick rather than being lost to a chain that could
	/// not have answered — the pre-seam Electrum skip-and-retry, now for every
	/// backend. Otherwise each package runs the chain and then the shared
	/// tail ([`ChainLayer::broadcast_package`]). Nothing here propagates: the
	/// queue carries no retry semantics, so a package the chain cannot place
	/// is logged and dropped, exactly as lossy as pre-seam.
	pub(crate) async fn process_broadcast_queue(&self) {
		if !self.any_broadcast_adapter_ready().await {
			return;
		}

		let mut receiver = self.shared.tx_broadcaster.get_broadcast_queue().await;
		while let Some(next_package) = receiver.recv().await {
			self.broadcast_package(next_package).await;
		}
	}

	async fn any_broadcast_adapter_ready(&self) -> bool {
		for adapter in self.slots.broadcast.adapters() {
			if adapter.ready().await {
				return true;
			}
		}
		false
	}

	/// Run `txs` through the BROADCAST chain. An adapter that is not ready is
	/// `Unavailable` without the round trip.
	///
	/// Besides the chain's verdict, the run keeps every transaction some
	/// adapter reported as on the network — accepted, or already known —
	/// whether or not the package as a whole got there. A package one adapter
	/// half-sent before the chain ran out is not un-sent by the exhaustion.
	async fn run_broadcast(&self, txs: &[Transaction]) -> BroadcastRun {
		let accepted = Mutex::new(HashSet::new());
		// A reference, so the `Fn` closure copies it into each future rather
		// than moving the set into the first.
		let accepted_ref = &accepted;
		let outcome = self
			.slots
			.broadcast
			.run(|a| async move {
				if !a.ready().await {
					return Err(ChainActionError::unavailable("not ready"));
				}
				let outcomes = a.broadcast_package(txs).await?;
				accepted_ref
					.lock()
					.unwrap_or_else(|e| e.into_inner())
					.extend(accepted_txids(&outcomes));
				package_result(outcomes)
			})
			.await;
		BroadcastRun { outcome, accepted: accepted.into_inner().unwrap_or_else(|e| e.into_inner()) }
	}

	/// One package through the BROADCAST chain, then the shared tail.
	///
	/// The tail is what every backend used to lack: it tells the on-chain
	/// wallet what the chain's answer means for the node's own coins.
	///
	/// * `Rejected` — each refused transaction is logged with its reason and
	///   evicted from the wallet, so the inputs it tried to spend are offered
	///   again. Relaying it elsewhere would only buy the same verdict.
	///   Transactions of the package that were not listed were accepted.
	/// * `Ok` — the package is on the network. If the engine
	///   [`SyncEngine::tracks_own_broadcasts`], the wallet is told the
	///   package is unconfirmed now, because nothing else ever will; an
	///   engine with a mempool view sees its own transactions come back and
	///   is left alone.
	/// * exhausted — logged at error and dropped, as lossy as pre-seam. But a
	///   transaction some adapter did hand to the network before the chain
	///   ran out is not dropped: an engine that tracks its own broadcasts is
	///   told it is unconfirmed, exactly as it would have been had the whole
	///   package gone, so the coins it spent stop being offered again.
	async fn broadcast_package(&self, package: Vec<Transaction>) {
		let BroadcastRun { outcome, accepted } = self.run_broadcast(&package).await;

		let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
		let echo_own = self.engine.tracks_own_broadcasts();

		let (unconfirmed, evicted): (Unconfirmed, Evicted) = match outcome {
			Ok(answered) => {
				log_trace!(
					self.shared.logger,
					"Broadcast a package of {} transaction(s) via {}",
					package.len(),
					answered.by
				);
				if !echo_own {
					return;
				}
				(package.into_iter().map(|tx| (tx, now)).collect(), Vec::new())
			},
			Err(ChainActionError::Unavailable { reason, .. }) => {
				log_error!(
					self.shared.logger,
					"Failed to broadcast a package of {} transaction(s); dropping it: {}",
					package.len(),
					reason
				);
				for tx in &package {
					if !accepted.contains(&tx.compute_txid()) {
						log_trace!(
							self.shared.logger,
							"Dropped broadcast transaction {}",
							tx.compute_txid()
						);
					}
				}
				if !echo_own || accepted.is_empty() {
					return;
				}
				log_debug!(
					self.shared.logger,
					"{} of the package's transaction(s) reached the network before the chain \
					 was exhausted; recording them as unconfirmed",
					accepted.len()
				);
				let sent = package
					.into_iter()
					.filter(|tx| accepted.contains(&tx.compute_txid()))
					.map(|tx| (tx, now))
					.collect();
				(sent, Vec::new())
			},
			Err(ChainActionError::Rejected(rejected)) => {
				for (txid, reason) in &rejected {
					log_warn!(
						self.shared.logger,
						"The network rejected transaction {}; giving it up and releasing its inputs in the on-chain wallet: {}",
						txid,
						reason
					);
				}
				let rejected_txids: HashSet<Txid> =
					rejected.iter().map(|(txid, _)| *txid).collect();
				let accepted = if echo_own {
					package
						.into_iter()
						.filter(|tx| !rejected_txids.contains(&tx.compute_txid()))
						.map(|tx| (tx, now))
						.collect()
				} else {
					Vec::new()
				};
				(accepted, rejected.into_iter().map(|(txid, _)| (txid, now)).collect())
			},
		};

		// Only an engine with no mempool view of its own reaches here with
		// transactions to echo, and only such an engine borrows a mempool view
		// that could evict them before the network has seen them: remember
		// what left, so the MEMPOOL tail knows a fresh absence is not a verdict.
		if !unconfirmed.is_empty() {
			let sent_at = Instant::now();
			let mut recent = self.recent_own_broadcasts.lock().unwrap_or_else(|e| e.into_inner());
			for (tx, _) in &unconfirmed {
				recent.record(tx.compute_txid(), sent_at);
			}
		}

		let Some(wallet) = self.engine.onchain_wallet() else {
			log_debug!(
				self.shared.logger,
				"No on-chain wallet to record a broadcast package in ({} unconfirmed, {} evicted)",
				unconfirmed.len(),
				evicted.len()
			);
			return;
		};
		if let Err(e) = wallet.apply_mempool_txs(unconfirmed, evicted) {
			log_error!(
				self.shared.logger,
				"Failed to record a broadcast package in the on-chain wallet: {}",
				e
			);
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
		self.engine.sync_once(self, channel_manager, chain_monitor, output_sweeper).await
	}

	/// Whether any adapter fills the MEMPOOL slot. An engine with no mempool
	/// view of its own asks this before a pass rather than running an empty
	/// chain and logging its exhaustion every time.
	#[cfg(feature = "cbf")]
	pub(crate) fn has_mempool_chain(&self) -> bool {
		!self.slots.mempool.is_empty()
	}

	/// The hybrid reorg-consistency check, run on every [`Anchored`] answer
	/// as its chain's check ([`ActionChain::run_checked`]) so a refused answer
	/// advances the chain. It runs after the adapter's budgeted call, not
	/// inside it: the header lookup it may make is bounded by the engine, and
	/// counting it against the adapter's budget would drop an answer that
	/// arrived in time. `Some(false)` still refuses the answer and advances.
	///
	/// An answer a provider computed on a chain this node does not consider
	/// best — the engine knows a different block at the tip's height — is
	/// `Unavailable`, never applied: its unconfirmed transactions, evictions
	/// and confirmations describe a branch this node is not on. An answer
	/// the engine cannot place (`None`: no header chain of its own, or the
	/// height outside what it holds) is accepted as it always was, and said
	/// so at debug once per tip. An answer with no tip carries nothing to
	/// check.
	async fn anchored_on_our_chain<T>(
		&self, slot: &'static str, by: &'static str, answer: Anchored<T>,
	) -> ActionResult<Anchored<T>> {
		let Some(tip) = answer.tip else {
			return Ok(answer);
		};
		match self.engine.is_on_chain(&tip).await {
			Some(true) => Ok(answer),
			Some(false) => {
				log_info!(
					self.shared.logger,
					"slot={} adapter={} answered at tip {} (height {}), which is not on this node's chain; refusing the answer",
					slot,
					by,
					tip.hash,
					tip.height
				);
				Err(ChainActionError::unavailable(format!(
					"provider tip {} at height {} is not on our chain",
					tip.hash, tip.height
				)))
			},
			None => {
				let mut last = self.last_unverifiable_tip.lock().unwrap_or_else(|e| e.into_inner());
				if *last != Some(tip) {
					log_debug!(
						self.shared.logger,
						"slot={} adapter={} answered at tip {} (height {}), which this node cannot place on its chain; accepting it unchecked",
						slot,
						by,
						tip.hash,
						tip.height
					);
					*last = Some(tip);
				}
				Ok(answer)
			},
		}
	}

	/// Ask the MEMPOOL chain.
	///
	/// The answer is handed back as the chain produced it — anchored to the
	/// tip the answering adapter took it at, tagged with that adapter — for
	/// the caller to apply: the block-polling engine applies it to the
	/// on-chain wallet exactly where it applied its own poll pre-seam, and the
	/// serving path projects it onto the wire. An empty chain is
	/// `Unavailable`; no engine with an empty chain asks.
	///
	/// Two things the tail does first, both for a node whose MEMPOOL chain is
	/// borrowed. An answer anchored to a tip that is not on this node's chain
	/// is refused and the chain advances ([`ChainLayer::anchored_on_our_chain`]).
	/// And when the engine [`SyncEngine::tracks_own_broadcasts`] — so the
	/// wallet learnt of its own transactions from the BROADCAST tail, and the
	/// mempool being asked is not the one they were handed to — an eviction
	/// of a transaction this node put on the network within
	/// [`OWN_BROADCAST_EVICTION_GRACE`] is dropped: the borrowed view may not
	/// have seen it yet, and releasing its inputs on that word would offer
	/// them to a second spend. An engine with a mempool of its own applies
	/// every eviction, because its own mempool's word is a verdict.
	pub(crate) async fn mempool(
		&self, query: &MempoolQuery,
	) -> ActionResult<Answered<Anchored<MempoolAnswer>>> {
		let mut answered = self
			.slots
			.mempool
			.run_checked(
				|a| async move { a.mempool(query).await },
				|by, answer| self.anchored_on_our_chain("mempool", by, answer),
			)
			.await?;

		if self.engine.tracks_own_broadcasts() {
			self.shield_own_broadcasts(&mut answered.value.value.evicted, answered.by);
		}
		Ok(answered)
	}

	/// Borrow a mempool view for this node's own on-chain wallet, and apply it.
	///
	/// For an engine with no mempool of its own: the filter-following engine
	/// asks on its own cadence and on every foreground pass. The answer goes
	/// through [`ChainLayer::mempool`] — refused if anchored off this node's
	/// chain, with fresh own broadcasts shielded from eviction — and is then
	/// stamped on this node's clock ([`stamp_locally`]) before the wallet sees
	/// it. An empty chain is `Unavailable`; the engine checks
	/// [`ChainLayer::has_mempool_chain`] before asking.
	#[cfg(feature = "cbf")]
	pub(crate) async fn borrow_mempool(
		&self, query: &MempoolQuery,
	) -> ActionResult<BorrowedMempool> {
		let Some(wallet) = self.engine.onchain_wallet() else {
			return Err(ChainActionError::unavailable(
				"no on-chain wallet to apply a mempool view to",
			));
		};
		let answered = self.mempool(query).await?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
		let (unconfirmed, evicted) = stamp_locally(answered.value.value, now);
		let borrowed = BorrowedMempool {
			by: answered.by,
			unconfirmed: unconfirmed.len(),
			evicted: evicted.len(),
		};
		wallet.apply_mempool_txs(unconfirmed, evicted).map_err(|e| {
			log_error!(self.shared.logger, "Failed to apply a borrowed mempool view: {}", e);
			ChainActionError::unavailable(format!("applying the mempool view failed: {}", e))
		})?;
		Ok(borrowed)
	}

	/// Drop from `evicted` every transaction this node itself broadcast within
	/// [`OWN_BROADCAST_EVICTION_GRACE`]; see [`ChainLayer::mempool`].
	fn shield_own_broadcasts(&self, evicted: &mut Evicted, by: &'static str) {
		if evicted.is_empty() {
			return;
		}
		let now = Instant::now();
		let mut recent = self.recent_own_broadcasts.lock().unwrap_or_else(|e| e.into_inner());
		evicted.retain(|(txid, _)| {
			let shielded = recent.is_recent(txid, now);
			if shielded {
				log_debug!(
					self.shared.logger,
					"Not evicting {} on {}'s word: this node broadcast it within the last {}s",
					txid,
					by,
					OWN_BROADCAST_EVICTION_GRACE.as_secs()
				);
			}
			!shielded
		});
	}

	/// Run the wide wallet scan `req` describes through the SCRIPT_HISTORY
	/// chain.
	///
	/// Filled only on a hybrid node, from its provider; the answer is
	/// [`Anchored`] to the update's checkpoint tip, and one anchored to a tip
	/// that is not on this node's chain is refused with the chain advancing,
	/// exactly as a MEMPOOL answer is. An empty chain is `Unavailable`.
	#[allow(dead_code)] // run by the hybrid script-history restore on first boot (T11)
	pub(crate) async fn script_history(
		&self, req: &WireSyncRequest,
	) -> ActionResult<Answered<Anchored<bdk_wallet::Update>>> {
		self.slots
			.script_history
			.run_checked(
				|a| async move { a.script_history(req.clone()).await },
				|by, answer| self.anchored_on_our_chain("script_history", by, answer),
			)
			.await
	}

	/// Ask the TX_STATUS chain about `txid`.
	///
	/// FAIL-CLOSED (E6): an exhausted chain — no adapter could answer — is
	/// [`RawTxObservation::Unreachable`], never an observation a caller could
	/// fold into "confirmed". A rejection is treated the same way; no
	/// TX_STATUS adapter rejects today, and "the network said no" is not a
	/// confirmation either.
	#[cfg(feature = "swaps")]
	async fn observe_tx(&self, txid: Txid, script_pubkey: Option<&ScriptBuf>) -> RawTxObservation {
		self.observe_tx_anchored(txid, script_pubkey).await.value
	}

	/// [`ChainLayer::observe_tx`] keeping the tip the answering adapter
	/// derived the observation against, for the serving path to pass on. An
	/// unreachable observation has no tip. An observation anchored to a tip
	/// that is not on this node's chain is refused and the chain advances
	/// ([`ChainLayer::anchored_on_our_chain`]): a confirmation on a branch
	/// this node is not on is no confirmation.
	#[cfg(feature = "swaps")]
	async fn observe_tx_anchored(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> Anchored<RawTxObservation> {
		match self
			.slots
			.tx_status
			.run_checked(
				|a| async move { a.tx_status(txid, script_pubkey).await },
				|by, answer| self.anchored_on_our_chain("tx_status", by, answer),
			)
			.await
		{
			Ok(answered) => answered.value,
			Err(_) => Anchored { value: RawTxObservation::Unreachable, tip: None },
		}
	}

	// ── SERVING ─────────────────────────────────────────────────────────────
	//
	// The Pro half of the Dependent tier: answering another node's questions
	// from this node's own chain source. Each of these reads through the same
	// slot this node uses itself, so a served answer and a local one cannot
	// diverge.
	//
	// And each of them first asks the engine whether this node has a chain
	// source of its own to answer from at all. A Dependent node's slots are
	// filled from its provider, a hybrid node's borrowed slots likewise, and
	// a filter-following node's own slots see only what its filters show: an
	// answer from any of them would be forwarded, or partial, and the asking
	// node could not tell. So they refuse, before the question reaches a slot.

	/// The rule every serve has: only a node whose slots are filled from a
	/// chain source it observes itself may answer another node.
	fn refuse_unless_serving(&self) -> Result<(), Error> {
		if self.engine.serves_peers() {
			Ok(())
		} else {
			Err(Error::ChainServeUnsupported)
		}
	}

	/// This node's current fee-rate cache, for a Dependent node to adopt.
	///
	/// Reported per target rather than per block count, because the per-target
	/// policy — bitcoind's conservative-versus-economical choice, and this
	/// node's own floors — is exactly what makes the answer worth asking for.
	///
	/// Refused — [`Error::ChainServeUnsupported`] — when this node's own fee
	/// cache is itself borrowed or derived rather than observed at a real
	/// chain source.
	pub(crate) fn serve_fee_estimates(&self) -> Result<WireFeeEstimates, Error> {
		self.refuse_unless_serving()?;

		let targets = get_all_conf_targets()
			.into_iter()
			.map(|target| WireFeeTarget {
				target: conf_target_wire_name(target).to_string(),
				sat_per_kwu: self.shared.fee_estimator.estimate_fee_rate(target).to_sat_per_kwu(),
			})
			.collect();

		Ok(WireFeeEstimates { version: CHAIN_WIRE_VERSION, targets })
	}

	/// Put another node's transaction on the network through this node's
	/// BROADCAST chain.
	///
	/// Returns once the transaction has been handed to the network — accepted
	/// or already known — never once it has reached a miner. Errors when the
	/// chain is exhausted (no adapter could send it) **or** when the network
	/// rejected it: the asking node must see a failed call either way, and the
	/// wire has no way to say which. The rejection is logged here so this
	/// node's operator can tell the two apart. The transaction is not this
	/// node's own, so the shared tail does not run for it. Refused —
	/// [`Error::ChainServeUnsupported`] — when this node's BROADCAST chain
	/// is not its own chain source.
	pub(crate) async fn serve_broadcast(&self, tx: &Transaction) -> Result<(), Error> {
		self.refuse_unless_serving()?;

		match self.run_broadcast(std::slice::from_ref(tx)).await.outcome {
			Ok(_) => Ok(()),
			Err(ChainActionError::Unavailable { reason, .. }) => {
				log_error!(
					self.shared.logger,
					"Could not broadcast another node's transaction {}: {}",
					tx.compute_txid(),
					reason
				);
				Err(Error::ChainServeFailed)
			},
			Err(ChainActionError::Rejected(rejected)) => {
				for (txid, reason) in &rejected {
					log_warn!(
						self.shared.logger,
						"The network rejected another node's transaction {}: {}",
						txid,
						reason
					);
				}
				Err(Error::ChainServeFailed)
			},
		}
	}

	/// Answer another node's question about an arbitrary transaction.
	///
	/// An exhausted TX_STATUS chain is an **error**, never a response. The
	/// wire type has no "unreachable" variant on purpose: if this node could
	/// not look, the asking node must see a failed call and fail closed, not a
	/// well-formed answer that reads as "not found". Refused —
	/// [`Error::ChainServeUnsupported`] — when this node's TX_STATUS chain is
	/// not its own chain source.
	#[cfg(feature = "swaps")]
	pub(crate) async fn serve_tx_status(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> Result<WireTxStatusResponse, Error> {
		self.refuse_unless_serving()?;

		let observed = self.observe_tx_anchored(txid, script_pubkey).await;
		// The tip the adapter derived the answer against, when it reported
		// one: its hash, for an asker that can place it on its own chain, and
		// its height with it, so the pair names one block. Without a tip the
		// height is reconstructed from the depth, as it always was.
		let tip_hash = observed.tip.map(|tip| tip.hash.to_string());
		let anchored_height = observed.tip.map(|tip| tip.height);
		let (confirmed, in_mempool, confirmation_height, depth_tip) = match observed.value {
			RawTxObservation::Confirmed { height, confirmations } => {
				// Reconstruct the tip the adapter derived depth against,
				// so the caller can recompute rather than trust a count
				// taken at a tip it cannot see.
				let tip = height.map(|h| h + confirmations.saturating_sub(1));
				(true, false, height, tip)
			},
			RawTxObservation::InMempool => (false, true, None, None),
			RawTxObservation::NotFound => (false, false, None, None),
			RawTxObservation::Unreachable => {
				log_info!(
						self.shared.logger,
						"Refusing to answer a chain lookup for {}: this node's own lookup is unreachable",
						txid
					);
				return Err(Error::ChainServeFailed);
			},
		};

		Ok(WireTxStatusResponse {
			version: CHAIN_WIRE_VERSION,
			confirmed,
			in_mempool,
			confirmation_height,
			tip_height: anchored_height.or(depth_tip),
			tip_hash,
		})
	}

	/// Answer another node's mempool question from this node's MEMPOOL
	/// chain.
	///
	/// Refused — [`Error::ChainServeUnsupported`] — unless this node serves
	/// peers at all ([`SyncEngine::serves_peers`]), the engine says the chain
	/// answers from a mempool this node observes itself
	/// ([`SyncEngine::serves_mempool`]), and the chain has an adapter at all.
	/// The question is asked in [`MempoolScope::Complete`], so the poll
	/// loop's own memory of what it answered is left alone.
	///
	/// An exhausted chain is [`Error::ChainServeFailed`], and so is an
	/// answer taken before the engine has synced to any tip: the wire
	/// requires the tip, because an asker that follows the chain itself
	/// must be able to place the answer on its chain, and a mempool view
	/// anchored nowhere is not one it should act on. So is a question of
	/// more than [`MAX_MEMPOOL_QUERY_ITEMS`] scripts and txids together,
	/// refused before it is decoded: the adapter filters the whole mempool
	/// by it under the locks the local poll shares.
	///
	/// [`MempoolScope::Complete`]: crate::chain::seam::MempoolScope::Complete
	pub(crate) async fn serve_mempool(
		&self, req: &WireMempoolRequest,
	) -> Result<WireMempoolResponse, Error> {
		self.refuse_unless_serving()?;
		if !self.engine.serves_mempool() || self.slots.mempool.is_empty() {
			return Err(Error::ChainServeUnsupported);
		}

		let items = req.spks.len().saturating_add(req.known_unconfirmed.len());
		if items > MAX_MEMPOOL_QUERY_ITEMS {
			log_info!(
				self.shared.logger,
				"Refusing a mempool question of {} scripts and {} known txids: more than the {} this node answers",
				req.spks.len(),
				req.known_unconfirmed.len(),
				MAX_MEMPOOL_QUERY_ITEMS
			);
			return Err(Error::ChainServeFailed);
		}

		let query = wire_to_mempool_query(req).map_err(|e| {
			log_error!(self.shared.logger, "Refusing a malformed mempool request: {}", e);
			Error::ChainServeFailed
		})?;

		let answered = self.mempool(&query).await.map_err(|e| {
			log_error!(
				self.shared.logger,
				"Could not answer another node's mempool question: {}",
				e
			);
			Error::ChainServeFailed
		})?;

		let Anchored { value: answer, tip } = answered.value;
		let Some(tip) = tip else {
			log_info!(
				self.shared.logger,
				"Refusing to answer a mempool question: this node has not synced to a tip yet"
			);
			return Err(Error::ChainServeFailed);
		};

		log_trace!(
			self.shared.logger,
			"Served a mempool question via {}: {} unconfirmed, {} evicted, at height {}",
			answered.by,
			answer.unconfirmed.len(),
			answer.evicted.len(),
			tip.height
		);
		Ok(mempool_answer_to_wire(&answer, &tip))
	}

	/// Run another node's on-chain wallet scan against this node's chain
	/// source. Refused — [`Error::ChainServeUnsupported`] — when this node
	/// has none of its own.
	pub(crate) async fn serve_wallet_sync(
		&self, req: &WireSyncRequest,
	) -> Result<WireUpdate, Error> {
		self.refuse_unless_serving()?;
		self.engine.serve_wallet_sync(req).await
	}

	/// Answer another node's Lightning sync. Refused —
	/// [`Error::ChainServeUnsupported`] — when this node has no chain source
	/// of its own.
	pub(crate) async fn serve_lightning_sync(
		&self, req: &WireLightningSyncRequest,
	) -> Result<WireLightningSyncResponse, Error> {
		self.refuse_unless_serving()?;
		self.engine.serve_lightning_sync(req).await
	}

	/// Reorg-aware status of a watched transaction (Peerswap native primitive B5).
	#[cfg(feature = "swaps")]
	pub(crate) async fn swap_query_tx(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> RawTxObservation {
		self.observe_tx(txid, script_pubkey).await
	}

	/// Tell the engine to watch `txid` for the TX_STATUS slot, with the output
	/// script it can be found by. An engine that answers from its chain
	/// source at query time ignores this; a filter-driven one needs it before
	/// the transaction confirms. See [`SyncEngine::watch_tx`].
	#[cfg(feature = "swaps")]
	pub(crate) fn watch_swap_tx(&self, txid: Txid, script_pubkey: ScriptBuf) {
		self.engine.watch_tx(txid, script_pubkey)
	}

	/// The counterpart of [`ChainLayer::watch_swap_tx`].
	#[cfg(feature = "swaps")]
	pub(crate) fn unwatch_swap_tx(&self, txid: &Txid) {
		self.engine.unwatch_tx(txid)
	}

	/// The shared on-chain fee estimator (Peerswap native primitive B6; also what a chain
	/// listener hands a channel monitor it rewinds on its own).
	pub(crate) fn fee_estimator(&self) -> &Arc<OnchainFeeEstimator> {
		&self.shared.fee_estimator
	}

	/// The shared transaction broadcaster, for the same listener use.
	pub(crate) fn tx_broadcaster(&self) -> &Arc<Broadcaster> {
		&self.shared.tx_broadcaster
	}
}

/// The action traits a single adapter must implement to fill every action
/// slot by itself. Spelled as one trait so the bound does not change shape
/// between feature sets.
#[cfg(feature = "swaps")]
trait SlotAdapters: FeeAction + BroadcastAction + TxStatusAction {}
#[cfg(feature = "swaps")]
impl<A: FeeAction + BroadcastAction + TxStatusAction> SlotAdapters for A {}

#[cfg(not(feature = "swaps"))]
trait SlotAdapters: FeeAction + BroadcastAction {}
#[cfg(not(feature = "swaps"))]
impl<A: FeeAction + BroadcastAction> SlotAdapters for A {}

impl Filter for ChainLayer {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.engine.register_tx(txid, script_pubkey)
	}

	fn register_output(&self, output: WatchedOutput) {
		self.engine.register_output(output)
	}
}

#[cfg(test)]
mod tests {
	//! N2: the BROADCAST drain and its shared tail, run against fake adapters,
	//! a fake engine and a real on-chain wallet — the tail's effect is what
	//! the wallet then offers to spend, so nothing narrower would prove it.
	//! N4: the MEMPOOL chain and the serving path over it.
	use super::*;

	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::time::Duration;

	use bdk_chain::BlockId;
	use bitcoin::hashes::Hash;
	use bitcoin::{
		absolute, transaction, Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, TxIn,
		TxOut, WPubkeyHash, Witness,
	};
	use lightning::chain::chaininterface::BroadcasterInterface;
	use lightning::util::test_utils::TestStore;

	use crate::chain::seam::{ActionResult, MempoolScope, PackageOutcomes, TxBroadcastOutcome};
	use crate::chain::test_wallet::fresh_regtest_wallet;
	use crate::chain::wire_convert::{script_to_wire, tx_to_wire, txid_to_wire};
	use crate::tx_broadcaster::TransactionBroadcaster;

	use async_trait::async_trait;

	const FUNDING_SATS: u64 = 100_000;

	/// What one fake adapter does with a package.
	enum Behaviour {
		Ok,
		Unavailable,
		NotReady,
		/// Rejects exactly these txids and accepts the rest of the package.
		Reject(Vec<Txid>),
		/// Accepts exactly these txids and cannot send the rest: the shape of
		/// a backend that went away halfway through a package.
		AcceptOnly(Vec<Txid>),
	}

	struct FakeBroadcast {
		name: &'static str,
		behaviour: Behaviour,
		calls: AtomicUsize,
	}

	impl FakeBroadcast {
		fn new(name: &'static str, behaviour: Behaviour) -> Arc<Self> {
			Arc::new(Self { name, behaviour, calls: AtomicUsize::new(0) })
		}

		fn calls(&self) -> usize {
			self.calls.load(Ordering::SeqCst)
		}
	}

	#[async_trait]
	impl BroadcastAction for FakeBroadcast {
		fn name(&self) -> &'static str {
			self.name
		}

		async fn ready(&self) -> bool {
			!matches!(self.behaviour, Behaviour::NotReady)
		}

		async fn broadcast_package(
			&self, txs: &[Transaction],
		) -> ActionResult<PackageOutcomes, BroadcastRejection> {
			self.calls.fetch_add(1, Ordering::SeqCst);
			let txids = txs.iter().map(|tx| tx.compute_txid());
			match &self.behaviour {
				Behaviour::Ok => {
					Ok(txids.map(|txid| (txid, TxBroadcastOutcome::Accepted)).collect())
				},
				Behaviour::Unavailable | Behaviour::NotReady => {
					Err(ChainActionError::unavailable(format!("{} is down", self.name)))
				},
				Behaviour::Reject(rejected) => Ok(txids
					.map(|txid| {
						let outcome = if rejected.contains(&txid) {
							TxBroadcastOutcome::Rejected("policy".to_string())
						} else {
							TxBroadcastOutcome::Accepted
						};
						(txid, outcome)
					})
					.collect()),
				Behaviour::AcceptOnly(accepted) => Ok(txids
					.map(|txid| {
						let outcome = if accepted.contains(&txid) {
							TxBroadcastOutcome::Accepted
						} else {
							TxBroadcastOutcome::Unavailable {
								reason: format!("{} went away", self.name),
								timed_out: false,
							}
						};
						(txid, outcome)
					})
					.collect()),
			}
		}
	}

	/// What one fake MEMPOOL adapter answers.
	enum MempoolBehaviour {
		/// Answers these transactions, anchored to this tip.
		Answer {
			unconfirmed: Vec<Transaction>,
			tip: Option<BlockId>,
		},
		Unavailable,
	}

	struct FakeMempool {
		name: &'static str,
		behaviour: MempoolBehaviour,
		/// Every query the adapter was asked, so a test can check what
		/// reached it.
		queries: Mutex<Vec<MempoolQuery>>,
	}

	impl FakeMempool {
		fn new(name: &'static str, behaviour: MempoolBehaviour) -> Arc<Self> {
			Arc::new(Self { name, behaviour, queries: Mutex::new(Vec::new()) })
		}

		fn queries(&self) -> Vec<MempoolQuery> {
			self.queries.lock().unwrap().clone()
		}
	}

	#[async_trait]
	impl MempoolAction for FakeMempool {
		fn name(&self) -> &'static str {
			self.name
		}

		async fn mempool(&self, query: &MempoolQuery) -> ActionResult<Anchored<MempoolAnswer>> {
			self.queries.lock().unwrap().push(query.clone());
			match &self.behaviour {
				MempoolBehaviour::Answer { unconfirmed, tip } => Ok(Anchored {
					value: MempoolAnswer {
						unconfirmed: unconfirmed.iter().map(|tx| (tx.clone(), 1)).collect(),
						evicted: query.known_unconfirmed.iter().map(|txid| (*txid, 2)).collect(),
					},
					tip: *tip,
				}),
				MempoolBehaviour::Unavailable => {
					Err(ChainActionError::unavailable(format!("{} is down", self.name)))
				},
			}
		}
	}

	/// What one fake TX_STATUS adapter observes, anchored where it says.
	#[cfg(feature = "swaps")]
	struct FakeTxStatus {
		name: &'static str,
		observation: RawTxObservation,
		tip: Option<BlockId>,
		calls: AtomicUsize,
	}

	#[cfg(feature = "swaps")]
	impl FakeTxStatus {
		fn new(
			name: &'static str, observation: RawTxObservation, tip: Option<BlockId>,
		) -> Arc<Self> {
			Arc::new(Self { name, observation, tip, calls: AtomicUsize::new(0) })
		}

		fn calls(&self) -> usize {
			self.calls.load(Ordering::SeqCst)
		}
	}

	#[cfg(feature = "swaps")]
	#[async_trait]
	impl TxStatusAction for FakeTxStatus {
		fn name(&self) -> &'static str {
			self.name
		}

		async fn tx_status(
			&self, _txid: Txid, _script_pubkey: Option<&ScriptBuf>,
		) -> ActionResult<Anchored<RawTxObservation>> {
			self.calls.fetch_add(1, Ordering::SeqCst);
			Ok(Anchored { value: self.observation, tip: self.tip })
		}
	}

	/// A fake SCRIPT_HISTORY adapter answering an empty update anchored where
	/// it says.
	struct FakeScriptHistory {
		name: &'static str,
		tip: Option<BlockId>,
		calls: AtomicUsize,
	}

	impl FakeScriptHistory {
		fn new(name: &'static str, tip: Option<BlockId>) -> Arc<Self> {
			Arc::new(Self { name, tip, calls: AtomicUsize::new(0) })
		}

		fn calls(&self) -> usize {
			self.calls.load(Ordering::SeqCst)
		}
	}

	#[async_trait]
	impl ScriptHistoryAction for FakeScriptHistory {
		fn name(&self) -> &'static str {
			self.name
		}

		async fn script_history(
			&self, _req: WireSyncRequest,
		) -> ActionResult<Anchored<bdk_wallet::Update>> {
			self.calls.fetch_add(1, Ordering::SeqCst);
			Ok(Anchored { value: bdk_wallet::Update::default(), tip: self.tip })
		}
	}

	/// An engine that syncs nothing and only answers the questions the
	/// BROADCAST tail, the hybrid tails and the serving path ask it.
	struct FakeEngine {
		wallet: Arc<Wallet>,
		tracks_own_broadcasts: bool,
		serves_mempool: bool,
		serves_peers: bool,
		/// The blocks this engine can place on its chain, and whether they are
		/// on it. A block not listed is one it cannot tell about.
		known_blocks: HashMap<BlockId, bool>,
	}

	#[async_trait]
	impl SyncEngine for FakeEngine {
		fn name(&self) -> &'static str {
			"fake"
		}

		fn tracks_own_broadcasts(&self) -> bool {
			self.tracks_own_broadcasts
		}

		fn onchain_wallet(&self) -> Option<&Arc<Wallet>> {
			Some(&self.wallet)
		}

		fn serves_mempool(&self) -> bool {
			self.serves_mempool
		}

		fn serves_peers(&self) -> bool {
			self.serves_peers
		}

		async fn is_on_chain(&self, block: &BlockId) -> Option<bool> {
			self.known_blocks.get(block).copied()
		}

		async fn sync_once(
			&self, _layer: &ChainLayer, _channel_manager: Arc<ChannelManager>,
			_chain_monitor: Arc<ChainMonitor>, _output_sweeper: Arc<Sweeper>,
		) -> Result<(), Error> {
			Ok(())
		}

		async fn run_background(
			&self, _layer: Arc<ChainLayer>, _stop_sync_receiver: tokio::sync::watch::Receiver<()>,
			_channel_manager: Arc<ChannelManager>, _chain_monitor: Arc<ChainMonitor>,
			_output_sweeper: Arc<Sweeper>,
		) {
		}
	}

	struct Harness {
		layer: ChainLayer,
		wallet: Arc<Wallet>,
		broadcaster: Arc<Broadcaster>,
	}

	/// Which fakes fill which slots, and what the fake engine answers.
	struct HarnessSpec {
		broadcast: Vec<Arc<dyn BroadcastAction>>,
		mempool: Vec<Arc<dyn MempoolAction>>,
		#[cfg(feature = "swaps")]
		tx_status: Vec<Arc<dyn TxStatusAction>>,
		script_history: Vec<Arc<dyn ScriptHistoryAction>>,
		tracks_own_broadcasts: bool,
		serves_mempool: bool,
		/// Defaults to serving, so a test of a serve path's own rules runs
		/// against a node that may serve at all.
		serves_peers: bool,
		known_blocks: HashMap<BlockId, bool>,
		/// An existing wallet to build over, so a test can fund a wallet
		/// once and then run different chains against it.
		wallet: Option<Arc<Wallet>>,
	}

	impl Default for HarnessSpec {
		fn default() -> Self {
			Self {
				broadcast: Vec::new(),
				mempool: Vec::new(),
				#[cfg(feature = "swaps")]
				tx_status: Vec::new(),
				script_history: Vec::new(),
				tracks_own_broadcasts: false,
				serves_mempool: false,
				serves_peers: true,
				known_blocks: HashMap::new(),
				wallet: None,
			}
		}
	}

	fn fresh_wallet(
		kv_store: &Arc<DynStore>, broadcaster: &Arc<Broadcaster>,
		fee_estimator: &Arc<OnchainFeeEstimator>, logger: &Arc<Logger>,
	) -> Arc<Wallet> {
		fresh_regtest_wallet(kv_store, broadcaster, fee_estimator, logger)
	}

	fn build(spec: HarnessSpec) -> Harness {
		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());

		let wallet = spec
			.wallet
			.unwrap_or_else(|| fresh_wallet(&kv_store, &broadcaster, &fee_estimator, &logger));

		let engine = Arc::new(FakeEngine {
			wallet: Arc::clone(&wallet),
			tracks_own_broadcasts: spec.tracks_own_broadcasts,
			serves_mempool: spec.serves_mempool,
			serves_peers: spec.serves_peers,
			known_blocks: spec.known_blocks,
		});
		let slots = ChainSlots {
			fee: ActionChain::new("fee", FEE_BUDGET, Vec::new(), Arc::clone(&logger)),
			#[cfg(feature = "swaps")]
			tx_status: ActionChain::new(
				"tx_status",
				TX_STATUS_BUDGET,
				spec.tx_status,
				Arc::clone(&logger),
			),
			broadcast: ActionChain::new(
				"broadcast",
				BROADCAST_BUDGET,
				spec.broadcast,
				Arc::clone(&logger),
			),
			mempool: ActionChain::new("mempool", MEMPOOL_BUDGET, spec.mempool, Arc::clone(&logger)),
			script_history: ActionChain::new(
				"script_history",
				SCRIPT_HISTORY_BUDGET,
				spec.script_history,
				Arc::clone(&logger),
			),
			utxo: None,
		};
		let layer = ChainLayer::new(
			slots,
			engine,
			fee_estimator,
			Arc::clone(&broadcaster),
			kv_store,
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		);

		Harness { layer, wallet, broadcaster }
	}

	fn as_broadcast(adapters: &[Arc<FakeBroadcast>]) -> Vec<Arc<dyn BroadcastAction>> {
		adapters.iter().map(|a| Arc::clone(a) as Arc<dyn BroadcastAction>).collect()
	}

	fn as_mempool(adapters: &[Arc<FakeMempool>]) -> Vec<Arc<dyn MempoolAction>> {
		adapters.iter().map(|a| Arc::clone(a) as Arc<dyn MempoolAction>).collect()
	}

	fn harness(adapters: &[Arc<FakeBroadcast>], tracks_own_broadcasts: bool) -> Harness {
		build(HarnessSpec {
			broadcast: as_broadcast(adapters),
			tracks_own_broadcasts,
			..HarnessSpec::default()
		})
	}

	/// A harness over an existing wallet, so a test can fund a wallet once and
	/// then run different chains against it.
	fn harness_with_wallet(
		adapters: &[Arc<FakeBroadcast>], tracks_own_broadcasts: bool, wallet: Arc<Wallet>,
	) -> Harness {
		build(HarnessSpec {
			broadcast: as_broadcast(adapters),
			tracks_own_broadcasts,
			wallet: Some(wallet),
			..HarnessSpec::default()
		})
	}

	fn mempool_harness(adapters: &[Arc<FakeMempool>], serves_mempool: bool) -> Harness {
		build(HarnessSpec {
			mempool: as_mempool(adapters),
			serves_mempool,
			..HarnessSpec::default()
		})
	}

	fn someone_elses_script() -> ScriptBuf {
		ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&[0x42u8; 33]))
	}

	fn tx_paying(previous_output: OutPoint, value: u64, script_pubkey: ScriptBuf) -> Transaction {
		Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(value), script_pubkey }],
		}
	}

	/// A deposit into the wallet, spending an outpoint nobody checks.
	fn deposit(wallet: &Wallet, seed: u8) -> Transaction {
		let address = wallet.get_new_address().expect("an address");
		tx_paying(
			OutPoint { txid: Txid::from_byte_array([seed; 32]), vout: 0 },
			FUNDING_SATS,
			address.script_pubkey(),
		)
	}

	/// Spends `deposit` whole to a foreign script — no change, so the wallet's
	/// total drops to nothing while the spend is canonical. Unsigned: BDK does
	/// not check signatures when told a transaction is unconfirmed.
	fn spend_of(deposit: &Transaction) -> Transaction {
		tx_paying(
			OutPoint { txid: deposit.compute_txid(), vout: 0 },
			FUNDING_SATS - 1_000,
			someone_elses_script(),
		)
	}

	/// A transaction the wallet has no stake in.
	fn unrelated(seed: u8) -> Transaction {
		tx_paying(
			OutPoint { txid: Txid::from_byte_array([seed; 32]), vout: 1 },
			5_000,
			someone_elses_script(),
		)
	}

	fn unconfirmed(wallet: &Wallet, txs: &[&Transaction]) {
		wallet
			.apply_mempool_txs(txs.iter().map(|tx| ((*tx).clone(), 1)).collect(), Vec::new())
			.expect("applying unconfirmed transactions");
	}

	fn unconfirmed_txids(wallet: &Wallet) -> Vec<Txid> {
		let mut txids = wallet.get_unconfirmed_txids();
		txids.sort();
		txids
	}

	fn total_sats(wallet: &Wallet) -> u64 {
		wallet.get_balances(0).expect("balances").0
	}

	#[tokio::test]
	async fn all_unready_abandons_pass_leaving_queue_intact() {
		let first = FakeBroadcast::new("first", Behaviour::NotReady);
		let second = FakeBroadcast::new("second", Behaviour::NotReady);
		let h = harness(&[Arc::clone(&first), Arc::clone(&second)], false);
		let tx = unrelated(1);
		h.broadcaster.broadcast_transactions(&[&tx]);

		h.layer.process_broadcast_queue().await;

		assert_eq!(first.calls(), 0);
		assert_eq!(second.calls(), 0, "nothing is asked to send when nobody is ready");
		let queued = h.broadcaster.get_broadcast_queue().await.try_recv();
		assert_eq!(queued, Ok(vec![tx.clone()]), "the package waits for the next tick");

		// One ready adapter is enough for the pass to run, and it runs the
		// chain — the unready adapter is skipped, not asked.
		let ready = FakeBroadcast::new("ready", Behaviour::Ok);
		let h = harness(&[Arc::clone(&first), Arc::clone(&ready)], false);
		h.broadcaster.broadcast_transactions(&[&tx]);

		let drained =
			tokio::time::timeout(Duration::from_millis(200), h.layer.process_broadcast_queue())
				.await;

		assert!(
			drained.is_err(),
			"the drain keeps waiting for more packages once the queue is empty"
		);
		assert_eq!(first.calls(), 0, "an unready adapter is `Unavailable` without a round trip");
		assert_eq!(ready.calls(), 1);
		assert!(h.broadcaster.get_broadcast_queue().await.try_recv().is_err(), "queue drained");
	}

	#[tokio::test]
	async fn rejected_package_evicts_listed_txids_only() {
		let h = harness(&[], false);
		let deposit_a = deposit(&h.wallet, 1);
		let deposit_b = deposit(&h.wallet, 2);
		let spend_a = spend_of(&deposit_a);
		let spend_b = spend_of(&deposit_b);
		unconfirmed(&h.wallet, &[&deposit_a, &deposit_b, &spend_a, &spend_b]);
		assert_eq!(
			total_sats(&h.wallet),
			0,
			"both deposits are spent while the spends are canonical"
		);

		let verdict =
			FakeBroadcast::new("verdict", Behaviour::Reject(vec![spend_a.compute_txid()]));
		let h = harness_with_wallet(&[verdict], false, h.wallet);

		h.layer.broadcast_package(vec![spend_a.clone(), spend_b.clone(), unrelated(3)]).await;

		let mut expected =
			vec![deposit_a.compute_txid(), deposit_b.compute_txid(), spend_b.compute_txid()];
		expected.sort();
		assert_eq!(unconfirmed_txids(&h.wallet), expected, "only the rejected spend is evicted");
		assert_eq!(
			total_sats(&h.wallet),
			FUNDING_SATS,
			"the rejected spend's input is offered again; the accepted spend's is not"
		);
	}

	#[tokio::test]
	async fn own_package_echo_only_when_engine_tracks_own_broadcasts() {
		// An engine with a mempool view: the wallet is left to learn of its
		// own transactions from the mempool, as pre-seam.
		let adapter = FakeBroadcast::new("ok", Behaviour::Ok);
		let h = harness(&[Arc::clone(&adapter)], false);
		let deposit_tx = deposit(&h.wallet, 1);
		unconfirmed(&h.wallet, &[&deposit_tx]);
		let spend = spend_of(&deposit_tx);

		h.layer.broadcast_package(vec![spend.clone()]).await;

		assert_eq!(adapter.calls(), 1);
		assert_eq!(unconfirmed_txids(&h.wallet), vec![deposit_tx.compute_txid()]);
		assert_eq!(total_sats(&h.wallet), FUNDING_SATS, "the wallet was not told about the spend");

		// An engine with no mempool view: the tail is the only way the wallet
		// hears that the deposit is spent.
		let h = harness(&[Arc::clone(&adapter)], true);
		let deposit_tx = deposit(&h.wallet, 1);
		unconfirmed(&h.wallet, &[&deposit_tx]);
		let spend = spend_of(&deposit_tx);

		h.layer.broadcast_package(vec![spend.clone()]).await;

		let mut expected = vec![deposit_tx.compute_txid(), spend.compute_txid()];
		expected.sort();
		assert_eq!(unconfirmed_txids(&h.wallet), expected, "the spend is applied as unconfirmed");
		assert_eq!(total_sats(&h.wallet), 0, "and its input is no longer offered");

		// With a rejection, an engine that tracks its own broadcasts still
		// echoes the transactions that were NOT listed: they were accepted.
		let deposit_a = deposit(&h.wallet, 2);
		let deposit_b = deposit(&h.wallet, 3);
		unconfirmed(&h.wallet, &[&deposit_a, &deposit_b]);
		let spend_a = spend_of(&deposit_a);
		let spend_b = spend_of(&deposit_b);
		let verdict =
			FakeBroadcast::new("verdict", Behaviour::Reject(vec![spend_a.compute_txid()]));
		let h = harness_with_wallet(&[verdict], true, h.wallet);

		h.layer.broadcast_package(vec![spend_a.clone(), spend_b.clone()]).await;

		let txids = unconfirmed_txids(&h.wallet);
		assert!(txids.contains(&spend_b.compute_txid()), "the accepted spend is echoed");
		assert!(!txids.contains(&spend_a.compute_txid()), "the rejected spend is not");
		assert_eq!(total_sats(&h.wallet), FUNDING_SATS, "exactly one deposit is spendable again");
	}

	/// N3: a package one adapter half-sent before the chain ran out is not
	/// un-sent by the exhaustion. The engine that tracks its own broadcasts
	/// is told about the transactions that did reach the network — and only
	/// those — while an engine with a mempool view is left alone as ever.
	#[tokio::test]
	async fn exhausted_chain_still_echoes_the_accepted_subset() {
		let h = harness(&[], true);
		let deposit_a = deposit(&h.wallet, 1);
		let deposit_b = deposit(&h.wallet, 2);
		unconfirmed(&h.wallet, &[&deposit_a, &deposit_b]);
		let spend_a = spend_of(&deposit_a);
		let spend_b = spend_of(&deposit_b);

		// The first adapter takes spend_a and then goes away; the second is
		// down. The package is `Unavailable` and the chain exhausted.
		let flaky =
			FakeBroadcast::new("flaky", Behaviour::AcceptOnly(vec![spend_a.compute_txid()]));
		let down = FakeBroadcast::new("down", Behaviour::Unavailable);
		let h = harness_with_wallet(&[Arc::clone(&flaky), Arc::clone(&down)], true, h.wallet);

		h.layer.broadcast_package(vec![spend_a.clone(), spend_b.clone()]).await;

		assert_eq!(flaky.calls(), 1);
		assert_eq!(down.calls(), 1, "the chain went on after the half-sent package");
		let txids = unconfirmed_txids(&h.wallet);
		assert!(txids.contains(&spend_a.compute_txid()), "the accepted spend is echoed");
		assert!(!txids.contains(&spend_b.compute_txid()), "the unsent spend is not");
		assert_eq!(
			total_sats(&h.wallet),
			FUNDING_SATS,
			"deposit_a is spent as far as the wallet knows; deposit_b is offered again"
		);

		// An engine with a mempool view learns of its transactions from the
		// mempool, half-sent or not.
		let h = harness(&[], false);
		let deposit_tx = deposit(&h.wallet, 3);
		unconfirmed(&h.wallet, &[&deposit_tx]);
		let spend = spend_of(&deposit_tx);
		let flaky = FakeBroadcast::new("flaky", Behaviour::AcceptOnly(vec![spend.compute_txid()]));
		let h = harness_with_wallet(&[flaky], false, h.wallet);

		h.layer.broadcast_package(vec![spend.clone(), unrelated(4)]).await;

		assert_eq!(unconfirmed_txids(&h.wallet), vec![deposit_tx.compute_txid()]);
		assert_eq!(total_sats(&h.wallet), FUNDING_SATS, "the wallet was not told about the spend");
	}

	#[tokio::test]
	async fn serve_broadcast_rejected_is_err() {
		let tx = unrelated(1);

		let verdict = FakeBroadcast::new("verdict", Behaviour::Reject(vec![tx.compute_txid()]));
		let h = harness(&[verdict], true);
		assert!(matches!(h.layer.serve_broadcast(&tx).await, Err(Error::ChainServeFailed)));

		let down = FakeBroadcast::new("down", Behaviour::Unavailable);
		let h = harness(&[down], true);
		assert!(matches!(h.layer.serve_broadcast(&tx).await, Err(Error::ChainServeFailed)));

		let not_ready = FakeBroadcast::new("not-ready", Behaviour::NotReady);
		let h = harness(&[not_ready], true);
		assert!(matches!(h.layer.serve_broadcast(&tx).await, Err(Error::ChainServeFailed)));

		let ok = FakeBroadcast::new("ok", Behaviour::Ok);
		let h = harness(&[ok], true);
		assert!(h.layer.serve_broadcast(&tx).await.is_ok());
		assert!(
			unconfirmed_txids(&h.wallet).is_empty(),
			"another node's transaction is not this node's own: the tail does not run"
		);
	}

	/// N4: the MEMPOOL chain hands an answer back as its adapter produced it —
	/// anchored to the adapter's tip, tagged with the adapter — and an empty
	/// chain is `Unavailable`, which is what every engine with one relies on
	/// by never asking.
	#[tokio::test]
	async fn mempool_answer_comes_through_the_chain_anchored_and_attributed() {
		let tip = BlockId { height: 7, hash: BlockHash::from_byte_array([7u8; 32]) };
		let tx = unrelated(1);
		let fake = FakeMempool::new(
			"fake",
			MempoolBehaviour::Answer { unconfirmed: vec![tx.clone()], tip: Some(tip) },
		);
		let h = mempool_harness(&[Arc::clone(&fake)], true);
		let known = Txid::from_byte_array([3u8; 32]);
		let query = MempoolQuery {
			scripts: vec![someone_elses_script()],
			known_unconfirmed: vec![known],
			scope: MempoolScope::Incremental { best_processed_height: 6 },
		};

		let answered = h.layer.mempool(&query).await.unwrap();

		assert_eq!(answered.by, "fake");
		assert_eq!(answered.value.tip, Some(tip));
		assert_eq!(answered.value.value.unconfirmed, vec![(tx, 1)]);
		assert_eq!(answered.value.value.evicted, vec![(known, 2)]);
		assert_eq!(fake.queries(), vec![query.clone()], "the query reaches the adapter as asked");

		let h = mempool_harness(&[], true);
		let err = h.layer.mempool(&query).await.unwrap_err();
		assert!(matches!(err, ChainActionError::Unavailable { timed_out: false, .. }), "{}", err);
	}

	/// N4: serving is refused unless this node observes a mempool itself —
	/// never forwarded — and fails, rather than answering, when the chain
	/// cannot answer or has no tip to anchor at. A served question is asked
	/// in `Complete` scope, so it never advances the poll loop's memory.
	#[tokio::test]
	async fn serve_mempool_refuses_without_local_mempool() {
		let tip = BlockId { height: 7, hash: BlockHash::from_byte_array([7u8; 32]) };
		let tx = unrelated(1);
		let known = Txid::from_byte_array([3u8; 32]);
		let req = WireMempoolRequest {
			version: CHAIN_WIRE_VERSION,
			spks: vec![script_to_wire(&someone_elses_script())],
			known_unconfirmed: vec![txid_to_wire(&known)],
		};

		// No adapter at all: a transaction-based engine.
		let h = mempool_harness(&[], false);
		assert!(matches!(h.layer.serve_mempool(&req).await, Err(Error::ChainServeUnsupported)));

		// An adapter, but an engine that does not observe a mempool itself:
		// the Dependent shape, whose adapter would forward.
		let forwarding = FakeMempool::new(
			"forwarding",
			MempoolBehaviour::Answer { unconfirmed: vec![tx.clone()], tip: Some(tip) },
		);
		let h = mempool_harness(&[Arc::clone(&forwarding)], false);
		assert!(matches!(h.layer.serve_mempool(&req).await, Err(Error::ChainServeUnsupported)));
		assert!(forwarding.queries().is_empty(), "a refused question is never asked");

		// A local mempool that cannot answer: an error, never an empty answer.
		let down = FakeMempool::new("down", MempoolBehaviour::Unavailable);
		let h = mempool_harness(&[down], true);
		assert!(matches!(h.layer.serve_mempool(&req).await, Err(Error::ChainServeFailed)));

		// A local mempool read before the engine has synced to any tip.
		let untipped = FakeMempool::new(
			"untipped",
			MempoolBehaviour::Answer { unconfirmed: vec![tx.clone()], tip: None },
		);
		let h = mempool_harness(&[untipped], true);
		assert!(matches!(h.layer.serve_mempool(&req).await, Err(Error::ChainServeFailed)));

		// A malformed request is failed, not answered.
		let local = FakeMempool::new(
			"local",
			MempoolBehaviour::Answer { unconfirmed: vec![tx.clone()], tip: Some(tip) },
		);
		let h = mempool_harness(&[Arc::clone(&local)], true);
		let mut stale = req.clone();
		stale.version += 1;
		assert!(matches!(h.layer.serve_mempool(&stale).await, Err(Error::ChainServeFailed)));
		assert!(local.queries().is_empty());

		// The one shape that serves.
		let resp = h.layer.serve_mempool(&req).await.unwrap();
		assert_eq!(resp.version, CHAIN_WIRE_VERSION);
		assert_eq!(resp.tip.height, 7);
		assert_eq!(resp.tip.hash, tip.hash.to_string());
		assert_eq!(resp.unconfirmed.len(), 1);
		assert_eq!(resp.unconfirmed[0].tx_hex, tx_to_wire(&tx));
		assert_eq!(resp.unconfirmed[0].seen_at, 1);
		assert_eq!(resp.evicted, vec![txid_to_wire(&known)]);

		let asked = local.queries();
		assert_eq!(asked.len(), 1);
		assert_eq!(asked[0].scope, MempoolScope::Complete);
		assert_eq!(asked[0].scripts, vec![someone_elses_script()]);
		assert_eq!(asked[0].known_unconfirmed, vec![known]);
	}

	/// A question of more scripts and txids together than
	/// `MAX_MEMPOOL_QUERY_ITEMS` is refused before the adapter is asked;
	/// one exactly at the bound is answered in full.
	#[tokio::test]
	async fn serve_mempool_refuses_a_question_above_the_bound() {
		let tip = BlockId { height: 7, hash: BlockHash::from_byte_array([7u8; 32]) };
		let local = FakeMempool::new(
			"local",
			MempoolBehaviour::Answer { unconfirmed: Vec::new(), tip: Some(tip) },
		);
		let h = mempool_harness(&[Arc::clone(&local)], true);
		let known = txid_to_wire(&Txid::from_byte_array([3u8; 32]));
		let spk = script_to_wire(&someone_elses_script());

		// Exactly the bound: MAX - 1 scripts and one txid.
		let at_bound = WireMempoolRequest {
			version: CHAIN_WIRE_VERSION,
			spks: vec![spk.clone(); MAX_MEMPOOL_QUERY_ITEMS - 1],
			known_unconfirmed: vec![known.clone()],
		};
		let resp = h.layer.serve_mempool(&at_bound).await.unwrap();
		assert_eq!(resp.evicted, vec![known.clone()]);
		let asked = local.queries();
		assert_eq!(asked.len(), 1);
		assert_eq!(asked[0].scripts.len(), MAX_MEMPOOL_QUERY_ITEMS - 1);
		assert_eq!(asked[0].known_unconfirmed.len(), 1);

		// One txid over, and the adapter is not asked.
		let mut over_by_a_txid = at_bound.clone();
		over_by_a_txid.known_unconfirmed.push(known);
		assert!(matches!(
			h.layer.serve_mempool(&over_by_a_txid).await,
			Err(Error::ChainServeFailed)
		));
		assert_eq!(local.queries().len(), 1, "refused before the adapter is asked");

		// Scripts alone can exceed it too.
		let over_by_scripts = WireMempoolRequest {
			version: CHAIN_WIRE_VERSION,
			spks: vec![spk; MAX_MEMPOOL_QUERY_ITEMS + 1],
			known_unconfirmed: Vec::new(),
		};
		assert!(matches!(
			h.layer.serve_mempool(&over_by_scripts).await,
			Err(Error::ChainServeFailed)
		));
		assert_eq!(local.queries().len(), 1);
	}

	/// A provider that answers nothing, for a preset whose shape — not whose
	/// answers — is under test.
	struct SilentProvider;

	#[async_trait]
	impl ChainDataProvider for SilentProvider {
		fn name(&self) -> String {
			"silent".into()
		}

		async fn fee_estimates(
			&self,
		) -> Result<WireFeeEstimates, crate::chain::provider::ChainProviderError> {
			Err(crate::chain::provider::ChainProviderError::Unreachable("silent".into()))
		}

		async fn broadcast(
			&self, _req: crate::chain::provider::WireBroadcastRequest,
		) -> Result<(), crate::chain::provider::ChainProviderError> {
			Err(crate::chain::provider::ChainProviderError::Unreachable("silent".into()))
		}

		async fn tx_status(
			&self, _req: crate::chain::provider::WireTxStatusRequest,
		) -> Result<
			crate::chain::provider::WireTxStatusResponse,
			crate::chain::provider::ChainProviderError,
		> {
			Err(crate::chain::provider::ChainProviderError::Unreachable("silent".into()))
		}

		async fn wallet_sync(
			&self, _req: WireSyncRequest,
		) -> Result<WireUpdate, crate::chain::provider::ChainProviderError> {
			Err(crate::chain::provider::ChainProviderError::Unreachable("silent".into()))
		}

		async fn lightning_sync(
			&self, _req: WireLightningSyncRequest,
		) -> Result<WireLightningSyncResponse, crate::chain::provider::ChainProviderError> {
			Err(crate::chain::provider::ChainProviderError::Unreachable("silent".into()))
		}
	}

	/// Builds the CBF preset over a fresh regtest wallet. Nothing connects:
	/// the engine parses its peers and resolves the birthday, the external
	/// Electrum status waits for `start`, and the provider is silent.
	#[cfg(feature = "cbf")]
	fn cbf_layer(
		peers: Vec<String>, cbf_config: CbfConfig, fallback: Option<Arc<dyn ChainDataProvider>>,
	) -> Result<ChainLayer, Error> {
		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		let config = Arc::new(Config { network: Network::Regtest, ..Config::default() });
		ChainLayer::new_cbf(
			peers,
			cbf_config,
			fallback,
			wallet,
			fee_estimator,
			broadcaster,
			kv_store,
			config,
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		)
	}

	/// The hybrid CBF preset: the operator's external fee server first, then
	/// in every slot the filter node can fill its own adapter ahead of the
	/// provider — coinbase-derived rates, the P2P relay, what this node saw
	/// confirm — and the slots a filter node cannot fill left to the provider.
	#[cfg(feature = "cbf")]
	#[test]
	fn new_cbf_puts_its_own_adapters_ahead_of_the_provider() {
		let cbf_config = CbfConfig {
			external_fee: Some(CbfExternalFee::Electrum("tcp://127.0.0.1:1".into())),
			..CbfConfig::default()
		};
		let layer = cbf_layer(
			vec!["127.0.0.1:18444".into(), "bitcoind.local:18444".into()],
			cbf_config,
			Some(Arc::new(SilentProvider)),
		)
		.expect("a well-formed preset");

		let slots = layer.slot_adapters();
		assert_eq!(slots.engine, "cbf");
		assert_eq!(slots.fee, vec!["electrum", "cbf_derived", "dependent"]);
		assert_eq!(slots.broadcast, vec!["cbf_p2p", "dependent"]);
		#[cfg(feature = "swaps")]
		assert_eq!(slots.tx_status, vec!["cbf_watch", "dependent"]);
		assert_eq!(slots.mempool, vec!["dependent"]);
		assert_eq!(slots.script_history, vec!["dependent"]);
		assert!(slots.utxo.is_none(), "announcements go unverified unless asked for");
		assert!(layer.has_mempool_chain());
		assert!(layer.engine.tracks_own_broadcasts(), "the tail must echo own broadcasts");
		assert!(!layer.engine.serves_mempool(), "a borrowed mempool is never served on");
	}

	/// A pure CBF node: what the filters and the node's own peers give, and
	/// nothing else — the borrowed slots stay empty, the UTXO source appears
	/// only when opted into, and a mistyped peer is a construction error
	/// rather than a dropped entry.
	#[cfg(feature = "cbf")]
	#[test]
	fn new_cbf_without_a_provider_runs_on_the_cbf_adapters_alone() {
		let layer =
			cbf_layer(Vec::new(), CbfConfig::default(), None).expect("a well-formed preset");
		let slots = layer.slot_adapters();
		assert_eq!(slots.fee, vec!["cbf_derived"]);
		assert_eq!(slots.broadcast, vec!["cbf_p2p"]);
		#[cfg(feature = "swaps")]
		assert_eq!(slots.tx_status, vec!["cbf_watch"]);
		assert!(slots.mempool.is_empty());
		assert!(slots.script_history.is_empty());
		assert!(slots.utxo.is_none());
		assert!(!layer.has_mempool_chain());

		let opted_in = CbfConfig { utxo_source: true, ..CbfConfig::default() };
		let layer = cbf_layer(Vec::new(), opted_in, None).expect("a well-formed preset");
		assert_eq!(layer.slot_adapters().utxo, Some(("cbf", UtxoVerification::ExistenceOnly)));
		assert!(layer.as_utxo_source().is_some(), "the gossip verifier gets a source");

		let err = cbf_layer(vec!["no-port-here".into()], CbfConfig::default(), None)
			.err()
			.expect("a peer without a port is refused");
		assert_eq!(err, Error::InvalidSocketAddress);
	}

	/// The Electrum preset fills MEMPOOL with its own server and says it may
	/// be served from, so a filter-following node can borrow the view. Its
	/// engine never runs the chain itself, and serving before the chain
	/// source is started is a failure, never an empty answer.
	#[tokio::test]
	async fn new_electrum_serves_its_own_mempool() {
		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		let config = Arc::new(Config { network: Network::Regtest, ..Config::default() });
		let layer = ChainLayer::new_electrum(
			"tcp://127.0.0.1:1".into(),
			ElectrumSyncConfig::default(),
			wallet,
			fee_estimator,
			broadcaster,
			kv_store,
			config,
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		);

		let slots = layer.slot_adapters();
		assert_eq!(slots.engine, "electrum-tx-sync");
		assert_eq!(slots.mempool, vec!["electrum"]);
		assert!(layer.engine.serves_mempool());
		assert!(!layer.engine.tracks_own_broadcasts(), "its sync sees its own transactions");

		let req = WireMempoolRequest {
			version: CHAIN_WIRE_VERSION,
			spks: vec![script_to_wire(&someone_elses_script())],
			known_unconfirmed: Vec::new(),
		};
		assert!(matches!(layer.serve_mempool(&req).await, Err(Error::ChainServeFailed)));
	}

	/// The fixtures every preset is built over. Nothing connects at
	/// construction: the Esplora and bitcoind clients are plain HTTP clients,
	/// the Electrum status waits for `start`, and the provider is silent.
	struct PresetFixture {
		wallet: Arc<Wallet>,
		fee_estimator: Arc<OnchainFeeEstimator>,
		broadcaster: Arc<Broadcaster>,
		kv_store: Arc<DynStore>,
		config: Arc<Config>,
		logger: Arc<Logger>,
	}

	fn preset_fixture() -> PresetFixture {
		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		let config = Arc::new(Config { network: Network::Regtest, ..Config::default() });
		PresetFixture { wallet, fee_estimator, broadcaster, kv_store, config, logger }
	}

	fn metrics() -> Arc<RwLock<NodeMetrics>> {
		Arc::new(RwLock::new(NodeMetrics::default()))
	}

	fn esplora_preset() -> ChainLayer {
		let f = preset_fixture();
		ChainLayer::new_esplora(
			"http://127.0.0.1:1".into(),
			EsploraSyncConfig::default(),
			f.wallet,
			f.fee_estimator,
			f.broadcaster,
			f.kv_store,
			f.config,
			f.logger,
			metrics(),
		)
	}

	fn electrum_preset() -> ChainLayer {
		let f = preset_fixture();
		ChainLayer::new_electrum(
			"tcp://127.0.0.1:1".into(),
			ElectrumSyncConfig::default(),
			f.wallet,
			f.fee_estimator,
			f.broadcaster,
			f.kv_store,
			f.config,
			f.logger,
			metrics(),
		)
	}

	fn bitcoind_rpc_preset() -> ChainLayer {
		let f = preset_fixture();
		ChainLayer::new_bitcoind_rpc(
			"127.0.0.1".into(),
			1,
			"user".into(),
			"password".into(),
			f.wallet,
			f.fee_estimator,
			f.broadcaster,
			f.kv_store,
			f.config,
			f.logger,
			metrics(),
		)
	}

	fn bitcoind_rest_preset() -> ChainLayer {
		let f = preset_fixture();
		ChainLayer::new_bitcoind_rest(
			"127.0.0.1".into(),
			1,
			"user".into(),
			"password".into(),
			f.wallet,
			f.fee_estimator,
			f.broadcaster,
			f.kv_store,
			f.config,
			BitcoindRestClientConfig { rest_host: "127.0.0.1".into(), rest_port: 2 },
			f.logger,
			metrics(),
		)
	}

	fn dependent_preset() -> ChainLayer {
		let f = preset_fixture();
		ChainLayer::new_dependent(
			Arc::new(SilentProvider),
			EsploraSyncConfig::default(),
			f.wallet,
			f.fee_estimator,
			f.broadcaster,
			f.kv_store,
			f.logger,
			metrics(),
		)
	}

	/// T9: the four presets that predate the CBF one keep their slot layout,
	/// and the public status reports the same layout the startup log prints.
	/// Each of them scans a chain source of its own and may serve peers —
	/// except the Dependent tier, whose every slot is its provider's.
	#[test]
	fn the_four_old_presets_are_unchanged() {
		let esplora = esplora_preset();
		let slots = esplora.slot_adapters();
		assert_eq!(slots.engine, "esplora-tx-sync");
		assert_eq!(slots.fee, vec!["esplora"]);
		assert_eq!(slots.broadcast, vec!["esplora"]);
		#[cfg(feature = "swaps")]
		assert_eq!(slots.tx_status, vec!["esplora"]);
		assert!(slots.mempool.is_empty(), "its sync carries the mempool itself");
		assert!(slots.script_history.is_empty());
		assert!(slots.utxo.is_none());
		assert!(!esplora.engine.serves_mempool());

		let electrum = electrum_preset();
		let slots = electrum.slot_adapters();
		assert_eq!(slots.engine, "electrum-tx-sync");
		assert_eq!(slots.fee, vec!["electrum"]);
		assert_eq!(slots.broadcast, vec!["electrum"]);
		#[cfg(feature = "swaps")]
		assert_eq!(slots.tx_status, vec!["electrum"]);
		assert_eq!(slots.mempool, vec!["electrum"], "filled to serve, never run for itself");
		assert!(slots.script_history.is_empty());
		assert!(slots.utxo.is_none());
		assert!(electrum.engine.serves_mempool());

		for bitcoind in [bitcoind_rpc_preset(), bitcoind_rest_preset()] {
			let slots = bitcoind.slot_adapters();
			assert_eq!(slots.engine, "bitcoind-block-poll");
			assert_eq!(slots.fee, vec!["bitcoind"]);
			assert_eq!(slots.broadcast, vec!["bitcoind"]);
			#[cfg(feature = "swaps")]
			assert_eq!(slots.tx_status, vec!["bitcoind"]);
			assert_eq!(slots.mempool, vec!["bitcoind"]);
			assert!(slots.script_history.is_empty());
			assert_eq!(slots.utxo, Some(("bitcoind", UtxoVerification::Full)));
			assert!(bitcoind.engine.serves_mempool());
		}

		let dependent = dependent_preset();
		let slots = dependent.slot_adapters();
		assert_eq!(slots.engine, "dependent-tx-sync");
		assert_eq!(slots.fee, vec!["dependent"]);
		assert_eq!(slots.broadcast, vec!["dependent"]);
		#[cfg(feature = "swaps")]
		assert_eq!(slots.tx_status, vec!["dependent"]);
		assert!(slots.mempool.is_empty());
		assert!(slots.script_history.is_empty());
		assert!(slots.utxo.is_none());
		assert!(!dependent.engine.serves_mempool(), "every slot is its provider's");

		// The public status says the same, as data, and no CBF status.
		let status = bitcoind_rpc_preset().slot_status();
		assert_eq!(status.engine, "bitcoind-block-poll");
		assert_eq!(status.fee.adapters, vec!["bitcoind".to_string()]);
		assert_eq!(status.fee.last_answered, None, "nothing has been asked yet");
		assert_eq!(status.mempool.adapters, vec!["bitcoind".to_string()]);
		assert!(status.script_history.adapters.is_empty());
		assert_eq!(
			status.utxo,
			Some(ChainUtxoStatus {
				adapter: "bitcoind".into(),
				verification: ChainUtxoVerification::Full
			})
		);
		#[cfg(feature = "swaps")]
		assert_eq!(status.tx_status.adapters, vec!["bitcoind".to_string()]);
		#[cfg(not(feature = "swaps"))]
		assert!(status.tx_status.adapters.is_empty(), "no adapter fills a slot the build lacks");
		assert_eq!(bitcoind_rpc_preset().cbf_sync_status(), None);
		assert_eq!(dependent_preset().cbf_sync_status(), None);
	}

	/// T9: the CBF preset with an external fee server puts it first — in
	/// front of the coinbase-derived rates, which lead the provider when there
	/// is one — and reports a CBF status.
	#[cfg(feature = "cbf")]
	#[test]
	fn new_cbf_puts_an_external_fee_server_first() {
		let esplora_fee = || CbfConfig {
			external_fee: Some(CbfExternalFee::Esplora("http://127.0.0.1:1".into())),
			..CbfConfig::default()
		};

		let hybrid = cbf_layer(Vec::new(), esplora_fee(), Some(Arc::new(SilentProvider)))
			.expect("a well-formed preset");
		let slots = hybrid.slot_adapters();
		assert_eq!(slots.fee, vec!["esplora", "cbf_derived", "dependent"]);
		assert_eq!(slots.broadcast, vec!["cbf_p2p", "dependent"]);
		assert_eq!(slots.mempool, vec!["dependent"]);
		assert_eq!(hybrid.cbf_sync_status(), Some(CbfSyncStatus::Syncing));

		let pure = cbf_layer(Vec::new(), esplora_fee(), None).expect("a well-formed preset");
		assert_eq!(pure.slot_adapters().fee, vec!["esplora", "cbf_derived"]);
		assert_eq!(pure.slot_adapters().broadcast, vec!["cbf_p2p"]);

		let electrum_fee = CbfConfig {
			external_fee: Some(CbfExternalFee::Electrum("tcp://127.0.0.1:1".into())),
			..CbfConfig::default()
		};
		let pure = cbf_layer(Vec::new(), electrum_fee, None).expect("a well-formed preset");
		assert_eq!(pure.slot_adapters().fee, vec!["electrum", "cbf_derived"]);

		// The public status carries the same layout.
		let status = hybrid.slot_status();
		assert_eq!(status.engine, "cbf");
		assert_eq!(
			status.fee.adapters,
			vec!["esplora".to_string(), "cbf_derived".to_string(), "dependent".to_string()]
		);
		assert_eq!(status.broadcast.adapters, vec!["cbf_p2p".to_string(), "dependent".to_string()]);
		assert_eq!(status.script_history.adapters, vec!["dependent".to_string()]);
		assert!(status.utxo.is_none());
	}

	/// The public slot status records which adapter answered last, per slot,
	/// as questions are asked.
	#[tokio::test]
	async fn slot_status_records_the_last_answerer() {
		let tip = BlockId { height: 7, hash: BlockHash::from_byte_array([7u8; 32]) };
		let down = FakeMempool::new("down", MempoolBehaviour::Unavailable);
		let up = FakeMempool::new(
			"up",
			MempoolBehaviour::Answer { unconfirmed: Vec::new(), tip: Some(tip) },
		);
		let h = mempool_harness(&[down, up], true);
		let before = h.layer.slot_status();
		assert_eq!(before.mempool.adapters, vec!["down".to_string(), "up".to_string()]);
		assert_eq!(before.mempool.last_answered, None);

		let query = MempoolQuery {
			scripts: Vec::new(),
			known_unconfirmed: Vec::new(),
			scope: MempoolScope::Complete,
		};
		h.layer.mempool(&query).await.expect("the second adapter answers");

		let after = h.layer.slot_status();
		assert_eq!(after.mempool.last_answered, Some("up".to_string()));
		assert_eq!(after.broadcast.last_answered, None, "an unasked slot has no answerer");
	}

	fn tip_at(height: u32, seed: u8) -> BlockId {
		BlockId { height, hash: BlockHash::from_byte_array([seed; 32]) }
	}

	fn complete_query(known_unconfirmed: Vec<Txid>) -> MempoolQuery {
		MempoolQuery { scripts: Vec::new(), known_unconfirmed, scope: MempoolScope::Complete }
	}

	fn sync_request() -> WireSyncRequest {
		WireSyncRequest {
			version: CHAIN_WIRE_VERSION,
			start_time: 0,
			chain_tip: Vec::new(),
			spks: Vec::new(),
			txids: Vec::new(),
			outpoints: Vec::new(),
			full_scan: false,
			stop_gap: 0,
		}
	}

	/// N6: an answer a provider computed on a chain this node does not
	/// consider best is refused inside the chain's run, so the next adapter
	/// is asked; when it was the only adapter, the chain is exhausted with
	/// the reason on record. For every anchored slot.
	#[tokio::test]
	async fn provider_answer_with_foreign_tip_is_dropped_and_chain_advances() {
		let foreign = tip_at(7, 0xf0);
		let ours = tip_at(7, 0x07);
		let known_blocks: HashMap<BlockId, bool> = [(foreign, false), (ours, true)].into();
		let (theirs, mine) = (unrelated(1), unrelated(2));

		// MEMPOOL: the foreign answer is refused, the second adapter's taken.
		let stale = FakeMempool::new(
			"stale",
			MempoolBehaviour::Answer { unconfirmed: vec![theirs.clone()], tip: Some(foreign) },
		);
		let good = FakeMempool::new(
			"good",
			MempoolBehaviour::Answer { unconfirmed: vec![mine.clone()], tip: Some(ours) },
		);
		let h = build(HarnessSpec {
			mempool: as_mempool(&[Arc::clone(&stale), Arc::clone(&good)]),
			known_blocks: known_blocks.clone(),
			..HarnessSpec::default()
		});
		let answered = h.layer.mempool(&complete_query(Vec::new())).await.unwrap();
		assert_eq!(answered.by, "good");
		assert_eq!(answered.value.tip, Some(ours));
		assert_eq!(answered.value.value.unconfirmed, vec![(mine, 1)]);
		assert_eq!(stale.queries().len(), 1, "the foreign adapter was asked");
		assert_eq!(good.queries().len(), 1, "and the chain advanced past it");

		// Alone, the foreign answer exhausts the chain, and says why.
		let h = build(HarnessSpec {
			mempool: as_mempool(&[Arc::clone(&stale)]),
			known_blocks: known_blocks.clone(),
			..HarnessSpec::default()
		});
		let err = h.layer.mempool(&complete_query(Vec::new())).await.unwrap_err();
		assert!(matches!(err, ChainActionError::Unavailable { timed_out: false, .. }), "{}", err);
		assert!(err.to_string().contains("not on our chain"), "{}", err);

		// SCRIPT_HISTORY: the same rule.
		let stale_scan = FakeScriptHistory::new("stale", Some(foreign));
		let good_scan = FakeScriptHistory::new("good", Some(ours));
		let h = build(HarnessSpec {
			script_history: vec![
				Arc::clone(&stale_scan) as Arc<dyn ScriptHistoryAction>,
				Arc::clone(&good_scan) as Arc<dyn ScriptHistoryAction>,
			],
			known_blocks: known_blocks.clone(),
			..HarnessSpec::default()
		});
		let answered = h.layer.script_history(&sync_request()).await.unwrap();
		assert_eq!(answered.by, "good");
		assert_eq!(answered.value.tip, Some(ours));
		assert_eq!(stale_scan.calls(), 1);
		assert_eq!(good_scan.calls(), 1);

		let h = build(HarnessSpec {
			script_history: vec![Arc::clone(&stale_scan) as Arc<dyn ScriptHistoryAction>],
			known_blocks: known_blocks.clone(),
			..HarnessSpec::default()
		});
		let err = h.layer.script_history(&sync_request()).await.unwrap_err();
		assert!(err.to_string().contains("not on our chain"), "{}", err);

		// TX_STATUS: a confirmation on a branch this node is not on is no
		// confirmation; alone, it fails closed.
		#[cfg(feature = "swaps")]
		{
			let confirmed = RawTxObservation::Confirmed { height: Some(6), confirmations: 2 };
			let stale_status = FakeTxStatus::new("stale", confirmed, Some(foreign));
			let good_status = FakeTxStatus::new("good", RawTxObservation::NotFound, Some(ours));
			let txid = theirs.compute_txid();
			let h = build(HarnessSpec {
				tx_status: vec![
					Arc::clone(&stale_status) as Arc<dyn TxStatusAction>,
					Arc::clone(&good_status) as Arc<dyn TxStatusAction>,
				],
				known_blocks: known_blocks.clone(),
				..HarnessSpec::default()
			});
			assert_eq!(h.layer.swap_query_tx(txid, None).await, RawTxObservation::NotFound);
			assert_eq!(stale_status.calls(), 1);
			assert_eq!(good_status.calls(), 1);

			let h = build(HarnessSpec {
				tx_status: vec![Arc::clone(&stale_status) as Arc<dyn TxStatusAction>],
				known_blocks,
				..HarnessSpec::default()
			});
			assert_eq!(
				h.layer.swap_query_tx(txid, None).await,
				RawTxObservation::Unreachable,
				"an exhausted chain fails closed, never a foreign confirmation"
			);
		}
	}

	/// N6: an answer with no tip carries nothing to check and is accepted,
	/// and so is one anchored to a tip this node cannot place — an engine
	/// with no header chain of its own does not refute what it cannot check.
	#[tokio::test]
	async fn provider_answer_without_tip_is_accepted() {
		let foreign = tip_at(7, 0xf0);
		let tx = unrelated(1);

		// The engine holds every block it knows as NOT on its chain — and
		// still a tipless answer goes through, from the first adapter.
		let untipped = FakeMempool::new(
			"untipped",
			MempoolBehaviour::Answer { unconfirmed: vec![tx.clone()], tip: None },
		);
		let never_asked = FakeMempool::new("never-asked", MempoolBehaviour::Unavailable);
		let h = build(HarnessSpec {
			mempool: as_mempool(&[Arc::clone(&untipped), Arc::clone(&never_asked)]),
			known_blocks: [(foreign, false)].into(),
			..HarnessSpec::default()
		});
		let answered = h.layer.mempool(&complete_query(Vec::new())).await.unwrap();
		assert_eq!(answered.by, "untipped");
		assert_eq!(answered.value.tip, None);
		assert_eq!(answered.value.value.unconfirmed, vec![(tx.clone(), 1)]);
		assert!(never_asked.queries().is_empty());

		// An engine that cannot tell about the tip accepts the answer as it
		// always was, twice over: the once-per-tip log is not a refusal.
		let unplaceable = FakeMempool::new(
			"unplaceable",
			MempoolBehaviour::Answer { unconfirmed: vec![tx.clone()], tip: Some(foreign) },
		);
		let h = build(HarnessSpec {
			mempool: as_mempool(&[Arc::clone(&unplaceable)]),
			known_blocks: HashMap::new(),
			..HarnessSpec::default()
		});
		for _ in 0..2 {
			let answered = h.layer.mempool(&complete_query(Vec::new())).await.unwrap();
			assert_eq!(answered.by, "unplaceable");
			assert_eq!(answered.value.tip, Some(foreign));
		}
		assert_eq!(unplaceable.queries().len(), 2);
		assert_eq!(*h.layer.last_unverifiable_tip.lock().unwrap(), Some(foreign));

		let scan = FakeScriptHistory::new("untipped", None);
		let h = build(HarnessSpec {
			script_history: vec![Arc::clone(&scan) as Arc<dyn ScriptHistoryAction>],
			known_blocks: [(foreign, false)].into(),
			..HarnessSpec::default()
		});
		assert_eq!(h.layer.script_history(&sync_request()).await.unwrap().by, "untipped");

		#[cfg(feature = "swaps")]
		{
			let in_mempool = FakeTxStatus::new("untipped", RawTxObservation::InMempool, None);
			let h = build(HarnessSpec {
				tx_status: vec![Arc::clone(&in_mempool) as Arc<dyn TxStatusAction>],
				known_blocks: [(foreign, false)].into(),
				..HarnessSpec::default()
			});
			let txid = tx.compute_txid();
			assert_eq!(h.layer.swap_query_tx(txid, None).await, RawTxObservation::InMempool);
		}
	}

	/// N6: a borrowed mempool answer that evicts a transaction this node
	/// itself just broadcast is not believed — the borrowed view may simply
	/// not have seen it yet — while every other eviction it reports is
	/// applied. An engine with a mempool of its own applies them all.
	#[tokio::test]
	async fn fresh_own_broadcast_is_not_evicted_by_a_borrowed_mempool_answer() {
		let tip = tip_at(7, 0x07);
		let ok = FakeBroadcast::new("ok", Behaviour::Ok);
		let borrowed = FakeMempool::new(
			"borrowed",
			MempoolBehaviour::Answer { unconfirmed: Vec::new(), tip: Some(tip) },
		);
		let stale = Txid::from_byte_array([9u8; 32]);

		// A filter-following node: the tail told the wallet about the spend,
		// and remembers it left.
		let h = build(HarnessSpec {
			broadcast: as_broadcast(&[Arc::clone(&ok)]),
			mempool: as_mempool(&[Arc::clone(&borrowed)]),
			tracks_own_broadcasts: true,
			known_blocks: [(tip, true)].into(),
			..HarnessSpec::default()
		});
		let deposit_tx = deposit(&h.wallet, 1);
		unconfirmed(&h.wallet, &[&deposit_tx]);
		let spend = spend_of(&deposit_tx);
		h.layer.broadcast_package(vec![spend.clone()]).await;
		assert!(unconfirmed_txids(&h.wallet).contains(&spend.compute_txid()));
		assert_eq!(h.layer.recent_own_broadcasts.lock().unwrap().len(), 1);

		let answered = h
			.layer
			.mempool(&complete_query(vec![spend.compute_txid(), stale]))
			.await
			.expect("the borrowed view answers");
		assert_eq!(
			answered.value.value.evicted,
			vec![(stale, 2)],
			"the fresh own broadcast is shielded; the stale txid is evicted"
		);
		assert_eq!(
			borrowed.queries().len(),
			1,
			"the shield is applied after the chain, not instead of it"
		);

		// An engine with a mempool of its own: the tail records nothing, and
		// its own mempool's eviction is a verdict.
		let h = build(HarnessSpec {
			broadcast: as_broadcast(&[Arc::clone(&ok)]),
			mempool: as_mempool(&[Arc::clone(&borrowed)]),
			tracks_own_broadcasts: false,
			known_blocks: [(tip, true)].into(),
			..HarnessSpec::default()
		});
		let deposit_tx = deposit(&h.wallet, 2);
		unconfirmed(&h.wallet, &[&deposit_tx]);
		let spend = spend_of(&deposit_tx);
		h.layer.broadcast_package(vec![spend.clone()]).await;
		assert_eq!(h.layer.recent_own_broadcasts.lock().unwrap().len(), 0);
		let answered =
			h.layer.mempool(&complete_query(vec![spend.compute_txid(), stale])).await.unwrap();
		assert_eq!(answered.value.value.evicted, vec![(spend.compute_txid(), 2), (stale, 2)]);
	}

	/// The hybrid's borrow: the answer reaches the wallet, stamped on this
	/// node's clock. A provider whose clock runs behind would otherwise have
	/// a transaction that re-entered its mempool stay evicted here, since the
	/// eviction was stamped locally and a sighting must be later to win.
	#[cfg(feature = "cbf")]
	#[tokio::test]
	async fn a_borrowed_mempool_view_reaches_the_wallet_on_this_nodes_clock() {
		let tip = tip_at(7, 0x07);
		let known = Txid::from_byte_array([3u8; 32]);
		let answer =
			MempoolAnswer { unconfirmed: vec![(unrelated(1), 1)], evicted: vec![(known, 2)] };
		assert_eq!(
			stamp_locally(answer, 1_000),
			(vec![(unrelated(1), 1_000)], vec![(known, 1_000)])
		);

		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		let incoming = deposit(&wallet, 1);
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		// Seen, then evicted a minute and a half ago on this node's clock.
		wallet.apply_mempool_txs(vec![(incoming.clone(), now - 120)], Vec::new()).unwrap();
		wallet.apply_mempool_txs(Vec::new(), vec![(incoming.compute_txid(), now - 90)]).unwrap();
		assert!(!unconfirmed_txids(&wallet).contains(&incoming.compute_txid()));

		// The provider sees it again, and stamps it `1` on its own clock.
		let provider = FakeMempool::new(
			"provider",
			MempoolBehaviour::Answer { unconfirmed: vec![incoming.clone()], tip: Some(tip) },
		);
		let h = build(HarnessSpec {
			mempool: as_mempool(&[Arc::clone(&provider)]),
			tracks_own_broadcasts: true,
			known_blocks: [(tip, true)].into(),
			wallet: Some(Arc::clone(&wallet)),
			..HarnessSpec::default()
		});
		let borrowed = h.layer.borrow_mempool(&complete_query(Vec::new())).await.unwrap();
		assert_eq!(borrowed, BorrowedMempool { by: "provider", unconfirmed: 1, evicted: 0 });
		assert!(
			unconfirmed_txids(&wallet).contains(&incoming.compute_txid()),
			"back in the mempool: the sighting is later than the eviction on one clock"
		);

		// No chain to borrow from: unavailable, and the wallet is left alone.
		let h = build(HarnessSpec {
			tracks_own_broadcasts: true,
			wallet: Some(Arc::clone(&wallet)),
			..HarnessSpec::default()
		});
		assert!(h.layer.borrow_mempool(&complete_query(Vec::new())).await.is_err());
	}

	/// The own-broadcast memory forgets by age and caps by count, oldest
	/// first, so a shielded eviction is one that arrived within the grace
	/// period and nothing else.
	#[test]
	fn recent_own_broadcasts_forget_by_age_and_cap_by_count() {
		let mut recent = RecentOwnBroadcasts::default();
		let t0 = Instant::now();
		let (a, b) = (Txid::from_byte_array([1u8; 32]), Txid::from_byte_array([2u8; 32]));

		recent.record(a, t0);
		assert!(recent.is_recent(&a, t0));
		assert!(
			recent.is_recent(&a, t0 + OWN_BROADCAST_EVICTION_GRACE),
			"at the edge, still fresh"
		);
		assert!(!recent.is_recent(&b, t0), "never broadcast");
		assert!(
			!recent.is_recent(&a, t0 + OWN_BROADCAST_EVICTION_GRACE + Duration::from_secs(1)),
			"past the grace period, an absence is a verdict"
		);
		assert_eq!(recent.len(), 0, "and the entry is gone");

		// Past the cap the oldest go first, whatever their age.
		let t1 = t0 + Duration::from_secs(1);
		for i in 0..OWN_BROADCAST_MEMORY_CAP {
			let mut bytes = [0u8; 32];
			bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
			recent.record(Txid::from_byte_array(bytes), t0);
		}
		assert_eq!(recent.len(), OWN_BROADCAST_MEMORY_CAP);
		recent.record(b, t1);
		assert_eq!(recent.len(), OWN_BROADCAST_MEMORY_CAP);
		assert!(recent.is_recent(&b, t1), "the newest survives");
		let survivors = (0..OWN_BROADCAST_MEMORY_CAP)
			.filter(|i| {
				let mut bytes = [0u8; 32];
				bytes[..8].copy_from_slice(&(*i as u64).to_le_bytes());
				recent.is_recent(&Txid::from_byte_array(bytes), t1)
			})
			.count();
		assert_eq!(survivors, OWN_BROADCAST_MEMORY_CAP - 1, "exactly one of the old ones went");
	}

	/// N6: a node whose engine does not serve peers refuses every serve
	/// entry point before any slot is asked — the Dependent tier and the
	/// filter-following node, hybrid or not — while a node over a real chain
	/// source answers.
	#[tokio::test]
	async fn dependent_and_cbf_nodes_refuse_every_serve() {
		let tx = unrelated(1);
		let tip = tip_at(7, 0x07);
		let mempool_req = WireMempoolRequest {
			version: CHAIN_WIRE_VERSION,
			spks: vec![script_to_wire(&someone_elses_script())],
			known_unconfirmed: Vec::new(),
		};
		let lightning_req = WireLightningSyncRequest {
			version: CHAIN_WIRE_VERSION,
			txids: Vec::new(),
			outputs: Vec::new(),
		};

		let ok = FakeBroadcast::new("ok", Behaviour::Ok);
		let local = FakeMempool::new(
			"local",
			MempoolBehaviour::Answer { unconfirmed: vec![tx.clone()], tip: Some(tip) },
		);
		let spec = || HarnessSpec {
			broadcast: as_broadcast(&[Arc::clone(&ok)]),
			mempool: as_mempool(&[Arc::clone(&local)]),
			serves_mempool: true,
			serves_peers: false,
			..HarnessSpec::default()
		};

		let h = build(spec());
		assert!(matches!(h.layer.serve_fee_estimates(), Err(Error::ChainServeUnsupported)));
		assert!(matches!(h.layer.serve_broadcast(&tx).await, Err(Error::ChainServeUnsupported)));
		assert!(matches!(
			h.layer.serve_mempool(&mempool_req).await,
			Err(Error::ChainServeUnsupported)
		));
		assert!(matches!(
			h.layer.serve_wallet_sync(&sync_request()).await,
			Err(Error::ChainServeUnsupported)
		));
		assert!(matches!(
			h.layer.serve_lightning_sync(&lightning_req).await,
			Err(Error::ChainServeUnsupported)
		));
		#[cfg(feature = "swaps")]
		assert!(matches!(
			h.layer.serve_tx_status(tx.compute_txid(), None).await,
			Err(Error::ChainServeUnsupported)
		));
		assert_eq!(ok.calls(), 0, "refused before the BROADCAST chain is asked");
		assert!(local.queries().is_empty(), "refused before the MEMPOOL chain is asked");

		// The same slots on a node that serves: the question reaches them.
		let h = build(HarnessSpec { serves_peers: true, ..spec() });
		assert!(h.layer.serve_fee_estimates().is_ok());
		assert!(h.layer.serve_broadcast(&tx).await.is_ok());
		assert!(h.layer.serve_mempool(&mempool_req).await.is_ok());
		assert_eq!(ok.calls(), 1);
		assert_eq!(local.queries().len(), 1);

		// The real presets: the Dependent tier and the CBF node refuse, the
		// engines over a chain source of their own answer.
		let dependent = dependent_preset();
		assert!(!dependent.engine.serves_peers(), "every slot is its provider's");
		assert!(matches!(dependent.serve_fee_estimates(), Err(Error::ChainServeUnsupported)));
		assert!(matches!(dependent.serve_broadcast(&tx).await, Err(Error::ChainServeUnsupported)));
		assert!(matches!(
			dependent.serve_lightning_sync(&lightning_req).await,
			Err(Error::ChainServeUnsupported)
		));
		for serving in
			[esplora_preset(), electrum_preset(), bitcoind_rpc_preset(), bitcoind_rest_preset()]
		{
			assert!(serving.engine.serves_peers(), "{}", serving.engine.name());
			assert!(serving.serve_fee_estimates().is_ok(), "{}", serving.engine.name());
		}

		#[cfg(feature = "cbf")]
		{
			for cbf in [
				cbf_layer(Vec::new(), CbfConfig::default(), None).expect("pure CBF"),
				cbf_layer(Vec::new(), CbfConfig::default(), Some(Arc::new(SilentProvider)))
					.expect("hybrid CBF"),
			] {
				assert!(matches!(cbf.serve_fee_estimates(), Err(Error::ChainServeUnsupported)));
				assert!(matches!(
					cbf.serve_broadcast(&tx).await,
					Err(Error::ChainServeUnsupported)
				));
				assert!(matches!(
					cbf.serve_mempool(&mempool_req).await,
					Err(Error::ChainServeUnsupported)
				));
				assert!(matches!(
					cbf.serve_wallet_sync(&sync_request()).await,
					Err(Error::ChainServeUnsupported)
				));
				assert!(matches!(
					cbf.serve_lightning_sync(&lightning_req).await,
					Err(Error::ChainServeUnsupported)
				));
				#[cfg(feature = "swaps")]
				assert!(matches!(
					cbf.serve_tx_status(tx.compute_txid(), None).await,
					Err(Error::ChainServeUnsupported)
				));
			}
		}
	}
}
