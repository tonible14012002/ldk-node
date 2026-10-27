// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! What one chain layer keeps in step: the sync targets.
//!
//! A [`SyncTarget`] is everything of ONE node that the chain has to be applied to — its
//! on-chain wallet, its `ChannelManager`, `ChainMonitor` and sweeper — plus the per-node
//! bookkeeping a sync pass writes: the node's own store, its metrics, its dead-funding
//! record. The engines used to hold one of each; they now iterate the
//! [`TargetRegistry`] instead, so one engine, one chain source and one fee cache serve
//! every node in the process.
//!
//! The registry is the only thing an engine reads targets from. Registration and removal
//! take the write lock for the length of a `Vec` push or `retain`; a pass snapshots the
//! list and runs on the snapshot, so a target removed mid-pass is finished for and then
//! never seen again — the same as a node stopping between two passes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::chain::WalletSyncStatus;
use crate::dead_funding::DeadFundingStore;
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::NodeMetrics;

/// The registry's handle on one target; stable for the target's lifetime, never reused.
pub(crate) type TargetId = u64;

/// Everything a node hands the chain layer to be kept in step. See the module docs.
pub(crate) struct SyncTargetSpec {
	/// A short name for logs — the node id's first characters.
	pub(crate) label: String,
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) chain_monitor: Arc<ChainMonitor>,
	pub(crate) output_sweeper: Arc<Sweeper>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
	pub(crate) dead_fundings: Arc<DeadFundingStore>,
	/// Where a filter scan for this wallet may start: nothing of this wallet's is older. A
	/// filter-driven engine registering the target after launch rescans from here; one
	/// launching with it floors its resume checkpoint on the lowest birthday it holds.
	pub(crate) birthday_height: Option<u32>,
}

/// One node as the chain layer sees it.
pub(crate) struct SyncTarget {
	pub(crate) id: TargetId,
	pub(crate) label: String,
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) chain_monitor: Arc<ChainMonitor>,
	pub(crate) output_sweeper: Arc<Sweeper>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
	pub(crate) dead_fundings: Arc<DeadFundingStore>,
	pub(crate) birthday_height: Option<u32>,
	/// The in-progress latch of this target's on-chain wallet sync — a block-polling engine
	/// uses it for its whole poll, which syncs both wallets at once. A second caller while a
	/// pass runs subscribes to its result rather than starting another.
	pub(crate) onchain_wallet_sync_status: Mutex<WalletSyncStatus>,
	/// The in-progress latch of this target's Lightning wallet sync.
	pub(crate) lightning_wallet_sync_status: Mutex<WalletSyncStatus>,
}

/// The targets a chain layer keeps in step, in registration order.
pub(crate) struct TargetRegistry {
	targets: RwLock<Vec<Arc<SyncTarget>>>,
	next_id: AtomicU64,
	/// Bumped on every registration and removal, so a reader caching something derived
	/// from the target set — a filter engine's match set — can tell that the set changed
	/// even when its sizes did not.
	generation: AtomicU64,
}

impl TargetRegistry {
	pub(crate) fn new() -> Self {
		Self { targets: RwLock::new(Vec::new()), next_id: AtomicU64::new(1), generation: AtomicU64::new(0) }
	}

	/// Adds a target and hands back its handle.
	pub(crate) fn register(&self, spec: SyncTargetSpec) -> Arc<SyncTarget> {
		let id = self.next_id.fetch_add(1, Ordering::AcqRel);
		let target = Arc::new(SyncTarget {
			id,
			label: spec.label,
			onchain_wallet: spec.onchain_wallet,
			channel_manager: spec.channel_manager,
			chain_monitor: spec.chain_monitor,
			output_sweeper: spec.output_sweeper,
			kv_store: spec.kv_store,
			node_metrics: spec.node_metrics,
			dead_fundings: spec.dead_fundings,
			birthday_height: spec.birthday_height,
			onchain_wallet_sync_status: Mutex::new(WalletSyncStatus::Completed),
			lightning_wallet_sync_status: Mutex::new(WalletSyncStatus::Completed),
		});
		self.targets.write().unwrap_or_else(|e| e.into_inner()).push(Arc::clone(&target));
		self.generation.fetch_add(1, Ordering::AcqRel);
		target
	}

	/// Removes the target with `id`; a pass already holding a snapshot finishes with it.
	pub(crate) fn unregister(&self, id: TargetId) {
		let mut targets = self.targets.write().unwrap_or_else(|e| e.into_inner());
		let before = targets.len();
		targets.retain(|t| t.id != id);
		if targets.len() != before {
			self.generation.fetch_add(1, Ordering::AcqRel);
		}
	}

	/// The targets as they are now, in registration order. A pass runs on this copy.
	pub(crate) fn snapshot(&self) -> Vec<Arc<SyncTarget>> {
		self.targets.read().unwrap_or_else(|e| e.into_inner()).clone()
	}

	pub(crate) fn get(&self, id: TargetId) -> Option<Arc<SyncTarget>> {
		self.targets.read().unwrap_or_else(|e| e.into_inner()).iter().find(|t| t.id == id).cloned()
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.targets.read().unwrap_or_else(|e| e.into_inner()).is_empty()
	}

	pub(crate) fn len(&self) -> usize {
		self.targets.read().unwrap_or_else(|e| e.into_inner()).len()
	}

	/// How many registrations and removals the registry has seen; see the field docs.
	pub(crate) fn generation(&self) -> u64 {
		self.generation.load(Ordering::Acquire)
	}
}

/// Builds the Lightning side of a target over a test wallet, so a layer or engine test
/// can register a real target without a `Node`.
#[cfg(test)]
pub(crate) mod test_support {
	use super::*;

	use std::time::SystemTime;

	use bitcoin::Network;

	use lightning::chain::{chainmonitor, BestBlock};
	use lightning::ln::channelmanager::{self, ChainParameters};
	use lightning::routing::router::DefaultRouter;
	use lightning::routing::scoring::{
		ProbabilisticScorer, ProbabilisticScoringDecayParameters,
		ProbabilisticScoringFeeParameters,
	};
	use lightning::util::sweep::OutputSweeper;

	use crate::config::{default_user_config, Config};
	use crate::fee_estimator::OnchainFeeEstimator;
	use crate::logger::Logger;
	use crate::types::{Broadcaster, Graph, KeysManager, MessageRouter};

	/// A target over `wallet` with a fresh `ChannelManager`, `ChainMonitor` and sweeper on
	/// regtest genesis, and its own metrics and dead-funding record.
	pub(crate) fn target_spec(
		label: &str, wallet: Arc<Wallet>, kv_store: Arc<DynStore>, broadcaster: Arc<Broadcaster>,
		fee_estimator: Arc<OnchainFeeEstimator>, logger: Arc<Logger>,
	) -> SyncTargetSpec {
		let config = Arc::new(Config { network: Network::Regtest, ..Config::default() });
		let chain_monitor: Arc<ChainMonitor> = Arc::new(chainmonitor::ChainMonitor::new(
			None,
			Arc::clone(&broadcaster),
			Arc::clone(&logger),
			Arc::clone(&fee_estimator),
			Arc::clone(&kv_store),
		));
		let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
		let keys_manager = Arc::new(KeysManager::new(
			&[7u8; 32],
			now.as_secs(),
			now.subsec_nanos(),
			Arc::clone(&wallet),
			Arc::clone(&logger),
		));
		let network_graph = Arc::new(Graph::new(config.network.into(), Arc::clone(&logger)));
		let scorer = Arc::new(Mutex::new(ProbabilisticScorer::new(
			ProbabilisticScoringDecayParameters::default(),
			Arc::clone(&network_graph),
			Arc::clone(&logger),
		)));
		let router = Arc::new(DefaultRouter::new(
			Arc::clone(&network_graph),
			Arc::clone(&logger),
			Arc::clone(&keys_manager),
			scorer,
			ProbabilisticScoringFeeParameters::default(),
		));
		let message_router =
			Arc::new(MessageRouter::new(Arc::clone(&network_graph), Arc::clone(&keys_manager)));
		let genesis = bitcoin::blockdata::constants::genesis_block(config.network).block_hash();
		let best_block = BestBlock::new(genesis, 0);
		let channel_manager = Arc::new(channelmanager::ChannelManager::new(
			Arc::clone(&fee_estimator),
			Arc::clone(&chain_monitor),
			Arc::clone(&broadcaster),
			Arc::clone(&router),
			Arc::clone(&message_router),
			Arc::clone(&logger),
			Arc::clone(&keys_manager),
			Arc::clone(&keys_manager),
			Arc::clone(&keys_manager),
			default_user_config(&config),
			ChainParameters { network: config.network.into(), best_block },
			now.as_secs() as u32,
		));
		let output_sweeper = Arc::new(OutputSweeper::new(
			best_block,
			Arc::clone(&broadcaster),
			Arc::clone(&fee_estimator),
			None,
			Arc::clone(&keys_manager),
			Arc::clone(&keys_manager),
			Arc::clone(&kv_store),
			Arc::clone(&logger),
		));
		let dead_fundings =
			Arc::new(DeadFundingStore::read_or_empty(Arc::clone(&kv_store), Arc::clone(&logger)));
		SyncTargetSpec {
			label: label.to_string(),
			onchain_wallet: wallet,
			channel_manager,
			chain_monitor,
			output_sweeper,
			kv_store,
			node_metrics: Arc::new(RwLock::new(NodeMetrics::default())),
			dead_fundings,
			birthday_height: None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::test_support::target_spec;
	use super::*;

	use lightning::util::test_utils::TestStore;

	use crate::chain::test_wallet::fresh_regtest_wallet;
	use crate::fee_estimator::OnchainFeeEstimator;
	use crate::logger::Logger;
	use crate::tx_broadcaster::TransactionBroadcaster;

	fn spec(label: &str) -> SyncTargetSpec {
		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_regtest_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		target_spec(label, wallet, kv_store, broadcaster, fee_estimator, logger)
	}

	#[test]
	fn targets_are_listed_in_registration_order_and_removed_by_id() {
		let registry = TargetRegistry::new();
		assert!(registry.is_empty());
		assert_eq!(registry.generation(), 0);

		let a = registry.register(spec("a"));
		let b = registry.register(spec("b"));
		assert_ne!(a.id, b.id, "ids are never reused");
		assert_eq!(registry.len(), 2);
		assert_eq!(registry.generation(), 2);

		let ids: Vec<TargetId> = registry.snapshot().iter().map(|t| t.id).collect();
		assert_eq!(ids, vec![a.id, b.id], "registration order");
		assert!(Arc::ptr_eq(&registry.get(a.id).unwrap(), &a));

		registry.unregister(a.id);
		assert_eq!(registry.generation(), 3);
		registry.unregister(a.id);
		assert_eq!(registry.generation(), 3, "removing a removed target changes nothing");
		let ids: Vec<TargetId> = registry.snapshot().iter().map(|t| t.id).collect();
		assert_eq!(ids, vec![b.id]);
		assert!(registry.get(a.id).is_none());

		let c = registry.register(spec("c"));
		assert!(c.id > b.id);
		assert_eq!(registry.len(), 2);
		assert!(!registry.is_empty());
	}
}
