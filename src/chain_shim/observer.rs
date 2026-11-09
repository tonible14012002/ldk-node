// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! What a sync pass writes back into one node: its sync timestamps in its persisted metrics,
//! the archival of its fully resolved channel monitors, and its dead fundings.
//!
//! The chain layer used to write these itself through the node's handles on its target; it
//! now tells the node through [`SyncObserver`], and this is the node's answer — the same
//! writes, in the same order.

use std::sync::{Arc, RwLock};

use node_chain::config::RESOLVED_CHANNEL_MONITOR_ARCHIVAL_INTERVAL;
use node_chain_seam::{ChainError, SyncObserver};

use super::chain_error;
use crate::dead_funding::{reap_dead_fundings, DeadFundingStore};
use crate::io::utils::write_node_metrics;
use crate::logger::Logger;
use crate::types::{ChainMonitor, ChannelManager, DynStore, Wallet};
use crate::NodeMetrics;

/// One node's [`SyncObserver`]: everything a sync pass writes into the node.
pub(crate) struct NodeSyncObserver {
	pub(crate) wallet: Arc<Wallet>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) chain_monitor: Arc<ChainMonitor>,
	pub(crate) kv_store: Arc<DynStore>,
	pub(crate) node_metrics: Arc<RwLock<NodeMetrics>>,
	pub(crate) dead_fundings: Arc<DeadFundingStore>,
	pub(crate) logger: Arc<Logger>,
}

impl NodeSyncObserver {
	/// Changes the node's metrics with `update` and persists them, under one write lock.
	fn write_metrics(&self, update: impl FnOnce(&mut NodeMetrics)) -> Result<(), ChainError> {
		let mut locked_node_metrics = self.node_metrics.write().unwrap_or_else(|e| e.into_inner());
		update(&mut locked_node_metrics);
		write_node_metrics(
			&*locked_node_metrics,
			Arc::clone(&self.kv_store),
			Arc::clone(&self.logger),
		)
		.map_err(chain_error)
	}

	fn read_metrics<T>(&self, read: impl FnOnce(&NodeMetrics) -> T) -> T {
		read(&self.node_metrics.read().unwrap_or_else(|e| e.into_inner()))
	}
}

impl SyncObserver for NodeSyncObserver {
	fn latest_onchain_wallet_sync(&self) -> Option<u64> {
		self.read_metrics(|m| m.latest_onchain_wallet_sync_timestamp)
	}

	fn latest_lightning_wallet_sync(&self) -> Option<u64> {
		self.read_metrics(|m| m.latest_lightning_wallet_sync_timestamp)
	}

	fn latest_fee_rate_cache_update(&self) -> Option<u64> {
		self.read_metrics(|m| m.latest_fee_rate_cache_update_timestamp)
	}

	fn onchain_wallet_synced(&self, at: Option<u64>) -> Result<(), ChainError> {
		self.write_metrics(|m| m.latest_onchain_wallet_sync_timestamp = at)
	}

	fn lightning_wallet_synced(&self, at: Option<u64>) -> Result<(), ChainError> {
		self.write_metrics(|m| m.latest_lightning_wallet_sync_timestamp = at)
	}

	fn wallets_synced(&self, at: Option<u64>) -> Result<(), ChainError> {
		self.write_metrics(|m| {
			m.latest_lightning_wallet_sync_timestamp = at;
			m.latest_onchain_wallet_sync_timestamp = at;
		})
	}

	fn fee_rate_cache_updated(&self, at: Option<u64>) -> Result<(), ChainError> {
		self.write_metrics(|m| m.latest_fee_rate_cache_update_timestamp = at)
	}

	/// Archives the channel monitors that are fully resolved, at most once every
	/// [`RESOLVED_CHANNEL_MONITOR_ARCHIVAL_INTERVAL`] blocks of the `ChannelManager`'s tip.
	fn archive_resolved_monitors(&self) -> Result<(), ChainError> {
		let mut locked_node_metrics = self.node_metrics.write().unwrap_or_else(|e| e.into_inner());
		let cur_height = self.channel_manager.current_best_block().height;
		let should_archive = locked_node_metrics
			.latest_channel_monitor_archival_height
			.as_ref()
			.map_or(true, |h| cur_height >= h + RESOLVED_CHANNEL_MONITOR_ARCHIVAL_INTERVAL);

		if should_archive {
			self.chain_monitor.archive_fully_resolved_channel_monitors();
			locked_node_metrics.latest_channel_monitor_archival_height = Some(cur_height);
			write_node_metrics(
				&*locked_node_metrics,
				Arc::clone(&self.kv_store),
				Arc::clone(&self.logger),
			)
			.map_err(chain_error)?;
		}
		Ok(())
	}

	fn reap_dead_fundings(&self) {
		reap_dead_fundings(
			&self.wallet,
			&self.channel_manager,
			&self.chain_monitor,
			&self.dead_fundings,
			&*self.kv_store,
			&self.logger,
		);
	}
}
