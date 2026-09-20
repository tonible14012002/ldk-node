// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Wallet synchronisation engines.
//!
//! The engine is **not** one of the three pluggable abilities. It is a separate,
//! explicit axis, because the backends do not implement one strategy — they
//! implement two structurally incompatible ones:
//!
//! ```text
//!   transaction-based   esplora, electrum
//!                       drives Confirm via lightning-transaction-sync,
//!                       needs Filter::register_tx / register_output
//!
//!   block-polling       bitcoind
//!                       drives Listen via lightning-block-sync, keeps a
//!                       header cache and a cached tip, handles reorgs,
//!                       registers nothing
//! ```
//!
//! Pre-seam both lived in one enum, so each strategy's methods had to exist on
//! the other and panic: four `unreachable!()` arms. Splitting the types removes
//! them by construction — a block-polling engine simply has no
//! `sync_onchain_wallet` to call.
//!
//! Esplora and electrum are both transaction-based but share no code, so this
//! is three implementations, not two.

pub(crate) mod bitcoind;
pub(crate) mod electrum;
pub(crate) mod esplora;

use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Script, Txid};

use lightning::chain::WatchedOutput;

use crate::chain::ChainLayer;
use crate::config::{BackgroundSyncConfig, WALLET_SYNC_INTERVAL_MINIMUM_SECS};
use crate::logger::{log_trace, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, Sweeper};
use crate::Error;

use async_trait::async_trait;

/// The two operations a transaction-based engine exposes to the shared loop.
///
/// Esplora and Electrum implement these completely differently; only the loop
/// that drives them is common, so only the loop is shared.
#[async_trait]
pub(crate) trait TxBasedBackend: Send + Sync {
	async fn sync_onchain_wallet(&self) -> Result<(), Error>;

	async fn sync_lightning_wallet(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error>;
}

/// The background loop shared by both transaction-based engines.
///
/// Moved verbatim from `ChainSource::start_tx_based_sync_loop`; the only
/// changes are that the backend is a parameter rather than `self`, and fee
/// refreshes go through the layer's FEE slot.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_tx_based_sync_loop(
	backend: &dyn TxBasedBackend, layer: Arc<ChainLayer>,
	mut stop_sync_receiver: tokio::sync::watch::Receiver<()>, channel_manager: Arc<ChannelManager>,
	chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
	background_sync_config: &BackgroundSyncConfig, logger: Arc<Logger>,
) {
	// Setup syncing intervals
	let onchain_wallet_sync_interval_secs = background_sync_config
		.onchain_wallet_sync_interval_secs
		.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS);
	let mut onchain_wallet_sync_interval =
		tokio::time::interval(Duration::from_secs(onchain_wallet_sync_interval_secs));
	onchain_wallet_sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

	let fee_rate_cache_update_interval_secs = background_sync_config
		.fee_rate_cache_update_interval_secs
		.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS);
	let mut fee_rate_update_interval =
		tokio::time::interval(Duration::from_secs(fee_rate_cache_update_interval_secs));
	// When starting up, we just blocked on updating, so skip the first tick.
	fee_rate_update_interval.reset();
	fee_rate_update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

	let lightning_wallet_sync_interval_secs = background_sync_config
		.lightning_wallet_sync_interval_secs
		.max(WALLET_SYNC_INTERVAL_MINIMUM_SECS);
	let mut lightning_wallet_sync_interval =
		tokio::time::interval(Duration::from_secs(lightning_wallet_sync_interval_secs));
	lightning_wallet_sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

	// Start the syncing loop.
	loop {
		tokio::select! {
			_ = stop_sync_receiver.changed() => {
				log_trace!(
					logger,
					"Stopping background syncing on-chain wallet.",
					);
				return;
			}
			_ = onchain_wallet_sync_interval.tick() => {
				let _ = backend.sync_onchain_wallet().await;
			}
			_ = fee_rate_update_interval.tick() => {
				let _ = layer.update_fee_rate_estimates().await;
			}
			_ = lightning_wallet_sync_interval.tick() => {
				let _ = backend.sync_lightning_wallet(
					Arc::clone(&channel_manager),
					Arc::clone(&chain_monitor),
					Arc::clone(&output_sweeper),
					).await;
			}
		}
	}
}

/// Keeps the on-chain and Lightning wallets in step with the chain.
#[async_trait]
pub(crate) trait SyncEngine: Send + Sync {
	/// Stable identifier, for logs and for answering "which engine is running".
	fn name(&self) -> &'static str;

	/// Start any runtime-dependent part of the engine. Only electrum has one.
	fn start(&self, _runtime: Arc<tokio::runtime::Runtime>) -> Result<(), Error> {
		Ok(())
	}

	/// Stop any runtime-dependent part of the engine.
	fn stop(&self) {}

	/// One full foreground sync pass, as triggered by
	/// [`crate::Node::sync_wallets`].
	///
	/// The per-engine ORDER is load-bearing and reproduced exactly from the
	/// pre-seam implementation: transaction-based syncs the Lightning wallet
	/// *before* the on-chain wallet. The caller refreshes fees first, in both
	/// cases, before calling this.
	async fn sync_once(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error>;

	/// Run until `stop_sync_receiver` fires.
	///
	/// Takes the layer so fee refreshes go through the FEE slot rather than
	/// through the engine's own backend — otherwise a swapped fee adapter
	/// would apply to foreground calls and silently not to background ones.
	async fn run_background(
		&self, layer: Arc<ChainLayer>, stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	);

	/// `Filter` registration. Transaction-based engines must watch these;
	/// block-polling engines see every block anyway and ignore them.
	fn register_tx(&self, _txid: &Txid, _script_pubkey: &Script) {}

	/// See [`SyncEngine::register_tx`].
	fn register_output(&self, _output: WatchedOutput) {}
}
