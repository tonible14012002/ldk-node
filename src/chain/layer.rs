// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The chain ability seam.
//!
//! [`ChainLayer`] is the single entry point the rest of the crate uses to reach
//! the Bitcoin chain. It exists so the three chain *abilities* — fee estimation,
//! lookup, and broadcast — can each be served by an independently chosen
//! adapter, instead of all three being implied by one closed "which chain source
//! is configured" enum.
//!
//! Phase 1 introduces the type and routes every caller through it while the
//! legacy [`ChainSource`] enum still does the work. Abilities then migrate out of
//! the enum one at a time; the enum is deleted once it is empty. Until then this
//! is deliberately pure indirection: **every method here must behave exactly as
//! the call it replaces.**

use std::sync::Arc;

use lightning::chain::{Filter, WatchedOutput};

use bitcoin::{Script, ScriptBuf, Txid};

use lightning_block_sync::gossip::UtxoSource;

use crate::chain::ChainSource;
use crate::types::{ChainMonitor, ChannelManager, Sweeper};
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use crate::fee_estimator::OnchainFeeEstimator;

/// The chain layer: the crate's single seam onto Bitcoin.
pub(crate) struct ChainLayer {
	/// The pre-seam chain source. Shrinks to nothing as abilities are extracted
	/// into slots, and is removed entirely at the end of Phase 1.
	///
	/// Held behind the `Arc` the builder already constructs purely to keep the
	/// Phase 1 wiring diff minimal; it goes away with the field.
	legacy: Arc<ChainSource>,
}

impl ChainLayer {
	pub(crate) fn new(legacy: Arc<ChainSource>) -> Self {
		Self { legacy }
	}

	/// Start any runtime-dependent parts of the layer (currently Electrum only).
	pub(crate) fn start(&self, runtime: Arc<tokio::runtime::Runtime>) -> Result<(), Error> {
		self.legacy.start(runtime)
	}

	pub(crate) fn stop(&self) {
		self.legacy.stop()
	}

	/// The UTXO source used to verify BOLT-7 `channel_announcement`s, if the
	/// configured lookup can serve one. `None` means announcements are accepted
	/// unverified.
	pub(crate) fn as_utxo_source(&self) -> Option<Arc<dyn UtxoSource>> {
		self.legacy.as_utxo_source()
	}

	pub(crate) async fn continuously_sync_wallets(
		&self, stop_sync_receiver: tokio::sync::watch::Receiver<()>,
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) {
		self.legacy
			.continuously_sync_wallets(
				stop_sync_receiver,
				channel_manager,
				chain_monitor,
				output_sweeper,
			)
			.await
	}

	pub(crate) async fn update_fee_rate_estimates(&self) -> Result<(), Error> {
		self.legacy.update_fee_rate_estimates().await
	}

	pub(crate) async fn process_broadcast_queue(&self) {
		self.legacy.process_broadcast_queue().await
	}

	/// One full synchronous sync pass, as triggered by [`crate::Node::sync_wallets`].
	///
	/// The engine choice lives here rather than at the call site: a caller asks
	/// for "sync everything once" and must not need to know which sync
	/// architecture is in play. The per-engine call ORDER is load-bearing and is
	/// reproduced exactly from the pre-seam implementation — in particular the
	/// transaction-based engine syncs the Lightning wallet *before* the on-chain
	/// wallet.
	pub(crate) async fn sync_wallets_once(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		match &*self.legacy {
			ChainSource::Esplora { .. } | ChainSource::Electrum { .. } => {
				self.legacy.update_fee_rate_estimates().await?;
				self.legacy
					.sync_lightning_wallet(channel_manager, chain_monitor, output_sweeper)
					.await?;
				self.legacy.sync_onchain_wallet().await?;
			},
			ChainSource::Bitcoind { .. } => {
				self.legacy.update_fee_rate_estimates().await?;
				self.legacy
					.poll_and_update_listeners(channel_manager, chain_monitor, output_sweeper)
					.await?;
			},
		}
		Ok(())
	}

	/// Reorg-aware status of a watched transaction (Peerswap native primitive B5).
	#[cfg(feature = "swaps")]
	pub(crate) async fn swap_query_tx(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> RawTxObservation {
		self.legacy.swap_query_tx(txid, script_pubkey).await
	}

	/// The shared on-chain fee estimator (Peerswap native primitive B6).
	#[cfg(feature = "swaps")]
	pub(crate) fn fee_estimator(&self) -> &Arc<OnchainFeeEstimator> {
		self.legacy.fee_estimator()
	}
}

impl Filter for ChainLayer {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.legacy.register_tx(txid, script_pubkey)
	}

	fn register_output(&self, output: WatchedOutput) {
		self.legacy.register_output(output)
	}
}
