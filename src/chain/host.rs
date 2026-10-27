// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! One chain layer per process, shared by every [`Node`] that attaches to it.
//!
//! A [`ChainHost`] owns a [`ChainLayer`] — the chain source, the sync engine, the fee
//! estimator and the broadcaster — and runs its background work exactly once, however many
//! nodes use it: the first node to attach starts the engine, refreshes the fee cache and
//! spawns the sync loop and the broadcast drain; the last to detach stops them. Each node is
//! one [`SyncTarget`] of the layer in between.
//!
//! Every node goes through a host, whether or not the application made one: a
//! [`Builder`] without [`Builder::set_chain_host`] builds a private host from its own chain
//! configuration, which is the node of before — one chain layer, one node — spelled the same
//! way as N. There is one code path.
//!
//! The host's tasks run on the runtime of the first node to attach. An application sharing
//! a host between nodes gives them one runtime ([`Node::start_with_runtime`]); the nodes'
//! own tasks each run on whatever runtime they were started with.
//!
//! [`Node`]: crate::Node
//! [`Builder`]: crate::Builder
//! [`Builder::set_chain_host`]: crate::Builder::set_chain_host
//! [`Node::start_with_runtime`]: crate::Node::start_with_runtime
//! [`SyncTarget`]: crate::chain::target::SyncTarget

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::Network;

use tokio::sync::watch;

use crate::builder::{BuildError, ChainDataSourceConfig, RawChainSourceConfig};
use crate::chain::provider::ChainDataProvider;
use crate::chain::target::{SyncTargetSpec, TargetId};
use crate::chain::{CbfSyncStatus, ChainLayer, ChainSlotStatus, DEFAULT_ESPLORA_SERVER_URL};
#[cfg(feature = "cbf")]
use crate::chain::cbf::source::FilterSource;
#[cfg(feature = "cbf")]
use crate::config::CbfConfig;
use crate::config::{
	BitcoindRestClientConfig, Config, ElectrumSyncConfig, EsploraSyncConfig, DEFAULT_LOG_FILENAME,
	DEFAULT_LOG_LEVEL,
};
use crate::fee_estimator::OnchainFeeEstimator;
use crate::logger::{log_debug, log_error, log_info, log_warn, LdkLogger, LogLevel, Logger};
use crate::tx_broadcaster::TransactionBroadcaster;
use crate::types::Broadcaster;
use crate::Error;

/// Builds a [`ChainHost`]: the chain-related half of [`Builder`], with the same setters,
/// so a configuration that used to pick a node's chain source now picks the host's.
///
/// Defaults match [`Builder`]: Esplora at `https://blockstream.info/api` on the configured
/// network, logging to the `log` facade unless [`ChainHostBuilder::set_logger`] says
/// otherwise.
///
/// [`Builder`]: crate::Builder
pub struct ChainHostBuilder {
	config: Config,
	chain_data_source_config: Option<ChainDataSourceConfig>,
	#[cfg(feature = "cbf")]
	chain_provider_fallback: Option<Arc<dyn ChainDataProvider>>,
	#[cfg(feature = "cbf")]
	cbf_filter_source: Option<Arc<dyn FilterSource>>,
	raw_chain_source_config: Option<RawChainSourceConfig>,
	raw_chain_source_allow_insecure_http: bool,
	logger: Option<Arc<Logger>>,
}

impl ChainHostBuilder {
	/// A host on `network` with every other setting at its default.
	pub fn new(network: Network) -> Self {
		Self::from_config(Config { network, ..Config::default() })
	}

	/// A host from a full [`Config`]: its network, and its storage directory for what the
	/// chain source keeps on disk (the filter engine's header store).
	pub fn from_config(config: Config) -> Self {
		Self {
			config,
			chain_data_source_config: None,
			#[cfg(feature = "cbf")]
			chain_provider_fallback: None,
			#[cfg(feature = "cbf")]
			cbf_filter_source: None,
			raw_chain_source_config: None,
			raw_chain_source_allow_insecure_http: false,
			logger: None,
		}
	}

	/// The logger the host — and the chain layer every attached node shares — writes to.
	/// Without one the host logs to the `log` facade.
	pub fn set_logger(&mut self, logger: Arc<Logger>) -> &mut Self {
		self.logger = Some(logger);
		self
	}

	/// See [`Builder::set_chain_source_esplora`](crate::Builder::set_chain_source_esplora).
	pub fn set_chain_source_esplora(
		&mut self, server_url: String, sync_config: Option<EsploraSyncConfig>,
	) -> &mut Self {
		self.chain_data_source_config =
			Some(ChainDataSourceConfig::Esplora { server_url, sync_config });
		self
	}

	/// See [`Builder::set_chain_source_electrum`](crate::Builder::set_chain_source_electrum).
	pub fn set_chain_source_electrum(
		&mut self, server_url: String, sync_config: Option<ElectrumSyncConfig>,
	) -> &mut Self {
		self.chain_data_source_config =
			Some(ChainDataSourceConfig::Electrum { server_url, sync_config });
		self
	}

	/// See [`Builder::set_chain_source_bitcoind_rpc`](crate::Builder::set_chain_source_bitcoind_rpc).
	pub fn set_chain_source_bitcoind_rpc(
		&mut self, rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String,
	) -> &mut Self {
		self.chain_data_source_config = Some(ChainDataSourceConfig::Bitcoind {
			rpc_host,
			rpc_port,
			rpc_user,
			rpc_password,
			rest_client_config: None,
		});
		self
	}

	/// See [`Builder::set_chain_source_bitcoind_rest`](crate::Builder::set_chain_source_bitcoind_rest).
	pub fn set_chain_source_bitcoind_rest(
		&mut self, rest_host: String, rest_port: u16, rpc_host: String, rpc_port: u16,
		rpc_user: String, rpc_password: String,
	) -> &mut Self {
		self.chain_data_source_config = Some(ChainDataSourceConfig::Bitcoind {
			rpc_host,
			rpc_port,
			rpc_user,
			rpc_password,
			rest_client_config: Some(BitcoindRestClientConfig { rest_host, rest_port }),
		});
		self
	}

	/// See [`Builder::set_chain_source_dependent`](crate::Builder::set_chain_source_dependent).
	pub fn set_chain_source_dependent(
		&mut self, provider: Arc<dyn ChainDataProvider>, sync_config: Option<EsploraSyncConfig>,
	) -> &mut Self {
		self.chain_data_source_config =
			Some(ChainDataSourceConfig::Dependent { provider, sync_config });
		self
	}

	/// See [`Builder::set_chain_source_cbf`](crate::Builder::set_chain_source_cbf).
	#[cfg(feature = "cbf")]
	pub fn set_chain_source_cbf(&mut self, peers: Vec<String>, config: CbfConfig) -> &mut Self {
		self.chain_data_source_config = Some(ChainDataSourceConfig::Cbf { peers, config });
		self
	}

	/// See [`Builder::set_chain_provider_fallback`](crate::Builder::set_chain_provider_fallback).
	#[cfg(feature = "cbf")]
	pub fn set_chain_provider_fallback(
		&mut self, provider: Arc<dyn ChainDataProvider>,
	) -> &mut Self {
		self.chain_provider_fallback = Some(provider);
		self
	}

	/// See [`Builder::set_cbf_filter_source`](crate::Builder::set_cbf_filter_source).
	#[cfg(feature = "cbf")]
	pub fn set_cbf_filter_source(&mut self, source: Arc<dyn FilterSource>) -> &mut Self {
		self.cbf_filter_source = Some(source);
		self
	}

	/// See [`Builder::set_raw_chain_source_bitcoind_rpc`](crate::Builder::set_raw_chain_source_bitcoind_rpc).
	pub fn set_raw_chain_source_bitcoind_rpc(
		&mut self, url: String, user: String, password: String, cert_sha256: Option<String>,
	) -> &mut Self {
		self.raw_chain_source_config = Some(RawChainSourceConfig {
			url,
			user,
			password,
			cert_sha256,
			allow_insecure_http: false,
		});
		self
	}

	/// See [`Builder::set_raw_chain_source_allow_insecure_http`](crate::Builder::set_raw_chain_source_allow_insecure_http).
	pub fn set_raw_chain_source_allow_insecure_http(&mut self, allow: bool) -> &mut Self {
		self.raw_chain_source_allow_insecure_http = allow;
		self
	}

	/// The node builder's chain configuration as a host builder: what a [`Builder`] without
	/// a host builds its private host from.
	///
	/// [`Builder`]: crate::Builder
	pub(crate) fn from_node_config(
		config: Config, chain_data_source_config: Option<ChainDataSourceConfig>,
		#[cfg(feature = "cbf")] chain_provider_fallback: Option<Arc<dyn ChainDataProvider>>,
		#[cfg(feature = "cbf")] cbf_filter_source: Option<Arc<dyn FilterSource>>,
		raw_chain_source_config: Option<RawChainSourceConfig>, logger: Arc<Logger>,
	) -> Self {
		let raw_chain_source_allow_insecure_http =
			raw_chain_source_config.as_ref().map_or(false, |raw| raw.allow_insecure_http);
		Self {
			config,
			chain_data_source_config,
			#[cfg(feature = "cbf")]
			chain_provider_fallback,
			#[cfg(feature = "cbf")]
			cbf_filter_source,
			raw_chain_source_config,
			raw_chain_source_allow_insecure_http,
			logger: Some(logger),
		}
	}

	/// The birthday height a filter-following host's fresh wallets are seeded at; `None`
	/// for every other chain source.
	#[cfg(feature = "cbf")]
	fn wallet_birthday_height(&self) -> Option<u32> {
		match &self.chain_data_source_config {
			Some(ChainDataSourceConfig::Cbf { config, .. }) => config.wallet_birthday_height,
			_ => None,
		}
	}

	/// Builds the host. Nothing connects yet: the chain source is started by the first node
	/// to attach.
	pub fn build(self) -> Result<Arc<ChainHost>, BuildError> {
		let logger = match self.logger.clone() {
			Some(logger) => logger,
			None => {
				// The same default a `Builder` without a log setting picks, so a host built
				// beside such a node logs where the node does.
				let log_file_path =
					format!("{}/{}", self.config.storage_dir_path, DEFAULT_LOG_FILENAME);
				let level: LogLevel = DEFAULT_LOG_LEVEL;
				Arc::new(
					Logger::new_fs_writer(log_file_path, level)
						.map_err(|_| BuildError::LoggerSetupFailed)?,
				)
			},
		};
		#[cfg(feature = "cbf")]
		let wallet_birthday_height = self.wallet_birthday_height();
		let config = Arc::new(self.config);
		let tx_broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());

		// The chain ability seam. Every consumer below talks to `ChainLayer`; none
		// of them knows which backend fills its slots.
		//
		// The fallback provider goes to the one preset that consults it; every
		// other arm hands it back untouched, to be announced as ignored below.
		#[cfg(feature = "cbf")]
		let chain_provider_fallback = self.chain_provider_fallback;
		#[cfg(not(feature = "cbf"))]
		let chain_provider_fallback: Option<Arc<dyn ChainDataProvider>> = None;
		let (layer, unconsulted_fallback) = match &self.chain_data_source_config {
			Some(ChainDataSourceConfig::Esplora { server_url, sync_config }) => {
				let sync_config = sync_config.unwrap_or(EsploraSyncConfig::default());
				let layer = ChainLayer::new_esplora(
					server_url.clone(),
					sync_config,
					Arc::clone(&fee_estimator),
					Arc::clone(&tx_broadcaster),
					Arc::clone(&config),
					Arc::clone(&logger),
				);
				(layer, chain_provider_fallback)
			},
			Some(ChainDataSourceConfig::Electrum { server_url, sync_config }) => {
				let sync_config = sync_config.unwrap_or(ElectrumSyncConfig::default());
				let layer = ChainLayer::new_electrum(
					server_url.clone(),
					sync_config,
					Arc::clone(&fee_estimator),
					Arc::clone(&tx_broadcaster),
					Arc::clone(&config),
					Arc::clone(&logger),
				);
				(layer, chain_provider_fallback)
			},
			Some(ChainDataSourceConfig::Bitcoind {
				rpc_host,
				rpc_port,
				rpc_user,
				rpc_password,
				rest_client_config,
			}) => {
				let layer = match rest_client_config {
					Some(rest_client_config) => ChainLayer::new_bitcoind_rest(
						rpc_host.clone(),
						*rpc_port,
						rpc_user.clone(),
						rpc_password.clone(),
						Arc::clone(&fee_estimator),
						Arc::clone(&tx_broadcaster),
						Arc::clone(&config),
						rest_client_config.clone(),
						Arc::clone(&logger),
					),
					None => ChainLayer::new_bitcoind_rpc(
						rpc_host.clone(),
						*rpc_port,
						rpc_user.clone(),
						rpc_password.clone(),
						Arc::clone(&fee_estimator),
						Arc::clone(&tx_broadcaster),
						Arc::clone(&config),
						Arc::clone(&logger),
					),
				};
				(layer, chain_provider_fallback)
			},
			Some(ChainDataSourceConfig::Dependent { provider, sync_config }) => {
				let sync_config = sync_config.unwrap_or(EsploraSyncConfig::default());
				let layer = ChainLayer::new_dependent(
					Arc::clone(provider),
					sync_config,
					Arc::clone(&fee_estimator),
					Arc::clone(&tx_broadcaster),
					Arc::clone(&logger),
				);
				(layer, chain_provider_fallback)
			},
			#[cfg(feature = "cbf")]
			Some(ChainDataSourceConfig::Cbf { peers, config: cbf_config }) => {
				let layer = ChainLayer::new_cbf(
					peers.clone(),
					cbf_config.clone(),
					chain_provider_fallback,
					self.cbf_filter_source,
					Arc::clone(&fee_estimator),
					Arc::clone(&tx_broadcaster),
					Arc::clone(&config),
					Arc::clone(&logger),
				)
				.map_err(|e| {
					log_error!(logger, "Failed to set up the CBF chain source: {}", e);
					BuildError::ChainSourceSetupFailed
				})?;
				(layer, None)
			},
			None => {
				// Default to Esplora client.
				let server_url = DEFAULT_ESPLORA_SERVER_URL.to_string();
				let sync_config = EsploraSyncConfig::default();
				let layer = ChainLayer::new_esplora(
					server_url,
					sync_config,
					Arc::clone(&fee_estimator),
					Arc::clone(&tx_broadcaster),
					Arc::clone(&config),
					Arc::clone(&logger),
				);
				(layer, chain_provider_fallback)
			},
		};

		if let Some(provider) = unconsulted_fallback {
			log_warn!(
				logger,
				"A chain provider fallback ({}) is set, but the configured chain source scans its own backend and never consults one; ignoring it.",
				provider.name()
			);
		}

		let mut layer = layer;
		if let Some(raw) = &self.raw_chain_source_config {
			// A refused configuration turns raw serving off and is logged; the host still builds.
			layer.set_raw_source_bitcoind_rpc(
				&raw.url,
				Some(raw.user.clone()),
				Some(raw.password.clone()),
				raw.cert_sha256.as_deref(),
				self.raw_chain_source_allow_insecure_http,
			);
		}

		Ok(Arc::new(ChainHost::from_layer(
			Arc::new(layer),
			logger,
			#[cfg(feature = "cbf")]
			wallet_birthday_height,
		)))
	}
}

impl std::fmt::Debug for ChainHost {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ChainHost")
			.field("engine", &self.layer.slot_adapters().engine)
			.field("attached", &self.run.lock().unwrap_or_else(|e| e.into_inner()).attached)
			.finish()
	}
}

/// The host's running state: how many nodes are attached, and what the first of them
/// started.
struct HostRun {
	attached: usize,
	runtime: Option<Arc<tokio::runtime::Runtime>>,
	/// Stops the sync loop and the broadcast drain; dropped with the last detach.
	stop_sender: Option<watch::Sender<()>>,
}

/// One chain layer, shared by every node attached to it. See the module docs.
pub struct ChainHost {
	layer: Arc<ChainLayer>,
	run: Mutex<HostRun>,
	#[cfg(feature = "cbf")]
	wallet_birthday_height: Option<u32>,
	logger: Arc<Logger>,
}

/// What a [`ChainHost`] is doing, for an application's status surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainHostStatus {
	/// The sync engine's name, e.g. `esplora-tx-sync`.
	pub engine: String,
	/// How many nodes are attached — started and not yet stopped.
	pub attached: usize,
	/// Which adapters occupy each chain ability slot; see
	/// [`Node::chain_slot_adapters`](crate::Node::chain_slot_adapters).
	pub slots: ChainSlotStatus,
	/// The compact-block-filter sync status, when the host follows the chain by filters.
	pub cbf_sync_status: Option<CbfSyncStatus>,
	/// When the shared fee cache was last refreshed, in seconds since the UNIX epoch;
	/// `None` until the first successful refresh of this process.
	pub fee_cache_updated_at: Option<u64>,
}

impl ChainHost {
	pub(crate) fn from_layer(
		layer: Arc<ChainLayer>, logger: Arc<Logger>,
		#[cfg(feature = "cbf")] wallet_birthday_height: Option<u32>,
	) -> Self {
		Self {
			layer,
			run: Mutex::new(HostRun { attached: 0, runtime: None, stop_sender: None }),
			#[cfg(feature = "cbf")]
			wallet_birthday_height,
			logger,
		}
	}

	pub(crate) fn layer(&self) -> &Arc<ChainLayer> {
		&self.layer
	}

	pub(crate) fn fee_estimator(&self) -> &Arc<OnchainFeeEstimator> {
		self.layer.fee_estimator()
	}

	pub(crate) fn tx_broadcaster(&self) -> &Arc<Broadcaster> {
		self.layer.tx_broadcaster()
	}

	/// The birthday a filter-following host's fresh wallets, channel managers and sweepers
	/// are seeded at; `None` for every other chain source.
	#[cfg(feature = "cbf")]
	pub(crate) fn wallet_birthday_height(&self) -> Option<u32> {
		self.wallet_birthday_height
	}

	/// What the host is doing now. Never blocks on the chain.
	pub fn status(&self) -> ChainHostStatus {
		let attached = self.run.lock().unwrap_or_else(|e| e.into_inner()).attached;
		ChainHostStatus {
			engine: self.layer.slot_adapters().engine.to_string(),
			attached,
			slots: self.layer.slot_status(),
			cbf_sync_status: self.layer.cbf_sync_status(),
			fee_cache_updated_at: self.layer.fee_cache_updated_at(),
		}
	}

	/// A node joins: its target is registered, and if it is the first node the chain source
	/// is started, the fee cache refreshed once, and the sync loop and broadcast drain
	/// spawned on `runtime`. Returns the node's target id, for [`ChainHost::detach`].
	///
	/// The order is the single-node start order of before: engine, target, fee refresh,
	/// loops — the target is in before the refresh so its stamp lands in the node's
	/// metrics, and before the loop so the first pass includes it.
	pub(crate) fn attach(
		&self, spec: SyncTargetSpec, runtime: Arc<tokio::runtime::Runtime>,
	) -> Result<TargetId, Error> {
		let mut run = self.run.lock().unwrap_or_else(|e| e.into_inner());
		let first = run.attached == 0;

		if first {
			// Start up any runtime-dependant chain sources (e.g. Electrum)
			self.layer.start(Arc::clone(&runtime)).map_err(|e| {
				log_error!(self.logger, "Failed to start chain syncing: {}", e);
				e
			})?;

			// Record which adapters occupy each chain ability slot, in chain order,
			// so a support question about a fee or broadcast answer can be traced
			// to the thing that produced it without guessing from config.
			let slots = self.layer.slot_adapters();
			log_info!(self.logger, "Chain ability slots: {}", slots);
			if slots.utxo.is_none() {
				// Say this out loud. Without a UTXO source the routing graph accepts
				// every peer's channel_announcement without checking that the funding
				// output exists, and nothing else reports it.
				log_info!(
					self.logger,
					"No chain adapter can verify BOLT-7 channel announcements; the routing graph will carry unverified channel capacities."
				);
			}
		}

		let target = match self.layer.register_target(spec) {
			Ok(target) => target,
			Err(e) => {
				if first {
					self.layer.stop();
				}
				return Err(e);
			},
		};

		if first {
			// Refresh the fee rate cache once on startup — but do NOT let a failure
			// stop the node coming up.
			//
			// DEVIATION from upstream ldk-node, which propagates this error with
			// `?` and refuses to start. Upstream's rule is a reachability probe on
			// the chain source, using the cheapest call available: fail fast rather
			// than come up blind. That is sound for a node whose chain source is an
			// external server it can retry until the network appears.
			//
			// It is wrong for a node whose chain source is reached through this
			// node's own transport. There the probe is gated on the node it is
			// gating — identity and message signing are served by the application
			// wrapping this crate, and that application cannot answer until start()
			// returns. The node then retries forever against a dependency that can
			// never be satisfied.
			//
			// Two facts make continuing safe rather than reckless:
			//
			//   * `FeeEstimator::estimate_fee_rate` cannot fail. Every target has a
			//     hardcoded fallback, so an empty cache yields constants, not an
			//     error. A node with no estimates runs.
			//   * this crate ALREADY tolerates indefinite fee failures — the
			//     background loop discards them (`let _ = …update_fee_rate_estimates`).
			//     A node whose provider dies after startup keeps running on a stale
			//     cache. Only the very first fetch was fatal, which is an asymmetry
			//     rather than a safety property.
			//
			// What replaces the guarantee: the failure is recorded rather than
			// swallowed. `latest_fee_rate_cache_update_timestamp` stays `None`,
			// which [`Node::chain_freshness`] reports so the embedding application
			// can refuse the operations where a wrong fee rate costs money —
			// building or broadcasting a transaction — while still serving reads.
			// Degraded and honest beats absent.
			//
			// [`Node::chain_freshness`]: crate::Node::chain_freshness
			let layer = Arc::clone(&self.layer);
			let runtime_ref = &runtime;
			let fee_update = tokio::task::block_in_place(move || {
				runtime_ref.block_on(async move { layer.update_fee_rate_estimates().await })
			});
			if let Err(e) = fee_update {
				log_error!(
					self.logger,
					"Initial fee rate cache update failed: {}. Continuing startup with fallback fee \
					 estimates; transaction-building operations should be refused until a refresh \
					 succeeds (see Node::chain_freshness).",
					e
				);
			}

			let (stop_sender, _) = watch::channel(());

			// Spawn background task continuously syncing onchain, lightning, and fee rate cache.
			let stop_sync_receiver = stop_sender.subscribe();
			let layer = Arc::clone(&self.layer);
			runtime.spawn(async move {
				layer.continuously_sync_wallets(stop_sync_receiver).await;
			});

			let mut stop_tx_bcast = stop_sender.subscribe();
			let layer = Arc::clone(&self.layer);
			let tx_bcast_logger = Arc::clone(&self.logger);
			runtime.spawn(async move {
				// Every second we try to clear our broadcasting queue.
				let mut interval = tokio::time::interval(Duration::from_secs(1));
				interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
				loop {
					tokio::select! {
							_ = stop_tx_bcast.changed() => {
								log_debug!(
									tx_bcast_logger,
									"Stopping broadcasting transactions.",
								);
								return;
							}
							_ = interval.tick() => {
								layer.process_broadcast_queue().await;
							}
					}
				}
			});

			run.runtime = Some(runtime);
			run.stop_sender = Some(stop_sender);
		}

		run.attached += 1;
		Ok(target.id)
	}

	/// A node leaves: its target is removed, and if it was the last node the chain source
	/// is stopped and the host's tasks are told to end. Stopping the chain source before
	/// signalling the tasks is the order [`Node::stop`](crate::Node::stop) always had.
	pub(crate) fn detach(&self, id: TargetId) {
		let mut run = self.run.lock().unwrap_or_else(|e| e.into_inner());
		self.layer.unregister_target(id);
		if run.attached == 0 {
			debug_assert!(false, "detach without a matching attach");
			return;
		}
		run.attached -= 1;
		if run.attached == 0 {
			// Stop any runtime-dependant chain sources.
			self.layer.stop();
			if let Some(stop_sender) = run.stop_sender.take() {
				let _ = stop_sender.send(());
			}
			run.runtime = None;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::sync::atomic::{AtomicUsize, Ordering};

	use lightning::util::test_utils::TestStore;

	use crate::chain::engine::SyncEngine;
	use crate::chain::target::test_support::target_spec;
	use crate::chain::target::SyncTarget;
	use crate::chain::test_wallet::fresh_regtest_wallet;
	use crate::types::DynStore;
	use crate::Builder;

	use async_trait::async_trait;

	/// An engine that counts its starts and stops and syncs nothing.
	struct CountingEngine {
		starts: AtomicUsize,
		stops: AtomicUsize,
	}

	#[async_trait]
	impl SyncEngine for CountingEngine {
		fn name(&self) -> &'static str {
			"counting"
		}

		fn start(&self, _runtime: Arc<tokio::runtime::Runtime>) -> Result<(), Error> {
			self.starts.fetch_add(1, Ordering::SeqCst);
			Ok(())
		}

		fn stop(&self) {
			self.stops.fetch_add(1, Ordering::SeqCst);
		}

		async fn sync_once(
			&self, _layer: &ChainLayer, _target: &Arc<SyncTarget>,
		) -> Result<(), Error> {
			Ok(())
		}

		async fn run_background(
			&self, _layer: Arc<ChainLayer>, _stop_sync_receiver: watch::Receiver<()>,
		) {
		}
	}

	fn spec(label: &str, host: &ChainHost, logger: &Arc<Logger>) -> SyncTargetSpec {
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let wallet = fresh_regtest_wallet(
			&kv_store,
			host.tx_broadcaster(),
			host.fee_estimator(),
			logger,
		);
		target_spec(
			label,
			wallet,
			kv_store,
			Arc::clone(host.tx_broadcaster()),
			Arc::clone(host.fee_estimator()),
			Arc::clone(logger),
		)
	}

	/// The engine starts with the first attach and stops with the last detach, once each;
	/// a fresh attach after that starts it again.
	#[test]
	fn the_engine_runs_from_the_first_attach_to_the_last_detach() {
		let logger = Arc::new(Logger::new_log_facade());
		let engine = Arc::new(CountingEngine {
			starts: AtomicUsize::new(0),
			stops: AtomicUsize::new(0),
		});
		let layer = Arc::new(ChainLayer::with_engine_for_test(
			Arc::clone(&engine) as Arc<dyn SyncEngine>,
			Arc::clone(&logger),
		));
		let host = ChainHost::from_layer(
			layer,
			Arc::clone(&logger),
			#[cfg(feature = "cbf")]
			None,
		);
		let runtime =
			Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());

		assert_eq!(host.status().attached, 0);
		let a = host.attach(spec("a", &host, &logger), Arc::clone(&runtime)).unwrap();
		assert_eq!(host.status().attached, 1);
		assert_eq!(engine.starts.load(Ordering::SeqCst), 1);
		let b = host.attach(spec("b", &host, &logger), Arc::clone(&runtime)).unwrap();
		assert_eq!(host.status().attached, 2);
		assert_eq!(engine.starts.load(Ordering::SeqCst), 1, "started once for both");
		assert_eq!(host.layer().targets().len(), 2);

		host.detach(a);
		assert_eq!(host.status().attached, 1);
		assert_eq!(engine.stops.load(Ordering::SeqCst), 0, "b is still attached");
		assert_eq!(host.layer().targets().len(), 1);
		host.detach(b);
		assert_eq!(host.status().attached, 0);
		assert_eq!(engine.stops.load(Ordering::SeqCst), 1, "stopped once, at zero");
		assert!(host.layer().targets().is_empty());

		let c = host.attach(spec("c", &host, &logger), Arc::clone(&runtime)).unwrap();
		assert_eq!(engine.starts.load(Ordering::SeqCst), 2, "a fresh attach restarts");
		host.detach(c);
		assert_eq!(engine.stops.load(Ordering::SeqCst), 2);
		assert_eq!(host.status().engine, "counting");
	}

	/// Two nodes on one host: the host counts them, both come up and go down through it,
	/// and the host's chain source outlives the first of them to stop.
	#[test]
	fn two_nodes_share_one_host() {
		let logger = Arc::new(Logger::new_log_facade());
		let mut host_builder = ChainHostBuilder::new(Network::Regtest);
		host_builder
			.set_chain_source_esplora("http://127.0.0.1:1".to_string(), None)
			.set_logger(Arc::clone(&logger));
		let host = host_builder.build().expect("a host that connects to nothing");

		let build_node = |seed: u8| {
			let mut builder = Builder::new();
			builder.set_network(Network::Regtest);
			builder.set_log_facade_logger();
			builder.set_entropy_seed_bytes([seed; 64]);
			builder.set_chain_host(Arc::clone(&host));
			builder.build_with_store(Arc::new(TestStore::new(false))).expect("a node builds")
		};
		let alice = build_node(1);
		let bob = build_node(2);
		assert_ne!(alice.node_id(), bob.node_id());

		let runtime =
			Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
		alice.start_with_runtime(Arc::clone(&runtime)).unwrap();
		assert_eq!(host.status().attached, 1);
		bob.start_with_runtime(Arc::clone(&runtime)).unwrap();
		let status = host.status();
		assert_eq!(status.attached, 2);
		assert_eq!(status.engine, "esplora-tx-sync");
		assert!(alice.status().is_running && bob.status().is_running);

		alice.stop().unwrap();
		assert_eq!(host.status().attached, 1);
		assert!(bob.status().is_running, "the host kept running for bob");
		bob.stop().unwrap();
		assert_eq!(host.status().attached, 0);
	}

	/// A node builder with both a host and a chain source of its own is refused: the two
	/// would disagree on where the chain comes from.
	#[test]
	fn a_host_and_a_chain_source_on_one_builder_is_refused() {
		let host = {
			let mut b = ChainHostBuilder::new(Network::Regtest);
			b.set_chain_source_esplora("http://127.0.0.1:1".to_string(), None)
				.set_logger(Arc::new(Logger::new_log_facade()));
			b.build().unwrap()
		};
		let mut builder = Builder::new();
		builder.set_network(Network::Regtest);
		builder.set_log_facade_logger();
		builder.set_entropy_seed_bytes([3; 64]);
		builder.set_chain_host(host);
		builder.set_chain_source_esplora("http://127.0.0.1:2".to_string(), None);
		let err = builder.build_with_store(Arc::new(TestStore::new(false))).err();
		assert_eq!(err, Some(BuildError::ChainHostConflict));
	}
}
