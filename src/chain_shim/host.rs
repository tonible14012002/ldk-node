// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! One chain layer per process, shared by every [`Node`] that attaches to it.
//!
//! A [`ChainHost`] owns a chain layer — the chain source, the sync engine, the fee estimator
//! and the broadcaster — and runs its background work exactly once, however many nodes use it:
//! the first node to attach starts the engine, refreshes the fee cache and spawns the sync
//! loop and the broadcast drain; the last to detach stops them. Each node is one target of the
//! layer in between.
//!
//! Every node goes through a host, whether or not the application made one: a [`Builder`]
//! without [`Builder::set_chain_host`] builds a private host from its own chain configuration,
//! which is the node of before — one chain layer, one node — spelled the same way as N. There
//! is one code path.
//!
//! The host's tasks run on the runtime of the first node to attach. An application sharing a
//! host between nodes gives them one runtime ([`Node::start_with_runtime`]); the nodes' own
//! tasks each run on whatever runtime they were started with.
//!
//! The host and its builder are `node-chain`'s; these wrap them so this crate's builder
//! defaults (its file logger) and its error types stay what they were.
//!
//! [`Node`]: crate::Node
//! [`Builder`]: crate::Builder
//! [`Builder::set_chain_host`]: crate::Builder::set_chain_host
//! [`Node::start_with_runtime`]: crate::Node::start_with_runtime

use std::sync::Arc;

use bitcoin::Network;

use node_chain::config::{ChainConfig, EsploraSyncConfig, RawChainSourceConfig};
use node_chain::fee_estimator::OnchainFeeEstimator;
use node_chain::provider::{ChainDataProvider, WireBlockId, WireBlockUpdateAck, WireBlockUpdates};
use node_chain::session::trace::{InboundSpan, SessionObserver, TraceOrigin};
use node_chain::session::{ChainProviderSession, ChainSessionStatus, TipClaimCheck};
use node_chain::{ChainHostStatus, ChainLayer, TransactionBroadcaster};
use node_chain_ldk::ChainDataSourceConfig;

#[cfg(feature = "cbf")]
use node_chain::cbf::source::FilterSource;
#[cfg(feature = "cbf")]
use node_chain::config::CbfConfig;
#[cfg(feature = "cbf")]
use node_chain::provider::BundleTransport;

use super::{ChainTargetSpec, TargetId};
use crate::builder::BuildError;
use crate::config::{Config, DEFAULT_LOG_FILENAME, DEFAULT_LOG_LEVEL};
use crate::logger::Logger;
use crate::Error;

/// Builds a [`ChainHost`]: the chain-related half of [`Builder`], with the same setters,
/// so a configuration that used to pick a node's chain source now picks the host's.
///
/// Defaults match [`Builder`]: Esplora at `https://blockstream.info/api` on the configured
/// network, logging to `ldk_node.log` under the storage directory unless
/// [`ChainHostBuilder::set_logger`] says otherwise.
///
/// [`Builder`]: crate::Builder
pub struct ChainHostBuilder {
	inner: node_chain_ldk::ChainHostBuilder,
}

/// The logger a host built without [`ChainHostBuilder::set_logger`] writes to: the same
/// default a [`Builder`](crate::Builder) without a log setting picks, so a host built beside
/// such a node logs where the node does.
fn default_logger() -> node_chain_ldk::DefaultLogger {
	Arc::new(|config: &ChainConfig| {
		let log_file_path = format!("{}/{}", config.storage_dir_path, DEFAULT_LOG_FILENAME);
		let logger: Arc<node_chain::Logger> =
			Arc::new(Logger::new_fs_writer(log_file_path, DEFAULT_LOG_LEVEL)?);
		Ok(logger)
	})
}

impl ChainHostBuilder {
	/// A host on `network` with every other setting at its default.
	pub fn new(network: Network) -> Self {
		Self::from_config(Config { network, ..Config::default() })
	}

	/// A host from a full [`Config`]: its network, and its storage directory for what the
	/// chain source keeps on disk (the filter engine's header store).
	pub fn from_config(config: Config) -> Self {
		let mut inner = node_chain_ldk::ChainHostBuilder::from_config(ChainConfig::from(&config));
		inner.set_default_logger(default_logger());
		Self { inner }
	}

	/// The logger the host — and the chain layer every attached node shares — writes to.
	/// Without one the host logs to `ldk_node.log` under the storage directory.
	pub fn set_logger(&mut self, logger: Arc<Logger>) -> &mut Self {
		self.inner.set_logger(logger);
		self
	}

	/// See [`Builder::set_chain_source_esplora`](crate::Builder::set_chain_source_esplora).
	pub fn set_chain_source_esplora(
		&mut self, server_url: String, sync_config: Option<EsploraSyncConfig>,
	) -> &mut Self {
		self.inner.set_chain_source_esplora(server_url, sync_config);
		self
	}

	/// See [`Builder::set_chain_source_electrum`](crate::Builder::set_chain_source_electrum).
	pub fn set_chain_source_electrum(
		&mut self, server_url: String, sync_config: Option<node_chain::config::ElectrumSyncConfig>,
	) -> &mut Self {
		self.inner.set_chain_source_electrum(server_url, sync_config);
		self
	}

	/// See [`Builder::set_chain_source_bitcoind_rpc`](crate::Builder::set_chain_source_bitcoind_rpc).
	pub fn set_chain_source_bitcoind_rpc(
		&mut self, rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String,
	) -> &mut Self {
		self.inner.set_chain_source_bitcoind_rpc(rpc_host, rpc_port, rpc_user, rpc_password);
		self
	}

	/// See [`Builder::set_chain_source_bitcoind_rest`](crate::Builder::set_chain_source_bitcoind_rest).
	pub fn set_chain_source_bitcoind_rest(
		&mut self, rest_host: String, rest_port: u16, rpc_host: String, rpc_port: u16,
		rpc_user: String, rpc_password: String,
	) -> &mut Self {
		self.inner.set_chain_source_bitcoind_rest(
			rest_host,
			rest_port,
			rpc_host,
			rpc_port,
			rpc_user,
			rpc_password,
		);
		self
	}

	/// See [`Builder::set_chain_source_dependent`](crate::Builder::set_chain_source_dependent).
	pub fn set_chain_source_dependent(
		&mut self, provider: Arc<dyn ChainDataProvider>, sync_config: Option<EsploraSyncConfig>,
	) -> &mut Self {
		self.inner.set_chain_source_dependent(provider, sync_config);
		self
	}

	/// See [`Builder::set_chain_source_cbf`](crate::Builder::set_chain_source_cbf).
	#[cfg(feature = "cbf")]
	pub fn set_chain_source_cbf(&mut self, peers: Vec<String>, config: CbfConfig) -> &mut Self {
		self.inner.set_chain_source_cbf(peers, config);
		self
	}

	/// See [`Builder::set_chain_provider_fallback`](crate::Builder::set_chain_provider_fallback).
	#[cfg(feature = "cbf")]
	pub fn set_chain_provider_fallback(
		&mut self, provider: Arc<dyn ChainDataProvider>,
	) -> &mut Self {
		self.inner.set_chain_provider_fallback(provider);
		self
	}

	/// See [`Builder::set_cbf_filter_source`](crate::Builder::set_cbf_filter_source).
	#[cfg(feature = "cbf")]
	pub fn set_cbf_filter_source(&mut self, source: Arc<dyn FilterSource>) -> &mut Self {
		self.inner.set_cbf_filter_source(source);
		self
	}

	/// Reads the node filter source through per-block bundles: when its tip moves, one
	/// `chain.since` over `transport` answers the new blocks' headers, filter headers and
	/// filters, and carries the Pro's fee estimates, which then lead the FEE slot after an
	/// external fee server. The tip is polled as before, unless a provider session
	/// ([`Self::set_chain_source_cbf_with_session`]) holds a lease, and everything a bundle
	/// carries is verified as raw data is.
	///
	/// Wraps the source given to [`Self::set_cbf_filter_source`]; with a P2P CBF source there
	/// is nothing to bundle and the transport is ignored. A Pro that does not know the route
	/// leaves the node on the raw routes, and is asked again after half an hour.
	#[cfg(feature = "cbf")]
	pub fn set_cbf_bundle_transport(&mut self, transport: Arc<dyn BundleTransport>) -> &mut Self {
		self.inner.set_cbf_bundle_transport(transport);
		self
	}

	/// The Dependent tier over a provider session: every chain slot asks whichever Pro `session`
	/// follows, which it can change while the node runs, and the node starts fine following none.
	/// Delivery stays pull: this sync does not read bundles.
	pub fn set_chain_source_dependent_with_session(
		&mut self, session: Arc<ChainProviderSession>, sync_config: Option<EsploraSyncConfig>,
	) -> &mut Self {
		self.inner.set_chain_source_dependent_with_session(session, sync_config);
		self
	}

	/// A filter-following node over a provider session: the fallback provider, the filter source
	/// and the bundle transport of [`Self::set_chain_source_cbf`] all ask whichever Pro `session`
	/// follows, which it can change while the node runs, and the node starts fine following none.
	#[cfg(feature = "cbf")]
	pub fn set_chain_source_cbf_with_session(
		&mut self, peers: Vec<String>, config: CbfConfig, session: Arc<ChainProviderSession>,
	) -> &mut Self {
		self.inner.set_chain_source_cbf_with_session(peers, config, session);
		self
	}

	/// See [`Builder::set_raw_chain_source_bitcoind_rpc`](crate::Builder::set_raw_chain_source_bitcoind_rpc).
	pub fn set_raw_chain_source_bitcoind_rpc(
		&mut self, url: String, user: String, password: String, cert_sha256: Option<String>,
	) -> &mut Self {
		self.inner.set_raw_chain_source_bitcoind_rpc(url, user, password, cert_sha256);
		self
	}

	/// See [`Builder::set_raw_chain_source_allow_insecure_http`](crate::Builder::set_raw_chain_source_allow_insecure_http).
	pub fn set_raw_chain_source_allow_insecure_http(&mut self, allow: bool) -> &mut Self {
		self.inner.set_raw_chain_source_allow_insecure_http(allow);
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
		let inner = node_chain_ldk::ChainHostBuilder::from_node_config(
			ChainConfig::from(&config),
			chain_data_source_config,
			#[cfg(feature = "cbf")]
			chain_provider_fallback,
			#[cfg(feature = "cbf")]
			cbf_filter_source,
			raw_chain_source_config,
			logger,
		);
		Self { inner }
	}

	/// Builds the host. Nothing connects yet: the chain source is started by the first node
	/// to attach.
	pub fn build(self) -> Result<Arc<ChainHost>, BuildError> {
		let inner = self.inner.build().map_err(BuildError::from)?;
		Ok(Arc::new(ChainHost { inner }))
	}
}

impl From<node_chain_ldk::BuildError> for BuildError {
	fn from(e: node_chain_ldk::BuildError) -> Self {
		match e {
			node_chain_ldk::BuildError::LoggerSetupFailed => BuildError::LoggerSetupFailed,
			node_chain_ldk::BuildError::ChainSourceSetupFailed(_) => {
				BuildError::ChainSourceSetupFailed
			},
		}
	}
}

/// One chain layer, shared by every node attached to it. See the module docs.
pub struct ChainHost {
	inner: Arc<node_chain::ChainHost>,
}

impl std::fmt::Debug for ChainHost {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.inner.fmt(f)
	}
}

impl ChainHost {
	pub(crate) fn layer(&self) -> &Arc<ChainLayer> {
		self.inner.layer()
	}

	pub(crate) fn fee_estimator(&self) -> &Arc<OnchainFeeEstimator> {
		self.inner.fee_estimator()
	}

	pub(crate) fn tx_broadcaster(&self) -> &Arc<TransactionBroadcaster> {
		self.inner.tx_broadcaster()
	}

	/// The birthday a filter-following host's fresh wallets, channel managers and sweepers
	/// are seeded at; `None` for every other chain source.
	#[cfg(feature = "cbf")]
	pub(crate) fn wallet_birthday_height(&self) -> Option<u32> {
		self.inner.wallet_birthday_height()
	}

	/// What the host is doing now. Never blocks on the chain.
	pub fn status(&self) -> ChainHostStatus {
		self.inner.status()
	}

	/// The ordered Pro nodes this host's provider session walks; see
	/// [`ChainProviderSession::set_candidates`]. For local callers only: a peer must never choose
	/// a node's source. [`Error::ChainServeUnsupported`] on a host built without a session.
	pub fn chain_set_candidates(&self, candidates: Vec<String>) -> Result<(), Error> {
		Ok(self.inner.chain_set_candidates(candidates)?)
	}

	/// Who on the list is known longest; see [`ChainProviderSession::set_longest_known`].
	pub fn chain_set_longest_known(&self, known: Vec<String>) -> Result<(), Error> {
		Ok(self.inner.chain_set_longest_known(known)?)
	}

	/// Whether a tip `node_id` claims is backed by headers it will show, on this node's own checks;
	/// see [`ChainProviderSession::verify_tip_claim`]. [`Error::ChainServeUnsupported`] on a host
	/// built without a session.
	pub async fn chain_verify_tip_claim(
		&self, node_id: &str, claim: WireBlockId,
	) -> Result<TipClaimCheck, Error> {
		Ok(self.inner.chain_verify_tip_claim(node_id, claim).await?)
	}

	/// Whether the node may take a source off the list by itself; see
	/// [`ChainProviderSession::set_auto_source`]. For the owner only.
	pub fn chain_set_auto_source(&self, allowed: Option<bool>) -> Result<(), Error> {
		Ok(self.inner.chain_set_auto_source(allowed)?)
	}

	/// The owner's pinned source, or `None` to clear it; see
	/// [`ChainProviderSession::set_source`]. For local callers only.
	/// [`Error::ChainServeUnsupported`] on a host built without a session.
	pub fn chain_set_source(&self, node_id: Option<String>) -> Result<(), Error> {
		Ok(self.inner.chain_set_source(node_id)?)
	}

	/// [`Self::chain_set_source`] as part of a trace; see [`ChainProviderSession::set_source_traced`].
	pub fn chain_set_source_traced(
		&self, node_id: Option<String>, origin: Option<TraceOrigin>,
	) -> Result<bool, Error> {
		Ok(self.inner.chain_set_source_traced(node_id, origin)?)
	}

	/// The owner's choice of a source for now; see [`ChainProviderSession::use_source_traced`].
	pub fn chain_use_source_traced(
		&self, node_id: String, origin: Option<TraceOrigin>,
	) -> Result<Option<bool>, Error> {
		Ok(self.inner.chain_use_source_traced(node_id, origin)?)
	}

	/// Where the provider session tells what it does. Nothing on a host without a session.
	pub fn chain_set_observer(&self, observer: Arc<dyn SessionObserver>) {
		self.inner.chain_set_observer(observer)
	}

	/// Where the provider session stands; `None` on a host built without one. Never blocks on
	/// the chain.
	pub fn chain_session_status(&self) -> Option<ChainSessionStatus> {
		self.inner.chain_session_status()
	}

	/// The gossip card of `node_id` was last seen `age_secs` ago. Can only bring a probe forward;
	/// nothing on a host without a session.
	pub fn chain_note_card_age(&self, node_id: &str, age_secs: u64) {
		self.inner.chain_note_card_age(node_id, age_secs)
	}

	/// Takes a block update from `caller_node_id`, as the transport verified it; see
	/// [`ChainProviderSession::receive_block_update`]. [`Error::ChainServeUnsupported`] on a host
	/// built without a session.
	pub fn chain_receive_block_update(
		&self, caller_node_id: &str, push: &WireBlockUpdates,
	) -> Result<WireBlockUpdateAck, Error> {
		Ok(self.inner.chain_receive_block_update(caller_node_id, push)?)
	}

	/// [`Self::chain_receive_block_update`], with what it does under `inbound`.
	pub fn chain_receive_block_update_traced(
		&self, caller_node_id: &str, push: &WireBlockUpdates, inbound: Option<&InboundSpan>,
	) -> Result<WireBlockUpdateAck, Error> {
		Ok(self.inner.chain_receive_block_update_traced(caller_node_id, push, inbound)?)
	}

	/// A node joins: its target is registered, and if it is the first node the chain source
	/// is started, the fee cache refreshed once, and the sync loop and broadcast drain
	/// spawned on `runtime`. Returns the node's target id, for [`ChainHost::detach`].
	pub(crate) fn attach(
		&self, spec: ChainTargetSpec, runtime: Arc<tokio::runtime::Runtime>,
	) -> Result<TargetId, Error> {
		Ok(self.inner.attach(spec, runtime)?)
	}

	/// A node leaves: its target is removed, and if it was the last node the chain source
	/// is stopped and the host's tasks are told to end.
	pub(crate) fn detach(&self, id: TargetId) {
		self.inner.detach(id)
	}
}
