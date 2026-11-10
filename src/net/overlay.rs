// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Lightning over an overlay network: dial a node by its id alone, take inbound streams the
//! overlay delivers.
//!
//! On a Node the overlay is the platform's iroh/QUIC network: the iroh app owns the endpoint
//! (hole punching, relays, the signed gossip card that maps a node id to it), and hands the
//! Lightning app each session as one end of a host pipe (node-net ADR 0001). This module does
//! not know that. It holds a [`node_net::Transport`] to dial with and an
//! [`node_net::InboundRouter`] that hands each inbound stream to the node its act one was
//! written for — the same door the TCP listener uses, so several wallets in one process are
//! reachable over one overlay identity as they are over one port.
//!
//! A node built with [`Builder::set_overlay`] dials every peer over the overlay first and
//! falls back to TCP at the peer's stored address (unless [`OverlayConfig::tcp_fallback`] is
//! off, or the address is [`overlay_address`]: a peer known only by node id). While running it
//! takes inbound overlay streams when it takes inbound connections at all (it has
//! [`Config::listening_addresses`]); no port is involved.
//!
//! [`Builder::set_overlay`]: crate::Builder::set_overlay
//! [`Config::listening_addresses`]: crate::config::Config::listening_addresses
//! [`overlay_address`]: crate::overlay_address

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::secp256k1::PublicKey;

use node_net::overlay::wire::AcceptRequest;
use node_net::{
	DialError, InboundRouter, Invoker, NetStats, PeerAddress, PeerEvents, PeerId, PeerStream,
	RouteOutcome, StreamInfo, Transport, TransportStats,
};

use crate::logger::{log_debug, log_info, log_trace, LdkLogger, Logger};
use crate::net::target::NodeTarget;
use crate::types::{KeysManager, PeerManager};
use crate::Error;

/// How an [`Overlay`] dials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayConfig {
	/// The budget of one overlay dial, resolution and connection included. A dial to a node
	/// with no overlay identity answers at once; this bounds an unreachable one.
	pub dial_timeout: Duration,
	/// Whether a peer the overlay cannot reach is then dialled over TCP at its stored address.
	/// Off, a node with an overlay never dials TCP (outside Lightning nodes become unreachable
	/// from it); the end-to-end proof runs that way.
	pub tcp_fallback: bool,
}

impl Default for OverlayConfig {
	fn default() -> Self {
		Self { dial_timeout: Duration::from_secs(20), tcp_fallback: true }
	}
}

/// The overlay the nodes of one process share; see the [module documentation](self).
pub struct Overlay {
	transport: Arc<dyn Transport>,
	config: OverlayConfig,
	router: Arc<InboundRouter>,
	stats: Arc<NetStats>,
	logger: Arc<Logger>,
	/// Where inbound streams are routed and their connections run, kept alive as long as the
	/// overlay is: the application may hand over its only reference.
	runtime: Arc<tokio::runtime::Runtime>,
}

impl Overlay {
	/// An overlay dialling through `transport`, routing inbound streams on `runtime`.
	pub fn new(
		transport: Arc<dyn Transport>, config: OverlayConfig,
		runtime: Arc<tokio::runtime::Runtime>, logger: Arc<Logger>,
	) -> Arc<Self> {
		let stats = Arc::new(NetStats::default());
		let router = Arc::new(
			InboundRouter::default().with_events(Arc::clone(&stats) as Arc<dyn PeerEvents>),
		);
		log_info!(
			logger,
			"Lightning overlay '{}' up (TCP fallback {})",
			transport.name(),
			if config.tcp_fallback { "on" } else { "off" }
		);
		Arc::new(Self { transport, config, router, stats, logger, runtime })
	}

	/// The overlay transport's name (`"iroh"`).
	pub fn name(&self) -> &'static str {
		self.transport.name()
	}

	/// How it dials.
	pub fn config(&self) -> OverlayConfig {
		self.config
	}

	/// Routes an inbound stream to the node its act one names, on the overlay's runtime.
	pub fn accept(&self, stream: PeerStream) {
		let router = Arc::clone(&self.router);
		let logger = Arc::clone(&self.logger);
		self.runtime.spawn(async move {
			let info = stream.info().to_string();
			match router.route(stream).await {
				RouteOutcome::Routed(node) => {
					log_trace!(logger, "Inbound overlay stream ({}) is for node {}", info, node);
				},
				outcome => {
					log_debug!(
						logger,
						"Inbound overlay stream ({}) not routed: {:?}",
						info,
						outcome
					);
				},
			}
		});
	}

	/// Routes an inbound stream that arrives as an owned socket (one end of a host pipe). The
	/// socket is registered with the overlay's runtime, which will drive it.
	pub fn accept_fd(&self, fd: OwnedFd, info: StreamInfo) -> Result<(), Error> {
		let stream = {
			let _guard = self.runtime.enter();
			node_net::pipe::peer_stream(fd, info).map_err(|e| {
				log_debug!(self.logger, "Could not take an inbound overlay stream: {}", e);
				Error::ConnectionFailed
			})?
		};
		self.accept(stream);
		Ok(())
	}

	/// The inbound half of a capability overlay: claims the pipe `request` names through
	/// `invoker` (the host's `core.pipe.claim`) and routes it.
	pub fn accept_claimed(
		&self, invoker: &dyn Invoker, request: &AcceptRequest,
	) -> Result<(), Error> {
		let (fd, _) = node_net::pipe::claim(invoker, &request.pipe_token).map_err(|e| {
			log_debug!(self.logger, "Could not claim an inbound overlay stream: {}", e);
			Error::ConnectionFailed
		})?;
		self.accept_fd(fd, StreamInfo::overlay(self.name(), request.remote_endpoint_id.clone()))
	}

	/// The node ids taking overlay connections, in matching order.
	pub fn registered_node_ids(&self) -> Vec<PublicKey> {
		self.router.registered().iter().filter_map(node_net_ldk::public_key).collect()
	}

	/// Whether `node_id` takes overlay connections.
	pub fn is_registered(&self, node_id: &PublicKey) -> bool {
		self.router.is_registered(&node_net_ldk::peer_id(node_id))
	}

	/// What the overlay's inbound door did, per transport.
	pub fn stats(&self) -> BTreeMap<String, TransportStats> {
		self.stats.snapshot()
	}

	pub(crate) fn register(
		&self, node_id: PublicKey, signer: Arc<KeysManager>, peer_manager: Arc<PeerManager>,
	) {
		self.router.register(Arc::new(NodeTarget::new(node_id, signer, peer_manager)));
		log_debug!(self.logger, "Node {} takes inbound '{}' connections", node_id, self.name());
	}

	pub(crate) fn unregister(&self, node_id: &PublicKey) {
		self.router.unregister(&node_net_ldk::peer_id(node_id));
	}

	/// One overlay dial under the configured budget, reported to `events`.
	pub(crate) async fn dial(
		&self, peer: PeerId, events: &dyn PeerEvents,
	) -> Result<PeerStream, DialError> {
		let started = Instant::now();
		let result = match tokio::time::timeout(
			self.config.dial_timeout,
			self.transport.dial(peer, &PeerAddress::Overlay),
		)
		.await
		{
			Ok(result) => result,
			Err(_) => Err(DialError::Timeout(self.config.dial_timeout)),
		};
		events.on_dial(&peer, self.name(), result.as_ref().map(|_| ()), started.elapsed());
		result
	}
}

impl std::fmt::Debug for Overlay {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Overlay")
			.field("transport", &self.name())
			.field("config", &self.config)
			.field("registered", &self.registered_node_ids())
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::sync::Mutex;

	use bitcoin::Network;
	use lightning::ln::msgs::SocketAddress;
	use lightning::util::test_utils::TestStore;
	use node_net::BoxFuture;

	use crate::{Builder, Node};

	/// The overlay's side of the platform in miniature: what the iroh app and the host broker
	/// do for real (node-net ADR 0001), here a process-local switchboard. A dial finds the
	/// overlay hosting the node id, makes a Unix socket pair — what `core.pipe.open` makes —
	/// hands one end to that overlay's inbound door and returns the other.
	#[derive(Default)]
	struct Switchboard {
		overlays: Mutex<Vec<Arc<Overlay>>>,
		/// Nodes the board knows but that do not take sessions on it: what a Node on an older
		/// release is to the iroh overlay (a card without the Lightning tag).
		not_on_it: Mutex<Vec<PublicKey>>,
	}

	struct SwitchboardTransport(Arc<Switchboard>);

	impl Transport for SwitchboardTransport {
		fn name(&self) -> &'static str {
			"memory-overlay"
		}

		fn dial<'a>(
			&'a self, peer: PeerId, _addr: &'a PeerAddress,
		) -> BoxFuture<'a, Result<PeerStream, DialError>> {
			Box::pin(async move {
				let key = node_net_ldk::public_key(&peer).ok_or(DialError::Unsupported)?;
				if self.0.not_on_it.lock().unwrap().contains(&key) {
					return Err(DialError::Unsupported);
				}
				let remote = self
					.0
					.overlays
					.lock()
					.unwrap()
					.iter()
					.find(|overlay| overlay.is_registered(&key))
					.cloned()
					.ok_or_else(|| DialError::Unresolved("no overlay hosts this node".into()))?;
				let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
				remote
					.accept_fd(OwnedFd::from(theirs), StreamInfo::overlay("memory-overlay", None))
					.map_err(|e| DialError::Platform(e.to_string()))?;
				Ok(node_net::pipe::peer_stream(
					OwnedFd::from(ours),
					StreamInfo::overlay("memory-overlay", None),
				)?)
			})
		}
	}

	fn runtime() -> Arc<tokio::runtime::Runtime> {
		Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap())
	}

	fn overlay(board: &Arc<Switchboard>, tcp_fallback: bool) -> Arc<Overlay> {
		let overlay = Overlay::new(
			Arc::new(SwitchboardTransport(Arc::clone(board))),
			OverlayConfig { dial_timeout: Duration::from_secs(10), tcp_fallback },
			runtime(),
			Arc::new(Logger::new_log_facade()),
		);
		board.overlays.lock().unwrap().push(Arc::clone(&overlay));
		overlay
	}

	fn loopback(port: u16) -> SocketAddress {
		SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port }
	}

	fn free_port() -> u16 {
		std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
	}

	/// A regtest node with an unreachable chain source and its own TCP port: enough to run
	/// the peer layer.
	fn node(seed: u8, overlay: Option<&Arc<Overlay>>) -> (Node, SocketAddress) {
		let address = loopback(free_port());
		let mut builder = Builder::new();
		builder.set_network(Network::Regtest);
		builder.set_log_facade_logger();
		builder.set_entropy_seed_bytes([seed; 64]);
		builder.set_chain_source_esplora("http://127.0.0.1:1".to_string(), None);
		builder.set_listening_addresses(vec![address.clone()]).unwrap();
		if let Some(overlay) = overlay {
			builder.set_overlay(Arc::clone(overlay));
		}
		let node = builder.build_with_store(Arc::new(TestStore::new(false))).unwrap();
		node.start().unwrap();
		(node, address)
	}

	fn wait_for_peer(node: &Node, peer: PublicKey) {
		let deadline = Instant::now() + Duration::from_secs(10);
		while !node.list_peers().iter().any(|p| p.node_id == peer && p.is_connected) {
			assert!(Instant::now() < deadline, "{} never saw {} connect", node.node_id(), peer);
			std::thread::sleep(Duration::from_millis(20));
		}
	}

	/// Two nodes in different "processes" (each its own overlay), TCP off: a dial by node id
	/// alone completes BOLT 8 over the overlay, the peer is kept under the overlay address,
	/// and no TCP dial is ever made.
	#[test]
	fn two_nodes_connect_over_the_overlay_with_tcp_off() {
		let board = Arc::new(Switchboard::default());
		let (overlay_a, overlay_b) = (overlay(&board, false), overlay(&board, false));
		let (a, _) = node(61, Some(&overlay_a));
		let (b, _) = node(62, Some(&overlay_b));
		assert_eq!(overlay_b.registered_node_ids(), vec![b.node_id()]);

		a.connect(b.node_id(), crate::overlay_address(), true).unwrap();
		wait_for_peer(&b, a.node_id());
		let kept = a.list_peers().into_iter().find(|p| p.node_id == b.node_id()).unwrap();
		assert!(kept.is_persisted && crate::is_overlay_address(&kept.address));

		let stats = a.network_stats();
		assert_eq!(stats.overlay_name, Some("memory-overlay"));
		assert_eq!(stats.dials["memory-overlay"].connected, 1);
		assert!(!stats.dials.contains_key("tcp"), "no TCP dial: {:?}", stats.dials);
		assert_eq!(b.network_stats().overlay.unwrap()["memory-overlay"].inbound_routed, 1);

		// A node id no overlay hosts fails fast and, with TCP off, is not dialled over TCP.
		let (c, c_address) = node(63, None);
		assert_eq!(a.connect(c.node_id(), c_address, false), Err(Error::ConnectionFailed));
		assert!(!a.network_stats().dials.contains_key("tcp"));

		// A stopped node leaves the overlay.
		b.stop().unwrap();
		assert!(overlay_b.registered_node_ids().is_empty());
		a.stop().unwrap();
		c.stop().unwrap();
	}

	/// Two wallets behind one overlay identity: a dialer reaches each by its node id, each
	/// handshake completes with the node it was meant for.
	#[test]
	fn two_wallets_share_one_overlay() {
		let board = Arc::new(Switchboard::default());
		let (shared, dialer_overlay) = (overlay(&board, false), overlay(&board, false));
		let (primary, _) = node(71, Some(&shared));
		let (secondary, _) = node(72, Some(&shared));
		assert_eq!(shared.registered_node_ids(), vec![primary.node_id(), secondary.node_id()]);
		let (dialer, _) = node(73, Some(&dialer_overlay));

		dialer.connect(primary.node_id(), crate::overlay_address(), false).unwrap();
		dialer.connect(secondary.node_id(), crate::overlay_address(), false).unwrap();
		wait_for_peer(&primary, dialer.node_id());
		wait_for_peer(&secondary, dialer.node_id());
		assert!(!primary.list_peers().iter().any(|p| p.node_id == secondary.node_id()));
		assert_eq!(shared.stats()["memory-overlay"].inbound_routed, 2);

		for node in [dialer, primary, secondary] {
			node.stop().unwrap();
		}
	}

	/// An outside Lightning node (no overlay identity): the overlay misses at once and the
	/// dial falls back to TCP at the stored address.
	#[test]
	fn an_overlay_miss_falls_back_to_tcp() {
		let board = Arc::new(Switchboard::default());
		let overlay_a = overlay(&board, true);
		let (a, _) = node(81, Some(&overlay_a));
		let (outside, outside_address) = node(82, None);

		a.connect(outside.node_id(), outside_address, false).unwrap();
		wait_for_peer(&outside, a.node_id());
		let stats = a.network_stats().dials;
		assert_eq!(stats["memory-overlay"].dial_skipped, 1);
		assert_eq!(stats["memory-overlay"].dial_attempts, 0, "a miss is not an attempt");
		assert_eq!(stats["memory-overlay"].last_error.as_deref(), Some("unresolved"));
		assert_eq!(stats["tcp"].connected, 1);

		a.stop().unwrap();
		outside.stop().unwrap();
	}

	/// A mixed fleet: a Node the overlay knows but that does not take sessions on it (an older
	/// release) is dialled over TCP at once, both ways — the upgraded node at the old one's
	/// stored address, the old one into the upgraded node's TCP listener, which it keeps.
	#[test]
	fn a_node_not_on_the_overlay_is_reached_over_tcp_both_ways() {
		let board = Arc::new(Switchboard::default());
		let upgraded_overlay = overlay(&board, true);
		let (upgraded, upgraded_address) = node(91, Some(&upgraded_overlay));
		let (old, old_address) = node(92, None);
		board.not_on_it.lock().unwrap().push(old.node_id());

		let started = Instant::now();
		upgraded.connect(old.node_id(), old_address, true).unwrap();
		assert!(started.elapsed() < Duration::from_secs(5), "waited on the overlay");
		wait_for_peer(&old, upgraded.node_id());
		let stats = upgraded.network_stats().dials;
		let overlay_dials = &stats["memory-overlay"];
		assert_eq!((overlay_dials.dial_attempts, overlay_dials.dial_skipped), (0, 1));
		assert_eq!(overlay_dials.last_error.as_deref(), Some("unsupported"));
		assert_eq!(stats["tcp"].connected, 1);

		// Until both sides saw the close: `connect` on a side that still holds the session is
		// a no-op.
		upgraded.disconnect(old.node_id()).unwrap();
		let deadline = Instant::now() + Duration::from_secs(10);
		let holds = |node: &Node, peer: PublicKey| {
			node.list_peers().iter().any(|p| p.node_id == peer && p.is_connected)
		};
		while holds(&upgraded, old.node_id()) || holds(&old, upgraded.node_id()) {
			assert!(Instant::now() < deadline, "the disconnect never landed");
			std::thread::sleep(Duration::from_millis(20));
		}
		old.connect(upgraded.node_id(), upgraded_address, false).unwrap();
		wait_for_peer(&upgraded, old.node_id());
		let listener = upgraded.network_stats().listener.unwrap();
		assert_eq!(listener.values().map(|s| s.inbound_routed).sum::<u64>(), 1);
		assert_eq!(upgraded_overlay.stats().values().map(|s| s.inbound_routed).sum::<u64>(), 0);

		upgraded.stop().unwrap();
		old.stop().unwrap();
	}
}
