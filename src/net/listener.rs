// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! One Lightning port for every node in the process.
//!
//! A process running several wallets — several [`Node`]s — has one public address. An
//! [`InboundListener`] owns the socket bound there and hands each inbound connection to the
//! node it was dialed for: it peeks (never reads) the 50-byte BOLT 8 act one, checks it
//! against each registered node's static key ([`act_one`](super::act_one)), and passes the
//! socket, act one still in the kernel buffer, to that node's `PeerManager` through
//! `lightning_net_tokio::setup_inbound`. A connection meant for no registered node is
//! closed.
//!
//! Every node listens through one, whether or not the application made it: a [`Node`] built
//! without [`Builder::set_inbound_listener`] binds a private listener on start from its
//! [`Config::listening_addresses`] and registers itself as the only node — the node of
//! before, spelled the same way as N. There is one code path.
//!
//! Registration order is matching order, so the node that registers first (the primary)
//! is tried first.
//!
//! [`Node`]: crate::Node
//! [`Builder::set_inbound_listener`]: crate::Builder::set_inbound_listener
//! [`Config::listening_addresses`]: crate::config::Config::listening_addresses

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;

use lightning::ln::msgs::SocketAddress;
use lightning::sign::{NodeSigner, Recipient};

use tokio::sync::watch;

use crate::logger::{log_debug, log_error, log_info, log_trace, LdkLogger, Logger};
use crate::net::act_one::{act_one_matches, ACT_ONE_LEN};
use crate::types::{KeysManager, PeerManager};
use crate::Error;

/// How long a dialer has to send act one before the connection is dropped. LDK's own
/// handshake timeout is of the same order (a few ticks of its 10 s timer).
const ACT_ONE_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause between peeks while act one has arrived only in part, so a slow sender does not
/// turn the peek loop into a busy wait (a readable socket stays readable while we only peek).
const PARTIAL_PEEK_BACKOFF: Duration = Duration::from_millis(10);

/// Pause after a failed `accept` (e.g. out of file descriptors) before trying again.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// A node that takes connections from the listener.
#[derive(Clone)]
struct Registration {
	node_id: PublicKey,
	signer: Arc<KeysManager>,
	peer_manager: Arc<PeerManager>,
}

/// A Lightning TCP listener shared by the [`Node`]s of one process; see the
/// [module documentation](self).
///
/// Bind it once with [`InboundListener::bind`], give it to each node's builder with
/// [`Builder::set_inbound_listener`]; a node registers when it starts (if it has
/// [`Config::listening_addresses`]) and unregisters when it stops. The application stops
/// the listener with [`InboundListener::stop`] once no node needs it.
///
/// [`Node`]: crate::Node
/// [`Builder::set_inbound_listener`]: crate::Builder::set_inbound_listener
/// [`Config::listening_addresses`]: crate::config::Config::listening_addresses
pub struct InboundListener {
	registrations: Arc<RwLock<Vec<Registration>>>,
	listening: Arc<AtomicBool>,
	stop_sender: watch::Sender<bool>,
	local_addr: SocketAddr,
	logger: Arc<Logger>,
	/// The runtime the accept loop and the connections run on, kept alive as long as the
	/// listener is: the application may hand over its only reference.
	_runtime: Arc<tokio::runtime::Runtime>,
}

impl InboundListener {
	/// Binds the first of `addrs` that can be bound — the same rule as a node's own listener
	/// always had — and starts accepting on `runtime`, which the listener keeps alive (so,
	/// as for any tokio runtime, drop the last reference outside the runtime's own tasks).
	///
	/// Errors with [`Error::InvalidSocketAddress`] when an address does not resolve and with
	/// [`Error::ListenFailed`] when none can be bound.
	pub fn bind(
		addrs: Vec<SocketAddress>, runtime: Arc<tokio::runtime::Runtime>, logger: Arc<Logger>,
	) -> Result<Arc<Self>, Error> {
		let mut bind_addrs = Vec::with_capacity(addrs.len());
		for addr in &addrs {
			let resolved = addr.to_socket_addrs().map_err(|e| {
				log_error!(
					logger,
					"Unable to resolve listening address: {:?}. Error details: {}",
					addr,
					e,
				);
				Error::InvalidSocketAddress
			})?;
			bind_addrs.extend(resolved);
		}
		if bind_addrs.is_empty() {
			log_error!(logger, "No listening address to bind.");
			return Err(Error::InvalidSocketAddress);
		}

		let std_listener = std::net::TcpListener::bind(&*bind_addrs)
			.and_then(|l| l.set_nonblocking(true).map(|()| l))
			.map_err(|e| {
				log_error!(
					logger,
					"Failed to bind to listen addresses/ports - is something else already listening on it?: {}",
					e
				);
				Error::ListenFailed
			})?;
		let local_addr = std_listener.local_addr().map_err(|e| {
			log_error!(logger, "Failed to read the bound listening address: {}", e);
			Error::ListenFailed
		})?;
		let listener = {
			let _guard = runtime.enter();
			tokio::net::TcpListener::from_std(std_listener).map_err(|e| {
				log_error!(logger, "Failed to register the listening socket with tokio: {}", e);
				Error::ListenFailed
			})?
		};

		let (stop_sender, mut stop_receiver) = watch::channel(false);
		let this = Arc::new(Self {
			registrations: Arc::new(RwLock::new(Vec::new())),
			listening: Arc::new(AtomicBool::new(true)),
			stop_sender,
			local_addr,
			logger: Arc::clone(&logger),
			_runtime: Arc::clone(&runtime),
		});
		log_info!(logger, "Listening for inbound Lightning connections on {}", local_addr);

		let registrations = Arc::clone(&this.registrations);
		let listening = Arc::clone(&this.listening);
		runtime.spawn(async move {
			loop {
				tokio::select! {
					_ = stop_receiver.changed() => {
						log_debug!(logger, "Stopping listening to inbound connections.");
						break;
					}
					res = listener.accept() => match res {
						Ok((stream, remote)) => {
							let registrations = Arc::clone(&registrations);
							let logger = Arc::clone(&logger);
							tokio::spawn(async move {
								route_inbound(stream, remote, registrations, logger).await;
							});
						},
						Err(e) => {
							log_error!(logger, "Failed to accept an inbound connection: {}", e);
							tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
						},
					},
				}
			}
			listening.store(false, Ordering::Release);
		});

		Ok(this)
	}

	/// The address the listener is bound to (with the port the OS picked, if port 0 was
	/// asked for).
	pub fn local_addr(&self) -> SocketAddr {
		self.local_addr
	}

	/// Whether the listener still accepts connections: true from [`InboundListener::bind`]
	/// until [`InboundListener::stop`].
	pub fn is_listening(&self) -> bool {
		self.listening.load(Ordering::Acquire)
	}

	/// The node ids taking connections, in matching order.
	pub fn registered_node_ids(&self) -> Vec<PublicKey> {
		self.registrations.read().unwrap().iter().map(|r| r.node_id).collect()
	}

	/// Whether `node_id` takes connections from this listener.
	pub fn is_registered(&self, node_id: &PublicKey) -> bool {
		self.registrations.read().unwrap().iter().any(|r| r.node_id == *node_id)
	}

	/// Stops accepting connections and drops every registration. Connections already handed
	/// to a node are the node's. Idempotent.
	pub fn stop(&self) {
		self.registrations.write().unwrap().clear();
		let _ = self.stop_sender.send(true);
	}

	/// Routes connections dialed for `node_id` to `peer_manager`. A node registered again
	/// replaces its earlier registration in place, keeping its matching position.
	pub(crate) fn register(
		&self, node_id: PublicKey, signer: Arc<KeysManager>, peer_manager: Arc<PeerManager>,
	) {
		let registration = Registration { node_id, signer, peer_manager };
		let mut registrations = self.registrations.write().unwrap();
		match registrations.iter_mut().find(|r| r.node_id == node_id) {
			Some(existing) => *existing = registration,
			None => registrations.push(registration),
		}
		log_debug!(
			self.logger,
			"Node {} takes inbound connections on {}",
			node_id,
			self.local_addr
		);
	}

	/// Stops routing connections to `node_id`.
	pub(crate) fn unregister(&self, node_id: &PublicKey) {
		self.registrations.write().unwrap().retain(|r| r.node_id != *node_id);
		log_debug!(self.logger, "Node {} no longer takes inbound connections", node_id);
	}
}

impl std::fmt::Debug for InboundListener {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("InboundListener")
			.field("local_addr", &self.local_addr)
			.field("listening", &self.is_listening())
			.field("registered", &self.registered_node_ids())
			.finish()
	}
}

impl Drop for InboundListener {
	fn drop(&mut self) {
		let _ = self.stop_sender.send(true);
	}
}

/// Waits for act one without consuming it, finds the node it was written for and hands
/// that node the socket.
async fn route_inbound(
	stream: tokio::net::TcpStream, remote: SocketAddr,
	registrations: Arc<RwLock<Vec<Registration>>>, logger: Arc<Logger>,
) {
	let mut act_one = [0u8; ACT_ONE_LEN];
	let deadline = tokio::time::Instant::now() + ACT_ONE_TIMEOUT;
	loop {
		match tokio::time::timeout_at(deadline, stream.peek(&mut act_one)).await {
			Err(_) => {
				log_debug!(logger, "Inbound connection from {} sent no act one in time", remote);
				return;
			},
			Ok(Err(e)) => {
				log_debug!(
					logger,
					"Inbound connection from {} failed before act one: {}",
					remote,
					e
				);
				return;
			},
			Ok(Ok(0)) => {
				log_trace!(logger, "Inbound connection from {} closed before act one", remote);
				return;
			},
			Ok(Ok(n)) if n >= ACT_ONE_LEN => break,
			Ok(Ok(_)) => tokio::time::sleep(PARTIAL_PEEK_BACKOFF).await,
		}
	}

	let candidates = registrations.read().unwrap().clone();
	let matched = candidates.into_iter().find(|r| {
		act_one_matches(&act_one, &r.node_id, |their_ephemeral| {
			r.signer.ecdh(Recipient::Node, their_ephemeral, None)
		})
	});
	let registration = match matched {
		Some(registration) => registration,
		None => {
			log_debug!(
				logger,
				"Inbound connection from {} is for no node on this listener; closing",
				remote
			);
			return;
		},
	};

	log_trace!(logger, "Inbound connection from {} is for node {}", remote, registration.node_id);
	match stream.into_std() {
		Ok(std_stream) => {
			lightning_net_tokio::setup_inbound(registration.peer_manager, std_stream).await
		},
		Err(e) => {
			log_error!(logger, "Failed to hand inbound connection from {} over: {}", remote, e);
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::time::Instant;

	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use bitcoin::Network;
	use lightning::util::test_utils::TestStore;

	use crate::{Builder, Node};

	fn runtime() -> Arc<tokio::runtime::Runtime> {
		Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap())
	}

	fn loopback(port: u16) -> SocketAddress {
		SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port }
	}

	fn free_port() -> u16 {
		std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
	}

	/// A node on regtest with an unreachable chain source: enough to run the peer layer.
	fn builder(seed: u8) -> Builder {
		let mut builder = Builder::new();
		builder.set_network(Network::Regtest);
		builder.set_log_facade_logger();
		builder.set_entropy_seed_bytes([seed; 64]);
		builder.set_chain_source_esplora("http://127.0.0.1:1".to_string(), None);
		builder
	}

	fn build(builder: &Builder) -> Node {
		builder.build_with_store(Arc::new(TestStore::new(false))).unwrap()
	}

	fn wait_for_peer(node: &Node, peer: PublicKey) {
		let deadline = Instant::now() + Duration::from_secs(10);
		while !node.list_peers().iter().any(|p| p.node_id == peer && p.is_connected) {
			assert!(Instant::now() < deadline, "{} never saw {} connect", node.node_id(), peer);
			std::thread::sleep(Duration::from_millis(20));
		}
	}

	/// Two wallets behind one port: a dialer reaches each by its node id at the same
	/// address, both handshakes complete with the right node, and a node id nobody here
	/// holds is refused.
	#[test]
	fn two_nodes_take_connections_on_one_port() {
		let listener =
			InboundListener::bind(vec![loopback(0)], runtime(), Arc::new(Logger::new_log_facade()))
				.unwrap();
		let shared = loopback(listener.local_addr().port());

		let behind_listener = |seed| {
			let mut builder = builder(seed);
			builder.set_listening_addresses(vec![shared.clone()]).unwrap();
			builder.set_inbound_listener(Arc::clone(&listener));
			build(&builder)
		};
		let primary = behind_listener(41);
		let secondary = behind_listener(42);
		primary.start().unwrap();
		secondary.start().unwrap();
		assert_eq!(listener.registered_node_ids(), vec![primary.node_id(), secondary.node_id()]);
		assert!(primary.status().is_listening && secondary.status().is_listening);

		let dialer = build(&builder(43));
		dialer.start().unwrap();
		dialer.connect(primary.node_id(), shared.clone(), false).unwrap();
		dialer.connect(secondary.node_id(), shared.clone(), false).unwrap();
		wait_for_peer(&primary, dialer.node_id());
		wait_for_peer(&secondary, dialer.node_id());
		assert!(
			!primary.list_peers().iter().any(|p| p.node_id == secondary.node_id()),
			"each connection reached the node it was dialed for"
		);

		let stranger = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&[0x77; 32]).unwrap(),
		);
		assert_eq!(dialer.connect(stranger, shared.clone(), false), Err(Error::ConnectionFailed));

		// A stopped node leaves the listener; the listener and the other node carry on.
		secondary.stop().unwrap();
		assert!(!secondary.status().is_listening);
		assert_eq!(listener.registered_node_ids(), vec![primary.node_id()]);
		assert!(listener.is_listening() && primary.status().is_listening);

		dialer.stop().unwrap();
		primary.stop().unwrap();
		listener.stop();
		assert!(listener.registered_node_ids().is_empty());
	}

	/// Without a shared listener a node binds its own on start — through the same
	/// listener type — and closes it on stop.
	#[test]
	fn a_node_on_its_own_binds_a_private_listener() {
		let address = loopback(free_port());
		let mut own = builder(51);
		own.set_listening_addresses(vec![address.clone()]).unwrap();
		let node = build(&own);
		node.start().unwrap();
		assert!(node.status().is_listening);

		let dialer = build(&builder(52));
		dialer.start().unwrap();
		dialer.connect(node.node_id(), address.clone(), false).unwrap();
		wait_for_peer(&node, dialer.node_id());

		dialer.stop().unwrap();
		node.stop().unwrap();
		assert!(!node.status().is_listening);

		// The port is free again once the private listener is gone.
		let deadline = Instant::now() + Duration::from_secs(5);
		let SocketAddress::TcpIpV4 { port, .. } = address else { unreachable!() };
		while std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
			assert!(Instant::now() < deadline, "the private listener kept the port");
			std::thread::sleep(Duration::from_millis(20));
		}
	}

	/// A port something else holds fails the start instead of panicking a background task.
	#[test]
	fn a_taken_port_fails_the_start() {
		let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let port = squatter.local_addr().unwrap().port();
		let mut own = builder(53);
		own.set_listening_addresses(vec![loopback(port)]).unwrap();
		let node = build(&own);
		assert_eq!(node.start(), Err(Error::ListenFailed));
		assert!(!node.status().is_running);
		drop(squatter);
		node.start().unwrap();
		node.stop().unwrap();
	}

	/// A port something else holds need not keep the node down: started outbound-only it
	/// runs without a listener and dials out, its listening addresses unchanged, and its next
	/// start listens on them again.
	#[test]
	fn an_outbound_only_start_runs_while_the_port_is_taken() {
		let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let address = loopback(squatter.local_addr().unwrap().port());
		let mut own = builder(54);
		own.set_listening_addresses(vec![address.clone()]).unwrap();
		let node = build(&own);
		assert_eq!(node.start(), Err(Error::ListenFailed));

		node.start_outbound_only_with_runtime(runtime()).unwrap();
		assert!(node.status().is_running);
		assert!(!node.status().is_listening);
		assert_eq!(node.listening_addresses(), Some(vec![address.clone()]));

		let peer_address = loopback(free_port());
		let mut listening = builder(55);
		listening.set_listening_addresses(vec![peer_address.clone()]).unwrap();
		let peer = build(&listening);
		peer.start().unwrap();
		node.connect(peer.node_id(), peer_address, false).unwrap();
		wait_for_peer(&peer, node.node_id());
		peer.stop().unwrap();
		node.stop().unwrap();

		drop(squatter);
		node.start().unwrap();
		assert!(node.status().is_listening, "the next start listens again");
		node.stop().unwrap();
	}

	/// A start that cannot bind leaves nothing running on the runtime it was given: the bind
	/// comes before any task is spawned. An RGS node used to keep the gossip sync task of
	/// every failed start until it stopped.
	#[test]
	fn a_start_that_cannot_bind_leaves_no_task_behind() {
		let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let mut own = builder(56);
		own.set_listening_addresses(vec![loopback(squatter.local_addr().unwrap().port())]).unwrap();
		own.set_gossip_source_rgs("http://127.0.0.1:1".to_string());
		let node = build(&own);
		let runtime = runtime();
		assert_eq!(node.start_with_runtime(Arc::clone(&runtime)), Err(Error::ListenFailed));

		let deadline = Instant::now() + Duration::from_secs(10);
		while runtime.metrics().num_alive_tasks() > 0 {
			assert!(
				Instant::now() < deadline,
				"a failed start left {} task(s) running",
				runtime.metrics().num_alive_tasks()
			);
			std::thread::sleep(Duration::from_millis(20));
		}
	}
}
