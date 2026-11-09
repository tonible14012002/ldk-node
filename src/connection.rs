// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::logger::{log_debug, log_error, log_info, LdkLogger};
use crate::net::overlay::Overlay;
use crate::types::PeerManager;
use crate::Error;

use lightning::ln::msgs::SocketAddress;

use node_net::{DialError, NetStats, PeerAddress, PeerEvents, PeerStream, TcpTransport, Transport};

use bitcoin::secp256k1::PublicKey;

use std::collections::hash_map::{self, HashMap};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a TCP dial may take (lightning-net-tokio's figure, kept).
const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Number of consecutive failed dial attempts between ERROR-level reports for a
/// single peer.
///
/// A node whose peer pool contains many unreachable addresses redials them on
/// every sweep, and logging each attempt makes the failures the largest thing
/// in the log while telling an operator nothing the first one did not. The
/// first failure and every `CONNECT_FAILURE_LOG_INTERVAL`-th one after it are
/// reported at ERROR; the attempts in between stay at DEBUG.
const CONNECT_FAILURE_LOG_INTERVAL: u64 = 64;

pub(crate) struct ConnectionManager<L: Deref + Clone + Sync + Send>
where
	L::Target: LdkLogger,
{
	pending_connections:
		Mutex<HashMap<PublicKey, Vec<tokio::sync::oneshot::Sender<Result<(), Error>>>>>,
	/// Consecutive failed dial attempts per peer, used to rate-limit the
	/// failure reports. An entry is removed as soon as the peer connects, so
	/// the map is bounded by the number of peers that are currently failing.
	connect_failures: Mutex<HashMap<PublicKey, u64>>,
	peer_manager: Arc<PeerManager>,
	/// Dialled first when present; see [`Overlay`].
	overlay: Option<Arc<Overlay>>,
	/// Every dial attempt, per transport.
	stats: Arc<NetStats>,
	logger: L,
}

impl<L: Deref + Clone + Sync + Send> ConnectionManager<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(
		peer_manager: Arc<PeerManager>, overlay: Option<Arc<Overlay>>, logger: L,
	) -> Self {
		let pending_connections = Mutex::new(HashMap::new());
		let connect_failures = Mutex::new(HashMap::new());
		let stats = Arc::new(NetStats::default());
		Self { pending_connections, connect_failures, peer_manager, overlay, stats, logger }
	}

	/// The overlay this node dials first, if any.
	pub(crate) fn overlay(&self) -> Option<&Arc<Overlay>> {
		self.overlay.as_ref()
	}

	/// What this node's dials did, per transport.
	pub(crate) fn stats(&self) -> &Arc<NetStats> {
		&self.stats
	}

	pub(crate) async fn connect_peer_if_necessary(
		&self, node_id: PublicKey, addr: SocketAddress,
	) -> Result<(), Error> {
		if self.peer_manager.peer_by_node_id(&node_id).is_some() {
			return Ok(());
		}

		self.do_connect_peer(node_id, addr).await
	}

	pub(crate) async fn do_connect_peer(
		&self, node_id: PublicKey, addr: SocketAddress,
	) -> Result<(), Error> {
		// First, we check if there is already an outbound connection in flight, if so, we just
		// await on the corresponding watch channel. The task driving the connection future will
		// send us the result..
		let pending_ready_receiver_opt = self.register_or_subscribe_pending_connection(&node_id);
		if let Some(pending_connection_ready_receiver) = pending_ready_receiver_opt {
			return pending_connection_ready_receiver.await.map_err(|e| {
				debug_assert!(false, "Failed to receive connection result: {:?}", e);
				log_error!(self.logger, "Failed to receive connection result: {:?}", e);
				Error::ConnectionFailed
			})?;
		}

		log_debug!(self.logger, "Connecting to peer: {}@{}", node_id, addr);

		let res = self.dial_and_handshake(node_id, &addr).await;
		match res {
			Ok(()) => self.clear_connect_failures(&node_id),
			Err(Error::ConnectionFailed) => self.log_connect_failure(&node_id, &addr),
			Err(_) => {},
		}
		self.propagate_result_to_subscribers(&node_id, res);
		res
	}

	/// Overlay first, then TCP: the first stream on which the BOLT 8 handshake completes.
	///
	/// A stream is not yet a connection — the handshake can still fail on it (an endpoint that
	/// is not the node, a peer that refuses) — so a failed handshake on the overlay falls
	/// through to TCP like a failed dial does.
	async fn dial_and_handshake(
		&self, node_id: PublicKey, addr: &SocketAddress,
	) -> Result<(), Error> {
		let peer = node_net_ldk::peer_id(&node_id);
		let target = node_net_ldk::peer_address(addr);

		if let Some(overlay) = &self.overlay {
			match overlay.dial(peer, &*self.stats).await {
				Ok(stream) => {
					if self.handshake(node_id, stream, overlay.name()).await.is_ok() {
						return Ok(());
					}
					log_debug!(
						self.logger,
						"Overlay '{}' reached {} but the handshake did not complete",
						overlay.name(),
						node_id
					);
				},
				Err(e) => {
					log_debug!(
						self.logger,
						"Overlay '{}' did not reach {}: {}",
						overlay.name(),
						node_id,
						e
					);
				},
			}
			if !overlay.config().tcp_fallback {
				return Err(Error::ConnectionFailed);
			}
		}

		if target == PeerAddress::Overlay {
			// Known only by node id, and the overlay did not reach it.
			return Err(Error::ConnectionFailed);
		}
		let started = Instant::now();
		let dialed =
			match tokio::time::timeout(TCP_DIAL_TIMEOUT, TcpTransport.dial(peer, &target)).await {
				Ok(result) => result,
				Err(_) => Err(DialError::Timeout(TCP_DIAL_TIMEOUT)),
			};
		self.stats.on_dial(&peer, "tcp", dialed.as_ref().map(|_| ()), started.elapsed());
		match dialed {
			Ok(stream) => self.handshake(node_id, stream, "tcp").await,
			Err(DialError::Unresolved(e)) => {
				log_error!(self.logger, "Failed to resolve network address {}: {}", addr, e);
				Err(Error::InvalidSocketAddress)
			},
			Err(_) => Err(Error::ConnectionFailed),
		}
	}

	/// Runs LDK over `stream` until the handshake with `node_id` completes or the stream
	/// closes.
	async fn handshake(
		&self, node_id: PublicKey, stream: PeerStream, transport: &'static str,
	) -> Result<(), Error> {
		let info = stream.info().to_string();
		let closed = node_net_ldk::setup_outbound(Arc::clone(&self.peer_manager), node_id, stream);
		if closed.was_refused() {
			return Err(Error::ConnectionFailed);
		}
		let mut closed = Box::pin(closed);
		loop {
			tokio::select! {
				_ = &mut closed => {
					log_info!(self.logger, "Peer connection closed: {} ({})", node_id, info);
					return Err(Error::ConnectionFailed);
				},
				_ = tokio::time::sleep(Duration::from_millis(10)) => {},
			};
			if self.peer_manager.peer_by_node_id(&node_id).is_some() {
				self.stats.on_connected(&node_net_ldk::peer_id(&node_id), transport);
				log_debug!(self.logger, "Connected to peer {} over {}", node_id, info);
				return Ok(());
			}
		}
	}

	/// Records a failed dial and reports it at a rate that does not scale with
	/// how often the peer is retried. See [`CONNECT_FAILURE_LOG_INTERVAL`].
	fn log_connect_failure(&self, node_id: &PublicKey, addr: &SocketAddress) {
		let failures = {
			let mut connect_failures_lock = self.connect_failures.lock().unwrap();
			let entry = connect_failures_lock.entry(*node_id).or_insert(0);
			*entry = entry.saturating_add(1);
			*entry
		};

		if failures == 1 || failures % CONNECT_FAILURE_LOG_INTERVAL == 0 {
			log_error!(
				self.logger,
				"Failed to connect to peer: {}@{} ({} consecutive failures)",
				node_id,
				addr,
				failures
			);
		} else {
			log_debug!(self.logger, "Failed to connect to peer: {}@{}", node_id, addr);
		}
	}

	/// Clears the failure count for a peer that just connected, reporting the
	/// recovery when there was a run of failures to clear.
	fn clear_connect_failures(&self, node_id: &PublicKey) {
		let failures = self.connect_failures.lock().unwrap().remove(node_id);
		if let Some(failures) = failures.filter(|failures| *failures > 0) {
			log_info!(
				self.logger,
				"Connected to peer {} after {} failed attempts",
				node_id,
				failures
			);
		}
	}

	fn register_or_subscribe_pending_connection(
		&self, node_id: &PublicKey,
	) -> Option<tokio::sync::oneshot::Receiver<Result<(), Error>>> {
		let mut pending_connections_lock = self.pending_connections.lock().unwrap();
		match pending_connections_lock.entry(*node_id) {
			hash_map::Entry::Occupied(mut entry) => {
				let (tx, rx) = tokio::sync::oneshot::channel();
				entry.get_mut().push(tx);
				Some(rx)
			},
			hash_map::Entry::Vacant(entry) => {
				entry.insert(Vec::new());
				None
			},
		}
	}

	fn propagate_result_to_subscribers(&self, node_id: &PublicKey, res: Result<(), Error>) {
		// Send the result to any other tasks that might be waiting on it by now.
		let mut pending_connections_lock = self.pending_connections.lock().unwrap();
		if let Some(connection_ready_senders) = pending_connections_lock.remove(node_id) {
			for sender in connection_ready_senders {
				let _ = sender.send(res).map_err(|e| {
					debug_assert!(
						false,
						"Failed to send connection result to subscribers: {:?}",
						e
					);
					log_error!(
						self.logger,
						"Failed to send connection result to subscribers: {:?}",
						e
					);
				});
			}
		}
	}
}
