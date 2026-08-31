// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::logger::{log_debug, log_error, log_info, LdkLogger};
use crate::types::PeerManager;
use crate::Error;

use lightning::ln::msgs::SocketAddress;

use bitcoin::secp256k1::PublicKey;

use std::collections::hash_map::{self, HashMap};
use std::net::ToSocketAddrs;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
	logger: L,
}

impl<L: Deref + Clone + Sync + Send> ConnectionManager<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(peer_manager: Arc<PeerManager>, logger: L) -> Self {
		let pending_connections = Mutex::new(HashMap::new());
		let connect_failures = Mutex::new(HashMap::new());
		Self { pending_connections, connect_failures, peer_manager, logger }
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

		let socket_addr = addr
			.to_socket_addrs()
			.map_err(|e| {
				log_error!(self.logger, "Failed to resolve network address {}: {}", addr, e);
				self.propagate_result_to_subscribers(&node_id, Err(Error::InvalidSocketAddress));
				Error::InvalidSocketAddress
			})?
			.next()
			.ok_or_else(|| {
				log_error!(self.logger, "Failed to resolve network address {}", addr);
				self.propagate_result_to_subscribers(&node_id, Err(Error::InvalidSocketAddress));
				Error::InvalidSocketAddress
			})?;

		let connection_future = lightning_net_tokio::connect_outbound(
			Arc::clone(&self.peer_manager),
			node_id,
			socket_addr,
		);

		let res = match connection_future.await {
			Some(connection_closed_future) => {
				let mut connection_closed_future = Box::pin(connection_closed_future);
				loop {
					tokio::select! {
						_ = &mut connection_closed_future => {
							log_info!(self.logger, "Peer connection closed: {}@{}", node_id, addr);
							break Err(Error::ConnectionFailed);
						},
						_ = tokio::time::sleep(Duration::from_millis(10)) => {},
					};

					match self.peer_manager.peer_by_node_id(&node_id) {
						Some(_) => break Ok(()),
						None => continue,
					}
				}
			},
			None => {
				self.log_connect_failure(&node_id, &addr);
				Err(Error::ConnectionFailed)
			},
		};

		if res.is_ok() {
			self.clear_connect_failures(&node_id);
		}

		self.propagate_result_to_subscribers(&node_id, res);

		res
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
