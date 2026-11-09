// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A node as an inbound door sees it: which act ones are its, and where its connections go.

use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;

use lightning::sign::{NodeSigner, Recipient};

use node_net::bolt8::{act_one_matches, ACT_ONE_LEN};
use node_net::{InboundTarget, PeerId, PeerStream};

use crate::types::{KeysManager, PeerManager};

/// One node taking connections through an [`node_net::InboundRouter`]: the TCP listener's or
/// the overlay's. The act-one check runs ECDH through the node's signer, so the static secret
/// never leaves it.
pub(crate) struct NodeTarget {
	node_id: PeerId,
	signer: Arc<KeysManager>,
	peer_manager: Arc<PeerManager>,
}

impl NodeTarget {
	pub(crate) fn new(
		node_id: PublicKey, signer: Arc<KeysManager>, peer_manager: Arc<PeerManager>,
	) -> Self {
		Self { node_id: node_net_ldk::peer_id(&node_id), signer, peer_manager }
	}
}

impl InboundTarget for NodeTarget {
	fn node_id(&self) -> PeerId {
		self.node_id
	}

	fn claims(&self, act_one: &[u8; ACT_ONE_LEN]) -> bool {
		act_one_matches(act_one, &self.node_id, |their_ephemeral| {
			let their_ephemeral = PublicKey::from_slice(their_ephemeral).ok()?;
			self.signer
				.ecdh(Recipient::Node, &their_ephemeral, None)
				.ok()
				.map(|shared| shared.secret_bytes())
		})
	}

	fn accept(&self, stream: PeerStream) {
		// The connection runs on its own tasks; its lifetime future is not needed here.
		drop(node_net_ldk::setup_inbound(Arc::clone(&self.peer_manager), stream));
	}
}
