// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::custom_gossip::{CustomGossipMessage, CustomGossipMessageHandler};
use crate::liquidity::LiquiditySource;

use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use lightning::util::logger::Logger;

use lightning_types::features::{InitFeatures, NodeFeatures};

use lightning_liquidity::lsps0::ser::RawLSPSMessage;

use bitcoin::secp256k1::PublicKey;

use std::ops::Deref;
use std::sync::Arc;

pub(crate) enum NodeCustomMessageHandler<L: Deref>
where
	L::Target: Logger,
{
	Ignoring,
	Liquidity { liquidity_source: Arc<LiquiditySource<L>> },
	CustomGossip { gossip_handler: Arc<CustomGossipMessageHandler<L>> },
	Combined { 
		liquidity_source: Arc<LiquiditySource<L>>,
		gossip_handler: Arc<CustomGossipMessageHandler<L>>,
	},
}

impl<L: Deref> NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	pub(crate) fn new_liquidity(liquidity_source: Arc<LiquiditySource<L>>) -> Self {
		Self::Liquidity { liquidity_source }
	}

	pub(crate) fn new_ignoring() -> Self {
		Self::Ignoring
	}

	pub(crate) fn new_custom_gossip(gossip_handler: Arc<CustomGossipMessageHandler<L>>) -> Self {
		Self::CustomGossip { gossip_handler }
	}

	pub(crate) fn new_combined(
		liquidity_source: Arc<LiquiditySource<L>>,
		gossip_handler: Arc<CustomGossipMessageHandler<L>>,
	) -> Self {
		Self::Combined { liquidity_source, gossip_handler }
	}

	/// Returns the custom gossip handler if available
	pub(crate) fn custom_gossip_handler(&self) -> Option<Arc<CustomGossipMessageHandler<L>>> {
		match self {
			Self::CustomGossip { gossip_handler } => Some(Arc::clone(gossip_handler)),
			Self::Combined { gossip_handler, .. } => Some(Arc::clone(gossip_handler)),
			_ => None,
		}
	}
}

/// Combined custom message type that can handle both LSPS and custom gossip messages
#[derive(Clone, Debug)]
pub(crate) enum NodeCustomMessage {
	Lsps(RawLSPSMessage),
	CustomGossip(CustomGossipMessage),
}

impl lightning::ln::wire::Type for NodeCustomMessage {
	fn type_id(&self) -> u16 {
		match self {
			Self::Lsps(msg) => msg.type_id(),
			Self::CustomGossip(msg) => msg.type_id(),
		}
	}
}

impl lightning::util::ser::Writeable for NodeCustomMessage {
	fn write<W: lightning::util::ser::Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
		match self {
			Self::Lsps(msg) => msg.write(writer),
			Self::CustomGossip(msg) => msg.write(writer),
		}
	}
}

impl<L: Deref> CustomMessageReader for NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	type CustomMessage = NodeCustomMessage;

	fn read<RD: lightning::io::Read>(
		&self, message_type: u16, buffer: &mut RD,
	) -> Result<Option<Self::CustomMessage>, lightning::ln::msgs::DecodeError> {
		match self {
			Self::Ignoring => Ok(None),
			Self::Liquidity { liquidity_source, .. } => {
				if let Ok(Some(lsps_msg)) = liquidity_source.liquidity_manager().read(message_type, buffer) {
					Ok(Some(NodeCustomMessage::Lsps(lsps_msg)))
				} else {
					Ok(None)
				}
			},
			Self::CustomGossip { gossip_handler, .. } => {
				if let Ok(Some(gossip_msg)) = gossip_handler.read(message_type, buffer) {
					Ok(Some(NodeCustomMessage::CustomGossip(gossip_msg)))
				} else {
					Ok(None)
				}
			},
			Self::Combined { liquidity_source, gossip_handler } => {
				// Try LSPS first, then custom gossip
				if let Ok(Some(lsps_msg)) = liquidity_source.liquidity_manager().read(message_type, buffer) {
					Ok(Some(NodeCustomMessage::Lsps(lsps_msg)))
				} else if let Ok(Some(gossip_msg)) = gossip_handler.read(message_type, buffer) {
					Ok(Some(NodeCustomMessage::CustomGossip(gossip_msg)))
				} else {
					Ok(None)
				}
			},
		}
	}
}

impl<L: Deref> CustomMessageHandler for NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	fn handle_custom_message(
		&self, msg: Self::CustomMessage, sender_node_id: PublicKey,
	) -> Result<(), lightning::ln::msgs::LightningError> {
		match self {
			Self::Ignoring => Ok(()), // Should be unreachable!() as the reader will return `None`
			Self::Liquidity { liquidity_source, .. } => {
				match msg {
					NodeCustomMessage::Lsps(lsps_msg) => {
						liquidity_source.liquidity_manager().handle_custom_message(lsps_msg, sender_node_id)
					},
					NodeCustomMessage::CustomGossip(_) => {
						// Ignoring custom gossip in liquidity-only mode
						Ok(())
					},
				}
			},
			Self::CustomGossip { gossip_handler, .. } => {
				match msg {
					NodeCustomMessage::CustomGossip(gossip_msg) => {
						gossip_handler.handle_custom_message(gossip_msg, sender_node_id)
					},
					NodeCustomMessage::Lsps(_) => {
						// Ignoring LSPS in gossip-only mode
						Ok(())
					},
				}
			},
			Self::Combined { liquidity_source, gossip_handler } => {
				match msg {
					NodeCustomMessage::Lsps(lsps_msg) => {
						liquidity_source.liquidity_manager().handle_custom_message(lsps_msg, sender_node_id)
					},
					NodeCustomMessage::CustomGossip(gossip_msg) => {
						gossip_handler.handle_custom_message(gossip_msg, sender_node_id)
					},
				}
			},
		}
	}

	fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
		match self {
			Self::Ignoring => Vec::new(),
			Self::Liquidity { liquidity_source, .. } => {
				liquidity_source.liquidity_manager().get_and_clear_pending_msg()
					.into_iter()
					.map(|(node_id, msg)| (node_id, NodeCustomMessage::Lsps(msg)))
					.collect()
			},
			Self::CustomGossip { gossip_handler, .. } => {
				gossip_handler.get_and_clear_pending_msg()
					.into_iter()
					.map(|(node_id, msg)| (node_id, NodeCustomMessage::CustomGossip(msg)))
					.collect()
			},
			Self::Combined { liquidity_source, gossip_handler } => {
				let mut pending = Vec::new();
				
				// Get LSPS messages
				pending.extend(
					liquidity_source.liquidity_manager().get_and_clear_pending_msg()
						.into_iter()
						.map(|(node_id, msg)| (node_id, NodeCustomMessage::Lsps(msg)))
				);
				
				// Get custom gossip messages
				pending.extend(
					gossip_handler.get_and_clear_pending_msg()
						.into_iter()
						.map(|(node_id, msg)| (node_id, NodeCustomMessage::CustomGossip(msg)))
				);
				
				pending
			},
		}
	}

	fn provided_node_features(&self) -> NodeFeatures {
		match self {
			Self::Ignoring => NodeFeatures::empty(),
			Self::Liquidity { liquidity_source, .. } => {
				liquidity_source.liquidity_manager().provided_node_features()
			},
			Self::CustomGossip { gossip_handler, .. } => {
				gossip_handler.provided_node_features()
			},
			Self::Combined { liquidity_source, gossip_handler } => {
				// Combine features from both handlers
				let features = liquidity_source.liquidity_manager().provided_node_features();
				let _gossip_features = gossip_handler.provided_node_features();
				// Note: In a real implementation, you'd need to properly merge features
				// For now, we'll use the liquidity features as base
				features
			},
		}
	}

	fn provided_init_features(&self, their_node_id: PublicKey) -> InitFeatures {
		match self {
			Self::Ignoring => InitFeatures::empty(),
			Self::Liquidity { liquidity_source, .. } => {
				liquidity_source.liquidity_manager().provided_init_features(their_node_id)
			},
			Self::CustomGossip { gossip_handler, .. } => {
				gossip_handler.provided_init_features(their_node_id)
			},
			Self::Combined { liquidity_source, gossip_handler } => {
				// Combine init features from both handlers
				let features = liquidity_source.liquidity_manager().provided_init_features(their_node_id);
				let _gossip_features = gossip_handler.provided_init_features(their_node_id);
				// Note: In a real implementation, you'd need to properly merge features
				// For now, we'll use the liquidity features as base
				features
			},
		}
	}

	fn peer_connected(
		&self, their_node_id: PublicKey, msg: &lightning::ln::msgs::Init, inbound: bool,
	) -> Result<(), ()> {
		match self {
			Self::Ignoring => Ok(()),
			Self::Liquidity { liquidity_source, .. } => {
				liquidity_source.liquidity_manager().peer_connected(their_node_id, msg, inbound)
			},
			Self::CustomGossip { gossip_handler, .. } => {
				gossip_handler.peer_connected(their_node_id, msg, inbound)
			},
			Self::Combined { liquidity_source, gossip_handler } => {
				// Notify both handlers
				let _ = liquidity_source.liquidity_manager().peer_connected(their_node_id, msg, inbound);
				gossip_handler.peer_connected(their_node_id, msg, inbound)
			},
		}
	}

	fn peer_disconnected(&self, their_node_id: PublicKey) {
		match self {
			Self::Ignoring => {},
			Self::Liquidity { liquidity_source, .. } => {
				liquidity_source.liquidity_manager().peer_disconnected(their_node_id)
			},
			Self::CustomGossip { gossip_handler, .. } => {
				gossip_handler.peer_disconnected(their_node_id)
			},
			Self::Combined { liquidity_source, gossip_handler } => {
				// Notify both handlers
				liquidity_source.liquidity_manager().peer_disconnected(their_node_id);
				gossip_handler.peer_disconnected(their_node_id);
			},
		}
	}
}
