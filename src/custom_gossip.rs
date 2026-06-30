// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Custom gossip message handling for extending P2P gossip sync with custom metadata.

use crate::logger::{log_debug, log_trace};
use lightning::util::logger::Logger as LightningLogger;

use lightning::io::{self, Read};
use lightning::ln::msgs::LightningError;
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning_types::features::{InitFeatures, NodeFeatures};

use bitcoin::secp256k1::PublicKey;

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

/// Custom message type for gossip metadata extensions
pub const CUSTOM_GOSSIP_MESSAGE_TYPE: u16 = 32769; // Odd number in custom range

/// Custom gossip message containing metadata extensions
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomGossipMessage {
    /// The metadata payload
    pub metadata: Vec<u8>,
}

impl CustomGossipMessage {
    /// Create a new custom gossip message with the given metadata
    pub fn new(metadata: Vec<u8>) -> Self {
        Self { metadata }
    }

    /// Get the metadata payload
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
}

impl Type for CustomGossipMessage {
    fn type_id(&self) -> u16 {
        CUSTOM_GOSSIP_MESSAGE_TYPE
    }
}

impl Writeable for CustomGossipMessage {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
        // Write length prefix (u16) followed by the metadata
        (self.metadata.len() as u16).write(writer)?;
        writer.write_all(&self.metadata)
    }
}

impl Readable for CustomGossipMessage {
    fn read<R: Read>(reader: &mut R) -> Result<Self, lightning::ln::msgs::DecodeError> {
        let length = <u16 as Readable>::read(reader)? as usize;
        
        // Limit metadata size to prevent DoS attacks
        if length > 4096 {
            return Err(lightning::ln::msgs::DecodeError::InvalidValue);
        }

        let mut metadata = vec![0u8; length];
        reader.read_exact(&mut metadata).map_err(|_| {
            lightning::ln::msgs::DecodeError::ShortRead
        })?;

        Ok(Self { metadata })
    }
}

/// Metadata entry for a node
#[derive(Clone, Debug)]
pub struct NodeMetadata {
    /// Node's public key
    pub node_id: PublicKey,
    /// Custom metadata payload
    pub metadata: Vec<u8>,
    /// Timestamp when metadata was received
    pub timestamp: u32,
}

/// Handler for custom gossip messages
pub struct CustomGossipMessageHandler<L: Deref>
where
    L::Target: LightningLogger,
{
    /// Logger instance
    logger: L,
    /// Store for node metadata
    node_metadata: Arc<Mutex<HashMap<PublicKey, NodeMetadata>>>,
    /// Pending messages to send
    pending_messages: Arc<Mutex<Vec<(PublicKey, CustomGossipMessage)>>>,
    /// Our own metadata to advertise
    our_metadata: Arc<Mutex<Option<Vec<u8>>>>,
}

impl<L: Deref> CustomGossipMessageHandler<L>
where
    L::Target: LightningLogger,
{
    /// Create a new custom gossip message handler
    pub fn new(logger: L) -> Self {
        Self {
            logger,
            node_metadata: Arc::new(Mutex::new(HashMap::new())),
            pending_messages: Arc::new(Mutex::new(Vec::new())),
            our_metadata: Arc::new(Mutex::new(None)),
        }
    }

    /// Set our own metadata to advertise to peers
    pub fn set_our_metadata(&self, metadata: Vec<u8>) {
        let mut our_metadata = self.our_metadata.lock().unwrap();
        *our_metadata = Some(metadata);
    }

    /// Get OUR OWN advertised metadata blob (the one broadcast to peers), if set.
    /// Distinct from [`get_all_metadata`], which returns PEERS' received blobs and
    /// NEVER our own — so this is the only way for the owning node to read back what
    /// it is currently advertising (needed for a correct read-merge-write of our blob).
    pub fn get_our_metadata(&self) -> Option<Vec<u8>> {
        self.our_metadata.lock().unwrap().clone()
    }

    /// Get metadata for a specific node
    pub fn get_node_metadata(&self, node_id: &PublicKey) -> Option<NodeMetadata> {
        let metadata_store = self.node_metadata.lock().unwrap();
        metadata_store.get(node_id).cloned()
    }

    /// Get all stored node metadata
    pub fn get_all_metadata(&self) -> HashMap<PublicKey, NodeMetadata> {
        let metadata_store = self.node_metadata.lock().unwrap();
        metadata_store.clone()
    }

    /// Send custom metadata to a specific peer
    pub fn send_metadata_to_peer(&self, peer_node_id: PublicKey, metadata: Vec<u8>) {
        let message = CustomGossipMessage::new(metadata);
        let mut pending = self.pending_messages.lock().unwrap();
        pending.push((peer_node_id, message));
    }

    /// Broadcast our metadata to all peers
    pub fn broadcast_our_metadata(&self, peer_node_ids: Vec<PublicKey>) {
        let our_metadata = self.our_metadata.lock().unwrap();
        if let Some(ref metadata) = *our_metadata {
            let message = CustomGossipMessage::new(metadata.clone());
            let mut pending = self.pending_messages.lock().unwrap();
            
            for node_id in peer_node_ids {
                pending.push((node_id, message.clone()));
            }
        }
    }

    /// Handle received custom gossip message
    fn handle_gossip_message(&self, msg: &CustomGossipMessage, sender_node_id: PublicKey) {
        log_debug!(
            self.logger,
            "Received custom gossip metadata from {}: {} bytes",
            sender_node_id,
            msg.metadata.len()
        );

        let metadata_entry = NodeMetadata {
            node_id: sender_node_id,
            metadata: msg.metadata.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32,
        };

        let mut metadata_store = self.node_metadata.lock().unwrap();
        metadata_store.insert(sender_node_id, metadata_entry);

        log_trace!(
            self.logger,
            "Stored metadata for node {}, total nodes: {}",
            sender_node_id,
            metadata_store.len()
        );
    }
}

impl<L: Deref> CustomMessageReader for CustomGossipMessageHandler<L>
where
    L::Target: LightningLogger,
{
    type CustomMessage = CustomGossipMessage;

    fn read<RD: Read>(
        &self, message_type: u16, buffer: &mut RD,
    ) -> Result<Option<Self::CustomMessage>, lightning::ln::msgs::DecodeError> {
        if message_type == CUSTOM_GOSSIP_MESSAGE_TYPE {
            log_trace!(self.logger, "Reading custom gossip message type {}", message_type);
            Ok(Some(CustomGossipMessage::read(buffer)?))
        } else {
            Ok(None)
        }
    }
}

impl<L: Deref> CustomMessageHandler for CustomGossipMessageHandler<L>
where
    L::Target: LightningLogger,
{
    fn handle_custom_message(
        &self, msg: Self::CustomMessage, sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        self.handle_gossip_message(&msg, sender_node_id);
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        let mut pending = self.pending_messages.lock().unwrap();
        std::mem::take(&mut *pending)
    }

    fn provided_node_features(&self) -> NodeFeatures {
        // Advertise that we support custom gossip messages
        // You can extend this to include specific feature flags
        NodeFeatures::empty()
    }

    fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
        // Advertise init features for custom gossip support
        InitFeatures::empty()
    }

    fn peer_connected(
        &self, their_node_id: PublicKey, _msg: &lightning::ln::msgs::Init, _inbound: bool,
    ) -> Result<(), ()> {
        log_debug!(self.logger, "Peer {} connected, will broadcast our metadata", their_node_id);
        
        // Optionally broadcast our metadata when a peer connects
        let our_metadata = self.our_metadata.lock().unwrap();
        if let Some(ref metadata) = *our_metadata {
            let message = CustomGossipMessage::new(metadata.clone());
            let mut pending = self.pending_messages.lock().unwrap();
            pending.push((their_node_id, message));
        }
        
        Ok(())
    }

    fn peer_disconnected(&self, their_node_id: PublicKey) {
        log_debug!(self.logger, "Peer {} disconnected", their_node_id);
        // Optionally clean up metadata for disconnected peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use lightning::util::test_utils::TestLogger;
    use lightning::util::ser::{Readable, Writeable};
    use std::io::Cursor;

    #[test]
    fn test_custom_gossip_message_serialization() {
        let metadata = b"custom_metadata_payload".to_vec();
        let msg = CustomGossipMessage::new(metadata.clone());
        
        assert_eq!(msg.metadata(), &metadata);
        assert_eq!(msg.type_id(), CUSTOM_GOSSIP_MESSAGE_TYPE);

        // Test serialization
        let mut buffer = Vec::new();
        msg.write(&mut buffer).unwrap();
        
        // Test deserialization
        let mut cursor = Cursor::new(buffer);
        let deserialized = CustomGossipMessage::read(&mut cursor).unwrap();
        
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_custom_gossip_handler() {
        let logger = Arc::new(TestLogger::new());
        let handler = CustomGossipMessageHandler::new(logger);
        
        // Test setting our metadata
        let our_metadata = b"our_node_metadata".to_vec();
        handler.set_our_metadata(our_metadata.clone());
        
        // Test handling a message
        let secp_ctx = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let sender_node_id = PublicKey::from_secret_key(&secp_ctx, &secret_key);
        
        let msg = CustomGossipMessage::new(b"peer_metadata".to_vec());
        handler.handle_custom_message(msg, sender_node_id).unwrap();
        
        // Verify metadata was stored
        let stored_metadata = handler.get_node_metadata(&sender_node_id).unwrap();
        assert_eq!(stored_metadata.metadata, b"peer_metadata");
        assert_eq!(stored_metadata.node_id, sender_node_id);
    }

    #[test]
    fn test_message_size_limit() {
        let large_metadata = vec![0u8; 5000]; // Exceeds 4096 byte limit
        let msg = CustomGossipMessage::new(large_metadata);
        
        let mut buffer = Vec::new();
        msg.write(&mut buffer).unwrap();
        
        let mut cursor = Cursor::new(buffer);
        let result = CustomGossipMessage::read(&mut cursor);
        
        assert!(result.is_err());
    }
}