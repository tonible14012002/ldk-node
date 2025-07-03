// Example demonstrating how to use custom gossip metadata in LDK Node

use ldk_node::{Builder, Event, Node};
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::Network;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create and configure a node with custom gossip enabled
    let mut builder = Builder::new();
    builder.set_network(Network::Testnet);
    builder.set_chain_source_esplora("https://blockstream.info/testnet/api".to_string(), None);
    builder.set_gossip_source_rgs("https://rapidsync.lightningdevkit.org/testnet/snapshot".to_string());
    
    // Enable custom gossip functionality
    builder.enable_custom_gossip();
    
    let node = builder.build()?;
    
    // Start the node
    node.start()?;
    
    // Get the custom gossip handler
    if let Some(custom_gossip) = node.custom_gossip() {
        println!("Custom gossip handler is available!");
        
        // Set our own metadata to advertise
        let our_metadata = serde_json::json!({
            "version": "1.0",
            "features": ["feature_a", "feature_b"],
            "timestamp": chrono::Utc::now().timestamp(),
            "description": "LDK Node with custom features"
        }).to_string().into_bytes();
        
        custom_gossip.set_our_metadata(our_metadata);
        
        // Example: Send custom metadata to a specific peer
        // (This would typically be done after connecting to a peer)
        let peer_metadata = serde_json::json!({
            "message": "Hello from custom gossip!",
            "data": {
                "custom_field": "custom_value"
            }
        }).to_string().into_bytes();
        
        // In a real scenario, you'd have connected peers
        // custom_gossip.send_metadata_to_peer(peer_node_id, peer_metadata);
        
        // Example: Get stored metadata for all nodes
        let all_metadata = custom_gossip.get_all_metadata().clone();
        println!("Currently have metadata for {} nodes", all_metadata.len());
        
        // Print metadata information
        for (node_id, metadata) in all_metadata.clone() {
            println!("Node {}: {} bytes of metadata", node_id, metadata.metadata.len());
            
            // Try to parse as JSON
            if let Ok(json_str) = String::from_utf8(metadata.metadata.clone()) {
                if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    println!("  Parsed JSON: {}", json_value);
                }
            }
        }
        
        // Demonstrate event handling with custom gossip
        println!("Monitoring for custom gossip events...");
        
        // In a real application, you would handle events in a loop
        // This is just a demonstration
        for _ in 0..5 {
            // Wait for events (timeout after 1 second)
            std::thread::sleep(Duration::from_secs(1));
            
            // In a real application, you would process events like this:
            // match node.wait_next_event() {
            //     Event::... => {
            //         // Handle other events
            //     }
            //     // Custom gossip events would be handled through the custom_gossip handler
            //     // as they are processed automatically when messages are received
            // }
        }
        
        // Example: Check if we received any new metadata
        let updated_metadata = custom_gossip.get_all_metadata();
        if updated_metadata.len() > all_metadata.clone().len() {
            println!("Received new metadata from {} nodes", 
                     updated_metadata.len() - all_metadata.len());
        }
        
    } else {
        println!("Custom gossip not enabled. Use builder.enable_custom_gossip() to enable it.");
    }
    
    // Stop the node
    node.stop()?;

    peer_to_peer_example()?;
    
    Ok(())
}

/// Example of how to integrate custom gossip in a peer-to-peer scenario
#[allow(dead_code)]
fn peer_to_peer_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create two nodes for demonstration
    let mut builder1 = Builder::new();
    builder1.set_network(Network::Regtest);
    builder1.enable_custom_gossip();
    let node1 = builder1.build()?;
    
    let mut builder2 = Builder::new();
    builder2.set_network(Network::Regtest);
    builder2.enable_custom_gossip();
    let node2 = builder2.build()?;
    
    // Start both nodes
    node1.start()?;
    node2.start()?;
    
    // Get custom gossip handlers
    let gossip1 = node1.custom_gossip().unwrap();
    let gossip2 = node2.custom_gossip().unwrap();
    
    // Set metadata for each node
    let metadata1 = b"Node 1 custom data".to_vec();
    let metadata2 = b"Node 2 custom data".to_vec();
    
    gossip1.set_our_metadata(metadata1);
    gossip2.set_our_metadata(metadata2);
    
    // In a real scenario, you would:
    // 1. Connect the nodes to each other
    // 2. Custom metadata would be automatically exchanged when peers connect
    // 3. Monitor the get_all_metadata() results to see received data
    
    println!("Peer-to-peer custom gossip example completed");
    
    // Stop nodes
    node1.stop()?;
    node2.stop()?;
    
    Ok(())
}

/// Example showing custom feature flags (placeholder for future implementation)
#[allow(dead_code)]
fn custom_features_example() {
    println!("Custom feature flags would be implemented in the provided_node_features() method");
    println!("This allows advertising custom capabilities to peers during connection");
}