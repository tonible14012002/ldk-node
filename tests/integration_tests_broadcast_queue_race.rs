// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The incident's race, reproduced with nothing but the plain channel-open API on a real
//! regtest bitcoind — so this file builds and runs unchanged on a node without the broadcast
//! queue, where it fails.
//!
//! Node A holds one coin and opens a channel to B, then one to C. C's funding spends the change
//! of B's. B is slow to persist its first channel monitor, so its `funding_signed` arrives after
//! C's: LDK hands the child to the broadcaster before its parent, and bitcoind refuses it with
//! `bad-txns-inputs-missingorspent` — the mainnet ordering of 2026-10-28, forced only by peer
//! timing. Both fundings must still confirm and both channels become ready.
#![cfg(not(feature = "uniffi"))]

mod common;

use common::{
	generate_blocks_and_wait, premine_and_distribute_funds, random_config,
	setup_bitcoind_and_electrsd, setup_node, TestChainSource,
};

use ldk_node::{Builder, Event, Node};

use lightning::util::persist::{KVStore, CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE};
use lightning_persister::fs_store::FilesystemStore;

use bitcoin::{Amount, OutPoint, Transaction, Txid};
use electrsd::corepc_node::Client as BitcoindClient;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const COIN_SATS: u64 = 1_000_000;
const CHANNEL_SATS: u64 = 200_000;
/// How long B takes to persist its first channel monitor, holding back its `funding_signed`.
const B_MONITOR_WRITE_DELAY: Duration = Duration::from_secs(6);

/// A filesystem store whose first channel-monitor write takes [`B_MONITOR_WRITE_DELAY`]: LDK
/// persists the new monitor before answering `funding_created`, so the peer is slow to answer.
struct SlowFirstMonitorWrite {
	inner: FilesystemStore,
	delayed: AtomicBool,
}

impl KVStore for SlowFirstMonitorWrite {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> lightning::io::Result<Vec<u8>> {
		self.inner.read(primary_namespace, secondary_namespace, key)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: &[u8],
	) -> lightning::io::Result<()> {
		if primary_namespace == CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE
			&& !self.delayed.swap(true, Ordering::SeqCst)
		{
			println!("B: holding its first monitor write for {:?}", B_MONITOR_WRITE_DELAY);
			std::thread::sleep(B_MONITOR_WRITE_DELAY);
		}
		self.inner.write(primary_namespace, secondary_namespace, key, buf)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> lightning::io::Result<()> {
		self.inner.remove(primary_namespace, secondary_namespace, key, lazy)
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> lightning::io::Result<Vec<String>> {
		self.inner.list(primary_namespace, secondary_namespace)
	}
}

fn slow_peer(bitcoind: &electrsd::corepc_node::Node) -> Node {
	let config = random_config(false).node_config;
	let mut builder = Builder::from_config(config.clone());
	let rpc_host = bitcoind.params.rpc_socket.ip().to_string();
	let rpc_port = bitcoind.params.rpc_socket.port();
	let values = bitcoind.params.get_cookie_values().unwrap().unwrap();
	builder.set_chain_source_bitcoind_rpc(rpc_host, rpc_port, values.user, values.password);
	builder.set_filesystem_logger(None, None);
	let mut dir = std::path::PathBuf::from(&config.storage_dir_path);
	dir.push("fs_store");
	let store =
		SlowFirstMonitorWrite { inner: FilesystemStore::new(dir), delayed: AtomicBool::new(false) };
	let node = builder.build_with_store(Arc::new(store)).unwrap();
	node.start().unwrap();
	node
}

fn wait_until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
	let start = Instant::now();
	while !f() {
		assert!(start.elapsed() < limit, "timed out after {:?} waiting for {}", limit, what);
		std::thread::sleep(Duration::from_millis(250));
	}
	println!("ok after {:?}: {}", start.elapsed(), what);
}

/// Consumes `node`'s events until it has seen a `ChannelPending` with each of `peers`, in any
/// order; returns the fundings by peer, and the order they came in.
fn channel_pendings(
	node: &Node, peers: &[&Node],
) -> (HashMap<bitcoin::secp256k1::PublicKey, OutPoint>, Vec<OutPoint>) {
	let start = Instant::now();
	let mut found = HashMap::new();
	let mut order = Vec::new();
	while found.len() < peers.len() {
		assert!(start.elapsed() < Duration::from_secs(60), "missing ChannelPending events");
		match node.next_event() {
			Some(Event::ChannelPending { counterparty_node_id, funding_txo, .. }) => {
				println!(
					"{} ChannelPending with {} funding {}",
					node.node_id(),
					counterparty_node_id,
					funding_txo
				);
				found.insert(counterparty_node_id, funding_txo);
				order.push(funding_txo);
				node.event_handled().unwrap();
			},
			Some(other) => {
				println!("{} skipping event {:?}", node.node_id(), other);
				node.event_handled().unwrap();
			},
			None => std::thread::sleep(Duration::from_millis(100)),
		}
	}
	(found, order)
}

fn open(from: &Node, to: &Node) {
	from.open_channel(
		to.node_id(),
		to.listening_addresses().unwrap().first().unwrap().clone(),
		CHANNEL_SATS,
		None,
		None,
	)
	.unwrap();
}

fn mempool(bitcoind: &BitcoindClient) -> Vec<Txid> {
	let raw: Vec<String> = bitcoind.call("getrawmempool", &[]).unwrap();
	raw.into_iter().map(|t| t.parse().unwrap()).collect()
}

fn mempool_tx(bitcoind: &BitcoindClient, txid: Txid) -> Transaction {
	let hex: String =
		bitcoind.call("getrawtransaction", &[serde_json::json!(txid.to_string())]).unwrap();
	bitcoin::consensus::encode::deserialize_hex(&hex).unwrap()
}

fn sync(nodes: &[&Node]) {
	for n in nodes {
		n.sync_wallets().unwrap();
	}
}

fn channel_ready(node: &Node, txo: OutPoint) -> bool {
	node.list_channels().iter().any(|c| c.funding_txo == Some(txo) && c.is_channel_ready)
}

#[test]
fn chained_funding_broadcast_child_first_by_a_slow_peer_still_confirms() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain = TestChainSource::BitcoindRpcSync(&bitcoind);
	let config_a = random_config(false);
	let a_dir = config_a.node_config.storage_dir_path.clone();
	let a = setup_node(&chain, config_a, None);
	let b = slow_peer(&bitcoind);
	let c = setup_node(&chain, random_config(false), None);

	let addr = a.onchain_payment().new_address().unwrap();
	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![addr],
		Amount::from_sat(COIN_SATS),
	);
	sync(&[&a, &b, &c]);
	assert_eq!(a.list_balances().spendable_onchain_balance_sats, COIN_SATS, "exactly one coin");

	// A→B first; once A built that funding (the coin is reserved) — while B still sits on its
	// monitor write — A→C, whose funding can only spend the first one's change.
	open(&a, &b);
	wait_until("A built the first funding", Duration::from_secs(30), || {
		a.list_balances().spendable_onchain_balance_sats < COIN_SATS
	});
	open(&a, &c);

	let (fundings, order) = channel_pendings(&a, &[&b, &c]);
	let parent = fundings[&b.node_id()];
	let child = fundings[&c.node_id()];
	assert_eq!(
		order,
		vec![child, parent],
		"C answered first: the child went to the broadcaster first"
	);

	// bitcoind refused the child for its missing parent — the incident's verdict, for real.
	let log_path = format!("{}/{}", a_dir, ldk_node::config::DEFAULT_LOG_FILENAME);
	wait_until("bitcoind refused the child", Duration::from_secs(30), || {
		let log = std::fs::read_to_string(&log_path).unwrap_or_default();
		log.lines().any(|l| l.contains(&child.txid.to_string()) && l.contains("missingorspent"))
	});
	let log = std::fs::read_to_string(&log_path).unwrap();
	for line in
		log.lines().filter(|l| l.contains(&child.txid.to_string()) && l.contains("missingorspent"))
	{
		println!("A: {}", line);
	}

	// The fix: both fundings reach the mempool, the child spending the parent's change.
	wait_until("parent and child in bitcoind's mempool", Duration::from_secs(60), || {
		let pool = mempool(&bitcoind.client);
		pool.contains(&parent.txid) && pool.contains(&child.txid)
	});
	let child_tx = mempool_tx(&bitcoind.client, child.txid);
	assert!(
		child_tx.input.iter().all(|i| i.previous_output.txid == parent.txid),
		"the second funding spends the first one's change"
	);

	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6);
	wait_until("both channels ready on every node", Duration::from_secs(90), || {
		sync(&[&a, &b, &c]);
		channel_ready(&a, parent)
			&& channel_ready(&a, child)
			&& channel_ready(&b, parent)
			&& channel_ready(&c, child)
	});
}
