// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The broadcast queue end to end, on a real regtest bitcoind.
//!
//! The incident (mainnet, 2026-10-28): a node with one coin opened two channels back to back.
//! The second funding spends the change of the first. The second peer answered `funding_signed`
//! first, so LDK handed the child to the broadcaster before its parent; bitcoind refused it with
//! `bad-txns-inputs-missingorspent`, the chain layer dropped it, and LDK 0.1 never broadcasts a
//! funding again — the channel waited for confirmations forever.
//!
//! The child-before-parent order is a race between two peers, so these tests force it: the
//! first open's funding is registered with a [`BroadcastPolicy::QueueUntilParents`] that
//! depends on a transaction that is never broadcast, which keeps the parent unsent while the
//! second open's funding — the child — reaches bitcoind and is refused for real. The parent is
//! then released (re-registered without the dependency), or left to expire.
#![cfg(not(feature = "uniffi"))]

mod common;

use common::{
	generate_blocks_and_wait, premine_and_distribute_funds, random_config,
	setup_bitcoind_and_electrsd, setup_node, TestChainSource,
};

use ldk_node::{
	BroadcastPolicy, BroadcastQueueEntry, BroadcastQueueState, Event, Node, OpenChannelOptions,
};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, Txid};
use electrsd::corepc_node::Client as BitcoindClient;

use std::time::{Duration, Instant};

const COIN_SATS: u64 = 1_000_000;
const CHANNEL_SATS: u64 = 200_000;

/// Never broadcast by anyone: a parent whose policy depends on it is held unsent.
fn never_broadcast() -> Txid {
	Txid::from_byte_array([0xab; 32])
}

fn wait_until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
	let start = Instant::now();
	while !f() {
		assert!(start.elapsed() < limit, "timed out after {:?} waiting for {}", limit, what);
		std::thread::sleep(Duration::from_millis(250));
	}
	println!("ok after {:?}: {}", start.elapsed(), what);
}

/// Consumes `node`'s events until a `ChannelPending` with `counterparty`; returns its funding.
fn channel_pending_with(node: &Node, counterparty: &Node) -> OutPoint {
	let start = Instant::now();
	loop {
		assert!(start.elapsed() < Duration::from_secs(60), "no ChannelPending");
		match node.next_event() {
			Some(Event::ChannelPending { counterparty_node_id, funding_txo, .. })
				if counterparty_node_id == counterparty.node_id() =>
			{
				node.event_handled().unwrap();
				return funding_txo;
			},
			Some(other) => {
				println!("{} skipping event {:?}", node.node_id(), other);
				node.event_handled().unwrap();
			},
			None => std::thread::sleep(Duration::from_millis(100)),
		}
	}
}

fn open(from: &Node, to: &Node, policy: BroadcastPolicy) {
	from.open_channel_with_options(
		to.node_id(),
		to.listening_addresses().unwrap().first().unwrap().clone(),
		CHANNEL_SATS,
		None,
		None,
		OpenChannelOptions {
			announce_for_forwarding: false,
			counterparty_reserve_proportional_millionths: None,
			broadcast_policy: policy,
		},
	)
	.unwrap();
}

fn entry(node: &Node, txid: Txid) -> Option<BroadcastQueueEntry> {
	node.list_broadcast_queue().into_iter().find(|e| e.txid == txid)
}

fn mempool(bitcoind: &BitcoindClient) -> Vec<Txid> {
	let raw: Vec<String> = bitcoind.call("getrawmempool", &[]).unwrap();
	raw.into_iter().map(|t| t.parse().unwrap()).collect()
}

/// Whether bitcoind knows `txo` as an unspent output, in its mempool or its chain.
fn utxo_known(bitcoind: &BitcoindClient, txo: OutPoint) -> bool {
	let out: serde_json::Value = bitcoind
		.call("gettxout", &[serde_json::json!(txo.txid.to_string()), serde_json::json!(txo.vout)])
		.unwrap();
	!out.is_null()
}

fn confirmations(bitcoind: &BitcoindClient, txo: OutPoint) -> u64 {
	let out: serde_json::Value = bitcoind
		.call("gettxout", &[serde_json::json!(txo.txid.to_string()), serde_json::json!(txo.vout)])
		.unwrap();
	out.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0)
}

fn sync(nodes: &[&Node]) {
	for n in nodes {
		n.sync_wallets().unwrap();
	}
}

fn channel_ready(node: &Node, txo: OutPoint) -> bool {
	node.list_channels().iter().any(|c| c.funding_txo == Some(txo) && c.is_channel_ready)
}

fn log_of(storage_dir: &str) -> String {
	std::fs::read_to_string(format!("{}/{}", storage_dir, ldk_node::config::DEFAULT_LOG_FILENAME))
		.unwrap_or_default()
}

struct Net {
	bitcoind: electrsd::corepc_node::Node,
	electrsd: electrsd::ElectrsD,
}

struct Nodes {
	a: Node,
	a_dir: String,
	b: Node,
	c: Node,
}

/// Node A holding exactly one confirmed coin; B and C with nothing.
fn setup(net: &Net, chain: &TestChainSource) -> Nodes {
	let config_a = random_config(false);
	let a_dir = config_a.node_config.storage_dir_path.clone();
	let a = setup_node(chain, config_a, None);
	let b = setup_node(chain, random_config(false), None);
	let c = setup_node(chain, random_config(false), None);

	let addr = a.onchain_payment().new_address().unwrap();
	premine_and_distribute_funds(
		&net.bitcoind.client,
		&net.electrsd.client,
		vec![addr],
		Amount::from_sat(COIN_SATS),
	);
	sync(&[&a, &b, &c]);
	assert_eq!(a.list_balances().spendable_onchain_balance_sats, COIN_SATS);
	assert_eq!(a.list_balances().total_onchain_balance_sats, COIN_SATS);
	Nodes { a, a_dir, b, c }
}

/// Opens A→B with the parent held unsent (policy `parent_policy`, which must depend on
/// [`never_broadcast`]), then A→C with `child_policy`: C's funding spends B's change and goes
/// to bitcoind first, where it is refused for the missing input. Returns (parent, child).
fn open_child_before_parent(
	n: &Nodes, parent_policy: BroadcastPolicy, child_policy: BroadcastPolicy,
) -> (OutPoint, OutPoint) {
	open(&n.a, &n.b, parent_policy);
	let parent = channel_pending_with(&n.a, &n.b);
	assert_eq!(channel_pending_with(&n.b, &n.a), parent);

	// The parent reached the broadcast path and is held there, unsent.
	wait_until("the parent is held for its dependency", Duration::from_secs(30), || {
		entry(&n.a, parent.txid).map_or(false, |e| e.state == BroadcastQueueState::Waiting)
	});

	open(&n.a, &n.c, child_policy);
	let child = channel_pending_with(&n.a, &n.c);
	assert_eq!(channel_pending_with(&n.c, &n.a), child);
	assert_ne!(parent.txid, child.txid);
	(parent, child)
}

fn chained_funding_child_is_queued_and_sent_after_its_parent(
	chain_of: fn(&Net) -> TestChainSource,
) {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let net = Net { bitcoind, electrsd };
	let chain = chain_of(&net);
	let n = setup(&net, &chain);

	let held_parent = BroadcastPolicy::QueueUntilParents {
		max_age_secs: 3_600,
		depends_on: vec![never_broadcast()],
	};
	let (parent, child) = open_child_before_parent(&n, held_parent, BroadcastPolicy::default());

	// bitcoind refused the child for its missing input, and the queue holds it.
	wait_until("the child is held after a missing-input refusal", Duration::from_secs(30), || {
		entry(&n.a, child.txid)
			.map_or(false, |e| e.state == BroadcastQueueState::Waiting && e.last_error.is_some())
	});
	let held = entry(&n.a, child.txid).unwrap();
	println!("held child: {:?}", held);
	assert!(held.waiting_on.contains(&parent.txid), "the child spends the parent's change");
	assert!(held.attempts >= 1);
	let error = held.last_error.clone().unwrap();
	assert!(
		error.contains("missingorspent") || error.contains("Missing inputs"),
		"bitcoind's verdict: {}",
		error
	);
	let pool = mempool(&net.bitcoind.client);
	assert!(!pool.contains(&parent.txid) && !pool.contains(&child.txid));
	// The child's inputs (the parent's change) stay reserved: the coin is not spendable.
	assert!(n.a.list_balances().spendable_onchain_balance_sats < COIN_SATS - 2 * CHANNEL_SATS);

	// Release the parent. It goes out on its backoff, and the child right after it.
	n.a.register_broadcast_policy(parent.txid, BroadcastPolicy::default());
	wait_until("parent and child in bitcoind's mempool", Duration::from_secs(60), || {
		let pool = mempool(&net.bitcoind.client);
		pool.contains(&parent.txid) && pool.contains(&child.txid)
	});
	wait_until("the queue is empty", Duration::from_secs(10), || {
		entry(&n.a, parent.txid).is_none() && entry(&n.a, child.txid).is_none()
	});

	generate_blocks_and_wait(&net.bitcoind.client, &net.electrsd.client, 6);
	assert!(confirmations(&net.bitcoind.client, parent) >= 6);
	assert!(confirmations(&net.bitcoind.client, child) >= 6);
	wait_until("both channels ready on every node", Duration::from_secs(90), || {
		sync(&[&n.a, &n.b, &n.c]);
		channel_ready(&n.a, parent)
			&& channel_ready(&n.a, child)
			&& channel_ready(&n.b, parent)
			&& channel_ready(&n.c, child)
	});
	let log = log_of(&n.a_dir);
	assert!(log.contains(&format!("Holding transaction {} for a rebroadcast", child.txid)));
}

#[test]
fn chained_funding_child_is_queued_and_sent_after_its_parent_bitcoind_rpc() {
	chained_funding_child_is_queued_and_sent_after_its_parent(|net| {
		TestChainSource::BitcoindRpcSync(&net.bitcoind)
	});
}

#[test]
fn chained_funding_child_is_queued_and_sent_after_its_parent_electrum() {
	chained_funding_child_is_queued_and_sent_after_its_parent(|net| {
		TestChainSource::Electrum(&net.electrsd)
	});
}

/// `DropOnReject` keeps the behaviour every transaction had before the queue — the incident's:
/// the refused child is dropped, nothing ever sends it again, and its channel never confirms
/// even once the parent is out and buried.
#[test]
fn drop_on_reject_child_is_dropped_and_its_channel_never_confirms() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let net = Net { bitcoind, electrsd };
	let chain = TestChainSource::BitcoindRpcSync(&net.bitcoind);
	let n = setup(&net, &chain);

	let held_parent = BroadcastPolicy::QueueUntilParents {
		max_age_secs: 3_600,
		depends_on: vec![never_broadcast()],
	};
	let (parent, child) = open_child_before_parent(&n, held_parent, BroadcastPolicy::DropOnReject);

	wait_until("the network rejected the child", Duration::from_secs(30), || {
		log_of(&n.a_dir)
			.contains(&format!("The network rejected transaction {}; giving it up", child.txid))
	});
	let log = log_of(&n.a_dir);
	let line = log
		.lines()
		.find(|l| l.contains(&format!("The network rejected transaction {}", child.txid)))
		.unwrap();
	println!("{}", line);
	assert!(line.contains("missingorspent") || line.contains("Missing inputs"));
	assert!(entry(&n.a, child.txid).is_none(), "a DropOnReject child is never queued");

	n.a.register_broadcast_policy(parent.txid, BroadcastPolicy::default());
	wait_until("the parent in bitcoind's mempool", Duration::from_secs(60), || {
		mempool(&net.bitcoind.client).contains(&parent.txid)
	});
	// Well past every retry the queue would have made.
	std::thread::sleep(Duration::from_secs(20));
	assert!(!mempool(&net.bitcoind.client).contains(&child.txid), "the dropped child came back");

	generate_blocks_and_wait(&net.bitcoind.client, &net.electrsd.client, 6);
	wait_until("the parent's channel ready", Duration::from_secs(90), || {
		sync(&[&n.a, &n.b, &n.c]);
		channel_ready(&n.a, parent) && channel_ready(&n.b, parent)
	});
	std::thread::sleep(Duration::from_secs(20));
	sync(&[&n.a, &n.b, &n.c]);
	assert!(!utxo_known(&net.bitcoind.client, child), "the child's funding never reached bitcoind");
	assert!(!mempool(&net.bitcoind.client).contains(&child.txid));
	assert!(!channel_ready(&n.a, child), "the child's channel can never be ready");
	let c_channel = n.a.list_channels().into_iter().find(|c| c.funding_txo == Some(child));
	println!(
		"child's channel on A: {:?}",
		c_channel.as_ref().map(|c| (c.confirmations, c.is_channel_ready))
	);
	assert!(c_channel.is_some(), "the child's channel is left pending");
}

/// A parent that never makes it out: held past its `max_age`, it is given up, and with it the
/// child refused for the parent's missing output. Both are released — the coin is spendable
/// again — and the reaper closes the child's channel on the queue's word.
#[test]
fn child_of_a_parent_that_never_goes_out_is_given_up_and_its_inputs_released() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let net = Net { bitcoind, electrsd };
	let chain = TestChainSource::BitcoindRpcSync(&net.bitcoind);
	let n = setup(&net, &chain);

	let doomed_parent = BroadcastPolicy::QueueUntilParents {
		max_age_secs: 25,
		depends_on: vec![never_broadcast()],
	};
	let (parent, child) = open_child_before_parent(&n, doomed_parent, BroadcastPolicy::default());

	wait_until("the child is held after a missing-input refusal", Duration::from_secs(20), || {
		entry(&n.a, child.txid).map_or(false, |e| {
			e.state == BroadcastQueueState::Waiting
				&& e.last_error
					.as_deref()
					.map_or(false, |r| r.contains("missingorspent") || r.contains("Missing inputs"))
		})
	});

	wait_until("parent and child given up", Duration::from_secs(60), || {
		let gave_up = |txid| {
			matches!(
				entry(&n.a, txid).map(|e| e.state),
				Some(BroadcastQueueState::Abandoned { .. })
			)
		};
		gave_up(parent.txid) && gave_up(child.txid)
	});
	for e in n.a.list_broadcast_queue() {
		println!("queue: {:?}", e);
	}
	match entry(&n.a, child.txid).unwrap().state {
		BroadcastQueueState::Abandoned { reason } => {
			assert!(reason.contains(&parent.txid.to_string()), "child reason: {}", reason)
		},
		other => panic!("{:?}", other),
	}
	let pool = mempool(&net.bitcoind.client);
	assert!(!pool.contains(&parent.txid) && !pool.contains(&child.txid));

	// Inputs released: the whole coin is spendable again.
	wait_until("the coin is spendable again", Duration::from_secs(30), || {
		let balances = n.a.list_balances();
		balances.spendable_onchain_balance_sats == COIN_SATS
			&& balances.total_onchain_balance_sats == COIN_SATS
	});

	// The child was given up definitively (its parent was given up): the reaper closes its
	// channel. The parent only expired without a verdict, so its channel is left alone.
	wait_until("the child's channel closed by the reaper", Duration::from_secs(60), || {
		sync(&[&n.a]);
		!n.a.list_channels().iter().any(|c| c.funding_txo == Some(child))
	});
	assert!(n.a.list_channels().iter().any(|c| c.funding_txo == Some(parent)));

	// And the coin really is free: a fresh on-chain send spends it.
	let addr = n.b.onchain_payment().new_address().unwrap();
	let txid = n.a.onchain_payment().send_to_address(&addr, 100_000, None).unwrap();
	wait_until("the new spend in bitcoind's mempool", Duration::from_secs(30), || {
		mempool(&net.bitcoind.client).contains(&txid)
	});
}
