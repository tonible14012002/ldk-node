// Network tuning end to end: two real nodes on regtest bitcoind.
//
// The confirmation-depth, announcement and reserve-floor checks need `lightning`
// and `lightning-block-sync` built with node-app-ldk-node's patches
// (patches/lightning/network-tuning.patch, patches/lightning-block-sync/), so
// this file only builds under `--cfg network_tuning_test`:
//
//   cargo update -p lightning --precise 0.1.11
//   RUSTFLAGS="--cfg network_tuning_test" cargo test --test integration_tests_network_tuning \
//     --config 'patch.crates-io.lightning.path="<node-app-ldk-node>/third_party/lightning"' \
//     --config 'patch.crates-io.lightning-block-sync.path="<node-app-ldk-node>/third_party/lightning-block-sync"' \
//     -- --nocapture
#![cfg(network_tuning_test)]

mod common;

use common::{
	expect_channel_pending_event, expect_channel_ready_event, expect_event,
	generate_blocks_and_wait, premine_and_distribute_funds, random_config,
	setup_bitcoind_and_electrsd, setup_node, wait_for_tx,
	TestChainSource,
};

use ldk_node::{Event, Node};

use bitcoin::{Amount, OutPoint, Txid};
use electrsd::electrum_client::ElectrumApi;

use std::str::FromStr;
use std::time::{Duration, Instant};

const CHANNEL_SATS: u64 = 10_000;

fn sync(nodes: &[&Node]) {
	for n in nodes {
		n.sync_wallets().unwrap();
	}
}

fn open_announced(a: &Node, b: &Node, electrsd: &electrsd::ElectrsD) -> OutPoint {
	a.open_announced_channel(
		b.node_id(),
		b.listening_addresses().unwrap().first().unwrap().clone(),
		CHANNEL_SATS,
		None,
		None,
	)
	.unwrap();
	let txo = expect_channel_pending_event!(a, b.node_id());
	assert_eq!(txo, expect_channel_pending_event!(b, a.node_id()));
	wait_for_tx(&electrsd.client, txo.txid);
	txo
}

fn channel_on(node: &Node, txo: OutPoint) -> ldk_node::ChannelDetails {
	node.list_channels().into_iter().find(|c| c.funding_txo == Some(txo)).unwrap()
}

fn wait_until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) -> bool {
	let start = Instant::now();
	while start.elapsed() < limit {
		if f() {
			println!("✓ {what} after {:?}", start.elapsed());
			return true;
		}
		std::thread::sleep(Duration::from_millis(250));
	}
	println!("✗ {what} not within {limit:?}");
	false
}

/// Mempool transactions spending any output of `parent`.
fn children_in_mempool(
	bitcoind: &electrsd::corepc_node::Client, electrs: &impl ElectrumApi, parent: Txid,
) -> Vec<bitcoin::Transaction> {
	bitcoind
		.get_raw_mempool()
		.unwrap()
		.0
		.iter()
		.filter_map(|id| electrs.transaction_get(&Txid::from_str(id).unwrap()).ok())
		.filter(|tx| tx.input.iter().any(|i| i.previous_output.txid == parent))
		.collect()
}

#[test]
fn channels_open_announce_and_reserve_for_small_channel_network() {
	// Regtest has no fee history: make only the closure targets expensive so a
	// force close must CPFP from the wallet.
	std::env::set_var("LDK_DEV_CLOSURE_SAT_PER_VB", "10");

	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::BitcoindRpcSync(&bitcoind);
	let mk = || {
		let mut c = random_config(true);
		let anchors = c.node_config.anchor_channels_config.as_mut().unwrap();
		anchors.per_channel_reserve_sats = 1_000;
		anchors.max_total_reserve_sats = Some(2_000);
		c
	};
	let a = setup_node(&chain_source, mk(), None);
	let b = setup_node(&chain_source, mk(), None);

	premine_and_distribute_funds(
		&bitcoind.client,
		&electrsd.client,
		vec![a.onchain_payment().new_address().unwrap(), b.onchain_payment().new_address().unwrap()],
		Amount::from_sat(100_000),
	);
	sync(&[&a, &b]);

	// --- 1. usable at 3 confirmations -------------------------------------------
	let txo1 = open_announced(&a, &b, &electrsd);
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 2);
	sync(&[&a, &b]);
	let ch = channel_on(&a, txo1);
	println!("after 2 blocks: confirmations={:?}/{:?} ready={}", ch.confirmations, ch.confirmations_required, ch.is_channel_ready);
	assert_eq!(ch.confirmations_required, Some(3), "acceptor (b) asks 3 confirmations");
	assert!(!ch.is_channel_ready);

	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1);
	sync(&[&a, &b]);
	expect_channel_ready_event!(a, b.node_id());
	expect_channel_ready_event!(b, a.node_id());
	println!("✓ channel ready at 3 confirmations");

	// --- 2. 354-sat in-channel reserve on both sides -----------------------------
	let ch = channel_on(&a, txo1);
	println!(
		"reserves: ours={:?} theirs={}",
		ch.unspendable_punishment_reserve, ch.counterparty_unspendable_punishment_reserve
	);
	assert_eq!(ch.unspendable_punishment_reserve, Some(354));
	assert_eq!(ch.counterparty_unspendable_punishment_reserve, 354);

	// --- 3. announced at 3 confirmations ----------------------------------------
	let scid = ch.short_channel_id.unwrap();
	let announced = wait_until("channel in both graphs at 3 confirmations", Duration::from_secs(30), || {
		a.network_graph().channel(scid).is_some() && b.network_graph().channel(scid).is_some()
	});
	assert!(announced, "channel must be announced before the 6th block");
	assert!(channel_on(&a, txo1).is_announced);

	// --- 4. the anchor reserve is pooled under the 2,000 cap --------------------
	assert_eq!(a.list_balances().total_anchor_channels_reserve_sats, 1_000);
	assert_eq!(b.list_balances().total_anchor_channels_reserve_sats, 1_000);
	let mut txos = vec![txo1];
	for expected in [2_000, 2_000] {
		let txo = open_announced(&a, &b, &electrsd);
		generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 3);
		sync(&[&a, &b]);
		expect_channel_ready_event!(a, b.node_id());
		expect_channel_ready_event!(b, a.node_id());
		txos.push(txo);
		println!(
			"{} channels: anchor reserve a={} b={}",
			txos.len(),
			a.list_balances().total_anchor_channels_reserve_sats,
			b.list_balances().total_anchor_channels_reserve_sats
		);
		assert_eq!(a.list_balances().total_anchor_channels_reserve_sats, expected);
		assert_eq!(b.list_balances().total_anchor_channels_reserve_sats, expected);
	}

	// --- 5. a funded force close CPFPs from the wallet --------------------------
	// The peer goes offline first, the usual reason to force close here. An online
	// peer answers our error by broadcasting its own commitment, and whichever
	// reaches the mempool first wins the race, which would make this flaky.
	let sink = b.onchain_payment().new_address().unwrap();
	b.stop().unwrap();
	let ch = channel_on(&a, txos[0]);
	a.force_close_channel(&ch.user_channel_id, b.node_id(), None).unwrap();
	expect_event!(a, ChannelClosed);
	let commitment = spender_in_mempool(&bitcoind.client, &electrsd.client, txos[0]);
	let mut child = None;
	wait_until("CPFP child of the commitment in the mempool", Duration::from_secs(60), || {
		a.sync_wallets().ok();
		child = children_in_mempool(&bitcoind.client, &electrsd.client, commitment).pop();
		child.is_some()
	});
	let child = child.expect("a funded wallet must bump the commitment");
	let entry = bitcoind.client.get_mempool_entry(child.compute_txid()).unwrap();
	println!(
		"child: {} vB, fees {:?}; parent commitment {} vB",
		child.vsize(),
		entry.0.fees,
		electrsd.client.transaction_get(&commitment).unwrap().vsize()
	);
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1);
	sync(&[&a]);

	// --- 6. an underfunded force close waits for a top-up -----------------------
	// LDK broadcasts an anchor commitment together with its CPFP child; when the
	// wallet cannot pay the child, nothing reaches the chain and LDK retries on
	// every block. Leave only the pooled reserve, which cannot pay 10 sat/vB.
	a.onchain_payment().send_all_to_address(&sink, true, None).unwrap();
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1);
	sync(&[&a]);
	let bal = a.list_balances();
	println!(
		"a after drain: total={} spendable={} reserve={}",
		bal.total_onchain_balance_sats, bal.spendable_onchain_balance_sats,
		bal.total_anchor_channels_reserve_sats
	);
	assert_eq!(bal.total_onchain_balance_sats, 2_000, "only the pooled reserve is left");

	let ch = channel_on(&a, txos[1]);
	a.force_close_channel(&ch.user_channel_id, ch.counterparty_node_id, None).unwrap();
	expect_event!(a, ChannelClosed);
	std::thread::sleep(Duration::from_secs(10));
	assert!(
		spender(&bitcoind.client, &electrsd.client, txos[1]).is_none(),
		"an unaffordable package is not broadcast"
	);
	println!("✓ underfunded: nothing broadcast");

	// Top up and confirm it: LDK only spends confirmed coins.
	let topup = a.onchain_payment().new_address().unwrap();
	let txid = bitcoind.client.send_to_address(&topup, Amount::from_sat(20_000)).unwrap().0;
	wait_for_tx(&electrsd.client, Txid::from_str(&txid).unwrap());
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1);
	sync(&[&a]);
	let commitment = spender_in_mempool(&bitcoind.client, &electrsd.client, txos[1]);
	let mut child = None;
	wait_until("CPFP child after the top-up", Duration::from_secs(60), || {
		child = children_in_mempool(&bitcoind.client, &electrsd.client, commitment).pop();
		child.is_some()
	});
	assert!(child.is_some(), "a confirmed top-up lets the next retry bump the close");
	println!("✓ top-up: commitment and CPFP child broadcast on the next block");

	a.stop().unwrap();
}

fn spender(
	bitcoind: &electrsd::corepc_node::Client, electrs: &impl ElectrumApi, outpoint: OutPoint,
) -> Option<Txid> {
	bitcoind.get_raw_mempool().unwrap().0.iter().map(|id| Txid::from_str(id).unwrap()).find(|id| {
		electrs
			.transaction_get(id)
			.map(|tx| tx.input.iter().any(|i| i.previous_output == outpoint))
			.unwrap_or(false)
	})
}

/// The mempool transaction spending `outpoint` (the commitment, for a funding outpoint).
fn spender_in_mempool(
	bitcoind: &electrsd::corepc_node::Client, electrs: &impl ElectrumApi, outpoint: OutPoint,
) -> Txid {
	let mut found = None;
	wait_until("commitment broadcast", Duration::from_secs(60), || {
		found = spender(bitcoind, electrs, outpoint);
		found.is_some()
	});
	found.expect("the commitment spending the funding output is in the mempool")
}
