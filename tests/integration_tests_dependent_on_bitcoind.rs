// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! End to end: a regtest bitcoind with `-blockfilterindex=1` → a Pro node following it over RPC
//! (the block-polling engine) → a Dependent node whose every chain slot is that Pro node, all in
//! one process.
//!
//! The provider here is what an embedding app's network provider is, minus the network: every
//! call goes through the Pro node's public `chain_serve_*` functions, so the Dependent sees
//! exactly the wire types it would see over a relay. The Pro node answers wallet and Lightning
//! syncs by scanning bitcoind's block filters.

mod common;

use common::random_config;

use ldk_node::bitcoin::{Address, Amount, BlockHash, Txid};
use ldk_node::chain_provider::{
	ChainDataProvider, ChainProviderError, WireBlockId, WireBroadcastRequest, WireFeeEstimates,
	WireLightningSyncRequest, WireLightningSyncResponse, WireMempoolRequest, WireMempoolResponse,
	WireSyncRequest, WireTxStatusRequest, WireTxStatusResponse, WireUpdate, WireWatchedTx,
	CHAIN_WIRE_VERSION,
};
use ldk_node::config::EsploraSyncConfig;
use ldk_node::logger::LogLevel;
use ldk_node::payment::{ConfirmationStatus, PaymentKind};
use ldk_node::{Builder, Node, NodeError};

use electrsd::corepc_node::Node as BitcoinD;
use electrsd::corepc_node::{self, Client as BitcoindClient};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(120);

/// Blocks one served scan covers at most (the fork's `FILTER_SCAN_MAX_BLOCKS`).
const SCAN_CAP: u32 = 2016;

fn setup_bitcoind() -> BitcoinD {
	let exe = std::env::var("BITCOIND_EXE")
		.ok()
		.or_else(|| corepc_node::downloaded_exe_path().ok())
		.expect(
			"you need to provide an env var BITCOIND_EXE or specify a bitcoind version feature",
		);
	let mut conf = corepc_node::Conf::default();
	conf.network = "regtest";
	conf.args.push("-blockfilterindex=1");
	BitcoinD::with_conf(exe, &conf).unwrap()
}

fn mine(client: &BitcoindClient, count: usize, to: &Address) -> Vec<BlockHash> {
	let res = client.generate_to_address(count, to).expect("generatetoaddress");
	res.0.iter().map(|h| h.parse().expect("block hash")).collect()
}

/// A block holding no transaction from the mempool.
fn mine_empty(client: &BitcoindClient, to: &Address) -> BlockHash {
	let res: serde_json::Value = client
		.call("generateblock", &[to.to_string().into(), serde_json::json!([])])
		.expect("generateblock");
	res["hash"].as_str().unwrap().parse().unwrap()
}

fn tip(client: &BitcoindClient) -> (u32, BlockHash) {
	(client.get_block_count().unwrap().0 as u32, client.best_block_hash().unwrap())
}

/// Waits for bitcoind's block filter index to reach its tip.
fn wait_for_filter_index(client: &BitcoindClient) {
	let deadline = Instant::now() + WAIT;
	loop {
		let info: serde_json::Value = client.call("getindexinfo", &[]).unwrap();
		let index = &info["basic block filter index"];
		let (height, _) = tip(client);
		if index["synced"].as_bool() == Some(true)
			&& index["best_block_height"].as_u64() == Some(height as u64)
		{
			return;
		}
		assert!(Instant::now() < deadline, "bitcoind never indexed the filters to its tip");
		std::thread::sleep(Duration::from_millis(100));
	}
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
	let deadline = Instant::now() + WAIT;
	while !cond() {
		assert!(Instant::now() < deadline, "timed out after {:?} waiting for {}", WAIT, what);
		std::thread::sleep(Duration::from_millis(250));
	}
}

fn setup_pro_node(bitcoind: &BitcoinD) -> Arc<Node> {
	let config = random_config(true);
	let mut builder = Builder::from_config(config.node_config.clone());
	let rpc = bitcoind.params.rpc_socket;
	let cookie = bitcoind.params.get_cookie_values().unwrap().unwrap();
	builder.set_chain_source_bitcoind_rpc(
		rpc.ip().to_string(),
		rpc.port(),
		cookie.user,
		cookie.password,
	);
	builder.set_filesystem_logger(None, Some(LogLevel::Debug));
	let node = Arc::new(builder.build().unwrap());
	node.start().unwrap();
	node
}

/// A Dependent node, syncing only when told to.
fn setup_dependent_node(provider: Arc<ProNodeProvider>) -> Node {
	let config = random_config(true);
	let mut builder = Builder::from_config(config.node_config.clone());
	builder.set_chain_source_dependent(
		provider as Arc<dyn ChainDataProvider>,
		Some(EsploraSyncConfig { background_sync_config: None }),
	);
	builder.set_filesystem_logger(None, Some(LogLevel::Debug));
	let node = builder.build().unwrap();
	node.start().unwrap();
	node
}

/// A [`ChainDataProvider`] over a Pro node's public serves. Counts the calls it makes.
struct ProNodeProvider {
	pro: Arc<Node>,
	calls: Mutex<HashMap<&'static str, usize>>,
}

impl ProNodeProvider {
	fn new(pro: Arc<Node>) -> Self {
		Self { pro, calls: Mutex::new(HashMap::new()) }
	}

	fn calls(&self, route: &'static str) -> usize {
		self.calls.lock().unwrap().get(route).copied().unwrap_or(0)
	}

	/// `Node::chain_serve_*` block on the Pro node's runtime, so each call leaves the
	/// Dependent's async context for a blocking thread, as a transport handler would.
	async fn serve<T: Send + 'static>(
		&self, route: &'static str, f: impl FnOnce(&Node) -> Result<T, NodeError> + Send + 'static,
	) -> Result<T, ChainProviderError> {
		*self.calls.lock().unwrap().entry(route).or_default() += 1;
		let pro = Arc::clone(&self.pro);
		tokio::task::spawn_blocking(move || f(&pro))
			.await
			.map_err(|e| ChainProviderError::Unreachable(format!("serve task failed: {}", e)))?
			.map_err(|e| ChainProviderError::Refused(format!("{}: {}", route, e)))
	}
}

#[async_trait::async_trait]
impl ChainDataProvider for ProNodeProvider {
	fn name(&self) -> String {
		"pro-node".to_string()
	}

	async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError> {
		self.serve("fee_estimates", |pro| pro.chain_serve_fee_estimates()).await
	}

	async fn broadcast(&self, req: WireBroadcastRequest) -> Result<(), ChainProviderError> {
		self.serve("broadcast", move |pro| pro.chain_serve_broadcast(&req)).await
	}

	#[allow(unused_variables)]
	async fn tx_status(
		&self, req: WireTxStatusRequest,
	) -> Result<WireTxStatusResponse, ChainProviderError> {
		#[cfg(feature = "swaps")]
		{
			self.serve("tx_status", move |pro| pro.chain_serve_tx_status(&req)).await
		}
		#[cfg(not(feature = "swaps"))]
		{
			Err(ChainProviderError::Refused("unsupported".into()))
		}
	}

	async fn wallet_sync(&self, req: WireSyncRequest) -> Result<WireUpdate, ChainProviderError> {
		self.serve("wallet_sync", move |pro| pro.chain_serve_wallet_sync(&req)).await
	}

	async fn lightning_sync(
		&self, req: WireLightningSyncRequest,
	) -> Result<WireLightningSyncResponse, ChainProviderError> {
		self.serve("lightning_sync", move |pro| pro.chain_serve_lightning_sync(&req)).await
	}

	async fn mempool(
		&self, req: WireMempoolRequest,
	) -> Result<WireMempoolResponse, ChainProviderError> {
		self.serve("mempool", move |pro| pro.chain_serve_mempool(&req)).await
	}
}

fn onchain_status(node: &Node, txid: Txid) -> Option<ConfirmationStatus> {
	node.list_payments().into_iter().find_map(|p| match p.kind {
		PaymentKind::Onchain { txid: t, status } if t == txid => Some(status),
		_ => None,
	})
}

fn best_block(node: &Node) -> (u32, BlockHash) {
	let best = node.status().current_best_block;
	(best.height, best.block_hash)
}

#[test]
fn dependent_node_syncs_through_a_bitcoind_pro_node() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);

	let pro = setup_pro_node(&bitcoind);
	let provider = Arc::new(ProNodeProvider::new(Arc::clone(&pro)));
	let dependent = setup_dependent_node(Arc::clone(&provider));
	assert_eq!(dependent.chain_slot_adapters().engine, "dependent-tx-sync");

	// (a) A first sync is a full scan from genesis, through the Pro node's filters.
	dependent.sync_wallets().unwrap();
	assert_eq!(best_block(&dependent), tip(client));
	assert!(provider.calls("wallet_sync") >= 1 && provider.calls("lightning_sync") >= 1);
	println!("(a) dependent synced to {:?}", best_block(&dependent));

	// (b) An incoming payment is seen unconfirmed, from the Pro node's mempool, before it is
	// mined — and confirmed once it is.
	let addr = dependent.onchain_payment().new_address().unwrap();
	let amount = Amount::from_sat(250_000);
	let txid: Txid = client.send_to_address(&addr, amount).unwrap().0.parse().unwrap();
	dependent.sync_wallets().unwrap();
	let balances = dependent.list_balances();
	assert_eq!(balances.total_onchain_balance_sats, amount.to_sat(), "seen in the mempool");
	assert_eq!(balances.spendable_onchain_balance_sats, 0, "not spendable unconfirmed");
	assert_eq!(onchain_status(&dependent, txid), Some(ConfirmationStatus::Unconfirmed));

	let funding_block = mine(client, 1, &miner)[0];
	wait_for_filter_index(client);
	dependent.sync_wallets().unwrap();
	assert_eq!(dependent.list_balances().spendable_onchain_balance_sats, amount.to_sat());
	match onchain_status(&dependent, txid) {
		Some(ConfirmationStatus::Confirmed { block_hash, .. }) => {
			assert_eq!(block_hash, funding_block)
		},
		other => panic!("the funding should be confirmed, is {:?}", other),
	}
	println!("(b) funding {} unconfirmed, then confirmed in {}", txid, funding_block);

	// (c) Reorg: the funding block is replaced by a longer branch without the funding, which
	// falls back to the mempool. The Dependent drops the stale block and sees the payment
	// unconfirmed again; mined on the new branch, it confirms there.
	client.invalidate_block(funding_block).unwrap();
	mine_empty(client, &miner);
	mine_empty(client, &miner);
	wait_for_filter_index(client);
	dependent.sync_wallets().unwrap();
	assert_eq!(best_block(&dependent), tip(client));
	let balances = dependent.list_balances();
	assert_eq!(balances.spendable_onchain_balance_sats, 0, "no longer confirmed");
	assert_eq!(balances.total_onchain_balance_sats, amount.to_sat(), "back in the mempool");
	assert_eq!(onchain_status(&dependent, txid), Some(ConfirmationStatus::Unconfirmed));

	let reconfirmed_in = mine(client, 1, &miner)[0];
	wait_for_filter_index(client);
	dependent.sync_wallets().unwrap();
	assert_eq!(dependent.list_balances().spendable_onchain_balance_sats, amount.to_sat());
	match onchain_status(&dependent, txid) {
		Some(ConfirmationStatus::Confirmed { block_hash, .. }) => {
			assert_eq!(block_hash, reconfirmed_in)
		},
		other => panic!("the funding should be re-confirmed, is {:?}", other),
	}
	println!("(c) reorg followed; funding re-confirmed in {}", reconfirmed_in);

	// (d) A spend of everything to someone else pays none of the Dependent's scripts: the
	// Pro node recognises it by the outpoint the Dependent says it holds.
	let external = client.new_address().unwrap();
	let sweep = dependent.onchain_payment().send_all_to_address(&external, false, None).unwrap();
	wait_until("bitcoind to have the sweep", || {
		client.call::<serde_json::Value>("getmempoolentry", &[sweep.to_string().into()]).is_ok()
	});
	assert!(provider.calls("broadcast") >= 1, "the sweep went out through the Pro node");
	let sweep_block = mine(client, 1, &miner)[0];
	wait_for_filter_index(client);
	dependent.sync_wallets().unwrap();
	assert_eq!(dependent.list_balances().total_onchain_balance_sats, 0);
	match onchain_status(&dependent, sweep) {
		Some(ConfirmationStatus::Confirmed { block_hash, .. }) => {
			assert_eq!(block_hash, sweep_block)
		},
		other => panic!("the sweep should be confirmed, is {:?}", other),
	}
	println!("(d) sweep {} confirmed in {}", sweep, sweep_block);

	// (e) Further behind than one scan covers: a served scan answers up to its cap, the next
	// request continues from there, and the Dependent chains the two itself within one sync.
	let (from_height, from_hash) = tip(client);
	let from = WireBlockId { height: from_height, hash: from_hash.to_string() };
	let late_addr = dependent.onchain_payment().new_address().unwrap();
	// In chunks: one long `generatetoaddress` outlasts the RPC client's timeout.
	let mut left = SCAN_CAP as usize + 50;
	while left > 0 {
		let n = left.min(200);
		mine(client, n, &miner);
		left -= n;
	}
	let late_amount = Amount::from_sat(80_000);
	let late_txid: Txid =
		client.send_to_address(&late_addr, late_amount).unwrap().0.parse().unwrap();
	let late_block = mine(client, 1, &miner)[0];
	wait_for_filter_index(client);
	let (tip_height, tip_hash) = tip(client);

	// The Pro node's side, asked directly.
	let request = |from: &WireBlockId| WireSyncRequest {
		version: CHAIN_WIRE_VERSION,
		start_time: 0,
		chain_tip: vec![from.clone()],
		spks: vec![late_addr.script_pubkey().to_hex_string()],
		txids: Vec::new(),
		outpoints: Vec::new(),
		full_scan: false,
		stop_gap: 0,
		owned_outpoints: Vec::new(),
	};
	let first = pro.chain_serve_wallet_sync(&request(&from)).unwrap();
	let first_end = first.checkpoints.last().unwrap().clone();
	assert_eq!(first_end.height, from_height + SCAN_CAP, "a partial answer ends at the cap");
	assert!(first.txs.is_empty(), "the payment is past the first answer");
	assert_eq!(first.server_tip.as_ref().map(|t| t.height), Some(tip_height), "and says so");
	let second = pro.chain_serve_wallet_sync(&request(&first_end)).unwrap();
	assert_eq!(second.checkpoints.last().unwrap().height, tip_height);
	assert!(second.server_tip.is_none(), "a complete answer names no other tip");
	assert_eq!(second.anchors.len(), 1);
	assert_eq!(second.anchors[0].txid, late_txid.to_string());
	assert_eq!(second.anchors[0].block.hash, late_block.to_string());

	let watched = |scan_from: &WireBlockId| WireLightningSyncRequest {
		version: CHAIN_WIRE_VERSION,
		txids: vec![WireWatchedTx {
			txid: late_txid.to_string(),
			known_block_hash: None,
			script_hex: Some(late_addr.script_pubkey().to_hex_string()),
		}],
		outputs: Vec::new(),
		scan_from: Some(scan_from.clone()),
	};
	let first = pro.chain_serve_lightning_sync(&watched(&from)).unwrap();
	assert_eq!(
		first.tip.height,
		from_height + SCAN_CAP,
		"a partial answer's tip is its last block"
	);
	assert!(first.confirmed.is_empty());
	assert_eq!(first.server_tip.as_ref().map(|t| t.height), Some(tip_height));
	let second = pro.chain_serve_lightning_sync(&watched(&first.tip)).unwrap();
	assert!(second.server_tip.is_none());
	assert_eq!((second.tip.height, second.tip.hash.clone()), (tip_height, tip_hash.to_string()));
	assert_eq!(second.confirmed.len(), 1);
	assert_eq!(second.confirmed[0].block.hash, late_block.to_string());

	// The Dependent's side: one sync reaches the tip and finds the payment.
	let wallet_syncs_before = provider.calls("wallet_sync");
	dependent.sync_wallets().unwrap();
	assert_eq!(best_block(&dependent), (tip_height, tip_hash));
	assert_eq!(dependent.list_balances().spendable_onchain_balance_sats, late_amount.to_sat());
	assert!(
		provider.calls("wallet_sync") - wallet_syncs_before >= 2,
		"the capped answer was followed by another"
	);
	println!(
		"(e) {} blocks behind: caught up to {} in one sync, payment {} found",
		tip_height - from_height,
		tip_height,
		late_txid
	);

	dependent.stop().unwrap();
	pro.stop().unwrap();
}
