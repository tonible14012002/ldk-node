// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! End to end: a regtest bitcoind with `-blockfilterindex=1` → a Pro node serving raw BIP157
//! data from it (`Node::chain_serve_*`) → a hybrid node following the chain by compact block
//! filters from that Pro node alone (`CbfSource::Node`), all in one process.
//!
//! The filter source here is what an embedding app's network-backed source is, minus the
//! network: every answer goes through the Pro node's public serve functions and the public wire
//! conversions in `ldk_node::chain_filter_source`, so the hybrid sees exactly the bytes it would
//! see over a relay.

#![cfg(feature = "cbf")]

mod common;

use common::random_config;

use ldk_node::chain_filter_source::{
	chain_tip_from_wire, filter_headers_from_wire, filters_from_wire, headers_from_wire,
	BlockChunkAssembler, BlockFilter, BlockId, FilterHeaders, FilterSource, IndexedFilter,
	SourceError,
};
use ldk_node::chain_provider::{
	WireBlockRequest, WireFilterHeadersRequest, WireFiltersRequest, WireHeadersRequest,
	CHAIN_WIRE_VERSION,
};
use ldk_node::logger::LogLevel;
use ldk_node::{Builder, CbfConfig, CbfSource, CbfSyncStatus, Node, NodeError};

use bitcoin::block::Header;
use bitcoin::{Address, Amount, Block, BlockHash};

use electrsd::corepc_node::Node as BitcoinD;
use electrsd::corepc_node::{self, Client as BitcoindClient};

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long any one condition is waited on. The hybrid polls its source's tip every 30s, so a
/// new block can take that long to be noticed; this leaves room for a few polls.
const WAIT: Duration = Duration::from_secs(150);

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

/// Waits for bitcoind's block filter index to reach its tip: the Pro node's raw source reads
/// filters through `getblockfilter`, which answers only for indexed blocks.
fn wait_for_filter_index(client: &BitcoindClient) {
	let deadline = Instant::now() + WAIT;
	loop {
		let tip: BlockHash = client.best_block_hash().unwrap();
		if client.call::<serde_json::Value>("getblockfilter", &[tip.to_string().into()]).is_ok() {
			return;
		}
		assert!(Instant::now() < deadline, "bitcoind never indexed the filter of its tip");
		std::thread::sleep(Duration::from_millis(200));
	}
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
	let deadline = Instant::now() + WAIT;
	while !cond() {
		assert!(Instant::now() < deadline, "timed out after {:?} waiting for {}", WAIT, what);
		std::thread::sleep(Duration::from_millis(250));
	}
}

/// A Pro node: follows regtest over bitcoind RPC, like the harness's nodes, and serves raw
/// BIP157 data read from the same bitcoind.
fn setup_pro_node(bitcoind: &BitcoinD) -> Arc<Node> {
	let config = random_config(true);
	let mut builder = Builder::from_config(config.node_config.clone());
	let rpc = bitcoind.params.rpc_socket;
	let cookie = bitcoind.params.get_cookie_values().unwrap().unwrap();
	builder.set_chain_source_bitcoind_rpc(
		rpc.ip().to_string(),
		rpc.port(),
		cookie.user.clone(),
		cookie.password.clone(),
	);
	builder.set_raw_chain_source_bitcoind_rpc(
		format!("http://{}", rpc),
		cookie.user,
		cookie.password,
		None,
	);
	builder.set_filesystem_logger(None, Some(LogLevel::Debug));
	let node = Arc::new(builder.build().unwrap());
	node.start().unwrap();
	node
}

/// A hybrid node that follows the chain by filters from `source` alone.
fn setup_hybrid_node(source: Arc<dyn FilterSource>) -> (Node, String) {
	let config = random_config(true);
	let storage_dir = config.node_config.storage_dir_path.clone();
	let mut builder = Builder::from_config(config.node_config.clone());
	builder.set_chain_source_cbf(
		vec![],
		CbfConfig { source: CbfSource::Node, wallet_birthday_height: None, ..Default::default() },
	);
	builder.set_cbf_filter_source(source);
	builder.set_filesystem_logger(None, Some(LogLevel::Debug));
	let node = builder.build().unwrap();
	node.start().unwrap();
	(node, storage_dir)
}

/// A [`FilterSource`] over a Pro node's public raw serves and the public wire conversions — the
/// shape of the app's network-backed source, minus the network. Counts the calls it makes.
///
/// `Node::chain_serve_*` block on the Pro node's own runtime, so each call leaves the hybrid's
/// async context for a blocking thread first, as a transport handler would run on its own.
struct ProNodeFilterSource {
	pro: Arc<Node>,
	calls: Mutex<HashMap<&'static str, usize>>,
	/// When set, the last filter of every span is replaced by a different, well-formed filter:
	/// a source that lies about what a block holds.
	corrupt_filters: AtomicBool,
}

impl ProNodeFilterSource {
	fn new(pro: Arc<Node>) -> Self {
		Self { pro, calls: Mutex::new(HashMap::new()), corrupt_filters: AtomicBool::new(false) }
	}

	fn calls(&self, method: &'static str) -> usize {
		self.calls.lock().unwrap().get(method).copied().unwrap_or(0)
	}

	async fn serve<T: Send + 'static>(
		&self, method: &'static str, f: impl FnOnce(&Node) -> Result<T, NodeError> + Send + 'static,
	) -> Result<T, SourceError> {
		*self.calls.lock().unwrap().entry(method).or_default() += 1;
		let pro = Arc::clone(&self.pro);
		tokio::task::spawn_blocking(move || f(&pro))
			.await
			.map_err(|e| SourceError::unavailable(format!("serve task failed: {}", e)))?
			.map_err(|e| SourceError::unavailable(format!("pro node: {}", e)))
	}
}

#[async_trait::async_trait]
impl FilterSource for ProNodeFilterSource {
	fn name(&self) -> &'static str {
		"pro-node"
	}

	async fn tip(&self) -> Result<BlockId, SourceError> {
		let wire = self.serve("tip", |pro| pro.chain_serve_tip()).await?;
		Ok(chain_tip_from_wire(&wire)?)
	}

	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		let req = WireHeadersRequest { version: CHAIN_WIRE_VERSION, from_height, count };
		let wire = self.serve("headers", move |pro| pro.chain_serve_headers(&req)).await?;
		Ok(headers_from_wire(&wire)?)
	}

	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		let req = WireFilterHeadersRequest {
			version: CHAIN_WIRE_VERSION,
			start_height,
			stop_hash: stop_hash.to_string(),
		};
		let wire =
			self.serve("filter_headers", move |pro| pro.chain_serve_filter_headers(&req)).await?;
		Ok(filter_headers_from_wire(&wire)?)
	}

	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		let req = WireFiltersRequest {
			version: CHAIN_WIRE_VERSION,
			start_height,
			stop_hash: stop_hash.to_string(),
		};
		let wire = self.serve("filters", move |pro| pro.chain_serve_filters(&req)).await?;
		let mut filters = filters_from_wire(&wire)?;
		if self.corrupt_filters.load(Ordering::Acquire) {
			if let Some(last) = filters.last_mut() {
				let mut content = last.filter.content.clone();
				content.push(0x00);
				last.filter = BlockFilter::new(&content);
			}
		}
		Ok(filters)
	}

	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		let mut assembler = BlockChunkAssembler::new(hash);
		loop {
			let req = WireBlockRequest {
				version: CHAIN_WIRE_VERSION,
				hash: hash.to_string(),
				chunk: assembler.next_chunk(),
			};
			let chunk = self.serve("block", move |pro| pro.chain_serve_block(&req)).await?;
			if let Some(block) = assembler.push(&chunk)? {
				return Ok(block);
			}
		}
	}
}

fn hybrid_best_block(node: &Node) -> BlockId {
	let best = node.status().current_best_block;
	BlockId { height: best.height, hash: best.block_hash }
}

fn bitcoind_tip(client: &BitcoindClient) -> BlockId {
	let hash = client.best_block_hash().unwrap();
	let height = client.get_block_count().unwrap().0 as u32;
	BlockId { height, hash }
}

fn wait_for_hybrid_at_tip(hybrid: &Node, client: &BitcoindClient, what: &str) {
	let want = bitcoind_tip(client);
	wait_until(what, || {
		hybrid.cbf_sync_status() == Some(CbfSyncStatus::Synced) && hybrid_best_block(hybrid) == want
	});
}

fn log_contains(storage_dir: &str, needle: &str) -> bool {
	let path = Path::new(storage_dir).join(ldk_node::config::DEFAULT_LOG_FILENAME);
	std::fs::read_to_string(&path).map(|log| log.contains(needle)).unwrap_or(false)
}

#[test]
fn hybrid_node_follows_regtest_through_a_pro_nodes_raw_routes() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);

	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	let (hybrid, hybrid_dir) = setup_hybrid_node(Arc::clone(&source) as Arc<dyn FilterSource>);

	// (a) A fresh regtest wallet has nothing to anchor on but genesis, and syncs from it.
	wait_for_hybrid_at_tip(&hybrid, client, "the hybrid to sync to bitcoind's tip");
	assert!(log_contains(&hybrid_dir, "no birthday on regtest; scanning from genesis"));
	assert_eq!(hybrid.chain_slot_adapters().engine, "cbf(node)");
	assert!(
		!Path::new(&hybrid_dir).join("bip157_data").exists(),
		"a node-source hybrid must never build kyoto"
	);
	println!(
		"(a) hybrid synced to {:?} over the Pro node's raw routes",
		hybrid_best_block(&hybrid)
	);

	// (b) Coins sent to the hybrid are found by filter match, fetched as a full block through
	// the Pro node, checked against the merkle root, and applied.
	let addr = hybrid.onchain_payment().new_address().unwrap();
	let amount = Amount::from_sat(250_000);
	let txid: bitcoin::Txid = client.send_to_address(&addr, amount).unwrap().0.parse().unwrap();
	let funding_block = mine(client, 1, &miner)[0];
	mine(client, 5, &miner);
	wait_for_filter_index(client);
	wait_for_hybrid_at_tip(&hybrid, client, "the hybrid to sync past the funding block");
	wait_until("the hybrid's wallet to see the funding", || {
		hybrid.list_balances().spendable_onchain_balance_sats == amount.to_sat()
	});
	assert!(source.calls("block") >= 1, "the funding block must have been fetched");
	println!(
		"(b) funding {} confirmed in {}; hybrid balance {} sat",
		txid,
		funding_block,
		amount.to_sat()
	);

	// (c) Reorg: drop every block from the funding block up and mine a longer branch. The
	// funding transaction falls back to bitcoind's mempool and is mined again on the new
	// branch, so the hybrid must disconnect, follow, and re-confirm it.
	let old_tip = bitcoind_tip(client);
	client.invalidate_block(funding_block).unwrap();
	let fork_height = bitcoind_tip(client).height;
	let new_branch = mine(client, 8, &miner);
	wait_for_filter_index(client);
	let new_tip = bitcoind_tip(client);
	assert!(new_tip.height > old_tip.height && new_tip.hash != old_tip.hash);
	let refunded_in: BlockHash = {
		let tx = client.get_transaction(txid).unwrap();
		tx.block_hash.expect("re-mined").parse().unwrap()
	};
	assert!(new_branch.contains(&refunded_in), "the funding must be re-mined on the new branch");
	wait_for_hybrid_at_tip(&hybrid, client, "the hybrid to follow the reorg");
	wait_until("the hybrid's wallet to re-confirm the funding", || {
		hybrid.list_balances().spendable_onchain_balance_sats == amount.to_sat()
	});
	hybrid.sync_wallets().unwrap();
	assert_eq!(hybrid.list_balances().spendable_onchain_balance_sats, amount.to_sat());
	assert!(log_contains(&hybrid_dir, "CBF reorg from filter source 'pro-node'"));
	println!(
		"(c) reorg from height {} ({}) at fork {} to {:?}; funding re-confirmed in {}",
		old_tip.height, old_tip.hash, fork_height, new_tip, refunded_in
	);

	// (d) Everything came through the Pro node's serves.
	println!(
		"(d) served calls: tip={} headers={} filter_headers={} filters={} block={}",
		source.calls("tip"),
		source.calls("headers"),
		source.calls("filter_headers"),
		source.calls("filters"),
		source.calls("block")
	);
	for method in ["tip", "headers", "filter_headers", "filters", "block"] {
		assert!(source.calls(method) >= 1, "no {} call reached the Pro node", method);
	}

	hybrid.stop().unwrap();
	pro.stop().unwrap();
}

#[test]
fn hybrid_node_refuses_a_filter_that_does_not_match_its_header() {
	let bitcoind = setup_bitcoind();
	let client = &bitcoind.client;
	let _ = client.create_wallet("ldk_node_test");
	let _ = client.load_wallet("ldk_node_test");
	let miner = client.new_address().unwrap();
	mine(client, 101, &miner);
	wait_for_filter_index(client);

	let pro = setup_pro_node(&bitcoind);
	let source = Arc::new(ProNodeFilterSource::new(Arc::clone(&pro)));
	source.corrupt_filters.store(true, Ordering::Release);
	let (hybrid, hybrid_dir) = setup_hybrid_node(Arc::clone(&source) as Arc<dyn FilterSource>);

	// (e) Every span's last filter disagrees with the served filter-header chain: nothing is
	// applied, three strikes fail the sync closed, and the log names the check.
	wait_until("the hybrid to fail closed", || {
		hybrid.cbf_sync_status() == Some(CbfSyncStatus::Failed)
	});
	assert_eq!(hybrid_best_block(&hybrid).height, 0, "nothing from the lying source was applied");
	assert!(log_contains(&hybrid_dir, "failed verification"));
	assert!(log_contains(&hybrid_dir, "failed closed"));
	println!(
		"(e) corrupted filters refused after {} filters calls; hybrid stayed at genesis",
		source.calls("filters")
	);

	hybrid.stop().unwrap();
	pro.stop().unwrap();
}
