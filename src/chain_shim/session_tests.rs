// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The session against real nodes: a [`crate::Node`] on a chain host over a session, Pros made of
//! the same fake chains and raw server the sync loop's own tests use, and real time. What depends
//! on the design's minutes is in `node_chain::session::machine`'s tests, on a fake clock.
//!
//! The first test answers the question this work started from: does a node start, and stay
//! healthy, with no chain answers at all.
//!
//! These are the session tests that need this crate's `Node` and `Builder`; the session's
//! node-free tests run in `node-chain` (`session/tests.rs`), over the same fakes (its
//! `_test_utils` feature).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use bdk_chain::BlockId;
use bitcoin::block::Header;
use bitcoin::{Block, BlockHash, Network};
use lightning::chain::BestBlock;
use lightning::util::test_utils::TestStore;

use super::{ChainHost, ChainHostBuilder};
use crate::config::{CbfConfig, CbfSource};
use crate::logger::Logger;
use crate::{Builder, Error, Node};
use node_chain::cbf::bundle_source::test_support::ServerTransport;
use node_chain::cbf::source::{FilterHeaders, IndexedFilter};
use node_chain::cbf::source::{FilterSource, SourceError};
use node_chain::cbf::source_sync::test_support::FakeSource;
use node_chain::provider::WireAckStatus;
use node_chain::provider::{
	BundleTransport, ChainDataProvider, ChainProviderError, WireBlockId, WireBlockUpdates,
	WireBroadcastRequest, WireFeeEstimates, WireLightningSyncRequest, WireLightningSyncResponse,
	WireMempoolRequest, WireMempoolResponse, WireSinceRequest, WireSubscribeRequest,
	WireSubscribeResponse, WireSyncRequest, WireTxStatusRequest, WireTxStatusResponse, WireUpdate,
	CHAIN_WIRE_VERSION,
};
use node_chain::session::machine::SessionState;
use node_chain::session::trace::TraceOrigin;
use node_chain::session::*;
use node_chain::subscription::SubscriptionRegistry;
use node_chain::wire_convert::block_id_to_wire;
use std::time::{SystemTime, UNIX_EPOCH};

const WAIT: Duration = Duration::from_secs(30);
/// For what only shows after the next 30 s tip poll, on a Pull node nobody pushes to.
const WAIT_POLL: Duration = Duration::from_secs(90);
const PRO_A: &str = "02aa";
const PRO_B: &str = "02bb";
const THIS_NODE: &str = "03cc";

fn logger() -> Arc<Logger> {
	Arc::new(Logger::new_log_facade())
}

fn temp_dir(name: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!(
		"ldk-node-session-{}-{}-{:?}",
		name,
		std::process::id(),
		std::thread::current().id()
	));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// A Pro node a test can reach and turn off.
struct TestPro {
	source: Arc<FakeSource>,
	transport: Arc<ServerTransport>,
	leases: Arc<SubscriptionRegistry>,
	down: AtomicBool,
	not_ready: AtomicBool,
	tip_calls: AtomicUsize,
	chain_calls: AtomicUsize,
	broadcasts: AtomicUsize,
	/// What it was handed to put on the network, in the order it came.
	sent: Mutex<Vec<String>>,
	/// It takes every broadcast and never answers.
	hangs_on_broadcast: AtomicBool,
	/// What it says of the mempool, if it answers that: which of the txids asked it does not hold.
	mempool_lacks: Mutex<Option<Vec<String>>>,
	/// The mempool questions it was asked.
	mempool_asked: Mutex<Vec<WireMempoolRequest>>,
	/// What it says of any transaction's status.
	tx_status_says: Mutex<Option<WireTxStatusResponse>>,
	fee_answer: Mutex<Option<WireFeeEstimates>>,
}

impl TestPro {
	/// `push`: whether it knows the lease routes, or is an older Pro.
	fn new(source: Arc<FakeSource>, push: bool) -> Arc<Self> {
		let transport =
			Arc::new(ServerTransport::new(Arc::clone(&source) as Arc<dyn FilterSource>));
		let leases = Arc::new(SubscriptionRegistry::default());
		if push {
			*transport.registry.lock().unwrap() =
				Some((Arc::clone(&leases), THIS_NODE.to_string()));
		}
		Arc::new(Self {
			source,
			transport,
			leases,
			down: AtomicBool::new(false),
			not_ready: AtomicBool::new(false),
			tip_calls: AtomicUsize::new(0),
			chain_calls: AtomicUsize::new(0),
			broadcasts: AtomicUsize::new(0),
			sent: Mutex::new(Vec::new()),
			hangs_on_broadcast: AtomicBool::new(false),
			mempool_lacks: Mutex::new(None),
			mempool_asked: Mutex::new(Vec::new()),
			tx_status_says: Mutex::new(None),
			fee_answer: Mutex::new(None),
		})
	}

	fn set_down(&self, down: bool) {
		self.down.store(down, Ordering::SeqCst);
		self.transport
			.refuse_with(down.then(|| ChainProviderError::Unreachable("test: down".into())));
	}

	/// Its node and app are up, its bitcoind is gone: what the app's raw routes say then.
	fn set_not_ready(&self) {
		self.not_ready.store(true, Ordering::SeqCst);
		self.transport.refuse_with(Some(ChainProviderError::Refused(
			"unsupported chain.since refused: not ready: bitcoind_unreachable".into(),
		)));
	}

	fn check_up(&self) -> Result<(), SourceError> {
		if self.down.load(Ordering::SeqCst) {
			return Err(SourceError::unavailable("test: down"));
		}
		Ok(())
	}
}

/// The Pro's raw routes as the app's `NodeFilterSource` would reach them.
struct Filters(Arc<TestPro>);

#[async_trait]
impl FilterSource for Filters {
	fn name(&self) -> &'static str {
		"test-filters"
	}
	async fn tip(&self) -> Result<BlockId, SourceError> {
		self.0.check_up()?;
		self.0.tip_calls.fetch_add(1, Ordering::SeqCst);
		self.0.source.tip().await
	}
	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		self.0.check_up()?;
		self.0.source.headers(from_height, count).await
	}
	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		self.0.check_up()?;
		self.0.source.filter_headers(start_height, stop_hash).await
	}
	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		self.0.check_up()?;
		self.0.source.filters(start_height, stop_hash).await
	}
	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		self.0.check_up()?;
		self.0.source.block(hash).await
	}
}

/// The Pro's other routes: reachable or not, serving nothing a test here looks at.
struct Chain(Arc<TestPro>);

impl Chain {
	fn answer<T>(&self) -> Result<T, ChainProviderError> {
		self.0.chain_calls.fetch_add(1, Ordering::SeqCst);
		if self.0.down.load(Ordering::SeqCst) {
			return Err(ChainProviderError::Unreachable("test: down".into()));
		}
		if self.0.not_ready.load(Ordering::SeqCst) {
			return Err(ChainProviderError::Refused(
				"unsupported chain.x refused: not ready: bitcoind_unreachable".into(),
			));
		}
		Err(ChainProviderError::Refused("failed: not served in this test".into()))
	}
}

#[async_trait]
impl ChainDataProvider for Chain {
	fn name(&self) -> String {
		"test-chain".into()
	}
	async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError> {
		if let Some(fees) = self.0.fee_answer.lock().unwrap().clone() {
			return Ok(fees);
		}
		// A Pro answers fees from what it cached, its bitcoind gone or not.
		if self.0.not_ready.load(Ordering::SeqCst) {
			return Ok(WireFeeEstimates { version: CHAIN_WIRE_VERSION, targets: Vec::new() });
		}
		self.answer()
	}
	async fn broadcast(&self, req: WireBroadcastRequest) -> Result<(), ChainProviderError> {
		self.0.broadcasts.fetch_add(1, Ordering::SeqCst);
		self.0.sent.lock().unwrap().push(req.tx_hex);
		if self.0.hangs_on_broadcast.load(Ordering::SeqCst) {
			std::future::pending::<()>().await;
		}
		if self.0.down.load(Ordering::SeqCst) {
			return Err(ChainProviderError::Unreachable("test: down".into()));
		}
		Ok(())
	}
	async fn mempool(
		&self, req: WireMempoolRequest,
	) -> Result<WireMempoolResponse, ChainProviderError> {
		self.0.mempool_asked.lock().unwrap().push(req.clone());
		let lacks = self.0.mempool_lacks.lock().unwrap().clone();
		let Some(lacks) = lacks else {
			return Err(ChainProviderError::Refused("unsupported".into()));
		};
		let tip = self.0.source.tip_id();
		Ok(WireMempoolResponse {
			version: CHAIN_WIRE_VERSION,
			tip: WireBlockId { height: tip.height, hash: tip.hash.to_string() },
			unconfirmed: Vec::new(),
			evicted: req.known_unconfirmed.into_iter().filter(|id| lacks.contains(id)).collect(),
		})
	}
	async fn tx_status(
		&self, _: WireTxStatusRequest,
	) -> Result<WireTxStatusResponse, ChainProviderError> {
		if let Some(says) = self.0.tx_status_says.lock().unwrap().clone() {
			return Ok(says);
		}
		self.answer()
	}
	async fn wallet_sync(&self, _: WireSyncRequest) -> Result<WireUpdate, ChainProviderError> {
		self.answer()
	}
	async fn lightning_sync(
		&self, _: WireLightningSyncRequest,
	) -> Result<WireLightningSyncResponse, ChainProviderError> {
		self.answer()
	}
}

#[derive(Default)]
struct Connector {
	pros: Mutex<HashMap<String, Arc<TestPro>>>,
}

impl Connector {
	fn with(pros: &[(&str, &Arc<TestPro>)]) -> Arc<Self> {
		let connector = Self::default();
		for (id, pro) in pros {
			connector.pros.lock().unwrap().insert(id.to_string(), Arc::clone(pro));
		}
		Arc::new(connector)
	}
}

impl ProviderConnector for Connector {
	fn connect(&self, node_id: &str) -> ProviderEndpoints {
		// An id nobody serves behaves as a Pro that is down.
		let pro = self.pros.lock().unwrap().get(node_id).cloned().unwrap_or_else(|| {
			let nobody = TestPro::new(Arc::new(FakeSource::new(1, &[])), false);
			nobody.set_down(true);
			nobody
		});
		ProviderEndpoints {
			chain: Arc::new(Chain(Arc::clone(&pro))),
			filters: Arc::new(Filters(Arc::clone(&pro))),
			bundles: Arc::clone(&pro.transport) as Arc<dyn BundleTransport>,
		}
	}
}

struct Stack {
	host: Arc<ChainHost>,
	node: Node,
	runtime: Arc<tokio::runtime::Runtime>,
}

impl Stack {
	fn stop(self) {
		let started = Instant::now();
		self.node.stop().unwrap();
		assert!(started.elapsed() < WAIT, "a node with nobody to ask stops all the same");
		drop(self.runtime);
	}
}

/// A fresh node, seeded at `birthday` of the chain the Pros serve, on a host over `session`,
/// with every chain answer coming through it.
fn cbf_node(session: Arc<ChainProviderSession>, birthday: Option<BestBlock>, seed: u8) -> Stack {
	let mut host_builder = ChainHostBuilder::new(Network::Regtest);
	host_builder.set_logger(logger());
	host_builder.set_chain_source_cbf_with_session(
		Vec::new(),
		CbfConfig { source: CbfSource::Node, ..CbfConfig::default() },
		session,
	);
	let host = host_builder.build().expect("a host with no provider builds");
	start_on(host, birthday, seed)
}

fn start_on(host: Arc<ChainHost>, birthday: Option<BestBlock>, seed: u8) -> Stack {
	let mut builder = Builder::new();
	builder.set_network(Network::Regtest);
	builder.set_log_facade_logger();
	builder.set_entropy_seed_bytes([seed; 64]);
	builder.set_chain_host(Arc::clone(&host));
	if let Some(birthday) = birthday {
		builder.set_wallet_birthday(birthday);
	}
	let node = builder.build_with_store(Arc::new(TestStore::new(false))).expect("a node builds");
	let runtime =
		Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
	node.start_with_runtime(Arc::clone(&runtime)).expect("a node starts");
	Stack { host, node, runtime }
}

fn birthday_of(source: &FakeSource, height: u32) -> BestBlock {
	BestBlock::new(source.block_at(height).block_hash(), height)
}

fn wait_for(what: &str, check: impl Fn() -> bool) {
	let started = Instant::now();
	while !check() {
		assert!(started.elapsed() < WAIT, "timed out waiting for {}", what);
		std::thread::sleep(Duration::from_millis(20));
	}
}

fn wait_for_poll(what: &str, check: impl Fn() -> bool) {
	let started = Instant::now();
	while !check() {
		assert!(started.elapsed() < WAIT_POLL, "timed out waiting for {}", what);
		std::thread::sleep(Duration::from_millis(20));
	}
}

fn session_on(
	connector: Arc<Connector>, preference: DeliveryPreference, dir: &Path,
) -> Arc<ChainProviderSession> {
	ChainProviderSession::new(
		connector,
		preference,
		Network::Regtest,
		dir.to_str().unwrap(),
		logger(),
	)
}

/// THE boot unknown: no provider, no answers. The node comes up, its Lightning and wallet state
/// serves reads and hands out addresses, nothing it runs dies, and a stop still stops. A provider
/// arriving later is taken with no restart.
#[test]
fn a_filter_node_boots_with_no_provider_stays_up_and_takes_one_without_a_restart() {
	let dir = temp_dir("boot-cbf");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let pro = TestPro::new(Arc::clone(&chain), true);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Push, &dir);
	let status = session.status();
	assert_eq!(status.state, SessionState::NoProvider);
	assert!(status.chain_stale);
	assert_eq!(status.active_node_id, None);

	let started = Instant::now();
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 21);
	assert!(
		started.elapsed() < Duration::from_secs(5),
		"start does not wait on a chain answer: took {:?}",
		started.elapsed()
	);

	// A while with no answers: long enough for every retry path to have run many times.
	std::thread::sleep(Duration::from_secs(3));
	assert!(stack.node.status().is_running);
	let cbf = stack.node.cbf_sync_status().expect("a filter node");
	assert!(
		!matches!(cbf, crate::CbfSyncStatus::Failed),
		"no answer is not a failed sync: {:?}",
		cbf
	);
	assert_eq!(stack.node.chain_freshness().fee_rates_updated_at, None, "and it says so");
	assert_eq!(stack.node.chain_freshness().onchain_wallet_synced_at, None);
	assert_eq!(stack.node.list_balances().total_onchain_balance_sats, 0);
	assert_eq!(stack.node.list_channels().len(), 0);
	assert!(stack.node.onchain_payment().new_address().is_ok(), "the wallet hands out addresses");
	assert_eq!(stack.node.status().current_best_block.height, 10, "the cursor stays where it was");
	assert_eq!(stack.node.chain_session_status().unwrap().state, SessionState::NoProvider);
	assert_eq!(pro.tip_calls.load(Ordering::SeqCst), 0, "nobody was asked");

	// A provider arrives. No restart.
	stack.node.chain_set_candidates(vec![PRO_A.to_string()]).unwrap();
	wait_for("the Pro to be picked", || session.status().active_node_id.as_deref() == Some(PRO_A));
	wait_for("the node to catch up", || stack.node.status().current_best_block.height == 29);
	let status = stack.node.chain_session_status().unwrap();
	assert_eq!(status.state, SessionState::Active);
	assert!(!status.chain_stale);
	assert_eq!(status.last_good.as_deref(), Some(PRO_A));
	assert!(status.last_ok_at.is_some());
	assert_eq!(status.cursor.map(|c| c.height), Some(29));
	wait_for("the lease", || !pro.leases.is_empty());
	wait_for("push delivery", || session.status().delivery == Delivery::Push);
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

/// The same for a Dependent node, whose every slot is the provider.
#[test]
fn a_dependent_node_boots_with_no_provider_and_its_calls_follow_the_source_once_set() {
	let dir = temp_dir("boot-dependent");
	let pro = TestPro::new(Arc::new(FakeSource::new(5, &[])), false);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);

	let mut host_builder = ChainHostBuilder::new(Network::Regtest);
	host_builder.set_logger(logger());
	host_builder.set_chain_source_dependent_with_session(Arc::clone(&session), None);
	let host = host_builder.build().unwrap();
	let started = Instant::now();
	let stack = start_on(host, None, 22);
	assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());

	std::thread::sleep(Duration::from_secs(2));
	assert!(stack.node.status().is_running);
	assert_eq!(stack.node.chain_freshness().fee_rates_updated_at, None);
	assert!(stack.node.onchain_payment().new_address().is_ok());
	assert_eq!(stack.node.chain_session_status().unwrap().state, SessionState::NoProvider);
	assert_eq!(pro.chain_calls.load(Ordering::SeqCst), 0);

	// The owner picks a source. The Pro is older and does not know `since`: not a lease, and not
	// a failure yet either.
	stack.host.chain_set_source(Some(PRO_A.to_string())).unwrap();
	let status = session.status();
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A));
	assert_eq!(status.pinned_node_id.as_deref(), Some(PRO_A));
	wait_for("a real call to reach it", || {
		// The fee refresh and wallet sync run on their own timers; a foreground sync does not wait.
		let _ = stack.node.sync_wallets();
		pro.chain_calls.load(Ordering::SeqCst) > 0
	});
	assert_eq!(session.status().delivery, Delivery::Pull, "a Dependent node never subscribes");
	assert!(pro.leases.is_empty());
	assert_eq!(pro.transport.calls("subscribe"), 0);
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

/// Found on regtest: a Pro whose node is up and whose bitcoind is gone. Its routes refuse, a
/// refusal said nothing, and the cached fee reply counted as an answer every few minutes, so the
/// node never probed: `active`, not stale, and the chain standing still. Saying "not ready" now
/// brings the probe forward, and a fee reply no longer counts as the Pro serving the chain.
#[test]
fn a_pro_that_is_not_ready_is_probed_at_once_and_its_cached_fees_do_not_keep_it() {
	let dir = temp_dir("not-ready");
	let pro = TestPro::new(Arc::new(FakeSource::new(5, &[])), true);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	let mut host_builder = ChainHostBuilder::new(Network::Regtest);
	host_builder.set_logger(logger());
	host_builder.set_chain_source_dependent_with_session(Arc::clone(&session), None);
	let stack = start_on(host_builder.build().unwrap(), None, 23);
	stack.host.chain_set_source(Some(PRO_A.to_string())).unwrap();
	wait_for("it to take the Pro", || session.status().state == SessionState::Active);

	let probes = pro.transport.calls("since");
	pro.set_not_ready();
	wait_for_poll("a probe soon after the first refusal, not at 10 min", || {
		let _ = stack.node.sync_wallets();
		pro.transport.calls("since") > probes
	});
	// The first `unsupported` does not count, the second one, 30 s on, does.
	wait_for_poll("suspect", || session.status().state == SessionState::Suspect);

	let last_ok = session.status().last_ok_at;
	let reply = stack.runtime.block_on(session.fee_estimates());
	assert!(reply.is_ok(), "a Pro answers fees from its cache");
	assert_eq!(session.status().state, SessionState::Suspect, "a fee reply proves no chain");
	assert_eq!(session.status().last_ok_at, last_ok);
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn on_push_nothing_polls_the_tip_a_push_moves_the_node_and_a_pin_moves_the_lease_at_once() {
	let dir = temp_dir("push-and-pin");
	let chain_a = Arc::new(FakeSource::new(30, &[]));
	let chain_b = Arc::new(FakeSource::new(0, &[]));
	for height in 0..30 {
		chain_b.push_raw(chain_a.block_at(height));
	}
	let pro_a = TestPro::new(Arc::clone(&chain_a), true);
	let pro_b = TestPro::new(Arc::clone(&chain_b), true);
	let session = session_on(
		Connector::with(&[(PRO_A, &pro_a), (PRO_B, &pro_b)]),
		DeliveryPreference::Push,
		&dir,
	);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain_a, 10)), 23);
	stack.node.chain_set_candidates(vec![PRO_A.to_string(), PRO_B.to_string()]).unwrap();
	wait_for("catching up", || stack.node.status().current_best_block.height == 29);
	wait_for("push delivery", || session.status().delivery == Delivery::Push);
	assert_eq!(pro_a.leases.len(), 1);
	assert_eq!(pro_b.leases.len(), 0);

	// While pushed to, the sync loop polling every 30 s never gets to ask, and a new block needs
	// no call of any kind.
	let tips = pro_a.tip_calls.load(Ordering::SeqCst);
	let since = pro_a.transport.calls("since");
	chain_a.mine(1, &[], 0);
	chain_b.mine(1, &[], 0);
	let push = stack.runtime.block_on(pro_a.transport.push(30..=30));
	let ack = stack.node.chain_receive_block_update(PRO_A, &push).unwrap();
	assert_eq!(ack.status, WireAckStatus::Applied);
	assert_eq!(ack.applied_tip.map(|t| t.height), Some(30));
	wait_for("the pushed block", || stack.node.status().current_best_block.height == 30);
	assert_eq!(pro_a.tip_calls.load(Ordering::SeqCst), tips, "no tip poll");
	assert_eq!(pro_a.transport.calls("since"), since, "no pull");

	// A push from anyone else is told it has no follower here.
	let ack = stack.node.chain_receive_block_update(PRO_B, &push).unwrap();
	assert_eq!(ack.status, WireAckStatus::NotSubscribed);

	// The owner picks the other Pro: the old lease goes at once, the new Pro grants one, and the
	// old Pro's next push is told to stop.
	stack.node.chain_set_source(Some(PRO_B.to_string())).unwrap();
	assert_eq!(session.status().active_node_id.as_deref(), Some(PRO_B), "at once");
	wait_for("the old lease to go", || pro_a.leases.is_empty());
	wait_for("the new lease", || pro_b.leases.len() == 1);
	wait_for("push delivery from it", || session.status().delivery == Delivery::Push);
	let ack = stack.node.chain_receive_block_update(PRO_A, &push).unwrap();
	assert_eq!(ack.status, WireAckStatus::NotSubscribed);

	// The new Pro's blocks move the node, without a restart.
	chain_b.mine(1, &[], 0);
	let push = stack.runtime.block_on(pro_b.transport.push(31..=31));
	let ack = stack.node.chain_receive_block_update(PRO_B, &push).unwrap();
	assert_eq!(ack.status, WireAckStatus::Applied);
	wait_for("the new Pro's block", || stack.node.status().current_best_block.height == 31);
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_pro_refusing_to_push_is_kept_and_the_node_pulls_from_it_polling_the_tip() {
	let dir = temp_dir("older-pro");
	let chain = Arc::new(FakeSource::new(30, &[]));
	// No lease routes: an older Pro.
	let pro = TestPro::new(Arc::clone(&chain), false);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Push, &dir);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 24);
	stack.node.chain_set_candidates(vec![PRO_A.to_string()]).unwrap();
	wait_for("catching up", || stack.node.status().current_best_block.height == 29);
	wait_for("the refused subscribe", || pro.transport.calls("subscribe") == 1);
	let status = session.status();
	assert_eq!(status.state, SessionState::Active);
	assert_eq!(status.delivery, Delivery::Pull);
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A), "it stays the Pro");
	assert!(pro.tip_calls.load(Ordering::SeqCst) > 0, "the tip is polled");
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

/// A restart with no app: nothing calls `chain_set_candidates`, and the node is on its last good
/// Pro from the first call.
#[test]
fn a_restart_resumes_on_the_last_good_pro_with_nobody_calling() {
	let dir = temp_dir("restart");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let pro = TestPro::new(Arc::clone(&chain), true);
	let connector = Connector::with(&[(PRO_A, &pro)]);
	{
		let session = session_on(Arc::clone(&connector), DeliveryPreference::Push, &dir);
		let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 25);
		stack.node.chain_set_candidates(vec![PRO_A.to_string()]).unwrap();
		wait_for("catching up", || stack.node.status().current_best_block.height == 29);
		stack.stop();
	}

	let session = session_on(connector, DeliveryPreference::Push, &dir);
	let status = session.status();
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A), "from disk alone");
	assert_eq!(status.last_good.as_deref(), Some(PRO_A));
	assert_eq!(status.candidates, vec![PRO_A.to_string()]);
	assert_eq!(status.state, SessionState::Active);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 26);
	wait_for("catching up", || stack.node.status().current_best_block.height == 29);
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

/// A transaction handed over with nobody to send it to waits for somebody: losing it to an
/// exhausted chain could be a force close never sent.
#[test]
fn a_broadcast_with_no_provider_waits_and_goes_when_a_source_is_set() {
	use bitcoin::{absolute, transaction, Transaction};
	use node_chain_seam::Broadcast;

	let dir = temp_dir("broadcast");
	let pro = TestPro::new(Arc::new(FakeSource::new(3, &[])), false);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	assert!(!session.is_available());
	let mut host_builder = ChainHostBuilder::new(Network::Regtest);
	host_builder.set_logger(logger());
	host_builder.set_chain_source_dependent_with_session(Arc::clone(&session), None);
	let stack = start_on(host_builder.build().unwrap(), None, 28);

	let tx = Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::ZERO,
		input: Vec::new(),
		output: Vec::new(),
	};
	stack.host.tx_broadcaster().broadcast(&[&tx]);
	// The drain looks every second.
	std::thread::sleep(Duration::from_millis(2500));
	assert_eq!(pro.broadcasts.load(Ordering::SeqCst), 0);

	stack.node.chain_set_source(Some(PRO_A.to_string())).unwrap();
	wait_for("the pin to take", || session.is_available());
	wait_for("the waiting transaction to go", || pro.broadcasts.load(Ordering::SeqCst) == 1);
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

fn a_tx(salt: u32) -> bitcoin::Transaction {
	use bitcoin::{absolute, transaction, Amount, ScriptBuf, Transaction, TxOut};
	Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::from_consensus(salt),
		input: Vec::new(),
		output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
	}
}

/// The longer run the boot question deserves: `cargo test ... soak -- --ignored --nocapture`,
/// `CHAIN_SESSION_SOAK_SECS` long, with no provider throughout. Prints what it sees.
#[test]
#[ignore = "a real-time observation, not a gate"]
fn soak_a_node_with_no_provider() {
	let secs: u64 =
		std::env::var("CHAIN_SESSION_SOAK_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
	let dir = temp_dir("soak");
	let session = session_on(Arc::new(Connector::default()), DeliveryPreference::Push, &dir);
	let started = Instant::now();
	let stack = cbf_node(Arc::clone(&session), None, 27);
	println!("started in {:?}", started.elapsed());
	let address = stack.node.onchain_payment().new_address();
	println!("new_address ok: {}", address.is_ok());
	let foreground = Instant::now();
	let (tx, rx) = std::sync::mpsc::channel();
	std::thread::scope(|scope| {
		scope.spawn(|| {
			let _ = tx.send(stack.node.sync_wallets());
		});
		let answer = rx.recv_timeout(Duration::from_secs(secs));
		println!("sync_wallets after {:?}: {:?}", foreground.elapsed(), answer);
	});
	while started.elapsed() < Duration::from_secs(secs) {
		std::thread::sleep(Duration::from_secs(10));
	}
	println!("running: {}", stack.node.status().is_running);
	println!("cbf status: {:?}", stack.node.cbf_sync_status());
	println!("freshness: {:?}", stack.node.chain_freshness());
	println!("slots: {:?}", stack.node.chain_slot_adapters());
	println!("session: {:?}", stack.node.chain_session_status());
	{
		use node_chain::fee_estimator::{ConfirmationTarget, FeeEstimator};
		let fee = stack.host.fee_estimator().estimate_fee_rate(ConfirmationTarget::ChannelFunding);
		println!("fee for a channel funding (the fallback constant): {:?}", fee);
	}
	let stopping = Instant::now();
	stack.stop();
	println!("stopped in {:?}", stopping.elapsed());
	std::fs::remove_dir_all(&dir).unwrap();
}

fn lying_copy_of(
	len: u32, lie: node_chain::cbf::source_sync::test_support::Lie,
) -> Arc<FakeSource> {
	let source = Arc::new(FakeSource::new(len, &[]));
	source.set_lie(lie);
	source
}

fn address_of_nobody() -> lightning::ln::msgs::SocketAddress {
	"127.0.0.1:9".parse().unwrap()
}

fn some_peer() -> (bitcoin::secp256k1::PublicKey, lightning::ln::msgs::SocketAddress) {
	let secp = bitcoin::secp256k1::Secp256k1::new();
	let key = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
	(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key), address_of_nobody())
}

/// One block paying `script`, on the tip of both chains. They stay the same chain.
fn mine_on_both(one: &FakeSource, other: &FakeSource, script: bitcoin::ScriptBuf) {
	let top = one.tip_id();
	let time = one.block_at(top.height).header.time + 600;
	let block =
		node_chain::cbf::source_sync::test_support::mine(top.hash, top.height + 1, time, script, 0);
	one.push_raw(block.clone());
	other.push_raw(block);
}

/// The Pro the node is on leaves out of a filter chain that holds together the output paying this
/// node, so the node does not see its money. The second Pro's filter header shows a difference,
/// the block shows who, and the node moves, scans again, finds the money and carries on, with no
/// restart and no failing closed.
#[test]
fn a_lying_active_pro_is_dropped_named_and_replaced_and_what_it_hid_is_found() {
	use node_chain::cbf::source_sync::test_support::{other_script, Lie};

	let dir = temp_dir("liar-active");
	let liar_chain = lying_copy_of(30, Lie::OmitOutputsFrom(30));
	let liar = TestPro::new(Arc::clone(&liar_chain), false);
	let honest_chain = Arc::new(FakeSource::new(30, &[]));
	let honest = TestPro::new(Arc::clone(&honest_chain), false);
	let session = session_on(
		Connector::with(&[(PRO_A, &liar), (PRO_B, &honest)]),
		DeliveryPreference::Pull,
		&dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&honest_chain, 10)), 31);
	let applied = || stack.node.status().current_best_block.height;
	wait_for("the node to follow the liar", || applied() == 29);
	assert_eq!(session.status().active_node_id.as_deref(), Some(PRO_A));

	let address = stack.node.onchain_payment().new_address().unwrap();
	mine_on_both(&liar_chain, &honest_chain, address.script_pubkey());
	mine_on_both(&liar_chain, &honest_chain, other_script(31));
	mine_on_both(&liar_chain, &honest_chain, other_script(32));
	wait_for_poll("three more blocks from the liar", || applied() == 32);
	let money = || stack.node.list_balances().total_onchain_balance_sats;
	assert_eq!(money(), 0, "the lie worked: the block's filter hid the payment");

	session.set_candidates(vec![PRO_A.into(), PRO_B.into()]);
	assert!(session.status().cross_check.supported, "a filter node can check");
	session.check_soon();

	wait_for("the liar to be dropped", || !session.status().dropped.is_empty());
	let status = session.status();
	assert_eq!(status.dropped[0].node_id, PRO_A);
	assert_eq!(status.dropped[0].reason, "filter_lacks_block_output");
	assert_eq!(status.dropped[0].height, 30);
	assert_eq!(status.cross_check.last_result.as_deref(), Some("dropped"));
	assert_eq!(status.cross_check.last_witness.as_deref(), Some(PRO_B));
	wait_for("the node to be on the honest Pro", || {
		session.status().active_node_id.as_deref() == Some(PRO_B)
	});
	wait_for_poll("the money it hid", || money() > 0);

	// The honest Pro's filter-header chain is accepted, and the next block comes through it.
	honest_chain.mine(1, &[], 0);
	wait_for_poll("the next block through the honest Pro", || applied() == 33);

	// It is not walked back to, and the file says so to a restart.
	let again = session_on(
		Connector::with(&[(PRO_A, &liar), (PRO_B, &honest)]),
		DeliveryPreference::Pull,
		&dir,
	);
	assert_eq!(again.status().dropped[0].node_id, PRO_A);
	assert_eq!(again.status().active_node_id.as_deref(), Some(PRO_B));
	stack.stop();
}

/// N2 on a real node. The Pro serves the sync loop a filter hiding the output paying this node, and
/// answers every question of the check honestly. What it told the loop proves it said two things
/// about one block: it goes for that, and the money is found through the witness.
#[test]
fn a_pro_answering_the_check_honestly_is_caught_by_what_it_told_the_sync_loop_and_the_money_found()
{
	use node_chain::cbf::source_sync::test_support::{other_script, Lie};

	let dir = temp_dir("two-faced");
	let liar_chain = lying_copy_of(30, Lie::OmitOutputsOnlyAt(30));
	let liar = TestPro::new(Arc::clone(&liar_chain), false);
	let honest_chain = Arc::new(FakeSource::new(30, &[]));
	let honest = TestPro::new(Arc::clone(&honest_chain), false);
	let session = session_on(
		Connector::with(&[(PRO_A, &liar), (PRO_B, &honest)]),
		DeliveryPreference::Pull,
		&dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&honest_chain, 10)), 33);
	let applied = || stack.node.status().current_best_block.height;
	wait_for("the node to follow it", || applied() == 29);

	let address = stack.node.onchain_payment().new_address().unwrap();
	mine_on_both(&liar_chain, &honest_chain, address.script_pubkey());
	mine_on_both(&liar_chain, &honest_chain, other_script(31));
	mine_on_both(&liar_chain, &honest_chain, other_script(32));
	wait_for_poll("three more blocks", || applied() == 32);
	let money = || stack.node.list_balances().total_onchain_balance_sats;
	assert_eq!(money(), 0, "the lie worked");

	// Now it answers everyone with the truth.
	liar_chain.set_lie(Lie::None);
	session.set_candidates(vec![PRO_A.into(), PRO_B.into()]);
	session.check_soon();

	wait_for("it to be dropped", || !session.status().dropped.is_empty());
	let status = session.status();
	assert_eq!(status.dropped[0].node_id, PRO_A);
	assert_eq!(status.dropped[0].reason, "answer_changed");
	assert_eq!(status.dropped[0].height, 30);
	wait_for_poll("the money it hid", || money() > 0);
	assert_eq!(session.status().cross_check.unread, None, "and it says so only now");
	stack.stop();
}

/// A witness not answering one check says nothing of what is left to read: it stays said, and its
/// place is kept. Reading it as done would be a limit reached reading as fine.
#[test]
fn a_witness_not_answering_for_a_while_leaves_what_is_unread_said() {
	let dir = temp_dir("unread-stays");
	let (chain_a, chain_b) =
		(Arc::new(FakeSource::new(30, &[])), Arc::new(FakeSource::new(30, &[])));
	let (pro_a, pro_b) =
		(TestPro::new(Arc::clone(&chain_a), false), TestPro::new(Arc::clone(&chain_b), false));
	let session = session_on(
		Connector::with(&[(PRO_A, &pro_a), (PRO_B, &pro_b)]),
		DeliveryPreference::Pull,
		&dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain_a, 10)), 36);
	wait_for("the node to catch up", || session.status().cursor.map_or(false, |c| c.height == 29));

	// The witness's filters point at blocks nobody will serve just now.
	let address = stack.node.onchain_payment().new_address().unwrap();
	chain_b.set_includes_at(24, address.script_pubkey());
	chain_b.set_includes_at(25, address.script_pubkey());
	chain_a.state.lock().unwrap().all.clear();
	chain_b.state.lock().unwrap().all.clear();
	session.set_candidates(vec![PRO_A.into(), PRO_B.into()]);
	session.check_soon();
	wait_for("it to say what is left", || session.status().cross_check.unread.is_some());

	pro_b.set_down(true);
	session.check_soon();
	wait_for("the check that came to nothing", || {
		session.status().cross_check.last_result.as_deref() == Some("inconclusive")
	});
	let unread = session.status().cross_check.unread;
	assert!(unread.is_some(), "still not read, and still said");
	stack.stop();
}

/// What the stage draws for a pushed block: what really happened, under the inbound row, the check
/// ending after the ack as the sync loop gets there. A Pro dropped is told too, under its move.
#[test]
fn a_pushed_block_is_told_as_it_went_and_a_drop_under_its_move() {
	use node_chain::session::trace::test_support::Kept;
	use node_chain::session::trace::{
		InboundSpan, NAME_BLOCK_ACK, NAME_BLOCK_CHECK, NAME_SOURCE_DROPPED,
	};

	let dir = temp_dir("block-spans");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let pro = TestPro::new(Arc::clone(&chain), true);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Push, &dir);
	let kept = Arc::new(Kept::default());
	session.set_observer(Arc::clone(&kept) as Arc<dyn trace::SessionObserver>);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 35);
	wait_for("the lease", || session.status().delivery == Delivery::Push);
	wait_for("the node to catch up", || stack.node.status().current_best_block.height == 29);

	chain.mine(1, &[], 0);
	let tip = chain.tip_id();
	let req = WireSinceRequest {
		version: CHAIN_WIRE_VERSION,
		from: WireBlockId {
			height: tip.height - 1,
			hash: chain.block_at(tip.height - 1).block_hash().to_string(),
		},
		max_blocks: 1,
		filter_offset: 0,
	};
	let push = stack.runtime.block_on(BundleTransport::since(&*pro.transport, req)).unwrap();
	let inbound = InboundSpan { trace_id: "aa".repeat(16), span_id: "bb".repeat(8) };
	let ack = session.receive_block_update_traced(PRO_A, &push, Some(&inbound)).unwrap();
	assert_eq!(ack.status, WireAckStatus::Applied);

	let named = |name: &str| -> Vec<trace::SessionSpan> {
		kept.0.lock().unwrap().iter().filter(|s| s.name == name).cloned().collect()
	};
	wait_for("the sync loop to get through it", || !named(NAME_BLOCK_CHECK).is_empty());
	assert_eq!(stack.node.status().current_best_block.height, 30);
	let check = named(NAME_BLOCK_CHECK).remove(0);
	let acked = named(NAME_BLOCK_ACK).remove(0);
	assert!(check.ok);
	assert!(acked.ok);
	assert_eq!(check.parent_span_id.as_deref(), Some(inbound.span_id.as_str()));
	assert_eq!(acked.parent_span_id.as_deref(), Some(inbound.span_id.as_str()));
	assert_eq!(check.trace_id, inbound.trace_id);
	assert_eq!(check.peer.as_deref(), Some(PRO_A));
	assert_eq!(acked.peer.as_deref(), Some(PRO_A));
	assert_eq!(check.kind, trace::SpanKind::Internal);
	assert_eq!(acked.kind, trace::SpanKind::Outbound);

	// A block already past is not told as checked by this push.
	let spans = kept.0.lock().unwrap().len();
	let again = session.receive_block_update_traced(PRO_A, &push, Some(&inbound)).unwrap();
	assert_eq!(again.status, WireAckStatus::Applied);
	let checks =
		kept.0.lock().unwrap().iter().skip(spans).filter(|s| s.name == NAME_BLOCK_CHECK).count();
	assert_eq!(checks, 0);

	// A drop on evidence is a span naming who, with the reason.
	use node_chain::cbf::source_sync::{SyncEvent, SyncObserver};
	let event = SyncEvent::Evidence { kind: machine::LieKind::BadHeader, height: 31 };
	SyncObserver::sync_event(&*session, FilterSource::epoch(&*session), event);
	wait_for("it to be dropped", || !session.status().dropped.is_empty());
	let dropped = named(NAME_SOURCE_DROPPED);
	assert_eq!(dropped.len(), 1);
	assert_eq!(dropped[0].peer.as_deref(), Some(PRO_A));
	assert!(dropped[0].detail.as_deref().unwrap().contains("reason="), "{:?}", dropped[0]);
	stack.stop();
}

/// N6 on a real node: the taker's question. The Pro says a transaction that exists nowhere has three
/// confirmations, anchored to the real tip. That fails closed. The same word for a transaction that
/// is in that block is believed, at the depth this node's own chain gives.
#[cfg(feature = "swaps")]
#[test]
fn a_confirmation_from_a_pro_stands_only_with_the_block() {
	use crate::ChainStatus;
	use node_chain::cbf::source_sync::test_support::{mine_with, other_script};

	let dir = temp_dir("n6");
	let chain = Arc::new(FakeSource::new(20, &[]));
	let top = chain.tip_id();
	let time = chain.block_at(top.height).header.time + 600;
	let real = a_tx(77);
	let held = mine_with(top.hash, top.height + 1, time, other_script(1), 0, vec![real.clone()]);
	chain.push_raw(held);
	chain.mine(2, &[], 0);
	let tip = chain.tip_id();
	let pro = TestPro::new(Arc::clone(&chain), false);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 34);
	wait_for("the node to catch up", || {
		stack.node.status().current_best_block.height == tip.height
	});

	*pro.tx_status_says.lock().unwrap() = Some(WireTxStatusResponse {
		version: CHAIN_WIRE_VERSION,
		confirmed: true,
		in_mempool: false,
		confirmation_height: Some(top.height + 1),
		tip_height: Some(tip.height),
		tip_hash: Some(tip.hash.to_string()),
	});
	let ask = |txid| stack.runtime.block_on(stack.node.get_tx_confirmations(txid)).unwrap();
	let made_up = a_tx(78).compute_txid();
	let refused = ask(made_up);
	assert_eq!(refused.status, ChainStatus::NoChainSource, "{:?}", refused);
	assert_eq!(refused.confirmations, 0);

	let shown = ask(real.compute_txid());
	assert_eq!(shown.status, ChainStatus::Confirmed, "{:?}", shown);
	assert_eq!(shown.height, Some(top.height + 1));
	assert_eq!(shown.confirmations, 3);

	// Its word on the height does not move the block looked in.
	pro.tx_status_says.lock().unwrap().as_mut().unwrap().confirmation_height = Some(top.height);
	assert_eq!(ask(real.compute_txid()).status, ChainStatus::NoChainSource);

	// And a block fetched once is not fetched again for the same word.
	pro.tx_status_says.lock().unwrap().as_mut().unwrap().confirmation_height = Some(top.height + 1);
	let fetched = chain.calls("block");
	assert_eq!(ask(real.compute_txid()).status, ChainStatus::Confirmed);
	assert_eq!(chain.calls("block"), fetched);
	stack.stop();
}

/// Review 3's F4. A restart holds headers only from the start of the retarget period. An opening
/// confirmed below that is no less confirmed: its header is fetched and held to what is held, by the
/// links, and a Pro cannot make one up. Then F5: no block to tell by is not a block without it.
#[test]
fn a_confirmation_below_what_a_restart_holds_is_shown_by_its_block_and_no_block_says_nothing() {
	use crate::{ChainStatus, SwapTxInBlock};
	use node_chain::cbf::source_sync::test_support::{mine_with, other_script};

	let dir = temp_dir("below-held");
	const INTERVAL: u32 = 2016;
	let opening_at = INTERVAL - 16;
	let chain = Arc::new(FakeSource::new(opening_at, &[]));
	let below = chain.tip_id();
	let time = chain.block_at(below.height).header.time + 600;
	let opening = a_tx(79);
	chain.push_raw(mine_with(
		below.hash,
		opening_at,
		time,
		other_script(1),
		0,
		vec![opening.clone()],
	));
	chain.mine(40, &[], 0);
	let tip = chain.tip_id();
	let pro = TestPro::new(Arc::clone(&chain), false);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	session.set_candidates(vec![PRO_A.into()]);
	// As a node that was up across the retarget and restarted after it, its anchor above it.
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, INTERVAL + 4)), 35);
	wait_for("the node to catch up", || {
		stack.node.status().current_best_block.height == tip.height
	});
	let says = WireTxStatusResponse {
		version: CHAIN_WIRE_VERSION,
		confirmed: true,
		in_mempool: false,
		confirmation_height: Some(opening_at),
		tip_height: Some(tip.height),
		tip_hash: Some(tip.hash.to_string()),
	};
	*pro.tx_status_says.lock().unwrap() = Some(says);
	let txid = opening.compute_txid();
	let ask = |txid| stack.runtime.block_on(stack.node.get_tx_confirmations(txid)).unwrap();
	let in_block = |txid, height| stack.runtime.block_on(stack.node.swap_tx_in_block(txid, height));

	let shown = ask(txid);
	assert_eq!(shown.status, ChainStatus::Confirmed, "{:?}", shown);
	assert_eq!(shown.height, Some(opening_at));
	assert_eq!(shown.confirmations, tip.height - opening_at + 1);
	assert_eq!(in_block(txid, opening_at), SwapTxInBlock::Holds);

	// A made-up transaction is still refused: the block holds no such thing, and that is an answer.
	let made_up = a_tx(80).compute_txid();
	assert_eq!(ask(made_up).status, ChainStatus::NoChainSource);
	assert_eq!(in_block(made_up, opening_at), SwapTxInBlock::Lacks);
	// Each answer changed in turn. The block refused says nothing of it. Nor does a height it cannot
	// reach, either way. And a block it holds headers for, equally.
	chain.state.lock().unwrap().all.clear();
	let other = a_tx(81).compute_txid();
	assert_eq!(ask(other).status, ChainStatus::NoChainSource, "nothing paid on no block");
	assert_eq!(in_block(other, opening_at), SwapTxInBlock::NoBlock);
	assert_eq!(in_block(other, tip.height - 1), SwapTxInBlock::NoBlock);
	assert_eq!(in_block(other, tip.height + 5), SwapTxInBlock::NoBlock);
	stack.stop();
}

/// Two Pros on the same chain, A followed to the tip and B there to ask, with a node on A.
fn on_a_with_b_to_ask(
	dir: &Path, seed: u8, push: bool,
) -> (Arc<FakeSource>, Arc<FakeSource>, Arc<ChainProviderSession>, Stack) {
	let chain_a = Arc::new(FakeSource::new(30, &[]));
	let chain_b = Arc::new(FakeSource::new(30, &[]));
	let pro_a = TestPro::new(Arc::clone(&chain_a), push);
	let pro_b = TestPro::new(Arc::clone(&chain_b), push);
	let session = session_on(
		Connector::with(&[(PRO_A, &pro_a), (PRO_B, &pro_b)]),
		DeliveryPreference::Pull,
		dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain_a, 10)), seed);
	wait_for("the node to catch up", || session.status().cursor.map_or(false, |c| c.height == 29));
	session.set_candidates(vec![PRO_A.into(), PRO_B.into()]);
	(chain_a, chain_b, session, stack)
}

/// B1: a Pro answers everything and leaves out the newest blocks. A second Pro's proof of work is
/// what shows it. The minutes it stays are in the machine's tests, on a fake clock.
#[test]
fn a_pro_withholding_blocks_is_shown_up_by_a_witness_and_the_node_stops_reading_healthy() {
	use node_chain::cbf::source_sync::test_support::Lie;

	let dir = temp_dir("withholding");
	let (chain_a, chain_b, session, stack) = on_a_with_b_to_ask(&dir, 43, false);
	assert!(!session.status().chain_stale);
	assert!(stack.node.check_chain_for_new_channel().is_ok());

	chain_a.set_lie(Lie::WithholdFrom(30));
	chain_a.mine(3, &[], 0);
	chain_b.mine(3, &[], 0);
	session.check_soon();
	wait_for("the witness to show it", || session.status().behind_witness.is_some());

	let status = session.status();
	let behind = status.behind_witness.clone().unwrap();
	assert_eq!(behind.witness, PRO_B);
	assert_eq!(behind.witness_height, 32, "what its headers reach, not what it says");
	assert!(behind.will_move);
	assert!(status.chain_stale);
	assert_eq!(status.state, SessionState::Active, "it still answers");
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A), "it has its time to catch up");
	assert!(stack.node.check_chain_for_new_channel().is_err());
	stack.stop();
}

/// A claim with no headers to show moves nothing, and a witness's made-up ones cost it.
#[test]
fn a_witness_with_only_a_claim_or_made_up_headers_shows_up_nobody() {
	use node_chain::cbf::source_sync::test_support::Lie;

	let dir = temp_dir("witness-forged");
	let (chain_a, chain_b, session, stack) = on_a_with_b_to_ask(&dir, 44, false);
	chain_b.mine(3, &[], 0);
	chain_b.set_lie(Lie::ForgedHeadersFrom(30));
	session.check_soon();
	wait_for("it to be dropped", || !session.status().dropped.is_empty());
	let status = session.status();
	assert_eq!(status.dropped[0].node_id, PRO_B);
	assert_eq!(status.dropped[0].reason, "bad_header");
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A));
	assert!(status.behind_witness.is_none());
	assert!(!status.chain_stale);
	drop(chain_a);
	stack.stop();
}

/// B2: one forged tip and made-up headers from the active Pro. Before, this ended the sync loop for
/// the life of the process. Now it costs the Pro, the node moves, and blocks keep coming.
#[test]
fn a_forged_tip_from_the_active_pro_moves_the_node_and_blocks_keep_coming() {
	use node_chain::cbf::source_sync::test_support::Lie;

	let dir = temp_dir("forged-tip");
	let (chain_a, chain_b, session, stack) = on_a_with_b_to_ask(&dir, 45, false);
	chain_a.set_lie(Lie::ForgedHeadersFrom(15));
	wait_for_poll("it to be dropped", || !session.status().dropped.is_empty());
	let status = session.status();
	assert_eq!(status.dropped[0].node_id, PRO_A);
	assert_eq!(status.dropped[0].reason, "bad_header");
	wait_for("the node to be on B", || session.status().active_node_id.as_deref() == Some(PRO_B));
	assert_eq!(session.status().moves.last().map(|m| m.by), Some(MoveBy::Evidence));

	chain_b.mine(1, &[], 0);
	wait_for_poll("the next block", || stack.node.status().current_best_block.height == 30);
	assert!(!matches!(stack.node.cbf_sync_status(), Some(crate::CbfSyncStatus::Failed)));
	assert!(!session.status().chain_stale);
	stack.stop();
}

/// H2: invalid data is evidence. The node moves with no process restart, the next Pro is not asked
/// to answer for it, and nothing it verified was forgotten on the way.
#[test]
fn invalid_data_from_the_active_pro_moves_the_node_with_its_checks_intact() {
	use node_chain::cbf::source_sync::test_support::Lie;

	let dir = temp_dir("invalid-data");
	let (chain_a, chain_b, session, stack) = on_a_with_b_to_ask(&dir, 46, false);
	chain_a.set_lie(Lie::FilterHeaderAt(30));
	chain_a.mine(1, &[], 0);
	chain_b.mine(1, &[], 0);
	wait_for_poll("it to be dropped", || !session.status().dropped.is_empty());
	let status = session.status();
	assert_eq!(status.dropped[0].node_id, PRO_A);
	assert_eq!(status.dropped[0].reason, "invalid_filter_data");
	wait_for("the node to be on B", || session.status().active_node_id.as_deref() == Some(PRO_B));
	wait_for_poll("the block, from B", || stack.node.status().current_best_block.height == 30);
	assert!(!session.status().chain_stale);
	stack.stop();
}

/// H2 on a pin: the owner's choice stands, the status says what it did, and nothing is taken.
#[test]
fn invalid_data_from_a_pin_stays_refused_and_the_status_says_so() {
	use node_chain::cbf::source_sync::test_support::Lie;

	let dir = temp_dir("invalid-pin");
	let (chain_a, _chain_b, session, stack) = on_a_with_b_to_ask(&dir, 47, false);
	session.set_source(Some(PRO_A.into()));
	chain_a.set_lie(Lie::FilterHeaderAt(30));
	chain_a.mine(1, &[], 0);
	wait_for_poll("it to be convicted", || session.status().on_proven_liar);
	assert_eq!(session.status().active_node_id.as_deref(), Some(PRO_A));
	assert!(session.status().chain_stale);
	assert_eq!(stack.node.status().current_best_block.height, 29, "nothing of it was taken");
	assert!(stack.node.check_chain_for_new_channel().is_err());
	stack.stop();
}

/// B2's other half: if the loop ends anyway, the session knows and it starts again, no restart.
#[test]
fn a_sync_loop_that_ends_is_told_and_started_again_without_a_restart() {
	let dir = temp_dir("loop-restart");
	let (chain_a, chain_b, session, stack) = on_a_with_b_to_ask(&dir, 48, false);
	stack.host.halt_the_applicator_for_test("a test says the listeners diverged");
	chain_a.mine(1, &[], 0);
	chain_b.mine(1, &[], 0);
	wait_for_poll("the session to know", || session.status().sync_loop.ended.is_some());
	assert!(session.status().chain_stale);
	assert!(stack.node.check_chain_for_new_channel().is_err());

	wait_for_poll("it to be started again", || session.status().sync_loop.restarts == 1);
	let status = session.status();
	assert_eq!(status.sync_loop.ended, None);
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A), "and nobody blamed");
	chain_a.mine(1, &[], 0);
	wait_for_poll("blocks again", || stack.node.status().current_best_block.height == 31);
	stack.stop();
}

/// What chain-store weighs an offer's tip with, on real answers.
#[test]
fn a_tip_claim_is_verified_by_the_headers_behind_it() {
	use node_chain::cbf::source_sync::test_support::Lie;

	let dir = temp_dir("tip-claim");
	let (_chain_a, chain_b, session, stack) = on_a_with_b_to_ask(&dir, 49, false);
	chain_b.mine(2, &[], 0);
	let tip = block_id_to_wire(&chain_b.tip_id());
	let check =
		|id: &str, claim: WireBlockId| stack.runtime.block_on(session.verify_tip_claim(id, claim));
	let good = check(PRO_B, tip.clone());
	assert!(good.verified, "{:?}", good);
	assert_eq!((good.proven_height, good.result), (Some(31), "proven"));
	assert_eq!(good.cursor.as_ref().map(|c| c.height), Some(29));

	// The height is reachable, the hash is not there.
	let wrong = WireBlockId { hash: "ab".repeat(32), ..tip };
	let wrong = check(PRO_B, wrong);
	assert!(!wrong.verified);
	assert_eq!(wrong.result, "proven_part_way");

	// A claim with nothing behind it: what two sybils say to push an honest Pro off a list.
	let far = WireBlockId { height: 970_500, hash: "ab".repeat(32) };
	let far = check(PRO_A, far);
	assert!(!far.verified);
	assert_eq!((far.proven_height, far.result), (None, "no_more_work"));

	let low = WireBlockId { height: 5, hash: "ab".repeat(32) };
	assert_eq!(check(PRO_A, low).result, "at_or_below_cursor");

	chain_b.set_lie(Lie::ForgedHeadersFrom(30));
	let forged =
		check(PRO_B, block_id_to_wire(&BlockId { height: 31, hash: chain_b.tip_id().hash }));
	assert!(!forged.verified);
	assert_eq!(forged.result, "forged_header");
	stack.stop();
}

/// H4's reference: asked with the hourly check, kept for a while, and what is out of bounds is not.
#[test]
fn a_cross_check_reads_the_witnesss_fees_as_the_reference() {
	let dir = temp_dir("fee-reference");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let (pro_a, pro_b) =
		(TestPro::new(Arc::clone(&chain), false), TestPro::new(Arc::clone(&chain), false));
	let session = session_on(
		Connector::with(&[(PRO_A, &pro_a), (PRO_B, &pro_b)]),
		DeliveryPreference::Pull,
		&dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 50);
	wait_for("the node to catch up", || session.status().cursor.map_or(false, |c| c.height == 29));
	session.set_candidates(vec![PRO_A.into(), PRO_B.into()]);
	let fee = |rate| WireFeeEstimates {
		version: CHAIN_WIRE_VERSION,
		targets: vec![node_chain::provider::WireFeeTarget {
			target: "channel_funding".to_string(),
			sat_per_kwu: rate,
		}],
	};
	*pro_b.fee_answer.lock().unwrap() = Some(fee(1_000));
	assert_eq!(session.fee_reference().witness, None);
	session.check_soon();
	wait_for("the reference", || session.fee_reference().witness.is_some());
	assert_eq!(session.fee_reference().witness, Some(fee(1_000)));

	*pro_b.fee_answer.lock().unwrap() = Some(fee(9_000_000));
	session.check_soon();
	std::thread::sleep(Duration::from_secs(3));
	assert_eq!(
		session.fee_reference().witness,
		Some(fee(1_000)),
		"out of bounds counts for nothing"
	);
	stack.stop();
}

/// One attacker tagged as a Pro says the honest active Pro is wrong. It is the one that goes.
#[test]
fn a_lying_witness_cannot_evict_the_honest_active_pro() {
	use node_chain::cbf::source_sync::test_support::Lie;

	let dir = temp_dir("liar-witness");
	let honest_chain = Arc::new(FakeSource::new(30, &[]));
	let honest = TestPro::new(Arc::clone(&honest_chain), false);
	let liar = TestPro::new(lying_copy_of(30, Lie::OmitOutputsFrom(20)), false);
	let session = session_on(
		Connector::with(&[(PRO_A, &honest), (PRO_B, &liar)]),
		DeliveryPreference::Pull,
		&dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&honest_chain, 10)), 32);
	wait_for("the node to catch up", || session.status().cursor.map_or(false, |c| c.height == 29));
	session.set_candidates(vec![PRO_A.into(), PRO_B.into()]);
	session.check_soon();
	wait_for("the liar to be dropped", || !session.status().dropped.is_empty());
	let status = session.status();
	assert_eq!(status.dropped[0].node_id, PRO_B);
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A));
	assert_eq!(status.state, SessionState::Active);
	assert!(!status.chain_stale);
	stack.stop();
}

/// The difference a block cannot judge. Nobody goes: both stay, and either can be chosen. The block
/// is read, and with its answers matching again the conflict closes.
#[test]
fn a_conflict_nobody_can_attribute_drops_nobody_and_its_answers_matching_closes_it() {
	use node_chain::cbf::source_sync::test_support::Lie;

	let dir = temp_dir("conflict-witness");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let active = TestPro::new(Arc::clone(&chain), false);
	let witness_source = lying_copy_of(30, Lie::ExtraElementFrom(20));
	let witness = TestPro::new(Arc::clone(&witness_source), false);
	let session = session_on(
		Connector::with(&[(PRO_A, &active), (PRO_B, &witness)]),
		DeliveryPreference::Pull,
		&dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 41);
	wait_for("the node to catch up", || session.status().cursor.map_or(false, |c| c.height == 29));
	session.set_candidates(vec![PRO_A.into(), PRO_B.into()]);
	session.check_soon();
	wait_for("the conflict", || session.status().cross_check.conflict.is_some());
	let status = session.status();
	assert!(status.dropped.is_empty(), "nobody is dropped for this");
	let conflict = status.cross_check.conflict.clone().unwrap();
	assert_eq!((conflict.active.as_str(), conflict.witness.as_str()), (PRO_A, PRO_B));
	assert_eq!(conflict.height, 20);
	assert_eq!(conflict.state, machine::ConflictState::NoThirdPro);
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A));
	assert_eq!(status.state, SessionState::Active);
	assert_eq!(status.cross_check.last_result.as_deref(), Some("conflict"));

	// Repaired: the re-check asks it again, and its answer matches.
	witness_source.set_lie(Lie::None);
	session.check_soon();
	wait_for("it to close", || session.status().cross_check.conflict.is_none());
	assert_eq!(session.status().active_node_id.as_deref(), Some(PRO_A), "and nothing moved");

	// Either can be chosen, whatever was said about it.
	assert_eq!(session.use_source_traced(PRO_B.to_string(), None), Some(false));
	assert_eq!(session.status().active_node_id.as_deref(), Some(PRO_B));
	stack.stop();
}

/// N5: two free keys must not be able to take the seat. A third Pro is asked about the block they
/// part at, its answer is what the status says, nobody is dropped and nobody moves: two to one
/// proves nothing. The other one stays only a witness, and never becomes the last good Pro.
#[test]
fn a_third_pro_is_told_to_the_owner_and_moves_nobody() {
	use node_chain::cbf::source_sync::test_support::Lie;

	const PRO_C: &str = "02dd";
	let dir = temp_dir("tie-break");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let active = TestPro::new(lying_copy_of(30, Lie::ExtraElementFrom(20)), false);
	let (witness, third) =
		(TestPro::new(Arc::clone(&chain), false), TestPro::new(Arc::clone(&chain), false));
	let session = session_on(
		Connector::with(&[(PRO_A, &active), (PRO_B, &witness), (PRO_C, &third)]),
		DeliveryPreference::Pull,
		&dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 42);
	wait_for("the node to catch up", || session.status().cursor.map_or(false, |c| c.height == 29));
	session.set_candidates(vec![PRO_A.into(), PRO_B.into(), PRO_C.into()]);
	session.check_soon();
	wait_for("the third's answer", || {
		session.status().cross_check.conflict.map(|c| c.state)
			== Some(machine::ConflictState::SidesWithWitness)
	});
	let status = session.status();
	assert!(status.dropped.is_empty(), "two to one proves nothing");
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A), "and it moves nobody");
	assert!(status.moves.iter().all(|m| m.to != PRO_B), "{:?}", status.moves);
	assert_ne!(status.last_good.as_deref(), Some(PRO_B));
	stack.stop();
}

/// H6 on real answers: a Dependent node asks no stranger until its owner says.
#[test]
fn a_dependent_node_asks_nobody_until_its_owner_chooses() {
	let dir = temp_dir("dependent-owner");
	let pro = TestPro::new(Arc::new(FakeSource::new(5, &[])), false);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	let mut host_builder = ChainHostBuilder::new(Network::Regtest);
	host_builder.set_logger(logger());
	host_builder.set_chain_source_dependent_with_session(Arc::clone(&session), None);
	let stack = start_on(host_builder.build().unwrap(), None, 51);
	stack.host.chain_set_candidates(vec![PRO_A.to_string()]).unwrap();
	std::thread::sleep(Duration::from_secs(3));
	let status = session.status();
	assert_eq!(status.state, SessionState::NoProvider);
	assert!(status.needs_owner_choice);
	assert!(!status.picks_by_itself);
	assert_eq!(pro.transport.calls("since"), 0, "nobody was asked");
	assert_eq!(pro.chain_calls.load(Ordering::SeqCst), 0);
	assert!(stack.node.check_chain_for_new_channel().is_err());

	stack.host.chain_set_auto_source(Some(true)).unwrap();
	wait_for("the owner's word", || session.status().state == SessionState::Active);
	assert!(!session.status().needs_owner_choice);
	assert_eq!(session.status().active_node_id.as_deref(), Some(PRO_A));
	stack.stop();

	// And it stays said.
	let again = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	assert!(again.status().picks_by_itself);
}

/// The move is real, leaves no pin, and the next list does not take it back.
#[test]
fn a_source_used_for_now_is_followed_unpinned_and_outlives_the_next_list_and_a_restart() {
	let dir = temp_dir("use-for-now");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let pro_a = TestPro::new(Arc::clone(&chain), true);
	let pro_b = TestPro::new(Arc::clone(&chain), true);
	let session = session_on(
		Connector::with(&[(PRO_A, &pro_a), (PRO_B, &pro_b)]),
		DeliveryPreference::Push,
		&dir,
	);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 42);
	wait_for("the lease on A", || pro_a.leases.len() == 1);

	assert_eq!(session.use_source_traced(PRO_B.to_string(), None), Some(false));
	let status = session.status();
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_B), "at once");
	assert_eq!(status.pinned_node_id, None);
	assert_eq!(status.used_for_now.as_deref(), Some(PRO_B));
	wait_for("the old lease to go", || pro_a.leases.is_empty());
	wait_for("the new lease", || pro_b.leases.len() == 1);

	// What a sweep hands over, with this source left out.
	session.set_candidates(vec![PRO_A.into()]);
	std::thread::sleep(Duration::from_secs(2));
	assert_eq!(session.status().active_node_id.as_deref(), Some(PRO_B));
	assert_eq!(pro_b.leases.len(), 1);
	wait_for("it to be the last good", || session.status().last_good.as_deref() == Some(PRO_B));
	stack.stop();

	let again = session_on(
		Connector::with(&[(PRO_A, &pro_a), (PRO_B, &pro_b)]),
		DeliveryPreference::Push,
		&dir,
	);
	let status = again.status();
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_B));
	assert_eq!(status.used_for_now.as_deref(), Some(PRO_B));
	assert_eq!(status.pinned_node_id, None);
}

/// A block this node took is told with when it saw it; what it held at the start has no such time.
#[test]
fn the_last_block_is_told_only_once_one_arrives() {
	let dir = temp_dir("last-block");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let pro = TestPro::new(Arc::clone(&chain), true);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Push, &dir);
	session.set_candidates(vec![PRO_A.into()]);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 43);
	wait_for("the node to catch up", || session.status().cursor.map_or(false, |c| c.height == 29));
	wait_for("the lease", || pro.leases.len() == 1);
	// Past the first look: without this the first tick could be what sees the next block.
	std::thread::sleep(Duration::from_millis(2500));
	let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() * 1000;
	chain.mine(1, &[], 0);
	let push = stack.runtime.block_on(pro.transport.push(30..=30));
	stack.node.chain_receive_block_update(PRO_A, &push).unwrap();
	wait_for("the block to be told", || session.status().last_block.map(|b| b.height) == Some(30));
	assert!(session.status().last_block.unwrap().at_ms >= before);
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

/// A Dependent node holds no filter headers: nothing to compare, so no call is made.
#[test]
fn a_dependent_node_has_nothing_to_compare_and_says_so() {
	let dir = temp_dir("dependent-no-check");
	let chain = Arc::new(FakeSource::new(5, &[]));
	let pro = TestPro::new(chain, false);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	let mut host_builder = ChainHostBuilder::new(Network::Regtest);
	host_builder.set_logger(logger());
	host_builder.set_chain_source_dependent_with_session(Arc::clone(&session), None);
	let host = host_builder.build().unwrap();
	let stack = start_on(host, None, 33);
	assert!(!session.status().cross_check.supported);
	stack.stop();
}

/// With no Pro, a new channel is refused with a type of its own, before anything is asked of a
/// peer. Everything else an app reads or an existing channel needs is left alone, and a source
/// arriving lifts it with no restart.
#[test]
fn with_no_provider_a_new_channel_is_refused_and_with_a_provider_it_is_not() {
	let dir = temp_dir("no-provider-open");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let pro = TestPro::new(Arc::clone(&chain), false);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 10)), 34);

	let (peer, _) = some_peer();
	let refused = stack.node.open_channel(peer, address_of_nobody(), 100_000, None, None);
	assert_eq!(refused.map(|_| ()), Err(Error::ChainProviderUnavailable));
	assert_eq!(stack.node.check_chain_for_new_channel(), Err(Error::ChainProviderUnavailable));
	assert!(stack.node.chain_session_status().unwrap().chain_stale);
	assert!(stack.node.list_channels().is_empty());

	// Nothing else is refused for it: each of these fails, or does not, for its own reason.
	let not_it =
		|result: Result<(), Error>| assert_ne!(result, Err(Error::ChainProviderUnavailable));
	let address = stack.node.onchain_payment().new_address().unwrap();
	not_it(stack.node.onchain_payment().send_to_address(&address, 10_000, None).map(|_| ()));
	not_it(stack.node.connect(peer, address_of_nobody(), false));
	let channel = crate::UserChannelId(1);
	not_it(stack.node.close_channel(&channel, peer));
	not_it(stack.node.force_close_channel(&channel, peer, None));

	session.set_candidates(vec![PRO_A.into()]);
	wait_for("a source", || !session.status().chain_stale);
	assert_eq!(stack.node.check_chain_for_new_channel(), Ok(()));
	let later = stack.node.open_channel(peer, address_of_nobody(), 100_000, None, None);
	assert_ne!(later.map(|_| ()), Err(Error::ChainProviderUnavailable));
	stack.stop();
}

/// A node on its own source has no session, and nothing can ever refuse it for lacking one.
#[test]
fn a_node_with_its_own_source_is_never_refused_for_having_no_provider() {
	let mut builder = Builder::new();
	builder.set_network(Network::Regtest);
	builder.set_log_facade_logger();
	builder.set_entropy_seed_bytes([35; 64]);
	let node = builder.build_with_store(Arc::new(TestStore::new(false))).unwrap();
	assert!(node.chain_session_status().is_none());
	assert_eq!(node.check_chain_for_new_channel(), Ok(()));
}

/// Each call: its route, the lease it asked for, and the trace and parent it carried.
type SeenCalls = Arc<Mutex<Vec<(&'static str, u32, Option<(String, String)>)>>>;

/// A Pro's bundle routes with a record of the trace each call carried: what the app's provider
/// reads to stamp its route row.
struct SeenTransport {
	inner: Arc<dyn BundleTransport>,
	seen: SeenCalls,
}

impl SeenTransport {
	fn note(&self, route: &'static str, lease_secs: u32) {
		let scope =
			trace::current_scope().map(|s| (s.trace_id.to_string(), s.parent_span_id.to_string()));
		self.seen.lock().unwrap().push((route, lease_secs, scope));
	}
}

#[async_trait]
impl BundleTransport for SeenTransport {
	fn name(&self) -> String {
		"seen".into()
	}
	async fn since(&self, req: WireSinceRequest) -> Result<WireBlockUpdates, ChainProviderError> {
		self.note("since", 0);
		self.inner.since(req).await
	}
	async fn subscribe(
		&self, req: WireSubscribeRequest,
	) -> Result<WireSubscribeResponse, ChainProviderError> {
		self.note("subscribe", req.lease_secs);
		self.inner.subscribe(req).await
	}
}

struct SeenConnector {
	inner: Arc<Connector>,
	seen: SeenCalls,
}

impl ProviderConnector for SeenConnector {
	fn connect(&self, node_id: &str) -> ProviderEndpoints {
		let mut endpoints = self.inner.connect(node_id);
		endpoints.bundles =
			Arc::new(SeenTransport { inner: endpoints.bundles, seen: Arc::clone(&self.seen) });
		endpoints
	}
}

/// A fee answer the update refuses, for being out of bounds, is a span naming the Pro. A number
/// for a target this build does not know is skipped and not refused, so it is not told either.
#[test]
fn a_fee_answer_the_update_refuses_is_told_as_a_span_naming_the_pro() {
	use node_chain::adapters::dependent::fee_update_from_wire;
	use node_chain::provider::WireFeeTarget;
	use trace::test_support::Kept;
	let answer = |target: &str, sat_per_kwu: u64| WireFeeEstimates {
		version: CHAIN_WIRE_VERSION,
		targets: vec![
			WireFeeTarget { target: "onchain_payment".to_string(), sat_per_kwu: 1_000 },
			WireFeeTarget { target: target.to_string(), sat_per_kwu },
		],
	};
	let dir = temp_dir("fee-rejected");
	let pro = TestPro::new(Arc::new(FakeSource::new(5, &[])), true);
	let session = session_on(Connector::with(&[(PRO_A, &pro)]), DeliveryPreference::Pull, &dir);
	let kept = Arc::new(Kept::default());
	session.set_observer(Arc::clone(&kept) as Arc<dyn trace::SessionObserver>);
	let mut host_builder = ChainHostBuilder::new(Network::Regtest);
	host_builder.set_logger(logger());
	host_builder.set_chain_source_dependent_with_session(Arc::clone(&session), None);
	let stack = start_on(host_builder.build().unwrap(), None, 24);
	stack.host.chain_set_source(Some(PRO_A.to_string())).unwrap();
	wait_for("it to take the Pro", || session.is_available());

	let future = answer("from_the_future", u64::MAX);
	*pro.fee_answer.lock().unwrap() = Some(future.clone());
	stack.runtime.block_on(session.fee_estimates()).unwrap();
	assert!(fee_update_from_wire(&future, &Default::default(), &logger()).is_ok());
	assert!(kept.named(trace::NAME_FEE_REJECTED).is_empty(), "skipped, not refused");

	let lying = answer("ldk.urgent_onchain_sweep", 10_000_000);
	*pro.fee_answer.lock().unwrap() = Some(lying.clone());
	stack.runtime.block_on(session.fee_estimates()).unwrap();
	assert!(fee_update_from_wire(&lying, &Default::default(), &logger()).is_err());
	let told = kept.named(trace::NAME_FEE_REJECTED);
	assert_eq!(told.len(), 1, "{told:?}");
	assert_eq!(told[0].peer.as_deref(), Some(PRO_A));
	stack.stop();
	std::fs::remove_dir_all(&dir).unwrap();
}

/// The requirement in one test: an owner's move of the source is one trace, its root the session's
/// though someone else started it, and the real route calls of the move carry its id.
#[test]
fn an_owners_switch_is_one_trace_and_its_route_calls_carry_the_id_across_the_seam() {
	use trace::test_support::{assert_nested, Kept};
	let dir = temp_dir("trace-switch");
	let chain = Arc::new(FakeSource::new(30, &[]));
	let pro_a = TestPro::new(Arc::clone(&chain), true);
	let pro_b = TestPro::new(Arc::clone(&chain), true);
	let seen = Arc::new(Mutex::new(Vec::new()));
	let connector = Arc::new(SeenConnector {
		inner: Connector::with(&[(PRO_A, &pro_a), (PRO_B, &pro_b)]),
		seen: Arc::clone(&seen),
	});
	let session = ChainProviderSession::new(
		connector,
		DeliveryPreference::Push,
		Network::Regtest,
		dir.to_str().unwrap(),
		logger(),
	);
	let kept = Arc::new(Kept::default());
	session.set_observer(Arc::clone(&kept) as Arc<dyn trace::SessionObserver>);
	let stack = cbf_node(Arc::clone(&session), Some(birthday_of(&chain, 28)), 41);
	session.set_candidates(vec![PRO_A.to_string(), PRO_B.to_string()]);
	wait_for("a lease on A", || !pro_a.leases.live(0).is_empty());
	wait_for("the find to close", || {
		!kept.named(trace::NAME_FIND_SOURCE).is_empty()
			&& kept.named(trace::NAME_FIND_SOURCE)[0].duration_ms.is_some()
	});
	seen.lock().unwrap().clear();

	let clock = trace::TraceClock::starting_now();
	let origin = TraceOrigin {
		trace_id: "ab".repeat(16),
		root_span_id: "cd".repeat(8),
		started_at_ms: clock.started_at_ms(),
		elapsed_us: clock.elapsed_us(),
	};
	assert!(session.set_source_traced(Some(PRO_B.to_string()), Some(origin.clone())));

	let closed =
		|| kept.spans().iter().any(|s| s.span_id == origin.root_span_id && s.duration_ms.is_some());
	wait_for("the switch to settle", closed);
	let spans: Vec<_> =
		kept.spans().into_iter().filter(|s| s.trace_id == origin.trace_id).collect();
	assert_nested(&spans);
	let names: Vec<&str> = spans.iter().map(|s| s.name).collect();
	for want in
		[trace::NAME_SWITCH, trace::NAME_RELEASE, trace::NAME_RETARGET, trace::NAME_SUBSCRIBE]
	{
		assert!(names.contains(&want), "{} in {:?}", want, names);
	}
	assert!(spans.iter().all(|s| s.duration_ms.is_some()), "{:?}", spans);

	let release = spans.iter().find(|s| s.name == trace::NAME_RELEASE).unwrap();
	assert_eq!(release.peer.as_deref(), Some(PRO_A));
	let lease = spans.iter().find(|s| s.name == trace::NAME_SUBSCRIBE).unwrap();
	assert_eq!(lease.peer.as_deref(), Some(PRO_B));

	let seen = seen.lock().unwrap().clone();
	let release_call = seen.iter().find(|(r, secs, _)| *r == "subscribe" && *secs == 0).unwrap();
	assert_eq!(
		release_call.2,
		Some((origin.trace_id.clone(), release.span_id.clone())),
		"the release's route call"
	);
	let lease_call = seen.iter().find(|(r, secs, _)| *r == "subscribe" && *secs > 0).unwrap();
	assert_eq!(
		lease_call.2,
		Some((origin.trace_id.clone(), lease.span_id.clone())),
		"the lease's route call"
	);
	let probe_call = seen.iter().find(|(r, _, _)| *r == "since");
	if let Some((_, _, Some((trace_id, _)))) = probe_call {
		assert_eq!(trace_id, &origin.trace_id);
	}
	stack.stop();
}

mod funding_attack;
