// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A BIP157 client that follows the chain through a [`FilterSource`] instead of the Bitcoin P2P
//! network, and verifies everything it is handed.
//!
//! The loop feeds the same [`BlockApplicator`](crate::chain::cbf::applicator::BlockApplicator)
//! kyoto does, with the same [`ChainOp`]s, so the per-listener gates, the resume anchor, the
//! [`WatchLedger`](crate::chain::cbf::WatchLedger) and the sync-state publishing are shared.
//! What differs is where the data comes from and who checks it: kyoto checks what its peers
//! send; here the source is a single node that may be broken or lying, and this loop checks:
//!
//! * **Headers** — each links to the one below, carries its proof of work, claims exactly the
//!   target the network rules require (the 2016-block retarget, testnet's minimum-difficulty
//!   rule, regtest's none), and has a timestamp above the median of the eleven before it and
//!   within two hours of this node's clock. See [`header_verify`](super::header_verify).
//! * **Fork choice** — a branch the source switches to replaces ours only when it has more
//!   work.
//! * **Filter headers** — the served span continues the filter-header chain already verified,
//!   and every filter hashes to its served filter header.
//! * **Filters** — belong to the block our header chain has at that height.
//! * **Blocks** — the header is ours, the merkle root and the witness commitment hold, and no
//!   transaction appears twice.
//!
//! One trust gap is documented rather than closed: the first filter-header span after a resume
//! has no verified predecessor (nothing about filters is persisted), so its `previous` is taken
//! from the source. Everything after it chains from there. A source that lies at that point
//! can hide the transactions of the blocks it serves until the next restart — it cannot make
//! this node accept a block, a header or a chain that is not valid.
//!
//! Headers and filter headers are held in RAM from the resume anchor (see [`HeaderChain`]),
//! pruned to the last [`SourceTuning::held_headers`]; filters and blocks are dropped once
//! used. Nothing new is persisted: the resume point comes from the wallet and LDK stores, as it
//! does for kyoto.

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bip157::IndexedBlock;

use bdk_chain::BlockId;

use bitcoin::bip158::FilterHeader;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Network, ScriptBuf, Work};

use tokio::sync::{mpsc, watch, Semaphore};

use async_trait::async_trait;

use crate::chain::cbf::applicator::ChainOp;
use crate::chain::cbf::fee_sampler::{BlockFetch, FeeBlockSource, SampleFailure};
use crate::chain::cbf::header_verify::{
	retarget_interval, verify_header, HeaderCheck, MEDIAN_TIME_SPAN,
};
use crate::chain::cbf::source::{
	FilterSource, SourceError, MAX_FILTERS_PER_REQUEST, MAX_HEADERS_PER_REQUEST,
};
use crate::chain::cbf::{mark_syncing, CbfSyncState};
use crate::logger::{log_debug, log_error, log_info, log_warn, LdkLogger, Logger};
use crate::Error;

/// How often the loop asks the source for its tip once caught up.
pub(crate) const SOURCE_TIP_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on any one call to the source. Implementations apply their own timeouts; this is the
/// backstop that keeps a wedged one from parking the loop.
pub(crate) const SOURCE_CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Consecutive invalid answers — data that fails a check, or that the source itself calls
/// invalid — before the loop gives up on the source and fails closed.
pub(crate) const MAX_INVALID_STRIKES: u32 = 3;

/// How long a `node,p2p` node waits on an unavailable node source before it starts kyoto.
pub(crate) const NODE_SOURCE_FALLBACK_AFTER: Duration = Duration::from_secs(5 * 60);

/// How many headers are held below the tip. Two retarget periods: the retarget and the
/// minimum-difficulty rules need the current period's first header, the median-time rule the
/// last eleven, and a reorg can be followed only as deep as the chain held.
pub(crate) const HELD_HEADERS: u32 = 2 * 2016;

/// How far the header chain may run ahead of the filters. Bounds the RAM a long catch-up
/// takes: headers are fetched a batch ahead, then the filters catch up to them.
pub(crate) const HEADER_LOOKAHEAD: u32 = MAX_HEADERS_PER_REQUEST;

/// The first window of a reorg walk-back, doubled on every miss.
const REORG_WALK_FIRST_WINDOW: u32 = 16;

/// A contiguous run of verified headers, from the lowest held up to the tip, with the filter
/// header of every block whose filter has been verified.
#[derive(Clone, Default)]
pub(crate) struct HeaderChain {
	base: u32,
	headers: Vec<Header>,
	hashes: Vec<BlockHash>,
	filter_headers: Vec<Option<FilterHeader>>,
}

impl HeaderChain {
	fn from_headers(base: u32, headers: Vec<Header>) -> Self {
		let hashes = headers.iter().map(Header::block_hash).collect();
		let filter_headers = vec![None; headers.len()];
		Self { base, headers, hashes, filter_headers }
	}

	fn index(&self, height: u32) -> Option<usize> {
		let index = height.checked_sub(self.base)? as usize;
		(index < self.headers.len()).then_some(index)
	}

	/// The best block held, or `None` before the loop has resumed.
	pub(crate) fn tip(&self) -> Option<BlockId> {
		let hash = *self.hashes.last()?;
		Some(BlockId { height: self.base + self.headers.len() as u32 - 1, hash })
	}

	/// The lowest height held.
	fn base(&self) -> u32 {
		self.base
	}

	pub(crate) fn header(&self, height: u32) -> Option<Header> {
		self.index(height).map(|i| self.headers[i])
	}

	pub(crate) fn hash(&self, height: u32) -> Option<BlockHash> {
		self.index(height).map(|i| self.hashes[i])
	}

	/// The height of `hash` in the held chain. Searched from the tip down, where every caller
	/// looks.
	pub(crate) fn height_of(&self, hash: &BlockHash) -> Option<u32> {
		self.hashes.iter().rposition(|h| h == hash).map(|i| self.base + i as u32)
	}

	fn push(&mut self, header: Header, hash: BlockHash) {
		self.headers.push(header);
		self.hashes.push(hash);
		self.filter_headers.push(None);
	}

	/// Drops everything above `height`.
	fn truncate_to(&mut self, height: u32) {
		let keep = (height + 1).saturating_sub(self.base) as usize;
		self.headers.truncate(keep);
		self.hashes.truncate(keep);
		self.filter_headers.truncate(keep);
	}

	/// Drops everything below `height`, keeping at least the tip.
	fn prune_below(&mut self, height: u32) {
		let drop =
			(height.saturating_sub(self.base) as usize).min(self.headers.len().saturating_sub(1));
		if drop == 0 {
			return;
		}
		self.headers.drain(..drop);
		self.hashes.drain(..drop);
		self.filter_headers.drain(..drop);
		self.base += drop as u32;
	}

	fn filter_header(&self, height: u32) -> Option<FilterHeader> {
		self.index(height).and_then(|i| self.filter_headers[i])
	}

	fn set_filter_header(&mut self, height: u32, filter_header: FilterHeader) {
		if let Some(i) = self.index(height) {
			self.filter_headers[i] = Some(filter_header);
		}
	}

	/// The total work of the held headers above `height`.
	fn work_above(&self, height: u32) -> Work {
		let from = (height + 1).saturating_sub(self.base) as usize;
		self.headers
			.iter()
			.skip(from)
			.fold(Work::from_be_bytes([0; 32]), |sum, header| sum + header.work())
	}
}

/// The verified header chain, shared between the sync loop that extends it and the readers —
/// the fee source and `is_on_chain` — that answer from it. Never held across an `.await`.
pub(crate) type SharedHeaderChain = Arc<Mutex<HeaderChain>>;

pub(crate) fn new_shared_header_chain() -> SharedHeaderChain {
	Arc::new(Mutex::new(HeaderChain::default()))
}

pub(crate) fn lock_headers(chain: &SharedHeaderChain) -> MutexGuard<'_, HeaderChain> {
	chain.lock().unwrap_or_else(|e| e.into_inner())
}

/// The scripts every filter is matched against — the wallet's and LDK's — behind a seam so the
/// loop can be driven without a wallet.
pub(crate) trait WatchedScripts: Send + Sync {
	/// Sizes of the underlying sets. Both only grow, so an unchanged pair means an unchanged
	/// set, and the cached copy stands.
	fn counts(&self) -> (usize, usize);
	/// Every watched script.
	fn scripts(&self) -> Vec<ScriptBuf>;
}

/// The watched scripts, copied once and refreshed only when a set grew; see the kyoto event
/// loop's `MatchSet`, whose reasoning this repeats.
#[derive(Default)]
struct ScriptCache {
	counts: Option<(usize, usize)>,
	scripts: Vec<ScriptBuf>,
}

impl ScriptCache {
	fn current(&mut self, watched: &dyn WatchedScripts) -> &[ScriptBuf] {
		let counts = watched.counts();
		if self.counts != Some(counts) {
			self.scripts = watched.scripts();
			self.counts = Some(counts);
		}
		&self.scripts
	}
}

/// A check the source's data failed. Nothing that failed one is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyFailure {
	/// A header failed a consensus check.
	Header(HeaderCheck),
	/// A run of headers the source served does not link up.
	BatchLink { height: u32 },
	/// The headers below the resume anchor do not end at the anchor.
	Anchor { height: u32, expected: BlockHash, got: BlockHash },
	/// A filter-header span of the wrong length.
	FilterHeaderCount { start: u32, expected: usize, got: usize },
	/// The span does not continue the verified filter-header chain.
	FilterHeaderChain { height: u32 },
	/// A filter span of the wrong length.
	FilterCount { start: u32, expected: usize, got: usize },
	/// A filter for another block or height than the one our header chain holds there.
	FilterBlock { height: u32 },
	/// A filter that does not hash to its filter header.
	FilterHeader { height: u32 },
	/// A filter that could not be decoded.
	FilterDecode { height: u32 },
	/// A block whose header is not the one our chain holds.
	BlockHeader { height: u32 },
	/// A block whose transactions do not hash to its merkle root.
	MerkleRoot { height: u32 },
	/// A block that lists a transaction twice (the CVE-2012-2459 malleation).
	DuplicateTransactions { height: u32 },
	/// A block whose witness data does not match its coinbase commitment.
	WitnessCommitment { height: u32 },
}

impl VerifyFailure {
	/// The name of the check, for logs.
	pub(crate) fn name(&self) -> &'static str {
		match self {
			Self::Header(check) => check.name(),
			Self::BatchLink { .. } => "header batch link",
			Self::Anchor { .. } => "resume anchor",
			Self::FilterHeaderCount { .. } => "filter header count",
			Self::FilterHeaderChain { .. } => "filter header chain",
			Self::FilterCount { .. } => "filter count",
			Self::FilterBlock { .. } => "filter block hash",
			Self::FilterHeader { .. } => "filter hash vs filter header",
			Self::FilterDecode { .. } => "filter decoding",
			Self::BlockHeader { .. } => "block header",
			Self::MerkleRoot { .. } => "merkle root",
			Self::DuplicateTransactions { .. } => "duplicate transactions",
			Self::WitnessCommitment { .. } => "witness commitment",
		}
	}
}

impl fmt::Display for VerifyFailure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Header(check) => write!(f, "{}", check),
			Self::Anchor { height, expected, got } => write!(
				f,
				"{} check failed: the source has {} at height {}, this node resumes from {}",
				self.name(),
				got,
				height,
				expected
			),
			Self::FilterHeaderCount { start, expected, got }
			| Self::FilterCount { start, expected, got } => write!(
				f,
				"{} check failed for the span from {}: {} served, {} expected",
				self.name(),
				start,
				got,
				expected
			),
			Self::BatchLink { height }
			| Self::FilterHeaderChain { height }
			| Self::FilterBlock { height }
			| Self::FilterHeader { height }
			| Self::FilterDecode { height }
			| Self::BlockHeader { height }
			| Self::MerkleRoot { height }
			| Self::DuplicateTransactions { height }
			| Self::WitnessCommitment { height } => {
				write!(f, "{} check failed at height {}", self.name(), height)
			},
		}
	}
}

/// Checks a full block against the header our chain holds at `height`.
pub(crate) fn verify_block(
	block: &Block, height: u32, header: &Header,
) -> Result<(), VerifyFailure> {
	if block.header != *header {
		return Err(VerifyFailure::BlockHeader { height });
	}
	if !block.check_merkle_root() {
		return Err(VerifyFailure::MerkleRoot { height });
	}
	let mut txids = HashSet::with_capacity(block.txdata.len());
	if !block.txdata.iter().all(|tx| txids.insert(tx.compute_txid())) {
		return Err(VerifyFailure::DuplicateTransactions { height });
	}
	if !block.check_witness_commitment() {
		return Err(VerifyFailure::WitnessCommitment { height });
	}
	Ok(())
}

/// Why one step of the loop did not complete.
#[derive(Debug)]
enum StepError {
	/// The source did not answer, or answered that it lacks the data, or called its own data
	/// invalid.
	Source(SourceError),
	/// The source's data failed a check.
	Verify(VerifyFailure),
	/// The source is on a branch with no more work than ours: behind, or lying. Waited out.
	LessWork { fork: u32 },
	/// The source's chain forks from ours below the lowest header held.
	ReorgTooDeep { held_from: u32 },
	/// The full-block permits were closed.
	PermitsClosed,
	/// The applicator is gone: it halted on a divergence and published the failure itself.
	ApplicatorGone,
}

impl fmt::Display for StepError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Source(e) => write!(f, "{}", e),
			Self::Verify(failure) => write!(f, "{}", failure),
			Self::LessWork { fork } => write!(
				f,
				"the source's branch from height {} has no more work than this node's",
				fork
			),
			Self::ReorgTooDeep { held_from } => write!(
				f,
				"the source's chain forks from this node's below height {}, the lowest header held",
				held_from
			),
			Self::PermitsClosed => f.write_str("the full-block permits were closed"),
			Self::ApplicatorGone => f.write_str("the block applicator is gone"),
		}
	}
}

impl From<VerifyFailure> for StepError {
	fn from(failure: VerifyFailure) -> Self {
		Self::Verify(failure)
	}
}

/// What a step achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
	/// Headers, filters or a reorg were taken: step again at once.
	Advanced,
	/// Caught up with the source: poll its tip again later.
	Idle,
}

/// How the loop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceSyncEnd {
	/// Asked to stop.
	Stopped,
	/// The applicator halted on a divergence and published the failure.
	ApplicatorGone,
	/// The source kept failing verification, or forked below what is held: the sync failed
	/// closed. The reason names the check.
	Failed(String),
	/// The node source stayed unavailable past [`SourceTuning::fallback_after`]: the caller
	/// starts kyoto.
	FallBack,
}

/// The loop's knobs. [`SourceTuning::production`] in the engine; shortened in the tests.
#[derive(Debug, Clone)]
pub(crate) struct SourceTuning {
	pub(crate) poll_interval: Duration,
	pub(crate) call_timeout: Duration,
	pub(crate) initial_backoff: Duration,
	pub(crate) max_backoff: Duration,
	/// While the source is unavailable, how often that is reported at warn.
	pub(crate) wait_report_interval: Duration,
	pub(crate) max_invalid_strikes: u32,
	/// `Some` for `node,p2p`: how long an unavailable source is waited on before falling back.
	pub(crate) fallback_after: Option<Duration>,
	pub(crate) header_lookahead: u32,
	pub(crate) held_headers: u32,
}

impl SourceTuning {
	pub(crate) fn production(fall_back_to_p2p: bool) -> Self {
		use crate::chain::engine::cbf::{
			CBF_MAX_BACKOFF_MS, CBF_PEER_WAIT_REPORT_INTERVAL, INITIAL_BACKOFF_MS,
		};
		Self {
			poll_interval: SOURCE_TIP_POLL_INTERVAL,
			call_timeout: SOURCE_CALL_TIMEOUT,
			initial_backoff: Duration::from_millis(INITIAL_BACKOFF_MS),
			max_backoff: Duration::from_millis(CBF_MAX_BACKOFF_MS),
			wait_report_interval: CBF_PEER_WAIT_REPORT_INTERVAL,
			max_invalid_strikes: MAX_INVALID_STRIKES,
			fallback_after: fall_back_to_p2p.then_some(NODE_SOURCE_FALLBACK_AFTER),
			header_lookahead: HEADER_LOOKAHEAD,
			held_headers: HELD_HEADERS,
		}
	}
}

/// How a failed step is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryReport {
	/// The source became unavailable just now, or has been for another report interval.
	WaitingWarn,
	/// Still unavailable, reported recently.
	WaitingQuiet,
	/// Invalid data: an error, counted.
	Invalid,
}

/// What to do after a failed step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryDecision {
	Retry { backoff: Duration, report: RetryReport },
	FallBack,
	Fail,
}

/// The retry rules, apart from the loop so they can be checked without a source.
///
/// Unavailable (and not-found, the sign of a raced reorg) is retried forever on a doubling
/// backoff capped like kyoto's network waits, reported once and then once per interval —
/// except on `node,p2p`, which falls back to kyoto once the wait outlasts
/// [`SourceTuning::fallback_after`]. Invalid data is retried too, but
/// [`SourceTuning::max_invalid_strikes`] in a row fail the sync closed. A completed step
/// resets both.
struct SourceRetryPolicy {
	tuning: SourceTuning,
	backoff: Duration,
	strikes: u32,
	waiting_since: Option<Instant>,
	last_report: Option<Instant>,
}

impl SourceRetryPolicy {
	fn new(tuning: SourceTuning) -> Self {
		let backoff = tuning.initial_backoff;
		Self { tuning, backoff, strikes: 0, waiting_since: None, last_report: None }
	}

	/// A step completed. How long the source had been unavailable, if it had.
	fn succeeded(&mut self) -> Option<Duration> {
		self.strikes = 0;
		self.backoff = self.tuning.initial_backoff;
		self.last_report = None;
		self.waiting_since.take().map(|since| since.elapsed())
	}

	fn next_backoff(&mut self) -> Duration {
		let backoff = self.backoff;
		self.backoff = self.backoff.saturating_mul(2).min(self.tuning.max_backoff);
		backoff
	}

	fn wait_report(&mut self, now: Instant) -> RetryReport {
		match self.last_report {
			Some(last)
				if now.saturating_duration_since(last) < self.tuning.wait_report_interval =>
			{
				RetryReport::WaitingQuiet
			},
			_ => {
				self.last_report = Some(now);
				RetryReport::WaitingWarn
			},
		}
	}

	fn decide(&mut self, error: &StepError, now: Instant) -> RetryDecision {
		match error {
			StepError::Source(SourceError::Unavailable { .. })
			| StepError::Source(SourceError::NotFound(_)) => {
				let since = *self.waiting_since.get_or_insert(now);
				if let Some(after) = self.tuning.fallback_after {
					if now.saturating_duration_since(since) >= after {
						return RetryDecision::FallBack;
					}
				}
				RetryDecision::Retry { backoff: self.next_backoff(), report: self.wait_report(now) }
			},
			StepError::LessWork { .. } => {
				RetryDecision::Retry { backoff: self.next_backoff(), report: self.wait_report(now) }
			},
			StepError::Source(SourceError::Invalid(_)) | StepError::Verify(_) => {
				self.strikes += 1;
				if self.strikes >= self.tuning.max_invalid_strikes {
					return RetryDecision::Fail;
				}
				RetryDecision::Retry { backoff: self.next_backoff(), report: RetryReport::Invalid }
			},
			StepError::ReorgTooDeep { .. }
			| StepError::PermitsClosed
			| StepError::ApplicatorGone => RetryDecision::Fail,
		}
	}

	fn waiting_for(&self, now: Instant) -> Duration {
		self.waiting_since.map(|since| now.saturating_duration_since(since)).unwrap_or_default()
	}
}

/// Runs a source call under `limit`; a call that runs out is an unavailable source.
async fn bounded<T>(
	limit: Duration, call: impl Future<Output = Result<T, SourceError>>,
) -> Result<T, StepError> {
	match tokio::time::timeout(limit, call).await {
		Ok(answer) => answer.map_err(StepError::Source),
		Err(_elapsed) => Err(StepError::Source(SourceError::Unavailable {
			reason: format!("no answer within {}s", limit.as_secs()),
			timed_out: true,
		})),
	}
}

fn now_secs() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Checks that `headers` link up among themselves, the first at `first_height`.
fn check_batch_links(first_height: u32, headers: &[Header]) -> Result<(), VerifyFailure> {
	for (i, pair) in headers.windows(2).enumerate() {
		if pair[1].prev_blockhash != pair[0].block_hash() {
			return Err(VerifyFailure::BatchLink { height: first_height + i as u32 + 1 });
		}
	}
	Ok(())
}

/// Verifies `headers`, starting at `first_height`, onto the tip of `chain`, pushing each one
/// that passes. A failure leaves the headers before it in place: they passed.
fn extend_verified(
	chain: &mut HeaderChain, network: Network, first_height: u32, headers: &[Header], now: u64,
) -> Result<(), VerifyFailure> {
	for (i, header) in headers.iter().enumerate() {
		let height = first_height + i as u32;
		let prev = chain.tip().map(|tip| tip.hash).unwrap_or_else(BlockHash::all_zeros);
		let hash = {
			let held: &HeaderChain = chain;
			verify_header(network, height, header, prev, |h| held.header(h), now)
				.map_err(VerifyFailure::Header)?
		};
		chain.push(*header, hash);
	}
	Ok(())
}

/// The sync loop over a [`FilterSource`]. Owned by one task; see the module docs.
pub(crate) struct SourceSync {
	source: Arc<dyn FilterSource>,
	network: Network,
	/// The block the sync resumes from: trusted, from this node's own persisted state.
	anchor: BlockId,
	chain: SharedHeaderChain,
	resumed: bool,
	/// Every filter up to this height has been verified and its op queued.
	filters_through: u32,
	/// The tip a `Synced` op was last queued for; cleared by anything that moves the chain.
	synced_at: Option<BlockHash>,
	scripts: Arc<dyn WatchedScripts>,
	script_cache: ScriptCache,
	ops_tx: mpsc::Sender<ChainOp>,
	sync_state_tx: watch::Sender<CbfSyncState>,
	full_block_permits: Arc<Semaphore>,
	stop_rx: watch::Receiver<bool>,
	tuning: SourceTuning,
	logger: Arc<Logger>,
}

impl SourceSync {
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new(
		source: Arc<dyn FilterSource>, network: Network, anchor: BlockId, chain: SharedHeaderChain,
		scripts: Arc<dyn WatchedScripts>, ops_tx: mpsc::Sender<ChainOp>,
		sync_state_tx: watch::Sender<CbfSyncState>, full_block_permits: Arc<Semaphore>,
		stop_rx: watch::Receiver<bool>, tuning: SourceTuning, logger: Arc<Logger>,
	) -> Self {
		Self {
			source,
			network,
			anchor,
			chain,
			resumed: false,
			filters_through: anchor.height,
			synced_at: None,
			scripts,
			script_cache: ScriptCache::default(),
			ops_tx,
			sync_state_tx,
			full_block_permits,
			stop_rx,
			tuning,
			logger,
		}
	}

	/// Runs until stopped, until the applicator is gone, until the source is given up on, or —
	/// on `node,p2p` — until it is time to fall back to kyoto.
	pub(crate) async fn run(mut self) -> SourceSyncEnd {
		let mut policy = SourceRetryPolicy::new(self.tuning.clone());
		loop {
			if *self.stop_rx.borrow() {
				return SourceSyncEnd::Stopped;
			}
			let mut stop_rx = self.stop_rx.clone();
			let step = tokio::select! {
				biased;
				_ = stop_rx.changed() => return SourceSyncEnd::Stopped,
				step = self.step() => step,
			};
			match step {
				Ok(progress) => {
					if let Some(waited) = policy.succeeded() {
						log_info!(
							self.logger,
							"CBF filter source '{}' answering again after {}s.",
							self.source.name(),
							waited.as_secs()
						);
					}
					if progress == Progress::Idle && !self.sleep(self.tuning.poll_interval).await {
						return SourceSyncEnd::Stopped;
					}
				},
				Err(StepError::ApplicatorGone) => return SourceSyncEnd::ApplicatorGone,
				Err(error) => {
					// Whatever failed, the source's tip is not known to be ours any more.
					self.synced_at = None;
					mark_syncing(&self.sync_state_tx);
					let now = Instant::now();
					match policy.decide(&error, now) {
						RetryDecision::Retry { backoff, report } => {
							self.report_retry(
								&error,
								report,
								backoff,
								policy.waiting_for(now),
								&policy,
							);
							if !self.sleep(backoff).await {
								return SourceSyncEnd::Stopped;
							}
						},
						RetryDecision::FallBack => {
							log_warn!(
								self.logger,
								"CBF filter source '{}' has been unavailable for {}s ({}); falling back to the P2P network.",
								self.source.name(),
								policy.waiting_for(now).as_secs(),
								error
							);
							return SourceSyncEnd::FallBack;
						},
						RetryDecision::Fail => {
							let reason = error.to_string();
							log_error!(
								self.logger,
								"CBF filter source '{}': {}; nothing from it was applied. Giving up on it: the CBF sync has failed closed.",
								self.source.name(),
								reason
							);
							self.sync_state_tx
								.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
							return SourceSyncEnd::Failed(reason);
						},
					}
				},
			}
		}
	}

	fn report_retry(
		&self, error: &StepError, report: RetryReport, backoff: Duration, waited: Duration,
		policy: &SourceRetryPolicy,
	) {
		let name = self.source.name();
		match report {
			RetryReport::WaitingWarn => log_warn!(
				self.logger,
				"CBF filter source '{}' cannot serve the sync: {}; waiting {}s so far, next retry in {}s.",
				name,
				error,
				waited.as_secs(),
				backoff.as_secs().max(1)
			),
			RetryReport::WaitingQuiet => log_debug!(
				self.logger,
				"CBF filter source '{}' still cannot serve the sync: {}; next retry in {}ms.",
				name,
				error,
				backoff.as_millis()
			),
			RetryReport::Invalid => log_error!(
				self.logger,
				"CBF filter source '{}' sent data that failed verification: {}; not applied. Strike {}/{}, retrying in {}ms.",
				name,
				error,
				policy.strikes,
				self.tuning.max_invalid_strikes,
				backoff.as_millis()
			),
		}
	}

	/// Sleeps `duration` unless told to stop first; `false` when stopped.
	async fn sleep(&mut self, duration: Duration) -> bool {
		// A dropped sender is a stop too.
		let interrupted = tokio::select! {
			biased;
			_ = self.stop_rx.changed() => true,
			_ = tokio::time::sleep(duration) => false,
		};
		!interrupted && !*self.stop_rx.borrow()
	}

	/// One unit of progress: resume, a header batch, a reorg, a filter batch, or the `Synced`
	/// that ends a catch-up.
	async fn step(&mut self) -> Result<Progress, StepError> {
		if !self.resumed {
			self.resume().await?;
			self.resumed = true;
			return Ok(Progress::Advanced);
		}

		// Re-read every step: after any failure, a stop hash taken from an older tip may no
		// longer be on the source's chain.
		let tip = bounded(self.tuning.call_timeout, self.source.tip()).await?;
		let (ours, tip_on_our_chain) = {
			let chain = lock_headers(&self.chain);
			let ours = chain.tip().expect("resumed");
			(ours, chain.hash(tip.height) == Some(tip.hash))
		};

		if !tip_on_our_chain {
			if tip.height <= ours.height {
				return self.reorg(tip, ours).await;
			}
			let room =
				(self.filters_through + self.tuning.header_lookahead).saturating_sub(ours.height);
			if room > 0 {
				let count = (tip.height - ours.height).min(room).min(MAX_HEADERS_PER_REQUEST);
				let headers =
					bounded(self.tuning.call_timeout, self.source.headers(ours.height + 1, count))
						.await?;
				let Some(first) = headers.first() else {
					return Err(StepError::Source(SourceError::Invalid(format!(
						"no headers above height {} though its tip is at {}",
						ours.height, tip.height
					))));
				};
				if first.prev_blockhash != ours.hash {
					return self.reorg(tip, ours).await;
				}
				let headers = &headers[..headers.len().min(count as usize)];
				self.extend(ours.height + 1, headers)?;
				return Ok(Progress::Advanced);
			}
		}

		if self.filters_through < ours.height {
			self.filter_batch(ours.height).await?;
			return Ok(Progress::Advanced);
		}
		if !tip_on_our_chain {
			// The header lookahead was full and the filters have caught up with it.
			return Ok(Progress::Advanced);
		}

		if self.synced_at != Some(ours.hash) {
			log_info!(
				self.logger,
				"CBF synced to tip {} from filter source '{}'.",
				ours.height,
				self.source.name()
			);
			self.send(ChainOp::Synced { tip_height: ours.height }).await?;
			self.synced_at = Some(ours.hash);
		}
		Ok(Progress::Idle)
	}

	async fn send(&self, op: ChainOp) -> Result<(), StepError> {
		self.ops_tx.send(op).await.map_err(|_| StepError::ApplicatorGone)
	}

	/// Fetches the headers from the start of the anchor's retarget period (and at least the
	/// eleven below it) up to the anchor, checks they link and end at the anchor, and holds
	/// them. They are authenticated by the anchor alone, which this node trusts; every header
	/// above it is fully verified.
	async fn resume(&mut self) -> Result<(), StepError> {
		let anchor = self.anchor;
		let interval = retarget_interval(self.network);
		let period_start = anchor.height - anchor.height % interval;
		let lowest = period_start.min(anchor.height.saturating_sub(MEDIAN_TIME_SPAN));

		let mut headers: Vec<Header> = Vec::with_capacity((anchor.height - lowest + 1) as usize);
		while (headers.len() as u32) < anchor.height - lowest + 1 {
			let next = lowest + headers.len() as u32;
			let count = (anchor.height - next + 1).min(MAX_HEADERS_PER_REQUEST);
			let batch = bounded(self.tuning.call_timeout, self.source.headers(next, count)).await?;
			if batch.is_empty() {
				return Err(StepError::Source(SourceError::Invalid(format!(
					"no headers from height {} though the resume anchor is at {}",
					next, anchor.height
				))));
			}
			headers.extend(batch.into_iter().take(count as usize));
		}
		check_batch_links(lowest, &headers)?;
		for (i, header) in headers.iter().enumerate() {
			if header.validate_pow(header.target()).is_err() {
				let height = lowest + i as u32;
				return Err(VerifyFailure::Header(HeaderCheck::ProofOfWork { height }).into());
			}
		}
		let top = headers.last().expect("at least the anchor").block_hash();
		if top != anchor.hash {
			return Err(VerifyFailure::Anchor {
				height: anchor.height,
				expected: anchor.hash,
				got: top,
			}
			.into());
		}

		*lock_headers(&self.chain) = HeaderChain::from_headers(lowest, headers);
		self.filters_through = anchor.height;
		log_info!(
			self.logger,
			"CBF resuming from height {} ({}) through filter source '{}'; holding headers from {}.",
			anchor.height,
			anchor.hash,
			self.source.name(),
			lowest
		);
		Ok(())
	}

	/// Verifies `headers` onto the tip and prunes what is no longer needed.
	fn extend(&mut self, first_height: u32, headers: &[Header]) -> Result<(), StepError> {
		let result = {
			let mut chain = lock_headers(&self.chain);
			extend_verified(&mut chain, self.network, first_height, headers, now_secs())
		};
		self.synced_at = None;
		self.prune();
		result.map_err(StepError::from)
	}

	/// Drops held headers below the last [`SourceTuning::held_headers`], never one whose
	/// filter is still to be processed.
	fn prune(&self) {
		let mut chain = lock_headers(&self.chain);
		if let Some(tip) = chain.tip() {
			let keep_from =
				(tip.height + 1).saturating_sub(self.tuning.held_headers).min(self.filters_through);
			chain.prune_below(keep_from);
		}
	}

	/// Follows the source onto another branch: finds where it forks from ours, verifies the
	/// branch, and — if it has more work — disconnects ours tip-first and holds the branch.
	async fn reorg(&mut self, tip: BlockId, ours: BlockId) -> Result<Progress, StepError> {
		let fork = self.find_fork(tip, ours).await?;

		// The source's branch above the fork, verified onto a copy of ours cut at the fork.
		let (mut branch, old_work) = {
			let chain = lock_headers(&self.chain);
			let mut branch = chain.clone();
			branch.truncate_to(fork);
			(branch, chain.work_above(fork))
		};
		let cap = fork + (ours.height - fork) + self.tuning.header_lookahead;
		let mut next = fork + 1;
		while next <= tip.height.min(cap) && branch.work_above(fork) <= old_work {
			let count = (tip.height.min(cap) - next + 1).min(MAX_HEADERS_PER_REQUEST);
			let batch = bounded(self.tuning.call_timeout, self.source.headers(next, count)).await?;
			if batch.is_empty() {
				return Err(StepError::Source(SourceError::Invalid(format!(
					"no headers from height {} though its tip is at {}",
					next, tip.height
				))));
			}
			let batch = &batch[..batch.len().min(count as usize)];
			extend_verified(&mut branch, self.network, next, batch, now_secs())?;
			next += batch.len() as u32;
		}
		if branch.work_above(fork) <= old_work {
			return Err(StepError::LessWork { fork });
		}

		// Ours above the fork, as far as ops were queued for it, tip first.
		let abandoned: Vec<(Header, u32)> = {
			let mut chain = lock_headers(&self.chain);
			let abandoned = ((fork + 1)..=ours.height.min(self.filters_through))
				.rev()
				.filter_map(|height| chain.header(height).map(|header| (header, height)))
				.collect();
			*chain = branch;
			abandoned
		};
		log_warn!(
			self.logger,
			"CBF reorg from filter source '{}': this node's blocks {}..={} replaced by a branch with more work; the fork point is {}.",
			self.source.name(),
			fork + 1,
			ours.height,
			fork
		);
		self.filters_through = self.filters_through.min(fork);
		self.synced_at = None;
		if !abandoned.is_empty() {
			self.send(ChainOp::Disconnect { headers: abandoned }).await?;
		}
		Ok(Progress::Advanced)
	}

	/// The highest height where the source's chain and ours agree, walking down from the lower
	/// of the two tips in growing windows. Fails closed below the lowest header held.
	async fn find_fork(&self, tip: BlockId, ours: BlockId) -> Result<u32, StepError> {
		let base = lock_headers(&self.chain).base();
		let mut hi = ours.height.min(tip.height);
		let mut window = REORG_WALK_FIRST_WINDOW;
		loop {
			if hi < base {
				return Err(StepError::ReorgTooDeep { held_from: base });
			}
			let lo = hi.saturating_sub(window - 1).max(base);
			let fetched =
				bounded(self.tuning.call_timeout, self.source.headers(lo, hi - lo + 1)).await?;
			if fetched.is_empty() {
				return Err(StepError::Source(SourceError::Invalid(format!(
					"no headers from height {} though its tip is at {}",
					lo, tip.height
				))));
			}
			let fetched = &fetched[..fetched.len().min((hi - lo + 1) as usize)];
			check_batch_links(lo, fetched)?;
			{
				let chain = lock_headers(&self.chain);
				for (i, header) in fetched.iter().enumerate().rev() {
					let height = lo + i as u32;
					if chain.hash(height) == Some(header.block_hash()) {
						return Ok(height);
					}
				}
			}
			if lo == base {
				return Err(StepError::ReorgTooDeep { held_from: base });
			}
			hi = lo - 1;
			window = window.saturating_mul(2).min(MAX_HEADERS_PER_REQUEST);
		}
	}

	/// Verifies the next span of filter headers and filters up to `top`, then queues one op per
	/// block: the full block when its filter matches a watched script, the header otherwise.
	/// Nothing is queued unless the whole span verified.
	async fn filter_batch(&mut self, top: u32) -> Result<(), StepError> {
		let start = self.filters_through + 1;
		let stop = top.min(start + MAX_FILTERS_PER_REQUEST - 1);
		let expected = (stop - start + 1) as usize;
		let (stop_hash, verified_previous) = {
			let chain = lock_headers(&self.chain);
			(chain.hash(stop).expect("held"), chain.filter_header(start - 1))
		};

		let served =
			bounded(self.tuning.call_timeout, self.source.filter_headers(start, stop_hash)).await?;
		if served.headers.len() != expected {
			return Err(VerifyFailure::FilterHeaderCount {
				start,
				expected,
				got: served.headers.len(),
			}
			.into());
		}
		match verified_previous {
			Some(previous) if previous != served.previous => {
				return Err(VerifyFailure::FilterHeaderChain { height: start }.into());
			},
			Some(_) => {},
			None => log_debug!(
				self.logger,
				"CBF taking the filter header below height {} from source '{}' unverified: the first span after a resume has no verified predecessor.",
				start,
				self.source.name()
			),
		}

		let filters =
			bounded(self.tuning.call_timeout, self.source.filters(start, stop_hash)).await?;
		if filters.len() != expected {
			return Err(VerifyFailure::FilterCount { start, expected, got: filters.len() }.into());
		}

		// Verify and match the whole span before queueing any of it.
		let scripts = self.script_cache.current(&*self.scripts);
		let mut planned: Vec<(u32, Header, BlockHash, FilterHeader, bool)> =
			Vec::with_capacity(expected);
		{
			let chain = lock_headers(&self.chain);
			let mut previous = served.previous;
			for (i, indexed) in filters.iter().enumerate() {
				let height = start + i as u32;
				let (header, hash) = match (chain.header(height), chain.hash(height)) {
					(Some(header), Some(hash)) => (header, hash),
					_ => unreachable!("every height up to the tip is held"),
				};
				if indexed.height != height || indexed.block_hash != hash {
					return Err(VerifyFailure::FilterBlock { height }.into());
				}
				let computed = indexed.filter.filter_header(&previous);
				if computed != served.headers[i] {
					return Err(VerifyFailure::FilterHeader { height }.into());
				}
				previous = computed;
				let matched = !scripts.is_empty()
					&& indexed
						.filter
						.match_any(&hash, scripts.iter().map(|s| s.as_bytes()))
						.map_err(|_| VerifyFailure::FilterDecode { height })?;
				planned.push((height, header, hash, computed, matched));
			}
		}
		drop(filters);

		for (height, header, hash, filter_header, matched) in planned {
			// We are behind by this block until it is applied; see `mark_syncing`.
			mark_syncing(&self.sync_state_tx);
			let op = if matched {
				self.fetch_block(height, header, hash).await?
			} else {
				ChainOp::ConnectFiltered { header, height }
			};
			self.send(op).await?;
			lock_headers(&self.chain).set_filter_header(height, filter_header);
			self.filters_through = height;
		}
		self.prune();
		Ok(())
	}

	/// Fetches a matched block under one of the full-block permits and verifies it against our
	/// header; the permit rides in the op until the applicator drops it.
	async fn fetch_block(
		&self, height: u32, header: Header, hash: BlockHash,
	) -> Result<ChainOp, StepError> {
		let permit = Arc::clone(&self.full_block_permits)
			.acquire_owned()
			.await
			.map_err(|_| StepError::PermitsClosed)?;
		let block = bounded(self.tuning.call_timeout, self.source.block(hash)).await?;
		verify_block(&block, height, &header)?;
		log_debug!(self.logger, "CBF fetched matched block {} at height {}", hash, height);
		Ok(ChainOp::ConnectFull { block: IndexedBlock { height, block }, permit })
	}
}

/// The verified header chain and a [`FilterSource`] as a [`FeeBlockSource`]: the fee window is
/// read from headers this node checked, and each sampled block is fetched through the source
/// and checked against them, under a free full-block permit.
///
/// The source has none of kyoto's five-second re-request behaviour, so the sampler's cooldown
/// after a slow block only ever costs a little time; it is kept so the sampling rules are the
/// same whichever source runs.
pub(crate) struct SourceFeeSource {
	source: Arc<dyn FilterSource>,
	chain: SharedHeaderChain,
	sync_state_rx: watch::Receiver<CbfSyncState>,
	full_block_permits: Arc<Semaphore>,
}

impl SourceFeeSource {
	pub(crate) fn new(
		source: Arc<dyn FilterSource>, chain: SharedHeaderChain,
		sync_state_rx: watch::Receiver<CbfSyncState>, full_block_permits: Arc<Semaphore>,
	) -> Self {
		Self { source, chain, sync_state_rx, full_block_permits }
	}
}

#[async_trait]
impl FeeBlockSource for SourceFeeSource {
	async fn tip_height(&self) -> Result<u32, SampleFailure> {
		lock_headers(&self.chain).tip().map(|tip| tip.height).ok_or(SampleFailure::NodeGone)
	}

	async fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SampleFailure> {
		Ok(lock_headers(&self.chain).hash(height))
	}

	fn can_fetch(&self) -> bool {
		matches!(*self.sync_state_rx.borrow(), CbfSyncState::Active { synced_to_tip: true, .. })
	}

	fn request_block(&self, hash: BlockHash) -> Result<BlockFetch, SampleFailure> {
		let (height, header) = {
			let chain = lock_headers(&self.chain);
			let height = chain.height_of(&hash).ok_or_else(|| {
				SampleFailure::FetchFailed("not in the verified header chain".to_string())
			})?;
			(height, chain.header(height).expect("held"))
		};
		let permit = Arc::clone(&self.full_block_permits)
			.try_acquire_owned()
			.map_err(|_| SampleFailure::NoPermit)?;
		let source = Arc::clone(&self.source);
		Ok(Box::pin(async move {
			let _permit = permit;
			let block =
				source.block(hash).await.map_err(|e| SampleFailure::FetchFailed(e.to_string()))?;
			verify_block(&block, height, &header).map_err(|_| SampleFailure::Mismatch)?;
			Ok((height, block))
		}))
	}
}

#[cfg(test)]
pub(crate) mod test_support {
	//! A deterministic in-memory [`FilterSource`] over regtest-difficulty blocks mined in the
	//! test, with switches to make it fail or lie.
	use super::*;

	use std::collections::HashMap;

	use bitcoin::bip158::BlockFilter;
	use bitcoin::block::Version;
	use bitcoin::{
		absolute, transaction, Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut,
		Witness,
	};

	use crate::chain::cbf::source::{FilterHeaders, IndexedFilter};

	pub(crate) const REGTEST_BITS: u32 = 0x207f_ffff;
	/// A recent, fixed timestamp for the first mined block.
	pub(crate) const BASE_TIME: u32 = 1_700_000_000;

	pub(crate) fn other_script(seed: u8) -> ScriptBuf {
		ScriptBuf::from_bytes(vec![0x51, 0x01, seed])
	}

	pub(crate) fn watched_script() -> ScriptBuf {
		ScriptBuf::from_bytes(vec![0x00, 0x14, 0xab, 0xcd, 0xef])
	}

	fn coinbase(height: u32, pay_to: ScriptBuf, salt: u8) -> Transaction {
		let mut script_sig = height.to_le_bytes().to_vec();
		script_sig.push(salt);
		Transaction {
			version: transaction::Version::ONE,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::from_bytes(script_sig),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(50_000), script_pubkey: pay_to }],
		}
	}

	/// Mines a regtest block at `height` on `prev`: the nonce is searched until the proof of
	/// work holds, which at the regtest limit takes a couple of tries.
	pub(crate) fn mine(
		prev: BlockHash, height: u32, time: u32, pay_to: ScriptBuf, salt: u8,
	) -> Block {
		let txdata = vec![coinbase(height, pay_to, salt)];
		let mut block = Block {
			header: Header {
				version: Version::TWO,
				prev_blockhash: prev,
				merkle_root: bitcoin::TxMerkleNode::all_zeros(),
				time,
				bits: CompactTarget::from_consensus(REGTEST_BITS),
				nonce: 0,
			},
			txdata,
		};
		block.header.merkle_root = block.compute_merkle_root().expect("one transaction");
		while block.header.validate_pow(block.header.target()).is_err() {
			block.header.nonce += 1;
		}
		block
	}

	pub(crate) fn filter_of(block: &Block) -> BlockFilter {
		BlockFilter::new_script_filter(block, |_| {
			Ok::<ScriptBuf, bitcoin::bip158::Error>(ScriptBuf::new())
		})
		.expect("a coinbase-only block")
	}

	/// What the source lies about.
	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
	pub(crate) enum Lie {
		None,
		/// The served filter header at this height is garbage.
		FilterHeaderAt(u32),
		/// The served `previous` of every filter-header span is garbage.
		FilterHeaderPrevious,
		/// The block served at this height has a transaction the header does not commit to.
		MerkleAt(u32),
	}

	pub(crate) struct FakeState {
		/// The best chain, genesis at index 0.
		pub(crate) blocks: Vec<Block>,
		/// Every block ever mined, stale ones included, so a stale block is still servable.
		pub(crate) all: HashMap<BlockHash, Block>,
		pub(crate) unavailable_calls: u32,
		pub(crate) lie: Lie,
		pub(crate) calls: HashMap<&'static str, usize>,
	}

	pub(crate) struct FakeSource {
		pub(crate) state: Mutex<FakeState>,
	}

	impl FakeSource {
		/// A chain of `len` blocks (heights `0..len`); the block at each height in `matched`
		/// pays the watched script.
		pub(crate) fn new(len: u32, matched: &[u32]) -> Self {
			let source = Self {
				state: Mutex::new(FakeState {
					blocks: Vec::new(),
					all: HashMap::new(),
					unavailable_calls: 0,
					lie: Lie::None,
					calls: HashMap::new(),
				}),
			};
			source.mine(len, matched, 0);
			source
		}

		fn st(&self) -> MutexGuard<'_, FakeState> {
			self.state.lock().unwrap()
		}

		/// Mines `count` more blocks on the best chain.
		pub(crate) fn mine(&self, count: u32, matched: &[u32], salt: u8) {
			let mut st = self.st();
			for _ in 0..count {
				let height = st.blocks.len() as u32;
				let prev = st.blocks.last().map_or(BlockHash::all_zeros(), |b| b.block_hash());
				let pay_to = if matched.contains(&height) {
					watched_script()
				} else {
					other_script(height as u8)
				};
				let block = mine(prev, height, BASE_TIME + height * 600, pay_to, salt);
				st.all.insert(block.block_hash(), block.clone());
				st.blocks.push(block);
			}
		}

		/// Replaces the top `depth` blocks with `new_len` others.
		pub(crate) fn reorg(&self, depth: u32, new_len: u32) {
			{
				let mut st = self.st();
				let keep = st.blocks.len() - depth as usize;
				st.blocks.truncate(keep);
			}
			self.mine(new_len, &[], 0xee);
		}

		/// Puts a block on the best chain as it is, without mining or checking it.
		pub(crate) fn push_raw(&self, block: Block) {
			let mut st = self.st();
			st.all.insert(block.block_hash(), block.clone());
			st.blocks.push(block);
		}

		pub(crate) fn block_at(&self, height: u32) -> Block {
			self.st().blocks[height as usize].clone()
		}

		pub(crate) fn tip_id(&self) -> BlockId {
			let st = self.st();
			let last = st.blocks.len() - 1;
			BlockId { height: last as u32, hash: st.blocks[last].block_hash() }
		}

		pub(crate) fn set_lie(&self, lie: Lie) {
			self.st().lie = lie;
		}

		pub(crate) fn fail_next(&self, calls: u32) {
			self.st().unavailable_calls = calls;
		}

		pub(crate) fn calls(&self, method: &'static str) -> usize {
			self.st().calls.get(method).copied().unwrap_or(0)
		}

		fn enter(&self, method: &'static str) -> Result<MutexGuard<'_, FakeState>, SourceError> {
			let mut st = self.st();
			*st.calls.entry(method).or_default() += 1;
			if st.unavailable_calls > 0 {
				st.unavailable_calls -= 1;
				return Err(SourceError::unavailable("the fake is down"));
			}
			Ok(st)
		}

		fn span(
			st: &FakeState, start: u32, stop: BlockHash,
		) -> Result<(usize, usize), SourceError> {
			let stop = st
				.blocks
				.iter()
				.position(|b| b.block_hash() == stop)
				.ok_or_else(|| SourceError::NotFound("stop hash".into()))?;
			Ok((start as usize, stop))
		}

		fn filter_header_chain(st: &FakeState, through: usize) -> Vec<FilterHeader> {
			let mut out: Vec<FilterHeader> = Vec::with_capacity(through + 1);
			for block in &st.blocks[..=through] {
				let previous = out.last().copied().unwrap_or_else(FilterHeader::all_zeros);
				out.push(filter_of(block).filter_header(&previous));
			}
			out
		}
	}

	#[async_trait]
	impl FilterSource for FakeSource {
		fn name(&self) -> &'static str {
			"fake"
		}

		async fn tip(&self) -> Result<BlockId, SourceError> {
			let st = self.enter("tip")?;
			let last = st.blocks.len() - 1;
			Ok(BlockId { height: last as u32, hash: st.blocks[last].block_hash() })
		}

		async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
			let st = self.enter("headers")?;
			let from = from_height as usize;
			if from >= st.blocks.len() {
				return Err(SourceError::NotFound("above tip".into()));
			}
			Ok(st.blocks[from..].iter().take(count as usize).map(|b| b.header).collect())
		}

		async fn filter_headers(
			&self, start_height: u32, stop_hash: BlockHash,
		) -> Result<FilterHeaders, SourceError> {
			let st = self.enter("filter_headers")?;
			let (start, stop) = Self::span(&st, start_height, stop_hash)?;
			let chain = Self::filter_header_chain(&st, stop);
			let mut previous =
				if start == 0 { FilterHeader::all_zeros() } else { chain[start - 1] };
			let mut headers = chain[start..=stop].to_vec();
			match st.lie {
				Lie::FilterHeaderAt(height) if (start..=stop).contains(&(height as usize)) => {
					headers[height as usize - start] = FilterHeader::from_byte_array([0x42; 32]);
				},
				Lie::FilterHeaderPrevious => previous = FilterHeader::from_byte_array([0x24; 32]),
				_ => {},
			}
			Ok(FilterHeaders { previous, headers })
		}

		async fn filters(
			&self, start_height: u32, stop_hash: BlockHash,
		) -> Result<Vec<IndexedFilter>, SourceError> {
			let st = self.enter("filters")?;
			let (start, stop) = Self::span(&st, start_height, stop_hash)?;
			Ok((start..=stop)
				.map(|h| IndexedFilter {
					height: h as u32,
					block_hash: st.blocks[h].block_hash(),
					filter: filter_of(&st.blocks[h]),
				})
				.collect())
		}

		async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
			let st = self.enter("block")?;
			let mut block =
				st.all.get(&hash).cloned().ok_or_else(|| SourceError::NotFound("block".into()))?;
			if let Lie::MerkleAt(height) = st.lie {
				if st.blocks.get(height as usize).map(|b| b.block_hash()) == Some(hash) {
					block.txdata[0].output[0].value = Amount::from_sat(21_000_000);
				}
			}
			Ok(block)
		}
	}

	/// A fixed script set for the loop to match against.
	pub(crate) struct FixedScripts(pub(crate) Vec<ScriptBuf>);

	impl WatchedScripts for FixedScripts {
		fn counts(&self) -> (usize, usize) {
			(self.0.len(), 0)
		}
		fn scripts(&self) -> Vec<ScriptBuf> {
			self.0.clone()
		}
	}

	/// Short waits all round, so a test sees retries and failures in milliseconds.
	pub(crate) fn fast_tuning() -> SourceTuning {
		SourceTuning {
			poll_interval: Duration::from_millis(20),
			call_timeout: Duration::from_secs(5),
			initial_backoff: Duration::from_millis(5),
			max_backoff: Duration::from_millis(20),
			wait_report_interval: Duration::from_secs(60),
			max_invalid_strikes: MAX_INVALID_STRIKES,
			fallback_after: None,
			header_lookahead: HEADER_LOOKAHEAD,
			held_headers: HELD_HEADERS,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::test_support::*;
	use super::*;

	use bitcoin::CompactTarget;

	use crate::chain::cbf::applicator::CBF_FULL_BLOCK_PERMITS;

	/// Any single wait in these tests; a test that would otherwise hang fails instead.
	const WAIT: Duration = Duration::from_secs(20);

	/// What an op did, without its payload.
	#[derive(Debug, Clone, PartialEq, Eq)]
	enum Op {
		Full(u32),
		Filtered(u32),
		Disconnect(Vec<u32>),
		Synced(u32),
	}

	struct Harness {
		source: Arc<FakeSource>,
		chain: SharedHeaderChain,
		ops_rx: mpsc::Receiver<ChainOp>,
		sync_state_tx: watch::Sender<CbfSyncState>,
		stop_tx: watch::Sender<bool>,
		permits: Arc<Semaphore>,
		task: tokio::task::JoinHandle<SourceSyncEnd>,
		/// Disconnected headers, by height, as the last `Disconnect` carried them.
		last_disconnect: Vec<(Header, u32)>,
	}

	fn start(source: FakeSource, anchor_height: u32, tuning: SourceTuning) -> Harness {
		let source = Arc::new(source);
		let anchor =
			BlockId { height: anchor_height, hash: source.block_at(anchor_height).block_hash() };
		let chain = new_shared_header_chain();
		let (ops_tx, ops_rx) = mpsc::channel(1024);
		let (sync_state_tx, _) = watch::channel(CbfSyncState::Active {
			applied_tip: Some(anchor_height),
			synced_to_tip: false,
		});
		let (stop_tx, stop_rx) = watch::channel(false);
		let permits = Arc::new(Semaphore::new(CBF_FULL_BLOCK_PERMITS));
		let sync = SourceSync::new(
			Arc::clone(&source) as Arc<dyn FilterSource>,
			Network::Regtest,
			anchor,
			Arc::clone(&chain),
			Arc::new(FixedScripts(vec![watched_script()])),
			ops_tx,
			sync_state_tx.clone(),
			Arc::clone(&permits),
			stop_rx,
			tuning,
			Arc::new(Logger::new_log_facade()),
		);
		let task = tokio::spawn(sync.run());
		Harness {
			source,
			chain,
			ops_rx,
			sync_state_tx,
			stop_tx,
			permits,
			task,
			last_disconnect: Vec::new(),
		}
	}

	impl Harness {
		async fn next_op(&mut self) -> Op {
			let op = tokio::time::timeout(WAIT, self.ops_rx.recv())
				.await
				.expect("an op in time")
				.expect("the loop is running");
			match op {
				ChainOp::ConnectFull { block, permit: _permit } => {
					assert_eq!(
						block.block.block_hash(),
						self.source.block_at(block.height).block_hash(),
						"the full block is the source's at that height"
					);
					Op::Full(block.height)
				},
				ChainOp::ConnectFiltered { header, height } => {
					// The chain may have been pruned or moved on since; the source's best chain
					// only changes when a test says so.
					assert_eq!(header.block_hash(), self.source.block_at(height).block_hash());
					Op::Filtered(height)
				},
				ChainOp::Disconnect { headers } => {
					let heights = headers.iter().map(|(_, h)| *h).collect();
					self.last_disconnect = headers;
					Op::Disconnect(heights)
				},
				ChainOp::Synced { tip_height } => Op::Synced(tip_height),
			}
		}

		/// Ops until (and including) the next `Synced`.
		async fn ops_until_synced(&mut self) -> Vec<Op> {
			let mut ops = Vec::new();
			loop {
				let op = self.next_op().await;
				let done = matches!(op, Op::Synced(_));
				ops.push(op);
				if done {
					return ops;
				}
			}
		}

		/// The loop's end, bounded.
		async fn end(self) -> SourceSyncEnd {
			tokio::time::timeout(WAIT, self.task).await.expect("the loop ended in time").unwrap()
		}

		async fn stop(self) -> SourceSyncEnd {
			self.stop_tx.send_replace(true);
			self.end().await
		}

		/// No op arrives for a while.
		async fn assert_quiet(&mut self) {
			let op = tokio::time::timeout(Duration::from_millis(150), self.ops_rx.recv()).await;
			assert!(op.is_err(), "no op expected, got one");
		}
	}

	fn filtered(range: std::ops::RangeInclusive<u32>) -> Vec<Op> {
		range.map(Op::Filtered).collect()
	}

	#[tokio::test]
	async fn syncs_to_the_tip_fetching_only_matched_blocks_then_follows_new_blocks() {
		let mut h = start(FakeSource::new(30, &[20]), 10, fast_tuning());

		let mut expected = filtered(11..=19);
		expected.push(Op::Full(20));
		expected.extend(filtered(21..=29));
		expected.push(Op::Synced(29));
		assert_eq!(h.ops_until_synced().await, expected);
		assert_eq!(h.source.calls("block"), 1, "only the matched block is downloaded");
		assert_eq!(
			h.permits.available_permits(),
			CBF_FULL_BLOCK_PERMITS,
			"its permit was released"
		);
		h.assert_quiet().await;

		// New blocks on the source: picked up on the next tip poll.
		h.source.mine(2, &[31], 0);
		assert_eq!(
			h.ops_until_synced().await,
			vec![Op::Filtered(30), Op::Full(31), Op::Synced(31)]
		);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn headers_are_fetched_only_a_lookahead_ahead_of_the_filters() {
		let tuning = SourceTuning { header_lookahead: 4, ..fast_tuning() };
		let mut h = start(FakeSource::new(40, &[]), 10, tuning);
		let mut expected = filtered(11..=39);
		expected.push(Op::Synced(39));
		assert_eq!(h.ops_until_synced().await, expected);
		assert!(h.source.calls("headers") >= (39 - 10) / 4, "headers came in lookahead-sized runs");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_served_filter_header_that_does_not_match_its_filter_is_rejected() {
		let source = FakeSource::new(30, &[]);
		source.set_lie(Lie::FilterHeaderAt(25));
		let mut h = start(source, 10, fast_tuning());
		let end = h.end_after_no_ops().await;
		assert!(
			matches!(&end, SourceSyncEnd::Failed(reason) if reason.contains("filter hash vs filter header")),
			"{:?}",
			end
		);
	}

	impl Harness {
		/// The loop's end, asserting no op at all was queued.
		async fn end_after_no_ops(&mut self) -> SourceSyncEnd {
			let task = &mut self.task;
			let end = tokio::time::timeout(WAIT, task).await.expect("ended in time").unwrap();
			assert!(self.ops_rx.try_recv().is_err(), "nothing was queued from unverified data");
			assert!(
				matches!(*self.sync_state_tx.borrow(), CbfSyncState::Failed(_)),
				"failed closed"
			);
			end
		}
	}

	#[tokio::test]
	async fn a_filter_header_span_that_does_not_continue_the_verified_chain_is_rejected() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;

		// The source now claims a different filter header below its spans.
		h.source.set_lie(Lie::FilterHeaderPrevious);
		h.source.mine(1, &[], 0);
		let end = tokio::time::timeout(WAIT, &mut h.task).await.expect("ended").unwrap();
		assert!(
			matches!(&end, SourceSyncEnd::Failed(reason) if reason.contains("filter header chain")),
			"{:?}",
			end
		);
		assert!(h.ops_rx.try_recv().is_err(), "block 30 was never queued");
	}

	#[tokio::test]
	async fn a_header_without_its_proof_of_work_is_rejected() {
		let source = FakeSource::new(30, &[]);
		let prev = source.block_at(29).block_hash();
		let mut bad = mine(prev, 30, BASE_TIME + 30 * 600, other_script(30), 0);
		// Walk the nonce until the hash misses the target.
		while bad.header.validate_pow(bad.header.target()).is_ok() {
			bad.header.nonce += 1;
		}
		source.push_raw(bad);
		let mut h = start(source, 10, fast_tuning());

		// Headers are taken before filters, so the sync fails closed at the bad header before
		// any block is queued; the good headers below it stay verified.
		let end = h.end_after_no_ops().await;
		assert!(
			matches!(&end, SourceSyncEnd::Failed(r) if r.contains("proof of work")),
			"{:?}",
			end
		);
	}

	#[tokio::test]
	async fn a_header_with_the_wrong_difficulty_is_rejected() {
		let source = FakeSource::new(30, &[]);
		let prev = source.block_at(29).block_hash();
		let mut bad = mine(prev, 30, BASE_TIME + 30 * 600, other_script(30), 0);
		// Mainnet's limit, far harder than regtest's: the rules require the parent's bits.
		bad.header.bits = CompactTarget::from_consensus(0x1d00_ffff);
		source.push_raw(bad);
		let mut h = start(source, 10, fast_tuning());
		let end = h.end_after_no_ops().await;
		assert!(matches!(&end, SourceSyncEnd::Failed(r) if r.contains("difficulty")), "{:?}", end);
	}

	#[tokio::test]
	async fn a_matched_block_whose_merkle_root_does_not_hold_is_rejected() {
		let source = FakeSource::new(30, &[20]);
		source.set_lie(Lie::MerkleAt(20));
		let mut h = start(source, 10, fast_tuning());
		let mut ops = Vec::new();
		for _ in 11..=19 {
			ops.push(h.next_op().await);
		}
		assert_eq!(ops, filtered(11..=19));
		let end = h.end_after_no_ops().await;
		assert!(matches!(&end, SourceSyncEnd::Failed(r) if r.contains("merkle root")), "{:?}", end);
		assert_eq!(h.permits.available_permits(), CBF_FULL_BLOCK_PERMITS, "no permit leaked");
	}

	#[tokio::test]
	async fn a_reorg_of_depth_two_disconnects_tip_first_and_connects_the_new_branch() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;
		let old_28 = h.source.block_at(28).header;
		let old_29 = h.source.block_at(29).header;

		// 28 and 29 replaced by three new blocks: more work.
		h.source.reorg(2, 3);
		let ops = h.ops_until_synced().await;
		assert_eq!(
			ops,
			vec![
				Op::Disconnect(vec![29, 28]),
				Op::Filtered(28),
				Op::Filtered(29),
				Op::Filtered(30),
				Op::Synced(30)
			]
		);
		assert_eq!(h.last_disconnect, vec![(old_29, 29), (old_28, 28)], "our abandoned headers");
		assert_eq!(lock_headers(&h.chain).tip(), Some(h.source.tip_id()));
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_branch_with_no_more_work_is_not_followed() {
		let mut h = start(FakeSource::new(30, &[]), 10, fast_tuning());
		h.ops_until_synced().await;
		let ours = lock_headers(&h.chain).tip();

		// Two blocks replaced by two: equal work, and ours came first.
		h.source.reorg(2, 2);
		h.assert_quiet().await;
		assert_eq!(lock_headers(&h.chain).tip(), ours, "the chain held did not move");
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { .. }), "not failed");
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn a_reorg_below_the_headers_held_fails_closed() {
		let tuning = SourceTuning { held_headers: 5, ..fast_tuning() };
		let mut h = start(FakeSource::new(30, &[]), 10, tuning);
		h.ops_until_synced().await;
		assert_eq!(lock_headers(&h.chain).base(), 25, "pruned to the last five");

		h.source.reorg(10, 12);
		let end = tokio::time::timeout(WAIT, &mut h.task).await.expect("ended").unwrap();
		assert!(
			matches!(&end, SourceSyncEnd::Failed(r) if r.contains("forks from this node's below height 25")),
			"{:?}",
			end
		);
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Failed(_)));
		assert!(h.ops_rx.try_recv().is_err(), "nothing disconnected on an unfollowable reorg");
	}

	#[tokio::test]
	async fn an_unavailable_source_is_retried_until_it_answers() {
		let source = FakeSource::new(30, &[]);
		source.fail_next(7);
		let mut h = start(source, 10, fast_tuning());
		let mut expected = filtered(11..=29);
		expected.push(Op::Synced(29));
		assert_eq!(h.ops_until_synced().await, expected);
		assert!(matches!(*h.sync_state_tx.borrow(), CbfSyncState::Active { .. }));

		// Down again once synced: retried, never failed, and back when it answers.
		h.source.fail_next(5);
		h.source.mine(1, &[], 0);
		assert_eq!(h.ops_until_synced().await, vec![Op::Filtered(30), Op::Synced(30)]);
		assert_eq!(h.stop().await, SourceSyncEnd::Stopped);
	}

	#[tokio::test]
	async fn node_then_p2p_falls_back_once_the_source_stays_unavailable() {
		let source = FakeSource::new(30, &[]);
		source.fail_next(u32::MAX);
		let tuning =
			SourceTuning { fallback_after: Some(Duration::from_millis(100)), ..fast_tuning() };
		let h = start(source, 10, tuning);
		assert_eq!(h.end().await, SourceSyncEnd::FallBack);
	}

	#[test]
	fn invalid_data_fails_closed_after_the_strikes_and_unavailable_never_does() {
		let now = Instant::now();
		let mut policy = SourceRetryPolicy::new(fast_tuning());
		let unavailable = StepError::Source(SourceError::unavailable("down"));
		for _ in 0..1000 {
			assert!(matches!(policy.decide(&unavailable, now), RetryDecision::Retry { .. }));
		}
		let invalid = StepError::Verify(VerifyFailure::MerkleRoot { height: 1 });
		assert!(matches!(
			policy.decide(&invalid, now),
			RetryDecision::Retry { report: RetryReport::Invalid, .. }
		));
		// An unavailable answer in between does not reset the strikes...
		policy.decide(&unavailable, now);
		assert!(matches!(policy.decide(&invalid, now), RetryDecision::Retry { .. }));
		assert_eq!(policy.decide(&invalid, now), RetryDecision::Fail);
		// ...a completed step does.
		policy.succeeded();
		assert!(matches!(policy.decide(&invalid, now), RetryDecision::Retry { .. }));
	}

	#[test]
	fn a_wait_is_reported_once_then_once_per_interval() {
		let now = Instant::now();
		let mut policy = SourceRetryPolicy::new(fast_tuning());
		let unavailable = StepError::Source(SourceError::unavailable("down"));
		let report = |d: RetryDecision| match d {
			RetryDecision::Retry { report, .. } => report,
			other => panic!("{:?}", other),
		};
		assert_eq!(report(policy.decide(&unavailable, now)), RetryReport::WaitingWarn);
		assert_eq!(report(policy.decide(&unavailable, now)), RetryReport::WaitingQuiet);
		let later = now + Duration::from_secs(61);
		assert_eq!(report(policy.decide(&unavailable, later)), RetryReport::WaitingWarn);
	}

	#[test]
	fn the_header_chain_prunes_truncates_and_sums_work() {
		let source = FakeSource::new(10, &[]);
		let headers: Vec<Header> = (0..10).map(|h| source.block_at(h).header).collect();
		let mut chain = HeaderChain::from_headers(0, headers.clone());
		assert_eq!(chain.tip().map(|t| t.height), Some(9));
		assert_eq!(chain.height_of(&headers[4].block_hash()), Some(4));
		assert!(chain.work_above(7) < chain.work_above(6));
		chain.prune_below(5);
		assert_eq!((chain.base(), chain.header(4)), (5, None));
		assert_eq!(chain.header(5), Some(headers[5]));
		chain.truncate_to(6);
		assert_eq!(chain.tip().map(|t| t.height), Some(6));
		chain.prune_below(100);
		assert_eq!(chain.tip().map(|t| t.height), Some(6), "pruning keeps the tip");
	}

	#[tokio::test]
	async fn the_fee_source_reads_the_verified_chain_and_checks_the_block() {
		let source = Arc::new(FakeSource::new(12, &[]));
		let chain = new_shared_header_chain();
		*lock_headers(&chain) =
			HeaderChain::from_headers(0, (0..12).map(|h| source.block_at(h).header).collect());
		let (_tx, rx) =
			watch::channel(CbfSyncState::Active { applied_tip: Some(11), synced_to_tip: true });
		let permits = Arc::new(Semaphore::new(1));
		let fee = SourceFeeSource::new(
			Arc::clone(&source) as Arc<dyn FilterSource>,
			Arc::clone(&chain),
			rx,
			Arc::clone(&permits),
		);
		assert_eq!(fee.tip_height().await, Ok(11));
		assert_eq!(fee.block_hash_at(3).await, Ok(Some(source.block_at(3).block_hash())));
		assert!(fee.can_fetch());

		let hash = source.block_at(11).block_hash();
		let fetch = fee.request_block(hash).unwrap();
		assert!(
			matches!(fee.request_block(hash), Err(SampleFailure::NoPermit)),
			"one permit, held by the first fetch"
		);
		let (height, block) = tokio::time::timeout(WAIT, fetch).await.unwrap().unwrap();
		assert_eq!((height, block.block_hash()), (11, hash));
		assert_eq!(permits.available_permits(), 1);

		source.set_lie(Lie::MerkleAt(11));
		let fetch = fee.request_block(hash).unwrap();
		assert_eq!(tokio::time::timeout(WAIT, fetch).await.unwrap(), Err(SampleFailure::Mismatch));
		assert!(matches!(
			fee.request_block(BlockHash::all_zeros()),
			Err(SampleFailure::FetchFailed(_))
		));
	}
}
