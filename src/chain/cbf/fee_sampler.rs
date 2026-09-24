// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Keeps the [`BlockFeeCache`] filled with the coinbase fee rates of the recent blocks.
//!
//! The applicator records the rate of every block it downloads, but a filter node downloads
//! only the blocks that match its scripts — on mainnet, almost none. The rest of the fee
//! window has to be fetched on purpose, and on mainnet that is a 1.5–2 MB block per sample
//! over the node's single peer.
//!
//! Kyoto (bip157 0.6.3) serves block requests one at a time, cannot cancel one, and while
//! the block it wants has not arrived it sends the peer the same `getdata` again every five
//! seconds ([`KYOTO_BLOCK_REREQUEST_INTERVAL`]). A peer answers every one of them, so a block
//! that takes 12 s to arrive is sent two more times, and the next block queues behind those
//! copies, takes longer, and provokes more of them. Probed against mainnet: the first block
//! of a pass arrived in ~12 s, the second in ~100 s behind ~20 copies of the first, the rest
//! never within their bound — which is why fetching the window serially under a 10 s bound
//! sampled nothing, pass after pass, and saturated the node's only peer link while it tried.
//!
//! So sampling is its own background task, off the FEE slot's path:
//!
//! * one block at a time, newest first, at most [`MAX_FEE_SAMPLE_FETCHES_PER_PASS`] per pass;
//! * after a block that took longer than the re-request interval, nothing more until the
//!   copies it provoked have drained (see [`cooldown_after`]);
//! * under a realistic per-block bound ([`CBF_FEE_SAMPLE_TIMEOUT`]), and a fetch that
//!   outlives it is **kept** and awaited again next pass rather than requested again;
//! * only while the engine is synced, so a sample never sits in kyoto's queue ahead of a
//!   matched block the applicator is waiting for;
//! * only under a free full-block permit, never waiting for one.
//!
//! The cache persists across passes, so once warm a pass fetches just the block(s) mined
//! since the last one. The FEE adapter only reads the cache (see [`window_samples`]), which
//! makes a fee refresh a handful of local header lookups instead of a block download.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::{Block, BlockHash, FeeRate};

use crate::chain::cbf::fee::FEE_WINDOW_BLOCKS;
use crate::chain::cbf::fee::{coinbase_fee_rate, record_block_fee, BlockFeeCache};
use crate::logger::{log_debug, log_info, LdkLogger, Logger};

use async_trait::async_trait;

/// How many block samples the window must hold before the FEE adapter answers. One block is
/// a single miner's template; three give the percentiles something to choose between, and
/// on a fresh start kyoto holds the eight headers from its resume checkpoint to the tip, so
/// three are reachable right away.
pub(crate) const MIN_FEE_SAMPLES: usize = 3;

/// How many blocks one sampling pass fetches at most. Enough to warm a fresh window in two
/// or three passes, few enough that a pass holds kyoto's block queue for well under a minute
/// on a healthy peer.
pub(crate) const MAX_FEE_SAMPLE_FETCHES_PER_PASS: usize = 4;

/// Bound on one sample's download. Measured on mainnet through one peer, a block takes 7–15
/// s end to end; a small device on a slow link takes longer. Running out does not abandon the
/// request — it is kept for the next pass — so this bounds only how long one pass waits.
pub(crate) const CBF_FEE_SAMPLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Kyoto's `SPAM_LIMIT`: how often it asks the peer again for a block that has not arrived.
pub(crate) const KYOTO_BLOCK_REREQUEST_INTERVAL: Duration = Duration::from_secs(5);

/// Ceiling on the pause after a slow sample, so one pathological block cannot stop sampling
/// for longer than about a block interval.
pub(crate) const MAX_FEE_SAMPLE_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// How long to leave the peer link alone after a sample that took `took` to arrive.
///
/// While it waited, kyoto re-requested it every `rerequest` interval, and the peer queued a
/// full copy for each: about `took / rerequest` copies still to drain, each taking one clean
/// transfer — `one_transfer`, the fastest sample seen so far (the slow one's own time is
/// mostly queueing, and would overstate it many times over). A block that arrived within
/// one interval provoked no copy, and the next may follow at once.
pub(crate) fn cooldown_after(
	took: Duration, rerequest: Duration, one_transfer: Duration,
) -> Duration {
	if took < rerequest || rerequest.is_zero() {
		return Duration::ZERO;
	}
	let copies = (took.as_nanos() / rerequest.as_nanos()) as u32;
	one_transfer.min(took).saturating_mul(copies).min(MAX_FEE_SAMPLE_COOLDOWN)
}

/// How often the sampler looks at the tip. A pass with nothing missing is a few local header
/// lookups, so this only sets how soon a new block is sampled.
pub(crate) const CBF_FEE_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);

/// Why one step of a pass came back without a sample.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum SampleFailure {
	/// The node is not running, or was rebuilt under a pending fetch.
	NodeGone,
	/// A header or tip lookup did not answer in time.
	LookupTimedOut,
	/// No free full-block permit: the applicator holds them all.
	NoPermit,
	/// The block did not arrive within [`CBF_FEE_SAMPLE_TIMEOUT`]; the fetch is kept.
	FetchTimedOut,
	/// Kyoto refused the fetch (for instance, the hash is no longer on the best chain).
	FetchFailed(String),
	/// The block that came back is not the one asked for, or not at the height asked for.
	Mismatch,
}

impl SampleFailure {
	fn label(&self) -> &'static str {
		match self {
			Self::NodeGone => "node_gone",
			Self::LookupTimedOut => "lookup_timeout",
			Self::NoPermit => "no_permit",
			Self::FetchTimedOut => "fetch_timeout",
			Self::FetchFailed(_) => "fetch_failed",
			Self::Mismatch => "mismatch",
		}
	}
}

impl fmt::Display for SampleFailure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::FetchFailed(reason) => write!(f, "fetch_failed ({})", reason),
			other => f.write_str(other.label()),
		}
	}
}

/// A block download in flight: the block and the height kyoto indexed it at.
pub(crate) type BlockFetch =
	Pin<Box<dyn Future<Output = Result<(u32, Block), SampleFailure>> + Send>>;

/// What the sampler, and the FEE adapter, read the chain through. The kyoto requester in
/// production; a script in the tests.
#[async_trait]
pub(crate) trait FeeBlockSource: Send + Sync {
	/// Height of the best header kyoto holds.
	async fn tip_height(&self) -> Result<u32, SampleFailure>;
	/// Hash of the best-chain block at `height`, or `None` for a height kyoto holds no header
	/// for — below the checkpoint it resumed from, or above its tip.
	async fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SampleFailure>;
	/// Whether a sample may be requested now: the engine is synced, so nothing the applicator
	/// needs is queued in kyoto.
	fn can_fetch(&self) -> bool;
	/// Starts downloading `hash`. The returned future owns whatever bounds the block in
	/// memory, and may be dropped and never polled again.
	fn request_block(&self, hash: BlockHash) -> Result<BlockFetch, SampleFailure>;
}

/// The best-chain hashes of the fee window ending at the tip, by height, and the tip. Heights
/// kyoto holds no header for are absent.
pub(crate) async fn canonical_window<S: FeeBlockSource + ?Sized>(
	source: &S,
) -> Result<(u32, BTreeMap<u32, BlockHash>), SampleFailure> {
	let tip = source.tip_height().await?;
	let lo = tip.saturating_sub(FEE_WINDOW_BLOCKS - 1);
	let mut window = BTreeMap::new();
	for height in lo..=tip {
		if let Some(hash) = source.block_hash_at(height).await? {
			window.insert(height, hash);
		}
	}
	Ok((tip, window))
}

/// The cached rates of the blocks in `canonical`, oldest first: a cached entry counts only
/// while its block is still the one on the best chain at that height.
pub(crate) fn window_samples(
	cached: &BTreeMap<u32, (BlockHash, FeeRate)>, canonical: &BTreeMap<u32, BlockHash>,
) -> Vec<FeeRate> {
	canonical
		.iter()
		.filter_map(|(height, hash)| {
			cached.get(height).filter(|(cached_hash, _)| cached_hash == hash).map(|(_, r)| *r)
		})
		.collect()
}

/// What one pass did, for its one-line summary.
#[derive(Debug, Default)]
pub(crate) struct SamplePass {
	pub(crate) window: Option<(u32, u32)>,
	/// Window heights kyoto holds no header for.
	pub(crate) no_header: u32,
	/// Samples in the window once the pass finished.
	pub(crate) samples: usize,
	/// Blocks downloaded and sampled this pass.
	pub(crate) fetched: usize,
	/// Of those, blocks whose coinbase claimed no fee at all.
	pub(crate) zero_fee: usize,
	pub(crate) failures: BTreeMap<&'static str, usize>,
	/// A pass stopped early because the engine fell behind the tip.
	pub(crate) deferred: bool,
	/// New requests held back while a slow sample's copies drain: how much longer.
	pub(crate) cooling_down: Option<Duration>,
	pub(crate) elapsed: Duration,
}

impl SamplePass {
	fn fail(&mut self, failure: &SampleFailure) {
		*self.failures.entry(failure.label()).or_default() += 1;
	}

	/// Whether the pass is worth an INFO line: it fetched, or something failed.
	pub(crate) fn eventful(&self) -> bool {
		self.fetched > 0 || !self.failures.is_empty()
	}
}

impl fmt::Display for SamplePass {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.window {
			Some((lo, hi)) => write!(f, "window {}..={}", lo, hi)?,
			None => f.write_str("no window")?,
		}
		write!(
			f,
			": {} sample(s) (need {}), fetched {} ({} zero-fee) in {:.1}s",
			self.samples,
			MIN_FEE_SAMPLES,
			self.fetched,
			self.zero_fee,
			self.elapsed.as_secs_f32()
		)?;
		if self.no_header > 0 {
			write!(f, ", {} below kyoto's checkpoint", self.no_header)?;
		}
		if !self.failures.is_empty() {
			f.write_str(", failed:")?;
			for (label, count) in &self.failures {
				write!(f, " {}={}", label, count)?;
			}
		}
		if self.deferred {
			f.write_str(", deferred to the applicator")?;
		}
		if let Some(left) = self.cooling_down {
			write!(f, ", cooling down {:.0}s", left.as_secs_f32())?;
		}
		Ok(())
	}
}

/// A download kept across passes because it outlived [`CBF_FEE_SAMPLE_TIMEOUT`].
struct PendingSample {
	height: u32,
	hash: BlockHash,
	fetch: BlockFetch,
	requested_at: Instant,
}

/// Whether a pass may go on to the next block after one sample.
enum Next {
	Continue,
	Stop,
}

/// Fills the [`BlockFeeCache`] incrementally. Owned by one task; see the module docs.
pub(crate) struct FeeSampler<S> {
	source: S,
	cache: BlockFeeCache,
	pending: Option<PendingSample>,
	/// No new request before this: the copies a slow sample provoked are still draining.
	cooldown_until: Option<Instant>,
	rerequest_interval: Duration,
	/// The fastest sample so far: the best estimate of one clean block transfer.
	fastest_fetch: Option<Duration>,
	fetch_timeout: Duration,
	max_fetches: usize,
	logger: Arc<Logger>,
}

impl<S: FeeBlockSource> FeeSampler<S> {
	pub(crate) fn new(source: S, cache: BlockFeeCache, logger: Arc<Logger>) -> Self {
		Self {
			source,
			cache,
			pending: None,
			cooldown_until: None,
			rerequest_interval: KYOTO_BLOCK_REREQUEST_INTERVAL,
			fastest_fetch: None,
			fetch_timeout: CBF_FEE_SAMPLE_TIMEOUT,
			max_fetches: MAX_FEE_SAMPLE_FETCHES_PER_PASS,
			logger,
		}
	}

	#[cfg(test)]
	fn with_limits(
		mut self, fetch_timeout: Duration, max_fetches: usize, rerequest_interval: Duration,
	) -> Self {
		self.fetch_timeout = fetch_timeout;
		self.max_fetches = max_fetches;
		self.rerequest_interval = rerequest_interval;
		self
	}

	/// Whether a download is carried over from an earlier pass.
	#[cfg(test)]
	fn has_pending(&self) -> bool {
		self.pending.is_some()
	}

	/// One pass: reconcile the cache with the best chain, then sample what the window lacks,
	/// newest first, within the per-pass bounds.
	pub(crate) async fn pass(&mut self) -> SamplePass {
		let started = Instant::now();
		let mut report = SamplePass::default();
		self.sample(&mut report).await;
		report.elapsed = started.elapsed();
		report
	}

	/// [`Self::pass`], logged: INFO when it fetched or something failed, DEBUG otherwise.
	pub(crate) async fn pass_logged(&mut self) -> SamplePass {
		let report = self.pass().await;
		if report.eventful() {
			log_info!(self.logger, "CBF fee sampler: {}", report);
		} else {
			log_debug!(self.logger, "CBF fee sampler: {}", report);
		}
		report
	}

	async fn sample(&mut self, report: &mut SamplePass) {
		let (tip, canonical) = match canonical_window(&self.source).await {
			Ok(window) => window,
			Err(failure) => {
				report.fail(&failure);
				return;
			},
		};
		let lo = tip.saturating_sub(FEE_WINDOW_BLOCKS - 1);
		report.window = Some((lo, tip));
		report.no_header = (tip - lo + 1) - canonical.len() as u32;

		// Drop what fell out of the window or was reorged out; keep anything the applicator
		// recorded above the tip this pass saw.
		{
			let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
			cache.retain(|height, (hash, _)| {
				*height > tip || canonical.get(height).is_some_and(|c| c == hash)
			});
		}

		let missing: Vec<(u32, BlockHash)> = {
			let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
			canonical
				.iter()
				.rev()
				.filter(|(height, _)| !cache.contains_key(height))
				.map(|(height, hash)| (*height, *hash))
				.collect()
		};

		let mut attempts = 0;
		if let Some(pending) = self.pending.take() {
			// Still wanted? A block that left the window or the best chain is not; its
			// download finishes inside kyoto regardless, so it is simply let go.
			if missing.contains(&(pending.height, pending.hash)) {
				attempts += 1;
				if let Next::Stop = self.await_sample(pending, report).await {
					self.finish(report, &canonical);
					return;
				}
			}
		}

		if let Some(until) = self.cooldown_until {
			let now = Instant::now();
			if now < until {
				report.cooling_down = Some(until - now);
				self.finish(report, &canonical);
				return;
			}
			self.cooldown_until = None;
		}

		for (height, hash) in missing {
			if attempts >= self.max_fetches {
				break;
			}
			if self.cache.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&height) {
				continue;
			}
			if !self.source.can_fetch() {
				report.deferred = true;
				break;
			}
			attempts += 1;
			let fetch = match self.source.request_block(hash) {
				Ok(fetch) => fetch,
				Err(failure) => {
					report.fail(&failure);
					break;
				},
			};
			let pending = PendingSample { height, hash, fetch, requested_at: Instant::now() };
			if let Next::Stop = self.await_sample(pending, report).await {
				break;
			}
		}
		self.finish(report, &canonical);
	}

	/// Awaits one download under the per-block bound and records it. The pass stops when the
	/// block did not arrive (it is kept for the next pass), when it arrived slowly enough to
	/// have provoked copies (see [`cooldown_after`]), or when the node is gone.
	async fn await_sample(&mut self, mut pending: PendingSample, report: &mut SamplePass) -> Next {
		let outcome = match tokio::time::timeout(self.fetch_timeout, &mut pending.fetch).await {
			Ok(outcome) => outcome,
			Err(_elapsed) => {
				report.fail(&SampleFailure::FetchTimedOut);
				self.pending = Some(pending);
				return Next::Stop;
			},
		};
		let took = pending.requested_at.elapsed();
		let fastest = self.fastest_fetch.map_or(took, |fastest| fastest.min(took));
		self.fastest_fetch = Some(fastest);
		// Never seen a clean transfer: assume one per re-request interval.
		let one_transfer =
			if fastest < self.rerequest_interval { fastest } else { self.rerequest_interval };
		let cooldown = cooldown_after(took, self.rerequest_interval, one_transfer);
		let next = if cooldown.is_zero() {
			Next::Continue
		} else {
			self.cooldown_until = Some(Instant::now() + cooldown);
			Next::Stop
		};
		match outcome {
			Ok((height, block))
				if height == pending.height && block.block_hash() == pending.hash =>
			{
				let rate = coinbase_fee_rate(&block, height);
				if rate == FeeRate::ZERO {
					report.zero_fee += 1;
				}
				record_block_fee(&self.cache, height, pending.hash, rate);
				report.fetched += 1;
				next
			},
			Ok(_) => {
				report.fail(&SampleFailure::Mismatch);
				next
			},
			Err(SampleFailure::NodeGone) => {
				report.fail(&SampleFailure::NodeGone);
				Next::Stop
			},
			Err(failure) => {
				report.fail(&failure);
				next
			},
		}
	}

	fn finish(&self, report: &mut SamplePass, canonical: &BTreeMap<u32, BlockHash>) {
		let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
		report.samples = window_samples(&cache, canonical).len();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::collections::HashMap;
	use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
	use std::sync::Mutex;

	use bitcoin::block::{Header, Version};
	use bitcoin::hashes::Hash;
	use bitcoin::{
		absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
		Witness,
	};

	use crate::chain::cbf::fee::{block_subsidy, new_block_fee_cache};
	use crate::logger::Logger;

	/// A block at `height` whose coinbase claims `fee` on top of the subsidy; `nonce` keeps
	/// two branches' blocks at one height apart.
	fn block(height: u32, fee: u64, nonce: u32) -> Block {
		let coinbase = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::from_bytes(height.to_le_bytes().to_vec()),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: block_subsidy(height) + Amount::from_sat(fee),
				script_pubkey: ScriptBuf::from_bytes(vec![0; 300]),
			}],
		};
		let header = Header {
			version: Version::TWO,
			prev_blockhash: BlockHash::all_zeros(),
			merkle_root: bitcoin::TxMerkleNode::all_zeros(),
			time: height,
			bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
			nonce,
		};
		Block { header, txdata: vec![coinbase] }
	}

	#[derive(Clone, Copy, PartialEq)]
	enum Delivery {
		/// Arrives at once.
		Now,
		/// Never arrives until released.
		Held,
	}

	/// A scripted chain: headers from `floor` to `tip`, blocks delivered per `delivery`.
	struct Script {
		tip: Mutex<u32>,
		floor: u32,
		blocks: Mutex<HashMap<u32, Block>>,
		delivery: Mutex<HashMap<BlockHash, Delivery>>,
		released: tokio::sync::Notify,
		synced: AtomicBool,
		requests: AtomicUsize,
	}

	#[derive(Clone)]
	struct Source(Arc<Script>);

	impl Source {
		fn new(floor: u32, tip: u32) -> Self {
			let blocks = (floor..=tip).map(|h| (h, block(h, 10_000 * h as u64, 0))).collect();
			Source(Arc::new(Script {
				tip: Mutex::new(tip),
				floor,
				blocks: Mutex::new(blocks),
				delivery: Mutex::new(HashMap::new()),
				released: tokio::sync::Notify::new(),
				synced: AtomicBool::new(true),
				requests: AtomicUsize::new(0),
			}))
		}
		fn hash(&self, height: u32) -> BlockHash {
			self.0.blocks.lock().unwrap()[&height].block_hash()
		}
		fn mine(&self, fee: u64) {
			let mut tip = self.0.tip.lock().unwrap();
			*tip += 1;
			self.0.blocks.lock().unwrap().insert(*tip, block(*tip, fee, 0));
		}
		fn hold(&self, height: u32) {
			let hash = self.hash(height);
			self.0.delivery.lock().unwrap().insert(hash, Delivery::Held);
		}
		fn release(&self, height: u32) {
			let hash = self.hash(height);
			self.0.delivery.lock().unwrap().insert(hash, Delivery::Now);
			self.0.released.notify_waiters();
		}
		fn requests(&self) -> usize {
			self.0.requests.load(Ordering::SeqCst)
		}
	}

	#[async_trait]
	impl FeeBlockSource for Source {
		async fn tip_height(&self) -> Result<u32, SampleFailure> {
			Ok(*self.0.tip.lock().unwrap())
		}
		async fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SampleFailure> {
			if height < self.0.floor {
				return Ok(None);
			}
			Ok(self.0.blocks.lock().unwrap().get(&height).map(|b| b.block_hash()))
		}
		fn can_fetch(&self) -> bool {
			self.0.synced.load(Ordering::SeqCst)
		}
		fn request_block(&self, hash: BlockHash) -> Result<BlockFetch, SampleFailure> {
			self.0.requests.fetch_add(1, Ordering::SeqCst);
			let script = Arc::clone(&self.0);
			Ok(Box::pin(async move {
				loop {
					let released = script.released.notified();
					let held =
						script.delivery.lock().unwrap().get(&hash).copied() == Some(Delivery::Held);
					if !held {
						let blocks = script.blocks.lock().unwrap();
						let found = blocks.iter().find(|(_, b)| b.block_hash() == hash);
						return found
							.map(|(h, b)| (*h, b.clone()))
							.ok_or(SampleFailure::FetchFailed("unknown hash".into()));
					}
					released.await;
				}
			}))
		}
	}

	fn sampler(source: &Source) -> (FeeSampler<Source>, BlockFeeCache) {
		let cache = new_block_fee_cache();
		let logger = Arc::new(Logger::new_log_facade());
		let sampler = FeeSampler::new(source.clone(), Arc::clone(&cache), logger).with_limits(
			Duration::from_millis(200),
			4,
			Duration::from_secs(3600),
		);
		(sampler, cache)
	}

	fn samples(source: &Source, cache: &BlockFeeCache) -> Vec<FeeRate> {
		let rt_tip = *source.0.tip.lock().unwrap();
		let lo = rt_tip.saturating_sub(FEE_WINDOW_BLOCKS - 1).max(source.0.floor);
		let canonical = (lo..=rt_tip).map(|h| (h, source.hash(h))).collect();
		window_samples(&cache.lock().unwrap(), &canonical)
	}

	#[tokio::test]
	async fn a_cold_window_warms_up_newest_first_a_few_blocks_per_pass() {
		// Resumed eight blocks below the tip, like a fresh start at the wallet's tip.
		let source = Source::new(993, 1_000);
		let (mut sampler, cache) = sampler(&source);

		let first = sampler.pass().await;
		assert_eq!(first.fetched, 4, "one pass fetches at most its per-pass bound");
		assert_eq!(first.no_header, FEE_WINDOW_BLOCKS - 8, "heights below the checkpoint");
		assert!(first.failures.is_empty(), "{}", first);
		let sampled: Vec<u32> = cache.lock().unwrap().keys().copied().collect();
		assert_eq!(sampled, vec![997, 998, 999, 1_000], "the newest blocks first");
		assert!(first.samples >= MIN_FEE_SAMPLES, "enough to answer after one pass");

		let second = sampler.pass().await;
		assert_eq!(second.fetched, 4);
		assert_eq!(second.samples, 8, "every block kyoto holds a header for");

		// Warm: a pass with nothing new fetches nothing.
		let idle = sampler.pass().await;
		assert_eq!(idle.fetched, 0);
		assert!(!idle.eventful());
		assert_eq!(source.requests(), 8);

		// One new block: one fetch.
		source.mine(77_000);
		let next = sampler.pass().await;
		assert_eq!(next.fetched, 1);
		assert_eq!(next.samples, 9);
		assert_eq!(samples(&source, &cache).len(), 9);
	}

	#[tokio::test]
	async fn a_slow_block_is_kept_and_awaited_again_never_requested_twice() {
		let source = Source::new(995, 1_000);
		source.hold(1_000);
		let (mut sampler, cache) = sampler(&source);

		// The newest block does not arrive in time: the pass ends there, with the fetch kept,
		// rather than queueing more requests behind it in kyoto.
		let first = sampler.pass().await;
		assert_eq!(first.fetched, 0);
		assert_eq!(first.failures.get("fetch_timeout"), Some(&1), "{}", first);
		assert!(sampler.has_pending());
		assert_eq!(source.requests(), 1);

		// It arrives: the next pass takes it from the kept fetch, not a new request.
		source.release(1_000);
		let second = sampler.pass().await;
		assert!(cache.lock().unwrap().contains_key(&1_000));
		assert!(!sampler.has_pending());
		assert_eq!(second.fetched, 4, "the kept block and three more");
		assert_eq!(source.requests(), 4, "the kept block was never asked for again");
	}

	#[tokio::test]
	async fn nothing_is_requested_while_the_applicator_is_catching_up() {
		let source = Source::new(995, 1_000);
		source.0.synced.store(false, Ordering::SeqCst);
		let (mut sampler, _cache) = sampler(&source);
		let pass = sampler.pass().await;
		assert!(pass.deferred);
		assert_eq!(source.requests(), 0);
	}

	#[tokio::test]
	async fn a_reorged_block_is_dropped_and_its_replacement_sampled() {
		let source = Source::new(995, 1_000);
		let (mut sampler, cache) = sampler(&source);
		sampler.pass().await;
		sampler.pass().await;
		let before = cache.lock().unwrap()[&1_000];

		// Replace the tip with a sibling.
		source.0.blocks.lock().unwrap().insert(1_000, block(1_000, 1, 9));
		let pass = sampler.pass().await;
		assert_eq!(pass.fetched, 1);
		let after = cache.lock().unwrap()[&1_000];
		assert_ne!(before.0, after.0, "the sibling replaced the reorged-out block");
		assert_eq!(after.0, source.hash(1_000));
	}

	#[tokio::test]
	async fn a_slow_sample_pauses_new_requests_until_its_copies_drain() {
		let source = Source::new(993, 1_000);
		source.hold(1_000);
		let cache = new_block_fee_cache();
		let logger = Arc::new(Logger::new_log_facade());
		// Kyoto re-requests every 20 ms here; the tip block takes ~60 ms.
		let mut sampler = FeeSampler::new(source.clone(), Arc::clone(&cache), logger).with_limits(
			Duration::from_secs(5),
			4,
			Duration::from_millis(20),
		);
		let releaser = source.clone();
		tokio::spawn(async move {
			tokio::time::sleep(Duration::from_millis(60)).await;
			releaser.release(1_000);
		});

		let slow = sampler.pass().await;
		assert_eq!(slow.fetched, 1, "the pass stops after the slow block: {}", slow);
		assert_eq!(source.requests(), 1);

		let paused = sampler.pass().await;
		assert!(paused.cooling_down.is_some(), "{}", paused);
		assert_eq!(paused.fetched, 0);
		assert_eq!(source.requests(), 1, "nothing asked while the copies drain");

		// ~60 ms at 20 ms per copy: ~3 copies of ~60 ms each, well under a second.
		tokio::time::sleep(Duration::from_millis(400)).await;
		let resumed = sampler.pass().await;
		assert!(resumed.cooling_down.is_none());
		assert_eq!(resumed.fetched, 4, "fast blocks provoke no copies and follow at once");
	}

	#[test]
	fn the_cooldown_scales_with_the_copies_a_slow_block_provoked() {
		let five = KYOTO_BLOCK_REREQUEST_INTERVAL;
		let secs = Duration::from_secs;
		// Arrived within one interval: no copy was asked for.
		assert_eq!(cooldown_after(secs(4), five, secs(4)), Duration::ZERO);
		// 12 s: two copies queued behind it, each one clean transfer.
		assert_eq!(cooldown_after(secs(12), five, secs(3)), secs(6));
		// The probe's stuck block: ~125 s, 25 copies of a ~2.7 s transfer.
		assert_eq!(
			cooldown_after(secs(125), five, Duration::from_millis(2_700)),
			secs(67) + Duration::from_millis(500)
		);
		// Never seen a clean transfer: one per interval.
		assert_eq!(cooldown_after(secs(15), five, five), secs(15));
		assert_eq!(cooldown_after(secs(3_600), five, five), MAX_FEE_SAMPLE_COOLDOWN);
	}

	#[test]
	fn window_samples_count_only_canonical_blocks() {
		let (a, b) = (BlockHash::from_byte_array([1; 32]), BlockHash::from_byte_array([2; 32]));
		let rate = FeeRate::from_sat_per_kwu(500);
		let cached: BTreeMap<_, _> = [(10, (a, rate)), (11, (b, rate))].into_iter().collect();
		let canonical: BTreeMap<_, _> = [(10, a), (11, a), (12, a)].into_iter().collect();
		assert_eq!(window_samples(&cached, &canonical), vec![rate]);
	}

	#[test]
	fn the_summary_is_one_line_with_reason_counts() {
		let mut pass =
			SamplePass { window: Some((1, 14)), samples: 2, fetched: 1, ..Default::default() };
		pass.fail(&SampleFailure::FetchTimedOut);
		pass.fail(&SampleFailure::FetchTimedOut);
		pass.fail(&SampleFailure::NoPermit);
		let line = pass.to_string();
		assert!(!line.contains('\n'));
		assert!(line.contains("fetch_timeout=2"), "{}", line);
		assert!(line.contains("no_permit=1"), "{}", line);
	}
}
