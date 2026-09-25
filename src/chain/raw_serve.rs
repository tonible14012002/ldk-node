// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Serving raw BIP157/158 data to other nodes from this node's raw source.
//!
//! [`RawChainServer`] is what [`ChainLayer`]'s `serve_tip`, `serve_headers`,
//! `serve_filter_headers`, `serve_filters` and `serve_block_chunk` delegate
//! to. It exists only on a node configured with a raw [`FilterSource`], and
//! is independent of the node's own sync engine: a Pro node following the
//! chain over Electrum may still serve raw data from a bitcoind.
//!
//! Nothing served here needs trusting — the asking node verifies proof of
//! work, the filter-header chain and merkle roots — so, unlike the indexed
//! serves, there is no "only a node with its own chain source" rule to apply.
//!
//! # Limits and caches
//!
//! Requests over the `MAX_*_PER_REQUEST` limits are refused before the source
//! is asked where the span is known up front (headers), and the answer is
//! checked against them afterwards everywhere. Blocks are cached so the
//! consecutive chunk requests for one block cost one fetch; small filter and
//! filter-header spans — the ones clients following the tip ask, and ask
//! alike — are cached too. Every cache is bounded in entries and bytes.
//!
//! # Bounding the work
//!
//! A raw serve is relayed as one peer message, and every one costs this node
//! RPC work, so each is bounded four ways:
//!
//! * **Reply size.** A filters reply carries at most
//!   [`FILTER_BYTES_PER_REPLY`] of raw filter bytes (hex doubles it, well
//!   under the ~2 MiB a relayed message may carry), a filter-headers reply at
//!   most [`FILTER_HEADERS_PER_REPLY`] headers, a headers reply at most
//!   [`HEADER_BYTES_PER_REPLY`]. A reply cut short is a *prefix* of the span
//!   asked — never empty — and the asking node continues from where it ended.
//! * **Concurrency.** At most [`RAW_SERVE_CONCURRENCY`] serves ask the source
//!   at once; the rest wait their turn. Cache hits do not wait.
//! * **Deadlines.** Each serve runs under a deadline a little under the host's
//!   serve timeout for its route, so work nobody waits for any more is
//!   dropped rather than finished.
//! * **Single flight.** Concurrent chunk requests for one uncached block share
//!   one fetch.
//!
//! [`ChainLayer`]: crate::chain::ChainLayer

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::consensus::encode::serialize;
use bitcoin::BlockHash;

use crate::chain::cbf::source::{FilterHeaders, FilterSource, IndexedFilter, SourceError};
use crate::chain::provider::{
	WireBlockChunk, WireBlockRequest, WireChainTip, WireFilterHeaders, WireFilterHeadersRequest,
	WireFilters, WireFiltersRequest, WireHeaders, WireHeadersRequest, MAX_FILTERS_PER_REQUEST,
	MAX_FILTER_HEADERS_PER_REQUEST, MAX_HEADERS_PER_REQUEST,
};
use crate::chain::wire_convert::{
	block_chunk_count, block_chunk_to_wire, block_hash_from_wire, chain_tip_to_wire, check_version,
	filter_headers_to_wire, filters_to_wire, headers_to_wire,
};
use crate::logger::{log_debug, log_info, log_trace, log_warn, LdkLogger, Logger};
use crate::Error;

use tokio::sync::{Semaphore, SemaphorePermit};

/// Blocks kept for chunked serving, by count…
pub(crate) const BLOCK_CACHE_ENTRIES: usize = 8;
/// …and by bytes: eight typical mainnet blocks, not eight worst-case ones.
pub(crate) const BLOCK_CACHE_BYTES: usize = 24 * 1024 * 1024;
/// Filter and filter-header spans kept, each cache.
pub(crate) const NEAR_TIP_CACHE_ENTRIES: usize = 256;
/// Only spans this short are cached: a client following the tip asks for the
/// last few blocks, and every such client asks for the same ones. A catch-up
/// span is one client's alone and would only evict the shared ones.
pub(crate) const NEAR_TIP_SPAN: usize = 16;
/// Bytes of filters kept.
pub(crate) const FILTER_CACHE_BYTES: usize = 8 * 1024 * 1024;
/// Bytes of filter headers kept.
pub(crate) const FILTER_HEADER_CACHE_BYTES: usize = 1024 * 1024;

/// Raw filter bytes one filters reply carries at most. Hex doubles them and the
/// JSON around them is small, so a reply stays under ~1.4 MiB — inside the
/// ~2 MiB a relayed message may carry even when a mainnet span of
/// [`MAX_FILTERS_PER_REQUEST`] filters runs to several MiB.
pub(crate) const FILTER_BYTES_PER_REPLY: usize = 700 * 1024;

/// Filter headers one reply carries at most. Answering a span costs one
/// `getblockfilter` read per block, whole filter included, so the span
/// [`MAX_FILTER_HEADERS_PER_REQUEST`] allows is served a prefix at a time.
pub(crate) const FILTER_HEADERS_PER_REPLY: u32 = 200;

/// Raw header bytes one headers reply carries at most — far above what
/// [`MAX_HEADERS_PER_REQUEST`] headers take, kept as a backstop.
pub(crate) const HEADER_BYTES_PER_REPLY: usize = FILTER_BYTES_PER_REPLY;

/// Serves asking the source at the same time.
pub(crate) const RAW_SERVE_CONCURRENCY: usize = 3;

/// Deadline of a tip, headers or filter-headers serve: under the host's 35 s.
pub(crate) const RAW_SERVE_SMALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Deadline of a filters serve: under the host's 45 s.
pub(crate) const RAW_SERVE_FILTERS_TIMEOUT: Duration = Duration::from_secs(40);
/// Deadline of a block-chunk serve: under the host's 54 s.
pub(crate) const RAW_SERVE_BLOCK_TIMEOUT: Duration = Duration::from_secs(50);

/// The bounds a [`RawChainServer`] applies; [`RawServeLimits::default`] in
/// production, shortened in the tests.
#[derive(Debug, Clone)]
pub(crate) struct RawServeLimits {
	pub(crate) concurrency: usize,
	pub(crate) small_timeout: Duration,
	pub(crate) filters_timeout: Duration,
	pub(crate) block_timeout: Duration,
}

impl Default for RawServeLimits {
	fn default() -> Self {
		Self {
			concurrency: RAW_SERVE_CONCURRENCY,
			small_timeout: RAW_SERVE_SMALL_TIMEOUT,
			filters_timeout: RAW_SERVE_FILTERS_TIMEOUT,
			block_timeout: RAW_SERVE_BLOCK_TIMEOUT,
		}
	}
}

/// How many of `filters`, from the first, fit in [`FILTER_BYTES_PER_REPLY`] —
/// at least one, so a reply always makes progress.
pub(crate) fn filters_prefix_len(filters: &[IndexedFilter]) -> usize {
	let mut bytes = 0usize;
	let mut fit = 0usize;
	for filter in filters {
		bytes = bytes.saturating_add(filter.filter.content.len());
		if fit > 0 && bytes > FILTER_BYTES_PER_REPLY {
			break;
		}
		fit += 1;
	}
	fit
}

/// Takes an in-flight block fetch's slot out of the map when the fetch ends,
/// however it ends — a serve dropped at its deadline included — unless a later
/// fetch has taken the slot since.
struct FlightSlot<'a> {
	flights: &'a Mutex<HashMap<BlockHash, Arc<tokio::sync::Mutex<()>>>>,
	hash: BlockHash,
	gate: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for FlightSlot<'_> {
	fn drop(&mut self) {
		let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
		if flights.get(&self.hash).is_some_and(|gate| Arc::ptr_eq(gate, &self.gate)) {
			flights.remove(&self.hash);
		}
	}
}

/// A small least-recently-used cache bounded by entry count and by bytes.
/// Linear scans: it holds a few hundred entries at most.
struct BoundedLru<K, V> {
	entries: VecDeque<(K, V, usize)>,
	max_entries: usize,
	max_bytes: usize,
	bytes: usize,
}

impl<K: PartialEq, V: Clone> BoundedLru<K, V> {
	fn new(max_entries: usize, max_bytes: usize) -> Self {
		Self { entries: VecDeque::new(), max_entries, max_bytes, bytes: 0 }
	}

	fn get(&mut self, key: &K) -> Option<V> {
		let pos = self.entries.iter().position(|(k, _, _)| k == key)?;
		let entry = self.entries.remove(pos)?;
		let value = entry.1.clone();
		self.entries.push_back(entry);
		Some(value)
	}

	fn insert(&mut self, key: K, value: V, size: usize) {
		if size > self.max_bytes {
			return;
		}
		if let Some(pos) = self.entries.iter().position(|(k, _, _)| *k == key) {
			if let Some((_, _, old)) = self.entries.remove(pos) {
				self.bytes -= old;
			}
		}
		self.entries.push_back((key, value, size));
		self.bytes += size;
		while self.entries.len() > self.max_entries || self.bytes > self.max_bytes {
			match self.entries.pop_front() {
				Some((_, _, evicted)) => self.bytes -= evicted,
				None => break,
			}
		}
	}

	#[cfg(test)]
	fn len(&self) -> usize {
		self.entries.len()
	}
}

/// Serves raw BIP157/158 data from one [`FilterSource`].
pub(crate) struct RawChainServer {
	source: Arc<dyn FilterSource>,
	blocks: Mutex<BoundedLru<BlockHash, Arc<Vec<u8>>>>,
	filter_headers: Mutex<BoundedLru<(u32, BlockHash), FilterHeaders>>,
	filters: Mutex<BoundedLru<(u32, BlockHash), Vec<IndexedFilter>>>,
	/// Turns at the source; see [`RAW_SERVE_CONCURRENCY`].
	permits: Semaphore,
	/// One gate per block being fetched, so concurrent chunk requests for it
	/// wait for the one fetch instead of each making their own.
	block_flights: Mutex<HashMap<BlockHash, Arc<tokio::sync::Mutex<()>>>>,
	limits: RawServeLimits,
	logger: Arc<Logger>,
}

impl RawChainServer {
	pub(crate) fn new(source: Arc<dyn FilterSource>, logger: Arc<Logger>) -> Self {
		Self::with_limits(source, RawServeLimits::default(), logger)
	}

	pub(crate) fn with_limits(
		source: Arc<dyn FilterSource>, limits: RawServeLimits, logger: Arc<Logger>,
	) -> Self {
		Self {
			source,
			blocks: Mutex::new(BoundedLru::new(BLOCK_CACHE_ENTRIES, BLOCK_CACHE_BYTES)),
			filter_headers: Mutex::new(BoundedLru::new(
				NEAR_TIP_CACHE_ENTRIES,
				FILTER_HEADER_CACHE_BYTES,
			)),
			filters: Mutex::new(BoundedLru::new(NEAR_TIP_CACHE_ENTRIES, FILTER_CACHE_BYTES)),
			permits: Semaphore::new(limits.concurrency.max(1)),
			block_flights: Mutex::new(HashMap::new()),
			limits,
			logger,
		}
	}

	/// Runs one serve under `limit`. A serve that runs out is dropped — its
	/// source call with it — and fails.
	async fn deadline<T>(
		&self, what: &str, limit: Duration, serve: impl Future<Output = Result<T, Error>>,
	) -> Result<T, Error> {
		match tokio::time::timeout(limit, serve).await {
			Ok(result) => result,
			Err(_elapsed) => {
				log_warn!(
					self.logger,
					"Raw {} request dropped: not served within {}s",
					what,
					limit.as_secs()
				);
				Err(Error::ChainServeFailed)
			},
		}
	}

	/// A turn at the source; see [`RAW_SERVE_CONCURRENCY`].
	async fn turn(&self) -> Result<SemaphorePermit<'_>, Error> {
		self.permits.acquire().await.map_err(|_| Error::ChainServeFailed)
	}

	/// A request this node will not answer as asked. Logged, because the
	/// wire carries only [`Error::ChainServeFailed`].
	fn refuse(&self, what: &str, why: impl std::fmt::Display) -> Error {
		log_info!(self.logger, "Refusing a raw {} request: {}", what, why);
		Error::ChainServeFailed
	}

	fn source_failed(&self, what: &str, e: SourceError) -> Error {
		match &e {
			SourceError::NotFound(_) => {
				log_debug!(self.logger, "Raw {} request not served: {}", what, e)
			},
			_ => log_info!(
				self.logger,
				"Raw {} request not served by {}: {}",
				what,
				self.source.name(),
				e
			),
		}
		Error::ChainServeFailed
	}

	pub(crate) async fn serve_tip(&self) -> Result<WireChainTip, Error> {
		self.deadline("tip", self.limits.small_timeout, async {
			let _turn = self.turn().await?;
			let tip = self.source.tip().await.map_err(|e| self.source_failed("tip", e))?;
			Ok(chain_tip_to_wire(&tip))
		})
		.await
	}

	/// Up to `count` headers; fewer when the tip comes first, or when they
	/// would outgrow [`HEADER_BYTES_PER_REPLY`].
	pub(crate) async fn serve_headers(
		&self, req: &WireHeadersRequest,
	) -> Result<WireHeaders, Error> {
		check_version(req.version).map_err(|e| self.refuse("headers", e))?;
		if req.count > MAX_HEADERS_PER_REQUEST {
			return Err(self.refuse(
				"headers",
				format_args!("{} headers asked, at most {}", req.count, MAX_HEADERS_PER_REQUEST),
			));
		}
		let count = req.count.min((HEADER_BYTES_PER_REPLY / HEADER_SIZE).max(1) as u32);
		self.deadline("headers", self.limits.small_timeout, async {
			let _turn = self.turn().await?;
			let headers = self
				.source
				.headers(req.from_height, count)
				.await
				.map_err(|e| self.source_failed("headers", e))?;
			if headers.len() > count as usize {
				return Err(self.source_failed(
					"headers",
					SourceError::Invalid(format!("{} headers for {} asked", headers.len(), count)),
				));
			}
			log_trace!(
				self.logger,
				"Served {} raw headers from height {}",
				headers.len(),
				req.from_height
			);
			Ok(headers_to_wire(&headers))
		})
		.await
	}

	/// The filter headers of the span, or of its first
	/// [`FILTER_HEADERS_PER_REPLY`] blocks.
	pub(crate) async fn serve_filter_headers(
		&self, req: &WireFilterHeadersRequest,
	) -> Result<WireFilterHeaders, Error> {
		check_version(req.version).map_err(|e| self.refuse("filter headers", e))?;
		let stop_hash =
			block_hash_from_wire(&req.stop_hash).map_err(|e| self.refuse("filter headers", e))?;
		let key = (req.start_height, stop_hash);

		if let Some(hit) = self.filter_headers.lock().unwrap().get(&key) {
			return Ok(filter_headers_to_wire(&hit));
		}

		self.deadline("filter headers", self.limits.small_timeout, async {
			let _turn = self.turn().await?;
			let mut answer = self
				.source
				.filter_headers(req.start_height, stop_hash)
				.await
				.map_err(|e| self.source_failed("filter headers", e))?;
			if answer.headers.len() > MAX_FILTER_HEADERS_PER_REQUEST as usize {
				return Err(self.refuse(
					"filter headers",
					format_args!(
						"span of {} blocks, at most {}",
						answer.headers.len(),
						MAX_FILTER_HEADERS_PER_REQUEST
					),
				));
			}
			if answer.headers.is_empty() {
				return Err(self.source_failed(
					"filter headers",
					SourceError::Invalid("no filter headers for the span".into()),
				));
			}
			answer.headers.truncate(FILTER_HEADERS_PER_REPLY as usize);
			if answer.headers.len() <= NEAR_TIP_SPAN {
				let size = (answer.headers.len() + 1) * 32;
				self.filter_headers.lock().unwrap().insert(key, answer.clone(), size);
			}
			Ok(filter_headers_to_wire(&answer))
		})
		.await
	}

	/// The filters of the span, or of as much of it, from the start, as fits
	/// in [`FILTER_BYTES_PER_REPLY`] — at least one.
	pub(crate) async fn serve_filters(
		&self, req: &WireFiltersRequest,
	) -> Result<WireFilters, Error> {
		check_version(req.version).map_err(|e| self.refuse("filters", e))?;
		let stop_hash =
			block_hash_from_wire(&req.stop_hash).map_err(|e| self.refuse("filters", e))?;
		let key = (req.start_height, stop_hash);

		if let Some(hit) = self.filters.lock().unwrap().get(&key) {
			return Ok(filters_to_wire(&hit));
		}

		self.deadline("filters", self.limits.filters_timeout, async {
			let _turn = self.turn().await?;
			let mut answer = self
				.source
				.filters(req.start_height, stop_hash)
				.await
				.map_err(|e| self.source_failed("filters", e))?;
			if answer.len() > MAX_FILTERS_PER_REQUEST as usize {
				return Err(self.refuse(
					"filters",
					format_args!(
						"span of {} blocks, at most {}",
						answer.len(),
						MAX_FILTERS_PER_REQUEST
					),
				));
			}
			if answer.is_empty() {
				return Err(self.source_failed(
					"filters",
					SourceError::Invalid("no filters for the span".into()),
				));
			}
			let fit = filters_prefix_len(&answer);
			if fit < answer.len() {
				log_debug!(
					self.logger,
					"Serving {} of {} filters from height {}: the rest would outgrow one reply",
					fit,
					answer.len(),
					req.start_height
				);
				answer.truncate(fit);
			}
			if answer.len() <= NEAR_TIP_SPAN {
				let size = answer.iter().map(|f| f.filter.content.len() + 40).sum();
				self.filters.lock().unwrap().insert(key, answer.clone(), size);
			}
			Ok(filters_to_wire(&answer))
		})
		.await
	}

	/// One chunk of a block, fetching the block from the source only when it
	/// is not cached from an earlier chunk.
	pub(crate) async fn serve_block_chunk(
		&self, req: &WireBlockRequest,
	) -> Result<WireBlockChunk, Error> {
		check_version(req.version).map_err(|e| self.refuse("block", e))?;
		let hash = block_hash_from_wire(&req.hash).map_err(|e| self.refuse("block", e))?;

		let cached = self.blocks.lock().unwrap().get(&hash);
		let bytes = match cached {
			Some(bytes) => bytes,
			None => {
				self.deadline("block", self.limits.block_timeout, self.fetch_block_once(hash))
					.await?
			},
		};

		block_chunk_to_wire(&hash, &bytes, req.chunk).ok_or_else(|| {
			self.refuse(
				"block",
				format_args!(
					"chunk {} of a block in {} chunks",
					req.chunk,
					block_chunk_count(bytes.len())
				),
			)
		})
	}

	/// Fetches `hash` into the block cache, once however many chunk requests
	/// ask at the same time: the first fetches, the others wait for it and
	/// then read the cache. A failed fetch is retried by the next in line.
	async fn fetch_block_once(&self, hash: BlockHash) -> Result<Arc<Vec<u8>>, Error> {
		let gate = {
			let mut flights = self.block_flights.lock().unwrap_or_else(|e| e.into_inner());
			Arc::clone(flights.entry(hash).or_default())
		};
		let _slot = FlightSlot { flights: &self.block_flights, hash, gate: Arc::clone(&gate) };
		let _flight = gate.lock().await;
		if let Some(bytes) = self.blocks.lock().unwrap().get(&hash) {
			return Ok(bytes);
		}

		let _turn = self.turn().await?;
		let block = self.source.block(hash).await.map_err(|e| self.source_failed("block", e))?;
		if block.block_hash() != hash {
			return Err(self.source_failed(
				"block",
				SourceError::Invalid(format!("asked for {}, got another block", hash)),
			));
		}
		let bytes = Arc::new(serialize(&block));
		self.blocks.lock().unwrap().insert(hash, Arc::clone(&bytes), bytes.len());
		Ok(bytes)
	}
}

/// A consensus-encoded block header's size.
const HEADER_SIZE: usize = 80;

/// A [`FilterSource`] that reads a [`ChainLayer`]'s raw serves in-process,
/// through the wire types — the shape a network-backed source in an app has,
/// minus the network. For tests that run a serving layer and a consuming
/// client against each other.
///
/// [`ChainLayer`]: crate::chain::ChainLayer
#[cfg(test)]
pub(crate) struct ServedFilterSource {
	pub(crate) layer: Arc<crate::chain::ChainLayer>,
}

#[cfg(test)]
impl ServedFilterSource {
	fn served(e: Error) -> SourceError {
		match e {
			Error::ChainServeUnsupported => {
				SourceError::unavailable("serving node has no raw chain source")
			},
			other => SourceError::unavailable(other.to_string()),
		}
	}
}

#[cfg(test)]
#[async_trait::async_trait]
impl FilterSource for ServedFilterSource {
	fn name(&self) -> &'static str {
		"served"
	}

	async fn tip(&self) -> Result<bdk_chain::BlockId, SourceError> {
		let wire = self.layer.serve_tip().await.map_err(Self::served)?;
		Ok(crate::chain::wire_convert::chain_tip_from_wire(&wire)?)
	}

	async fn headers(
		&self, from_height: u32, count: u32,
	) -> Result<Vec<bitcoin::block::Header>, SourceError> {
		let req = WireHeadersRequest {
			version: crate::chain::provider::CHAIN_WIRE_VERSION,
			from_height,
			count,
		};
		let wire = self.layer.serve_headers(&req).await.map_err(Self::served)?;
		Ok(crate::chain::wire_convert::headers_from_wire(&wire)?)
	}

	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		let req = WireFilterHeadersRequest {
			version: crate::chain::provider::CHAIN_WIRE_VERSION,
			start_height,
			stop_hash: stop_hash.to_string(),
		};
		let wire = self.layer.serve_filter_headers(&req).await.map_err(Self::served)?;
		Ok(crate::chain::wire_convert::filter_headers_from_wire(&wire)?)
	}

	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		let req = WireFiltersRequest {
			version: crate::chain::provider::CHAIN_WIRE_VERSION,
			start_height,
			stop_hash: stop_hash.to_string(),
		};
		let wire = self.layer.serve_filters(&req).await.map_err(Self::served)?;
		Ok(crate::chain::wire_convert::filters_from_wire(&wire)?)
	}

	async fn block(&self, hash: BlockHash) -> Result<bitcoin::Block, SourceError> {
		let mut assembler = crate::chain::wire_convert::BlockChunkAssembler::new(hash);
		loop {
			let req = WireBlockRequest {
				version: crate::chain::provider::CHAIN_WIRE_VERSION,
				hash: hash.to_string(),
				chunk: assembler.next_chunk(),
			};
			let chunk = self.layer.serve_block_chunk(&req).await.map_err(Self::served)?;
			if let Some(block) = assembler.push(&chunk)? {
				return Ok(block);
			}
		}
	}
}

/// An in-memory [`FilterSource`] over a fixed chain, counting what it is
/// asked. `filters_len`, when set, makes every filters answer that long
/// regardless of the span — for checking the server's own limits.
#[cfg(test)]
pub(crate) struct MockFilterSource {
	pub(crate) blocks: Vec<bitcoin::Block>,
	pub(crate) filters_len: Option<usize>,
	/// When set, every filter is this many bytes.
	pub(crate) filter_bytes: Option<usize>,
	/// When set, every call takes this long.
	pub(crate) delay: Option<Duration>,
	/// When set, `tip` never answers, and raises the flag once dropped.
	pub(crate) hang_tip: Option<Arc<std::sync::atomic::AtomicBool>>,
	pub(crate) calls: Mutex<std::collections::HashMap<&'static str, usize>>,
	in_flight: std::sync::atomic::AtomicUsize,
	pub(crate) max_in_flight: std::sync::atomic::AtomicUsize,
}

/// Counts a mock call out of flight however it ends.
#[cfg(test)]
struct InFlight<'a>(&'a std::sync::atomic::AtomicUsize);

#[cfg(test)]
impl Drop for InFlight<'_> {
	fn drop(&mut self) {
		self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
	}
}

/// Raises a flag once dropped.
#[cfg(test)]
struct DropFlag(Arc<std::sync::atomic::AtomicBool>);

#[cfg(test)]
impl Drop for DropFlag {
	fn drop(&mut self) {
		self.0.store(true, std::sync::atomic::Ordering::SeqCst);
	}
}

#[cfg(test)]
impl MockFilterSource {
	/// A chain of `len` blocks, the last one about `last_block_bytes` large.
	pub(crate) fn new(len: u32, last_block_bytes: usize) -> Self {
		let mut blocks: Vec<bitcoin::Block> = Vec::new();
		for i in 0..len {
			let payload = if i + 1 == len { last_block_bytes } else { 10 };
			let mut block = crate::chain::wire_convert::synthetic_block(payload, i);
			if let Some(prev) = blocks.last() {
				block.header.prev_blockhash = prev.block_hash();
			}
			blocks.push(block);
		}
		Self {
			blocks,
			filters_len: None,
			filter_bytes: None,
			delay: None,
			hang_tip: None,
			calls: Mutex::new(Default::default()),
			in_flight: Default::default(),
			max_in_flight: Default::default(),
		}
	}

	pub(crate) fn calls(&self, method: &'static str) -> usize {
		self.calls.lock().unwrap().get(method).copied().unwrap_or(0)
	}

	/// Counts the call, holds it in flight for the configured delay.
	async fn count(&self, method: &'static str) {
		use std::sync::atomic::Ordering;
		*self.calls.lock().unwrap().entry(method).or_default() += 1;
		let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
		self.max_in_flight.fetch_max(now, Ordering::SeqCst);
		let _in_flight = InFlight(&self.in_flight);
		if let Some(delay) = self.delay {
			tokio::time::sleep(delay).await;
		}
	}

	pub(crate) fn filter(&self, height: usize) -> bitcoin::bip158::BlockFilter {
		match self.filter_bytes {
			Some(len) => {
				let mut content = vec![0xcd; len.max(2)];
				content[0] = height as u8;
				content[1] = (height >> 8) as u8;
				bitcoin::bip158::BlockFilter::new(&content)
			},
			None => bitcoin::bip158::BlockFilter::new(&[1, height as u8, 0xcd]),
		}
	}

	fn span(
		&self, start: u32, stop: BlockHash,
	) -> Result<std::ops::RangeInclusive<usize>, SourceError> {
		let stop = self
			.blocks
			.iter()
			.position(|b| b.block_hash() == stop)
			.ok_or_else(|| SourceError::NotFound("stop hash".into()))?;
		Ok(start as usize..=stop)
	}
}

#[cfg(test)]
#[async_trait::async_trait]
impl FilterSource for MockFilterSource {
	fn name(&self) -> &'static str {
		"mock"
	}

	async fn tip(&self) -> Result<bdk_chain::BlockId, SourceError> {
		if let Some(dropped) = &self.hang_tip {
			let _flag = DropFlag(Arc::clone(dropped));
			std::future::pending::<()>().await;
		}
		self.count("tip").await;
		let last = self.blocks.len() - 1;
		Ok(bdk_chain::BlockId { height: last as u32, hash: self.blocks[last].block_hash() })
	}

	async fn headers(
		&self, from_height: u32, count: u32,
	) -> Result<Vec<bitcoin::block::Header>, SourceError> {
		self.count("headers").await;
		let from = from_height as usize;
		if from >= self.blocks.len() {
			return Err(SourceError::NotFound("above tip".into()));
		}
		Ok(self.blocks[from..].iter().take(count as usize).map(|b| b.header).collect())
	}

	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		use bitcoin::hashes::Hash;
		self.count("filter_headers").await;
		let span = self.span(start_height, stop_hash)?;
		let mut below = bitcoin::bip158::FilterHeader::all_zeros();
		let mut headers = Vec::new();
		for h in 0..=*span.end() {
			let header = self.filter(h).filter_header(headers.last().unwrap_or(&below));
			if h < *span.start() {
				below = header;
			} else {
				headers.push(header);
			}
		}
		Ok(FilterHeaders { previous: below, headers })
	}

	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		self.count("filters").await;
		let span = self.span(start_height, stop_hash)?;
		let mut out: Vec<IndexedFilter> = span
			.map(|h| IndexedFilter {
				height: h as u32,
				block_hash: self.blocks[h].block_hash(),
				filter: self.filter(h),
			})
			.collect();
		if let Some(len) = self.filters_len {
			out = std::iter::repeat(out[0].clone()).take(len).collect();
		}
		Ok(out)
	}

	async fn block(&self, hash: BlockHash) -> Result<bitcoin::Block, SourceError> {
		self.count("block").await;
		self.blocks
			.iter()
			.find(|b| b.block_hash() == hash)
			.cloned()
			.ok_or_else(|| SourceError::NotFound("block".into()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::bip158::FilterHeader;
	use bitcoin::hashes::Hash;

	use crate::chain::provider::CHAIN_WIRE_VERSION;
	use crate::chain::wire_convert::{
		filter_headers_from_wire, filters_from_wire, headers_from_wire, BlockChunkAssembler,
	};

	fn server(source: MockFilterSource) -> (RawChainServer, Arc<MockFilterSource>) {
		let source = Arc::new(source);
		let logger = Arc::new(Logger::new_log_facade());
		(RawChainServer::new(Arc::clone(&source) as Arc<dyn FilterSource>, logger), source)
	}

	fn filters_req(start_height: u32, stop: BlockHash) -> WireFiltersRequest {
		WireFiltersRequest {
			version: CHAIN_WIRE_VERSION,
			start_height,
			stop_hash: stop.to_string(),
		}
	}

	#[test]
	fn the_lru_is_bounded_by_entries_and_bytes() {
		let mut lru = BoundedLru::new(3, 100);
		lru.insert(1, "a", 10);
		lru.insert(2, "b", 10);
		lru.insert(3, "c", 10);
		assert_eq!(lru.get(&1), Some("a"), "touching 1 makes 2 the oldest");
		lru.insert(4, "d", 10);
		assert_eq!(lru.len(), 3);
		assert_eq!(lru.get(&2), None);

		lru.insert(5, "e", 85);
		assert_eq!(lru.bytes, 95);
		assert_eq!(lru.len(), 2, "bytes evicted the oldest two");
		lru.insert(6, "too big", 101);
		assert_eq!(lru.get(&6), None, "an entry over the whole budget is not kept");
		lru.insert(5, "e2", 5);
		assert_eq!(lru.bytes, 15, "replacing an entry releases its old size");
		assert_eq!(lru.get(&5), Some("e2"));
	}

	#[tokio::test]
	async fn requests_over_the_limits_are_refused() {
		let (server, source) = server(MockFilterSource::new(5, 10));
		let too_many =
			WireHeadersRequest { version: CHAIN_WIRE_VERSION, from_height: 0, count: 2001 };
		assert!(matches!(server.serve_headers(&too_many).await, Err(Error::ChainServeFailed)));
		assert_eq!(source.calls("headers"), 0, "refused before the source is asked");
		let at_limit = WireHeadersRequest { count: MAX_HEADERS_PER_REQUEST, ..too_many };
		let wire = server.serve_headers(&at_limit).await.unwrap();
		assert_eq!(headers_from_wire(&wire).unwrap().len(), 5, "fewer: the tip came first");

		let other_version = WireHeadersRequest { version: CHAIN_WIRE_VERSION + 1, ..at_limit };
		assert!(matches!(server.serve_headers(&other_version).await, Err(Error::ChainServeFailed)));

		// A source answering a wider span than the wire allows is not
		// passed on.
		let mut wide = MockFilterSource::new(5, 10);
		wide.filters_len = Some(MAX_FILTERS_PER_REQUEST as usize + 1);
		let tip = wide.blocks[4].block_hash();
		let (server, _) = self::server(wide);
		assert!(matches!(
			server.serve_filters(&filters_req(0, tip)).await,
			Err(Error::ChainServeFailed)
		));

		let bad_hash = WireFiltersRequest { stop_hash: "nope".into(), ..filters_req(0, tip) };
		assert!(matches!(server.serve_filters(&bad_hash).await, Err(Error::ChainServeFailed)));
	}

	#[tokio::test]
	async fn source_failures_are_serve_failures() {
		let (server, _) = server(MockFilterSource::new(3, 10));
		let unknown = BlockHash::from_byte_array([7u8; 32]);
		assert!(matches!(
			server.serve_filters(&filters_req(0, unknown)).await,
			Err(Error::ChainServeFailed)
		));
		let req =
			WireBlockRequest { version: CHAIN_WIRE_VERSION, hash: unknown.to_string(), chunk: 0 };
		assert!(matches!(server.serve_block_chunk(&req).await, Err(Error::ChainServeFailed)));
	}

	#[tokio::test]
	async fn a_block_is_fetched_once_for_all_its_chunks() {
		let (server, source) = server(MockFilterSource::new(3, 1_300_000));
		let block = source.blocks[2].clone();
		let hash = block.block_hash();

		let mut assembler = BlockChunkAssembler::new(hash);
		let rebuilt = loop {
			let req = WireBlockRequest {
				version: CHAIN_WIRE_VERSION,
				hash: hash.to_string(),
				chunk: assembler.next_chunk(),
			};
			let chunk = server.serve_block_chunk(&req).await.unwrap();
			assert_eq!(chunk.total_chunks, 2);
			if let Some(block) = assembler.push(&chunk).unwrap() {
				break block;
			}
		};
		assert_eq!(rebuilt, block);
		assert_eq!(source.calls("block"), 1, "the second chunk came from the cache");

		let past_the_end =
			WireBlockRequest { version: CHAIN_WIRE_VERSION, hash: hash.to_string(), chunk: 2 };
		assert!(matches!(
			server.serve_block_chunk(&past_the_end).await,
			Err(Error::ChainServeFailed)
		));
	}

	fn fast_server(source: MockFilterSource) -> (Arc<RawChainServer>, Arc<MockFilterSource>) {
		let source = Arc::new(source);
		let limits = RawServeLimits {
			concurrency: RAW_SERVE_CONCURRENCY,
			small_timeout: Duration::from_millis(300),
			filters_timeout: Duration::from_secs(5),
			block_timeout: Duration::from_secs(5),
		};
		let server = RawChainServer::with_limits(
			Arc::clone(&source) as Arc<dyn FilterSource>,
			limits,
			Arc::new(Logger::new_log_facade()),
		);
		(Arc::new(server), source)
	}

	#[tokio::test]
	async fn a_filters_reply_is_cut_to_a_prefix_that_fits_one_message() {
		let mut source = MockFilterSource::new(60, 10);
		source.filter_bytes = Some(30_000);
		let tip = source.blocks[59].block_hash();
		let (server, _) = server(source);

		let wire = server.serve_filters(&filters_req(0, tip)).await.unwrap();
		let expected = FILTER_BYTES_PER_REPLY / 30_000;
		assert_eq!(wire.filters.len(), expected, "as many whole filters as fit");
		let served = filters_from_wire(&wire).unwrap();
		for (i, filter) in served.iter().enumerate() {
			assert_eq!(filter.height, i as u32, "a prefix of the span, from its start");
		}
		let encoded = serde_json::to_vec(&wire).unwrap();
		assert!(encoded.len() < 3 * 1024 * 1024 / 2, "{} bytes on the wire", encoded.len());

		// One filter larger than the whole budget still goes: a reply always makes progress.
		let mut huge = MockFilterSource::new(3, 10);
		huge.filter_bytes = Some(FILTER_BYTES_PER_REPLY + 1);
		let tip = huge.blocks[2].block_hash();
		let (server, _) = self::server(huge);
		assert_eq!(server.serve_filters(&filters_req(0, tip)).await.unwrap().filters.len(), 1);
	}

	#[tokio::test]
	async fn a_long_filter_header_span_is_served_a_prefix_at_a_time() {
		let (server, source) = server(MockFilterSource::new(500, 10));
		let req = WireFilterHeadersRequest {
			version: CHAIN_WIRE_VERSION,
			start_height: 1,
			stop_hash: source.blocks[450].block_hash().to_string(),
		};
		let served =
			filter_headers_from_wire(&server.serve_filter_headers(&req).await.unwrap()).unwrap();
		assert_eq!(served.headers.len(), FILTER_HEADERS_PER_REPLY as usize);
		let mut previous = source.filter(0).filter_header(&FilterHeader::all_zeros());
		assert_eq!(served.previous, previous);
		for (i, header) in served.headers.iter().enumerate() {
			previous = source.filter(1 + i).filter_header(&previous);
			assert_eq!(*header, previous, "the prefix chains from the span's start");
		}
	}

	#[tokio::test]
	async fn at_most_a_few_serves_ask_the_source_at_once() {
		let mut source = MockFilterSource::new(20, 10);
		source.delay = Some(Duration::from_millis(40));
		let (server, source) = fast_server(source);
		let serves: Vec<_> = (0..10)
			.map(|i| {
				let server = Arc::clone(&server);
				tokio::spawn(async move {
					let req = WireHeadersRequest {
						version: CHAIN_WIRE_VERSION,
						from_height: i,
						count: 3,
					};
					server.serve_headers(&req).await
				})
			})
			.collect();
		for serve in serves {
			let served = tokio::time::timeout(Duration::from_secs(20), serve).await.unwrap();
			assert!(served.unwrap().is_ok(), "every serve got its turn");
		}
		let max = source.max_in_flight.load(std::sync::atomic::Ordering::SeqCst);
		assert!(max <= RAW_SERVE_CONCURRENCY, "{} serves at the source at once", max);
		assert_eq!(source.calls("headers"), 10);
	}

	#[tokio::test]
	async fn concurrent_chunk_requests_for_one_block_share_one_fetch() {
		let mut source = MockFilterSource::new(3, 1_300_000);
		source.delay = Some(Duration::from_millis(100));
		let hash = source.blocks[2].block_hash();
		let (server, source) = fast_server(source);
		let serves: Vec<_> = (0..8)
			.map(|i| {
				let server = Arc::clone(&server);
				tokio::spawn(async move {
					let req = WireBlockRequest {
						version: CHAIN_WIRE_VERSION,
						hash: hash.to_string(),
						chunk: i % 2,
					};
					server.serve_block_chunk(&req).await
				})
			})
			.collect();
		for serve in serves {
			let served = tokio::time::timeout(Duration::from_secs(20), serve).await.unwrap();
			assert_eq!(served.unwrap().unwrap().total_chunks, 2);
		}
		assert_eq!(source.calls("block"), 1, "one getblock for all eight chunk requests");
		assert!(server.block_flights.lock().unwrap().is_empty(), "no flight left behind");
	}

	#[tokio::test]
	async fn a_serve_past_its_deadline_is_dropped() {
		let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
		let mut source = MockFilterSource::new(3, 10);
		source.hang_tip = Some(Arc::clone(&dropped));
		let (server, _) = fast_server(source);

		let started = std::time::Instant::now();
		let served = tokio::time::timeout(Duration::from_secs(20), server.serve_tip()).await;
		assert!(matches!(served, Ok(Err(Error::ChainServeFailed))));
		assert!(started.elapsed() < Duration::from_secs(5));
		assert!(
			dropped.load(std::sync::atomic::Ordering::SeqCst),
			"the source call was dropped, not left running"
		);
		// Its turn at the source was given back.
		assert_eq!(server.permits.available_permits(), RAW_SERVE_CONCURRENCY);
	}

	#[tokio::test]
	async fn short_spans_near_the_tip_are_cached_and_long_ones_are_not() {
		let (server, source) = server(MockFilterSource::new(40, 10));
		let tip = source.blocks[39].block_hash();

		let near_tip = filters_req(37, tip);
		let first = server.serve_filters(&near_tip).await.unwrap();
		let second = server.serve_filters(&near_tip).await.unwrap();
		assert_eq!(first, second);
		assert_eq!(source.calls("filters"), 1);
		assert_eq!(filters_from_wire(&first).unwrap().len(), 3);

		let catch_up = filters_req(0, tip);
		server.serve_filters(&catch_up).await.unwrap();
		server.serve_filters(&catch_up).await.unwrap();
		assert_eq!(source.calls("filters"), 3, "a 40-block span is not cached");

		let fh_req = WireFilterHeadersRequest {
			version: CHAIN_WIRE_VERSION,
			start_height: 38,
			stop_hash: tip.to_string(),
		};
		let fh = server.serve_filter_headers(&fh_req).await.unwrap();
		assert_eq!(server.serve_filter_headers(&fh_req).await.unwrap(), fh);
		assert_eq!(source.calls("filter_headers"), 1);
		let fh = filter_headers_from_wire(&fh).unwrap();
		assert_eq!(fh.headers.len(), 2);
		assert_eq!(source.filter(38).filter_header(&fh.previous), fh.headers[0]);
	}
}
