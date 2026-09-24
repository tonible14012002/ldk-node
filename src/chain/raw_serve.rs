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
//! [`ChainLayer`]: crate::chain::ChainLayer

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

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
use crate::logger::{log_debug, log_info, log_trace, LdkLogger, Logger};
use crate::Error;

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
	logger: Arc<Logger>,
}

impl RawChainServer {
	pub(crate) fn new(source: Arc<dyn FilterSource>, logger: Arc<Logger>) -> Self {
		Self {
			source,
			blocks: Mutex::new(BoundedLru::new(BLOCK_CACHE_ENTRIES, BLOCK_CACHE_BYTES)),
			filter_headers: Mutex::new(BoundedLru::new(
				NEAR_TIP_CACHE_ENTRIES,
				FILTER_HEADER_CACHE_BYTES,
			)),
			filters: Mutex::new(BoundedLru::new(NEAR_TIP_CACHE_ENTRIES, FILTER_CACHE_BYTES)),
			logger,
		}
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
		let tip = self.source.tip().await.map_err(|e| self.source_failed("tip", e))?;
		Ok(chain_tip_to_wire(&tip))
	}

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
		let headers = self
			.source
			.headers(req.from_height, req.count)
			.await
			.map_err(|e| self.source_failed("headers", e))?;
		if headers.len() > req.count as usize {
			return Err(self.source_failed(
				"headers",
				SourceError::Invalid(format!("{} headers for {} asked", headers.len(), req.count)),
			));
		}
		log_trace!(
			self.logger,
			"Served {} raw headers from height {}",
			headers.len(),
			req.from_height
		);
		Ok(headers_to_wire(&headers))
	}

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

		let answer = self
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
		if answer.headers.len() <= NEAR_TIP_SPAN {
			let size = (answer.headers.len() + 1) * 32;
			self.filter_headers.lock().unwrap().insert(key, answer.clone(), size);
		}
		Ok(filter_headers_to_wire(&answer))
	}

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

		let answer = self
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
		if answer.len() <= NEAR_TIP_SPAN {
			let size = answer.iter().map(|f| f.filter.content.len() + 40).sum();
			self.filters.lock().unwrap().insert(key, answer.clone(), size);
		}
		Ok(filters_to_wire(&answer))
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
				let block =
					self.source.block(hash).await.map_err(|e| self.source_failed("block", e))?;
				if block.block_hash() != hash {
					return Err(self.source_failed(
						"block",
						SourceError::Invalid(format!("asked for {}, got another block", hash)),
					));
				}
				let bytes = Arc::new(serialize(&block));
				self.blocks.lock().unwrap().insert(hash, Arc::clone(&bytes), bytes.len());
				bytes
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
}

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
	pub(crate) calls: Mutex<std::collections::HashMap<&'static str, usize>>,
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
		Self { blocks, filters_len: None, calls: Mutex::new(Default::default()) }
	}

	pub(crate) fn calls(&self, method: &'static str) -> usize {
		self.calls.lock().unwrap().get(method).copied().unwrap_or(0)
	}

	fn count(&self, method: &'static str) {
		*self.calls.lock().unwrap().entry(method).or_default() += 1;
	}

	pub(crate) fn filter(&self, height: usize) -> bitcoin::bip158::BlockFilter {
		bitcoin::bip158::BlockFilter::new(&[1, height as u8, 0xcd])
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
		self.count("tip");
		let last = self.blocks.len() - 1;
		Ok(bdk_chain::BlockId { height: last as u32, hash: self.blocks[last].block_hash() })
	}

	async fn headers(
		&self, from_height: u32, count: u32,
	) -> Result<Vec<bitcoin::block::Header>, SourceError> {
		self.count("headers");
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
		self.count("filter_headers");
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
		self.count("filters");
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
		self.count("block");
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
