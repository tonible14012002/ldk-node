// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Gossip verification on a pruned bitcoind.
//!
//! A BOLT-7 `channel_announcement` names its funding output by block height, transaction
//! index and output index, so LDK's gossip verifier reads that whole block. A pruned node has
//! dropped every block below its prune height: `getblock` answers "Block not available
//! (pruned data)", the lookup fails and LDK drops the announcement without a log line. A
//! pruned Pro node then knows only the channels funded within its last few days of blocks,
//! cannot route to the rest of the network, and draws a near-empty topology.
//!
//! [`PrunedBlockRefetch`] wraps the node's UTXO source. When a block read fails because the
//! block was pruned, it asks a full-history peer for exactly that block (`getblockfrompeer`,
//! Bitcoin Core 23+), waits for it to arrive and answers with it. The check itself does not
//! change: the output is still read from the block and checked against the UTXO set, so a
//! forged announcement is still refused. Downloads are bounded per hour, because any peer
//! can announce a validly signed channel that names an old block.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::{BlockHash, OutPoint};
use lightning_block_sync::gossip::UtxoSource;
use lightning_block_sync::http::JsonResponse;
use lightning_block_sync::rpc::RpcClient;
use lightning_block_sync::{
	AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, BlockSourceError,
};

use crate::logger::{log_debug, log_info, log_warn, LdkLogger, Logger};

/// How many pruned blocks may be fetched per window. One fleet-wide graph reset needs a few
/// dozen; the bound caps what a peer can make the node download with announcements naming
/// old blocks (~2 MB each).
const FETCHES_PER_WINDOW: u32 = 60;
const FETCH_WINDOW: Duration = Duration::from_secs(3600);
/// How many full-history peers are asked for one block before giving up on it.
const PEERS_PER_BLOCK: usize = 3;
/// How long one peer is given to deliver the block.
const POLL_EVERY: Duration = Duration::from_secs(1);
const POLLS_PER_PEER: u32 = 20;

/// What the refetch needs from bitcoind beyond the UTXO source.
pub(crate) trait BlockFetcher: Send + Sync {
	/// Ids of connected outbound peers that serve the whole chain (`NODE_NETWORK`).
	fn full_history_peers<'a>(
		&'a self,
	) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u64>>> + Send + 'a>>;

	/// Asks `peer` for the block `hash`. The block arrives asynchronously.
	fn request_block<'a>(
		&'a self, hash: &'a BlockHash, peer: u64,
	) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>>;
}

/// The poll cadence, injectable so tests do not wait seconds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RefetchTiming {
	pub(crate) poll_every: Duration,
	pub(crate) polls_per_peer: u32,
	pub(crate) peers_per_block: usize,
	pub(crate) fetches_per_window: u32,
	pub(crate) window: Duration,
}

impl Default for RefetchTiming {
	fn default() -> Self {
		Self {
			poll_every: POLL_EVERY,
			polls_per_peer: POLLS_PER_PEER,
			peers_per_block: PEERS_PER_BLOCK,
			fetches_per_window: FETCHES_PER_WINDOW,
			window: FETCH_WINDOW,
		}
	}
}

struct FetchBudget {
	window_start: Instant,
	used: u32,
}

/// A [`UtxoSource`] that fetches a pruned block from a full-history peer instead of failing.
pub(crate) struct PrunedBlockRefetch {
	inner: Arc<dyn UtxoSource>,
	fetcher: Arc<dyn BlockFetcher>,
	timing: RefetchTiming,
	budget: Mutex<FetchBudget>,
	in_flight: Mutex<HashSet<BlockHash>>,
	logger: Arc<Logger>,
}

impl PrunedBlockRefetch {
	pub(crate) fn new(
		inner: Arc<dyn UtxoSource>, fetcher: Arc<dyn BlockFetcher>, logger: Arc<Logger>,
	) -> Self {
		Self::with_timing(inner, fetcher, RefetchTiming::default(), logger)
	}

	pub(crate) fn with_timing(
		inner: Arc<dyn UtxoSource>, fetcher: Arc<dyn BlockFetcher>, timing: RefetchTiming,
		logger: Arc<Logger>,
	) -> Self {
		Self {
			inner,
			fetcher,
			timing,
			budget: Mutex::new(FetchBudget { window_start: Instant::now(), used: 0 }),
			in_flight: Mutex::new(HashSet::new()),
			logger,
		}
	}

	/// Spends one fetch from the hourly budget; `false` when it is used up.
	fn take_budget(&self) -> bool {
		let mut budget = self.budget.lock().unwrap_or_else(|p| p.into_inner());
		let now = Instant::now();
		if now.duration_since(budget.window_start) >= self.timing.window {
			budget.window_start = now;
			budget.used = 0;
		}
		if budget.used < self.timing.fetches_per_window {
			budget.used += 1;
			true
		} else {
			false
		}
	}

	/// Polls the inner source until the block is readable, at most `polls` times.
	async fn wait_for(&self, hash: &BlockHash, polls: u32) -> Option<BlockData> {
		for _ in 0..polls {
			tokio::time::sleep(self.timing.poll_every).await;
			if let Ok(block) = self.inner.get_block(hash).await {
				return Some(block);
			}
		}
		None
	}

	/// Asks full-history peers for `hash`, one after the other, until one delivers it.
	async fn fetch(&self, hash: &BlockHash) -> Option<BlockData> {
		let peers = match self.fetcher.full_history_peers().await {
			Ok(peers) => peers,
			Err(e) => {
				log_warn!(self.logger, "Gossip: cannot list peers to fetch pruned block {}: {}", hash, e);
				return None;
			},
		};
		if peers.is_empty() {
			log_warn!(
				self.logger,
				"Gossip: block {} is pruned here and no connected peer serves full history",
				hash
			);
			return None;
		}
		for peer in peers.iter().take(self.timing.peers_per_block) {
			// A failed request is not final: the block may already be on its way from an
			// earlier request, or be in the store by now. Poll either way.
			if let Err(e) = self.fetcher.request_block(hash, *peer).await {
				log_debug!(self.logger, "Gossip: getblockfrompeer {} from peer {}: {}", hash, peer, e);
			}
			if let Some(block) = self.wait_for(hash, self.timing.polls_per_peer).await {
				log_info!(
					self.logger,
					"Gossip: fetched pruned block {} from peer {} to verify a channel announcement",
					hash,
					peer
				);
				return Some(block);
			}
		}
		log_warn!(
			self.logger,
			"Gossip: could not fetch pruned block {} from {} peer(s); its channel announcements are dropped until they are gossiped again",
			hash,
			peers.len().min(self.timing.peers_per_block)
		);
		None
	}
}

/// Whether a block read failed because the block was pruned.
fn is_pruned(e: &BlockSourceError) -> bool {
	format!("{:?}", e).to_ascii_lowercase().contains("pruned")
}

impl BlockSource for PrunedBlockRefetch {
	fn get_header<'a>(
		&'a self, header_hash: &'a BlockHash, height_hint: Option<u32>,
	) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		self.inner.get_header(header_hash, height_hint)
	}

	fn get_block<'a>(&'a self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, BlockData> {
		Box::pin(async move {
			let err = match self.inner.get_block(header_hash).await {
				Ok(block) => return Ok(block),
				Err(e) => e,
			};
			if !is_pruned(&err) {
				return Err(err);
			}
			// One fetch per block: a second announcement in the same block waits for the
			// first fetch instead of starting another one.
			let first = self.in_flight.lock().unwrap_or_else(|p| p.into_inner()).insert(*header_hash);
			if !first {
				let polls = self.timing.polls_per_peer.saturating_mul(self.timing.peers_per_block as u32);
				return self.wait_for(header_hash, polls).await.ok_or(err);
			}
			let fetched = if self.take_budget() {
				self.fetch(header_hash).await
			} else {
				log_warn!(
					self.logger,
					"Gossip: block {} is pruned here and this hour's re-fetch budget ({} blocks) is spent",
					header_hash,
					self.timing.fetches_per_window
				);
				None
			};
			self.in_flight.lock().unwrap_or_else(|p| p.into_inner()).remove(header_hash);
			fetched.ok_or(err)
		})
	}

	fn get_best_block<'a>(&'a self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		self.inner.get_best_block()
	}
}

impl UtxoSource for PrunedBlockRefetch {
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> AsyncBlockSourceResult<'a, BlockHash> {
		self.inner.get_block_hash_by_height(block_height)
	}

	fn is_output_unspent<'a>(&'a self, outpoint: OutPoint) -> AsyncBlockSourceResult<'a, bool> {
		self.inner.is_output_unspent(outpoint)
	}
}

/// [`BlockFetcher`] over bitcoind's RPC: `getpeerinfo` and `getblockfrompeer`.
pub(crate) struct RpcBlockFetcher(pub(crate) Arc<RpcClient>);

impl BlockFetcher for RpcBlockFetcher {
	fn full_history_peers<'a>(
		&'a self,
	) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u64>>> + Send + 'a>> {
		Box::pin(async move {
			let PeerIds(ids) = self.0.call_method::<PeerIds>("getpeerinfo", &[]).await?;
			Ok(ids)
		})
	}

	fn request_block<'a>(
		&'a self, hash: &'a BlockHash, peer: u64,
	) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
		Box::pin(async move {
			let params = [serde_json::json!(hash.to_string()), serde_json::json!(peer)];
			self.0.call_method::<Accepted>("getblockfrompeer", &params).await.map(|_| ())
		})
	}
}

/// `getpeerinfo` reduced to the peers a pruned block can be fetched from.
pub(crate) struct PeerIds(pub(crate) Vec<u64>);

impl TryInto<PeerIds> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<PeerIds> {
		let peers = self.0.as_array().ok_or_else(|| {
			std::io::Error::new(std::io::ErrorKind::Other, "getpeerinfo did not answer a list")
		})?;
		Ok(PeerIds(full_history_peer_ids(peers)))
	}
}

/// Any answer: `getblockfrompeer` answers `{}` and delivers the block later.
pub(crate) struct Accepted;

impl TryInto<Accepted> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<Accepted> {
		Ok(Accepted)
	}
}

/// Outbound peers advertising `NODE_NETWORK` (service bit 0), in `getpeerinfo` order.
/// `NODE_NETWORK_LIMITED` peers only keep the last 288 blocks, and an inbound peer may be a
/// light client.
fn full_history_peer_ids(peers: &[serde_json::Value]) -> Vec<u64> {
	const NODE_NETWORK: u64 = 1;
	peers
		.iter()
		.filter(|p| p["inbound"].as_bool() == Some(false))
		.filter(|p| {
			p["services"]
				.as_str()
				.and_then(|s| u64::from_str_radix(s, 16).ok())
				.map_or(false, |services| services & NODE_NETWORK != 0)
		})
		.filter_map(|p| p["id"].as_u64())
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::sync::atomic::{AtomicBool, Ordering};

	use bitcoin::blockdata::constants::genesis_block;
	use bitcoin::{Block, Network};
	use lightning_block_sync::rpc::RpcError;

	/// A UTXO source holding one block that reads as pruned until a peer delivers it.
	struct FakeSource {
		block: Block,
		present: AtomicBool,
		error: &'static str,
	}

	impl BlockSource for FakeSource {
		fn get_header<'a>(
			&'a self, _: &'a BlockHash, _: Option<u32>,
		) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
			Box::pin(async { Err(BlockSourceError::transient("unused")) })
		}

		fn get_block<'a>(&'a self, _: &'a BlockHash) -> AsyncBlockSourceResult<'a, BlockData> {
			Box::pin(async move {
				if self.present.load(Ordering::SeqCst) {
					Ok(BlockData::FullBlock(self.block.clone()))
				} else {
					Err(BlockSourceError::transient(std::io::Error::new(
						std::io::ErrorKind::Other,
						RpcError { code: -1, message: self.error.to_string() },
					)))
				}
			})
		}

		fn get_best_block<'a>(&'a self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
			Box::pin(async { Err(BlockSourceError::transient("unused")) })
		}
	}

	impl UtxoSource for FakeSource {
		fn get_block_hash_by_height<'a>(&'a self, _: u32) -> AsyncBlockSourceResult<'a, BlockHash> {
			Box::pin(async { Err(BlockSourceError::transient("unused")) })
		}

		fn is_output_unspent<'a>(&'a self, _: OutPoint) -> AsyncBlockSourceResult<'a, bool> {
			Box::pin(async { Ok(true) })
		}
	}

	/// Peers of which only `delivering` actually sends the block.
	struct FakeFetcher {
		source: Arc<FakeSource>,
		peers: Vec<u64>,
		delivering: Option<u64>,
		requests: Mutex<Vec<u64>>,
	}

	impl BlockFetcher for FakeFetcher {
		fn full_history_peers<'a>(
			&'a self,
		) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u64>>> + Send + 'a>> {
			Box::pin(async move { Ok(self.peers.clone()) })
		}

		fn request_block<'a>(
			&'a self, _: &'a BlockHash, peer: u64,
		) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
			Box::pin(async move {
				self.requests.lock().unwrap().push(peer);
				if self.delivering == Some(peer) {
					self.source.present.store(true, Ordering::SeqCst);
				}
				Ok(())
			})
		}
	}

	const PRUNED: &str = "Block not available (pruned data)";

	fn timing(fetches_per_window: u32) -> RefetchTiming {
		RefetchTiming {
			poll_every: Duration::from_millis(2),
			polls_per_peer: 3,
			peers_per_block: 3,
			fetches_per_window,
			window: Duration::from_secs(3600),
		}
	}

	fn setup(
		present: bool, error: &'static str, peers: Vec<u64>, delivering: Option<u64>,
		fetches_per_window: u32,
	) -> (PrunedBlockRefetch, Arc<FakeFetcher>, BlockHash) {
		let block = genesis_block(Network::Regtest);
		let hash = block.block_hash();
		let source = Arc::new(FakeSource { block, present: AtomicBool::new(present), error });
		let fetcher = Arc::new(FakeFetcher {
			source: Arc::clone(&source),
			peers,
			delivering,
			requests: Mutex::new(Vec::new()),
		});
		let refetch = PrunedBlockRefetch::with_timing(
			source,
			Arc::clone(&fetcher) as Arc<dyn BlockFetcher>,
			timing(fetches_per_window),
			Arc::new(Logger::new_log_facade()),
		);
		(refetch, fetcher, hash)
	}

	#[tokio::test]
	async fn a_block_still_on_disk_is_read_without_any_fetch() {
		let (refetch, fetcher, hash) = setup(true, PRUNED, vec![7], Some(7), 60);
		assert!(matches!(refetch.get_block(&hash).await, Ok(BlockData::FullBlock(_))));
		assert!(fetcher.requests.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn a_pruned_block_is_fetched_from_a_full_history_peer_and_answered() {
		let (refetch, fetcher, hash) = setup(false, PRUNED, vec![7, 9], Some(7), 60);
		assert!(matches!(refetch.get_block(&hash).await, Ok(BlockData::FullBlock(_))));
		assert_eq!(*fetcher.requests.lock().unwrap(), vec![7]);
	}

	#[tokio::test]
	async fn a_peer_that_never_delivers_is_skipped_for_the_next() {
		let (refetch, fetcher, hash) = setup(false, PRUNED, vec![7, 9, 11], Some(9), 60);
		assert!(matches!(refetch.get_block(&hash).await, Ok(BlockData::FullBlock(_))));
		assert_eq!(*fetcher.requests.lock().unwrap(), vec![7, 9]);
	}

	#[tokio::test]
	async fn at_most_three_peers_are_asked_then_the_read_fails_as_before() {
		let (refetch, fetcher, hash) = setup(false, PRUNED, vec![1, 2, 3, 4, 5], None, 60);
		let err = match refetch.get_block(&hash).await {
			Ok(_) => panic!("no peer delivers, so the read must fail"),
			Err(e) => e,
		};
		assert!(is_pruned(&err), "the original pruned error is returned: {:?}", err);
		assert_eq!(*fetcher.requests.lock().unwrap(), vec![1, 2, 3]);
	}

	#[tokio::test]
	async fn any_other_read_error_passes_through_untouched() {
		let (refetch, fetcher, hash) = setup(false, "Block not found", vec![7], Some(7), 60);
		assert!(refetch.get_block(&hash).await.is_err());
		assert!(fetcher.requests.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn the_hourly_budget_bounds_how_many_blocks_are_fetched() {
		let (refetch, fetcher, hash) = setup(false, PRUNED, vec![7], None, 1);
		assert!(refetch.get_block(&hash).await.is_err());
		assert_eq!(fetcher.requests.lock().unwrap().len(), 1, "the first read spends the budget");
		assert!(refetch.get_block(&hash).await.is_err());
		assert_eq!(fetcher.requests.lock().unwrap().len(), 1, "the second read asks nobody");
	}

	#[tokio::test]
	async fn reads_of_the_same_block_share_one_fetch() {
		let (refetch, fetcher, hash) = setup(false, PRUNED, vec![7, 9], Some(9), 60);
		let refetch = Arc::new(refetch);
		let (a, b) = tokio::join!(refetch.get_block(&hash), refetch.get_block(&hash));
		assert!(a.is_ok() && b.is_ok());
		assert_eq!(*fetcher.requests.lock().unwrap(), vec![7, 9], "one round of requests");
	}

	#[test]
	fn only_outbound_full_history_peers_are_asked() {
		let peers: Vec<serde_json::Value> = serde_json::from_str(
			r#"[
				{"id": 2, "inbound": false, "services": "0000000000000c09"},
				{"id": 3, "inbound": false, "services": "0000000000000c08"},
				{"id": 4, "inbound": true,  "services": "0000000000000c09"},
				{"id": 5, "inbound": false, "services": "0000000000000409"},
				{"id": 6, "services": "0000000000000c09"}
			]"#,
		)
		.unwrap();
		assert_eq!(full_history_peer_ids(&peers), vec![2, 5]);
	}
}
