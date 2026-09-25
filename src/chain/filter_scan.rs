// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Server-side compact-filter scans: how a Pro node whose chain source is a
//! bitcoind answers a Dependent node's wallet and Lightning syncs.
//!
//! bitcoind indexes nothing by script, so there is no history to look a script
//! up in the way an Electrum or Esplora server does. What it does have, with
//! `-blockfilterindex=1`, is a BIP158 filter per block. A scan therefore walks
//! the blocks the asker has not seen yet, tests each block's filter against
//! the asker's scripts, and reads — and checks against its merkle root — only
//! the blocks that match. The answer has the shape the Electrum serve gives:
//! full transactions, their anchors, and a checkpoint chain that connects to
//! the asker's own.
//!
//! # Where a scan starts
//!
//! * **Wallet.** At the highest block of the asker's checkpoint chain that is
//!   still on this node's best chain. Checkpoints above it are stale (a reorg)
//!   and are displaced in the answer by this node's blocks at the same
//!   heights, which is what makes BDK drop them — and every anchor on them.
//! * **Lightning.** Just above the block the asker says it has synced to
//!   ([`WireLightningSyncRequest::scan_from`]), or above the point where that
//!   block's branch left this node's best chain. A transaction the asker
//!   believes confirmed in a block that is no longer on the best chain pulls
//!   the start down to that block's fork point too.
//!
//! # Bounds
//!
//! One answer scans at most [`FILTER_SCAN_MAX_BLOCKS`] blocks, and stops
//! reading filters once its time budget is spent. An asker further behind gets
//! a correct *partial* answer: its chain tip — the wallet update's last
//! checkpoint, the Lightning response's `tip` — is the last block scanned, and
//! its next request continues from there. A block a match needs that this
//! node has pruned fails the answer: never a silently incomplete one.
//!
//! # What a wallet scan can recognise
//!
//! A basic filter commits to every output script of a block and to the script
//! of every output its inputs spend, so a block that pays *or spends* one of
//! the asker's scripts matches. Within a matched block a payment is plain to
//! see; a spend is recognised by the outpoint it spends, which must be one of
//! the asker's — sent as [`WireSyncRequest::owned_outpoints`], or found paying
//! the asker earlier in the same scan. (The script of an arbitrary spent
//! output is not available without `-txindex`.)
//!
//! [`WireLightningSyncRequest::scan_from`]: crate::chain::provider::WireLightningSyncRequest::scan_from
//! [`WireSyncRequest::owned_outpoints`]: crate::chain::provider::WireSyncRequest::owned_outpoints

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;

use bitcoin::bip158::BlockFilter;
use bitcoin::block::Header;
use bitcoin::{Block, BlockHash, OutPoint, ScriptBuf, Transaction, Txid};

use bdk_chain::BlockId;

use crate::chain::adapters::bitcoind_raw::NO_FILTER_INDEX_REASON;
use crate::chain::cbf::source::SourceError;

/// Blocks one served scan covers at most: two weeks of mainnet blocks. An
/// asker further behind is answered up to here and continues from the tip it
/// was given. Shared with the Dependent engine, which reads an answer that
/// advanced this far as possibly partial and asks again at once.
pub(crate) const FILTER_SCAN_MAX_BLOCKS: u32 = 2016;

/// Filters asked for in one call.
pub(crate) const FILTER_SCAN_BATCH: usize = 50;

/// How far back a Lightning scan starts when the asker names a block this
/// node has never seen, or names none at all (an asker that predates
/// [`WireLightningSyncRequest::scan_from`]).
///
/// [`WireLightningSyncRequest::scan_from`]: crate::chain::provider::WireLightningSyncRequest::scan_from
pub(crate) const LIGHTNING_FALLBACK_LOOKBACK: u32 = 144;

/// Checkpoints of the asker's chain looked up at most, top down, while
/// looking for one this node agrees with.
pub(crate) const MAX_AGREEMENT_CHECKS: usize = 256;

/// What a scan reads from the chain source. [`BitcoindRpcSource`] is the one
/// implementation; the tests run the scan over an in-memory chain.
///
/// [`BitcoindRpcSource`]: crate::chain::adapters::bitcoind_raw::BitcoindRpcSource
#[async_trait]
pub(crate) trait ScanSource: Send + Sync {
	/// The best block and its header.
	async fn scan_tip(&self) -> Result<(BlockId, Header), SourceError>;

	/// The best-chain block at `height`; `None` above the tip.
	async fn hash_at(&self, height: u32) -> Result<Option<BlockHash>, SourceError>;

	/// Best-chain hashes from `from`, at most `count`, stopping at the tip.
	async fn best_hashes(&self, from: u32, count: u32) -> Result<Vec<BlockHash>, SourceError>;

	/// Where `hash` is: its height, whether it is on the best chain, and its
	/// parent. `None` when the source has never seen it.
	async fn header_state(&self, hash: &BlockHash) -> Result<Option<HeaderState>, SourceError>;

	/// The 80-byte header of `hash`.
	async fn block_header(&self, hash: &BlockHash) -> Result<Header, SourceError>;

	/// The basic filter of each of `hashes`, in order.
	async fn block_filters(&self, hashes: &[BlockHash]) -> Result<Vec<BlockFilter>, SourceError>;

	/// The full block `hash`.
	async fn full_block(&self, hash: &BlockHash) -> Result<Block, SourceError>;
}

/// Where a block sits, as a [`ScanSource`] knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeaderState {
	pub(crate) height: u32,
	pub(crate) in_best_chain: bool,
	/// `None` only for genesis.
	pub(crate) prev: Option<BlockHash>,
}

/// How much one scan may do.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanLimits {
	/// Blocks scanned at most; see [`FILTER_SCAN_MAX_BLOCKS`].
	pub(crate) max_blocks: u32,
	/// Time spent reading filters at most, after which the scan answers for
	/// what it has read (at least one batch).
	pub(crate) filter_budget: Duration,
}

/// Why a scan could not answer.
#[derive(Debug)]
pub(crate) enum ScanError {
	/// The chain source has no block filter index: it cannot scan at all.
	NoFilterIndex(String),
	/// A block the answer needs has been pruned.
	Pruned { height: u32, hash: BlockHash, reason: String },
	/// The source failed, or answered with data that does not check out.
	Source(SourceError),
	/// The request cannot be answered as asked; the reason says why.
	Refused(String),
}

impl ScanError {
	fn from_source(e: SourceError) -> Self {
		match &e {
			SourceError::Unavailable { reason, .. }
				if reason.starts_with(NO_FILTER_INDEX_REASON) =>
			{
				Self::NoFilterIndex(reason.clone())
			},
			_ => Self::Source(e),
		}
	}
}

impl fmt::Display for ScanError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::NoFilterIndex(reason) => write!(f, "no block filter index: {}", reason),
			Self::Pruned { height, hash, reason } => write!(
				f,
				"block {} at height {} is needed but pruned from the chain source ({})",
				hash, height, reason
			),
			Self::Source(e) => write!(f, "{}", e),
			Self::Refused(reason) => write!(f, "{}", reason),
		}
	}
}

/// Whether an `Unavailable` reason for a block read says the block was pruned.
fn is_pruned(e: &SourceError) -> bool {
	match e {
		SourceError::Unavailable { reason, .. } => reason.to_ascii_lowercase().contains("prune"),
		_ => false,
	}
}

/// Read `hash` at `height` and check it: the right block, and transactions
/// that hash to its merkle root.
async fn checked_block(
	source: &dyn ScanSource, height: u32, hash: &BlockHash,
) -> Result<Block, ScanError> {
	let block = source.full_block(hash).await.map_err(|e| {
		if is_pruned(&e) {
			ScanError::Pruned { height, hash: *hash, reason: e.to_string() }
		} else {
			ScanError::Source(e)
		}
	})?;
	if block.block_hash() != *hash {
		return Err(ScanError::Source(SourceError::Invalid(format!(
			"asked for block {} and got {}",
			hash,
			block.block_hash()
		))));
	}
	if !block.check_merkle_root() {
		return Err(ScanError::Source(SourceError::Invalid(format!(
			"block {} does not match its merkle root",
			hash
		))));
	}
	Ok(block)
}

/// Which of `hashes` — consecutive best-chain blocks — have a filter matching
/// any of `queries`. Returns how many were scanned (a prefix, when the budget
/// ran out; at least one batch) and the indices of those that matched.
async fn scan_filters(
	source: &dyn ScanSource, hashes: &[BlockHash], queries: &[Vec<u8>], limits: &ScanLimits,
	began: Instant,
) -> Result<(usize, Vec<usize>), ScanError> {
	let mut scanned = 0usize;
	let mut matched = Vec::new();
	for chunk in hashes.chunks(FILTER_SCAN_BATCH) {
		if scanned > 0 && began.elapsed() >= limits.filter_budget {
			break;
		}
		let filters = source.block_filters(chunk).await.map_err(ScanError::from_source)?;
		if filters.len() != chunk.len() {
			return Err(ScanError::Source(SourceError::Invalid(format!(
				"{} filters for {} blocks",
				filters.len(),
				chunk.len()
			))));
		}
		for (i, filter) in filters.iter().enumerate() {
			let index = scanned + i;
			let hit = filter
				.match_any(&hashes[index], queries.iter().map(|q| q.as_slice()))
				.map_err(|e| {
					ScanError::Source(SourceError::Invalid(format!(
						"filter of block {} does not decode: {}",
						hashes[index], e
					)))
				})?;
			if hit {
				matched.push(index);
			}
		}
		scanned += chunk.len();
	}
	Ok((scanned, matched))
}

// ── wallet ────────────────────────────────────────────────────────────────

/// A wallet scan, decoded from the wire.
#[derive(Debug, Clone, Default)]
pub(crate) struct WalletScan {
	/// The asker's checkpoint chain, ascending.
	pub(crate) chain: Vec<BlockId>,
	pub(crate) spks: Vec<ScriptBuf>,
	/// Transactions the asker asked about by id.
	pub(crate) txids: HashSet<Txid>,
	/// Outputs the asker holds, so their spends are recognised.
	pub(crate) owned: HashSet<OutPoint>,
}

/// One relevant confirmed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FoundTx {
	pub(crate) tx: Transaction,
	pub(crate) block: BlockId,
	pub(crate) pos: u32,
	pub(crate) header: Header,
}

/// What a wallet scan found.
#[derive(Debug, Clone)]
pub(crate) struct WalletScanned {
	/// Relevant confirmed transactions, in chain order.
	pub(crate) found: Vec<FoundTx>,
	/// The checkpoint chain to answer with, ascending; its last block is the
	/// last block scanned.
	pub(crate) checkpoints: Vec<BlockId>,
	/// The asker's outputs as of the end of the scan — what it sent plus
	/// what the scan found paying it — for recognising mempool spends.
	pub(crate) owned: HashSet<OutPoint>,
	/// The source's tip when the scan began.
	pub(crate) tip: BlockId,
	/// How many blocks were scanned; `checkpoints` ends below `tip` when this
	/// was capped.
	pub(crate) blocks_scanned: u32,
}

/// Scan for the asker's wallet from the highest checkpoint this node agrees
/// with, up to the tip or the limits.
pub(crate) async fn scan_wallet(
	source: &dyn ScanSource, req: WalletScan, limits: &ScanLimits,
) -> Result<WalletScanned, ScanError> {
	let began = Instant::now();
	let (tip, _tip_header) = source.scan_tip().await.map_err(ScanError::from_source)?;

	if req.chain.is_empty() {
		return Err(ScanError::Refused(
			"the request carries no checkpoint chain to scan from".to_string(),
		));
	}
	if req.chain.windows(2).any(|w| w[0].height >= w[1].height) {
		return Err(ScanError::Refused("the checkpoint chain is not ascending".to_string()));
	}

	// The highest checkpoint on this node's best chain. Everything above it
	// is either stale (at or below our tip) or ahead of us.
	let mut agreement: Option<BlockId> = None;
	let mut stale_heights: Vec<u32> = Vec::new();
	let mut ahead: Option<BlockId> = None;
	for (checked, cp) in req.chain.iter().rev().enumerate() {
		if checked >= MAX_AGREEMENT_CHECKS {
			return Err(ScanError::Refused(format!(
				"none of the asker's top {} checkpoints is on this node's best chain",
				MAX_AGREEMENT_CHECKS
			)));
		}
		if cp.height > tip.height {
			ahead.get_or_insert(*cp);
			continue;
		}
		match source.hash_at(cp.height).await.map_err(ScanError::from_source)? {
			Some(hash) if hash == cp.hash => {
				agreement = Some(*cp);
				break;
			},
			_ => stale_heights.push(cp.height),
		}
	}
	let agreement = agreement.ok_or_else(|| {
		ScanError::Refused(
			"no checkpoint of the asker is on this node's best chain (another network?)"
				.to_string(),
		)
	})?;
	if let Some(ahead) = ahead {
		return Err(ScanError::Refused(format!(
			"the asker has a block at height {} and this node's chain source only reaches {}",
			ahead.height, tip.height
		)));
	}

	let start = agreement.height + 1;
	let count = tip.height.saturating_sub(agreement.height).min(limits.max_blocks);
	let hashes = if count == 0 {
		Vec::new()
	} else {
		let hashes = source.best_hashes(start, count).await.map_err(ScanError::from_source)?;
		// The run must hang off the agreement block, or the best chain moved
		// between reading the two.
		if let Some(first) = hashes.first() {
			let state = source.header_state(first).await.map_err(ScanError::from_source)?;
			if state.and_then(|s| s.prev) != Some(agreement.hash) {
				return Err(ScanError::Source(SourceError::unavailable(
					"the best chain changed while the scan was starting",
				)));
			}
		}
		hashes
	};

	let queries: Vec<Vec<u8>> = req.spks.iter().map(|s| s.to_bytes()).collect();
	let (scanned, matched) = if hashes.is_empty() || queries.is_empty() {
		// No scripts: nothing to find, and the chain advances all the same.
		(hashes.len(), Vec::new())
	} else {
		scan_filters(source, &hashes, &queries, limits, began).await?
	};
	let scanned_to = if scanned == 0 {
		agreement
	} else {
		BlockId { height: start + scanned as u32 - 1, hash: hashes[scanned - 1] }
	};

	// A stale checkpoint must be displaced by this node's block at its height,
	// and that block must be one this answer covers.
	let mut chain: BTreeMap<u32, BlockHash> = req
		.chain
		.iter()
		.filter(|cp| cp.height <= agreement.height)
		.map(|cp| (cp.height, cp.hash))
		.collect();
	for height in stale_heights {
		if height > scanned_to.height {
			return Err(ScanError::Refused(format!(
				"the asker's stale checkpoint at height {} is above what one answer scans (up to {})",
				height, scanned_to.height
			)));
		}
		chain.insert(height, hashes[(height - start) as usize]);
	}

	let spks: HashSet<&ScriptBuf> = req.spks.iter().collect();
	let mut owned = req.owned;
	let mut found = Vec::new();
	for index in matched {
		let height = start + index as u32;
		let hash = hashes[index];
		let block = checked_block(source, height, &hash).await?;
		let block_id = BlockId { height, hash };
		for (pos, tx) in block.txdata.iter().enumerate() {
			let txid = tx.compute_txid();
			let pays = tx.output.iter().any(|o| spks.contains(&o.script_pubkey));
			let spends =
				!tx.is_coinbase() && tx.input.iter().any(|i| owned.contains(&i.previous_output));
			if !(pays || spends || req.txids.contains(&txid)) {
				continue;
			}
			for (vout, out) in tx.output.iter().enumerate() {
				if spks.contains(&out.script_pubkey) {
					owned.insert(OutPoint { txid, vout: vout as u32 });
				}
			}
			found.push(FoundTx {
				tx: tx.clone(),
				block: block_id,
				pos: pos as u32,
				header: block.header,
			});
		}
		chain.insert(height, hash);
	}
	chain.insert(scanned_to.height, scanned_to.hash);

	Ok(WalletScanned {
		found,
		checkpoints: chain.into_iter().map(|(height, hash)| BlockId { height, hash }).collect(),
		owned,
		tip,
		blocks_scanned: scanned as u32,
	})
}

// ── lightning ─────────────────────────────────────────────────────────────

/// A watched transaction, decoded from the wire.
#[derive(Debug, Clone)]
pub(crate) struct WatchedTxScan {
	pub(crate) txid: Txid,
	/// The block the asker last saw it confirmed in.
	pub(crate) known: Option<BlockHash>,
	/// One of its output scripts: what finds it by filter.
	pub(crate) script: Option<ScriptBuf>,
}

/// A Lightning scan, decoded from the wire.
#[derive(Debug, Clone, Default)]
pub(crate) struct LightningScan {
	pub(crate) txs: Vec<WatchedTxScan>,
	pub(crate) outputs: Vec<(OutPoint, ScriptBuf)>,
	/// The block the asker has synced to.
	pub(crate) scan_from: Option<BlockId>,
}

/// What a Lightning scan found.
#[derive(Debug, Clone)]
pub(crate) struct LightningScanned {
	/// The tip to report: the last block scanned when the scan was capped,
	/// the source's tip otherwise.
	pub(crate) tip: BlockId,
	pub(crate) tip_header: Header,
	/// The source's tip when the scan began; above `tip` when the scan was
	/// capped.
	pub(crate) source_tip: BlockId,
	/// Newly confirmed watched transactions and spends of watched outputs,
	/// by height then position.
	pub(crate) confirmed: Vec<FoundTx>,
	/// Watched transactions the asker believed confirmed in a block no longer
	/// on the best chain, and not found again in what was scanned.
	pub(crate) unconfirmed: Vec<Txid>,
	pub(crate) blocks_scanned: u32,
	/// Watched transactions without a script to look for.
	pub(crate) unscannable: usize,
}

/// The first height worth scanning for an asker at `block`: just above it
/// when it is on the best chain, just above where its branch left the best
/// chain when it is not, and `None` when the source has never seen it.
async fn resume_height(
	source: &dyn ScanSource, block: &BlockHash, max_walk: u32,
) -> Result<Option<u32>, ScanError> {
	let mut hash = *block;
	for _ in 0..=max_walk {
		match source.header_state(&hash).await.map_err(ScanError::from_source)? {
			None => return Ok(None),
			Some(state) if state.in_best_chain => return Ok(Some(state.height + 1)),
			Some(HeaderState { prev: Some(prev), .. }) => hash = prev,
			Some(_) => return Ok(Some(0)),
		}
	}
	Err(ScanError::Refused(format!(
		"block {} left the best chain more than {} blocks down",
		block, max_walk
	)))
}

/// Scan for the asker's watched transactions and outputs from the block it
/// has synced to, up to the tip or the limits.
pub(crate) async fn scan_lightning(
	source: &dyn ScanSource, req: LightningScan, limits: &ScanLimits,
) -> Result<LightningScanned, ScanError> {
	let began = Instant::now();
	let (tip, tip_header) = source.scan_tip().await.map_err(ScanError::from_source)?;

	let fallback = |height: u32| height.saturating_sub(LIGHTNING_FALLBACK_LOOKBACK - 1);
	let mut start = match &req.scan_from {
		Some(from) => match resume_height(source, &from.hash, limits.max_blocks).await? {
			Some(height) => height,
			None => fallback(from.height.min(tip.height)),
		},
		None => fallback(tip.height),
	};

	// Where each block the asker names is, asked once.
	let mut known_state: HashMap<BlockHash, Option<HeaderState>> = HashMap::new();
	for watched in &req.txs {
		let Some(known) = watched.known else { continue };
		if known_state.contains_key(&known) {
			continue;
		}
		let state = source.header_state(&known).await.map_err(ScanError::from_source)?;
		if let Some(s) = state {
			if !s.in_best_chain {
				// Confirmed on a branch that lost: it may be in a block of
				// the winning branch since its fork point.
				if let Some(height) = resume_height(source, &known, limits.max_blocks).await? {
					start = start.min(height);
				}
			}
		}
		known_state.insert(known, state);
	}

	let mut unscannable = 0usize;
	let mut queries: Vec<Vec<u8>> = Vec::new();
	for watched in &req.txs {
		match &watched.script {
			Some(script) => queries.push(script.to_bytes()),
			None if watched.known.is_none() => unscannable += 1,
			None => {},
		}
	}
	for (_, script) in &req.outputs {
		queries.push(script.to_bytes());
	}

	let count = if start > tip.height || queries.is_empty() {
		0
	} else {
		(tip.height - start + 1).min(limits.max_blocks)
	};
	let hashes = if count == 0 {
		Vec::new()
	} else {
		source.best_hashes(start, count).await.map_err(ScanError::from_source)?
	};
	let (scanned, matched) = if hashes.is_empty() {
		(0, Vec::new())
	} else {
		scan_filters(source, &hashes, &queries, limits, began).await?
	};

	let watched_txids: HashSet<Txid> = req.txs.iter().map(|w| w.txid).collect();
	let watched_outpoints: HashSet<OutPoint> = req.outputs.iter().map(|(op, _)| *op).collect();
	let mut found_at: HashMap<Txid, FoundTx> = HashMap::new();
	let mut spends: Vec<FoundTx> = Vec::new();
	let mut last_block: Option<Block> = None;
	for index in matched {
		let height = start + index as u32;
		let hash = hashes[index];
		let block = checked_block(source, height, &hash).await?;
		let block_id = BlockId { height, hash };
		for (pos, tx) in block.txdata.iter().enumerate() {
			// Bitcoin's merkle tree cannot tell an inner node from a 64-byte
			// leaf, so such a transaction is never reported. LDK's guard.
			if tx.total_size() == 64 {
				continue;
			}
			let txid = tx.compute_txid();
			let entry =
				FoundTx { tx: tx.clone(), block: block_id, pos: pos as u32, header: block.header };
			if watched_txids.contains(&txid) {
				found_at.insert(txid, entry);
			} else if !tx.is_coinbase()
				&& tx.input.iter().any(|i| watched_outpoints.contains(&i.previous_output))
			{
				spends.push(entry);
			}
		}
		if index + 1 == scanned {
			last_block = Some(block);
		}
	}

	let mut confirmed: Vec<FoundTx> = Vec::new();
	let mut unconfirmed: Vec<Txid> = Vec::new();
	for watched in &req.txs {
		if let Some(entry) = found_at.remove(&watched.txid) {
			// Still in the block the asker recorded: nothing to say.
			if watched.known != Some(entry.block.hash) {
				confirmed.push(entry);
			}
			continue;
		}
		if let Some(known) = watched.known {
			let on_best =
				known_state.get(&known).copied().flatten().is_some_and(|s| s.in_best_chain);
			if !on_best && !unconfirmed.contains(&watched.txid) {
				unconfirmed.push(watched.txid);
			}
		}
	}
	confirmed.extend(spends);
	confirmed.sort_by_key(|e| (e.block.height, e.pos));
	confirmed.dedup_by_key(|e| e.tx.compute_txid());

	let source_tip = tip;
	let (tip, tip_header) = if scanned > 0 && scanned < (tip.height - start + 1) as usize {
		let hash = hashes[scanned - 1];
		let header = match last_block {
			Some(block) => block.header,
			None => source.block_header(&hash).await.map_err(ScanError::from_source)?,
		};
		(BlockId { height: start + scanned as u32 - 1, hash }, header)
	} else {
		(tip, tip_header)
	};

	Ok(LightningScanned {
		tip,
		tip_header,
		source_tip,
		confirmed,
		unconfirmed,
		blocks_scanned: scanned as u32,
		unscannable,
	})
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;

	use std::sync::Mutex;

	use bitcoin::absolute::LockTime;
	use bitcoin::block::Version as BlockVersion;
	use bitcoin::hashes::Hash;
	use bitcoin::transaction::Version;
	use bitcoin::{Amount, CompactTarget, Sequence, TxIn, TxMerkleNode, TxOut, Witness};

	/// A chain the tests control: a best chain plus any stale blocks, with
	/// real BIP158 filters over them.
	pub(crate) struct MemChain {
		best: Vec<Block>,
		stale: Vec<(u32, Block)>,
		/// Every output ever created, for the filters' spent scripts.
		outputs: HashMap<OutPoint, ScriptBuf>,
		pruned_below: u32,
		filter_index: bool,
		/// Full-block reads, for asserting which blocks a scan fetched.
		pub(crate) block_reads: Mutex<Vec<BlockHash>>,
		pub(crate) filter_reads: Mutex<usize>,
		/// Each filter read sleeps this long, to exercise the time budget.
		filter_delay: Duration,
	}

	pub(crate) fn script(n: u8) -> ScriptBuf {
		ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([n; 20]))
	}

	fn coinbase(height: u32, pay_to: &ScriptBuf) -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: bitcoin::script::Builder::new()
					.push_int(height as i64)
					.push_int(0x5ca1ab1e)
					.into_script(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(50_000), script_pubkey: pay_to.clone() }],
		}
	}

	/// A transaction spending `inputs` and paying `outputs`.
	pub(crate) fn spend(inputs: &[OutPoint], outputs: &[(&ScriptBuf, u64)]) -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: inputs
				.iter()
				.map(|op| TxIn {
					previous_output: *op,
					script_sig: ScriptBuf::new(),
					sequence: Sequence::MAX,
					witness: Witness::from_slice(&[vec![0u8; 72], vec![2u8; 33]]),
				})
				.collect(),
			output: outputs
				.iter()
				.map(|(s, v)| TxOut { value: Amount::from_sat(*v), script_pubkey: (*s).clone() })
				.collect(),
		}
	}

	fn make_block(prev: BlockHash, height: u32, miner: &ScriptBuf, txs: Vec<Transaction>) -> Block {
		let mut txdata = vec![coinbase(height, miner)];
		txdata.extend(txs);
		let mut block = Block {
			header: Header {
				version: BlockVersion::TWO,
				prev_blockhash: prev,
				merkle_root: TxMerkleNode::all_zeros(),
				time: 1_700_000_000 + height,
				bits: CompactTarget::from_consensus(0x207fffff),
				nonce: height,
			},
			txdata,
		};
		block.header.merkle_root = block.compute_merkle_root().unwrap();
		block
	}

	impl MemChain {
		/// Genesis plus `len - 1` empty blocks, each coinbase paying a
		/// miner script nobody watches.
		pub(crate) fn new(len: u32) -> Self {
			let mut chain = Self {
				best: Vec::new(),
				stale: Vec::new(),
				outputs: HashMap::new(),
				pruned_below: 0,
				filter_index: true,
				block_reads: Mutex::new(Vec::new()),
				filter_reads: Mutex::new(0),
				filter_delay: Duration::ZERO,
			};
			for _ in 0..len {
				chain.mine(Vec::new());
			}
			chain
		}

		fn miner() -> ScriptBuf {
			script(0xee)
		}

		fn record_outputs(&mut self, block: &Block) {
			for tx in &block.txdata {
				let txid = tx.compute_txid();
				for (vout, out) in tx.output.iter().enumerate() {
					self.outputs
						.insert(OutPoint { txid, vout: vout as u32 }, out.script_pubkey.clone());
				}
			}
		}

		/// Mine a block on the best chain with `txs`.
		pub(crate) fn mine(&mut self, txs: Vec<Transaction>) -> BlockHash {
			let height = self.best.len() as u32;
			let prev =
				self.best.last().map(|b| b.block_hash()).unwrap_or_else(BlockHash::all_zeros);
			let block = make_block(prev, height, &Self::miner(), txs);
			self.record_outputs(&block);
			let hash = block.block_hash();
			self.best.push(block);
			hash
		}

		/// Replace everything from `height` up with a new branch of `len`
		/// blocks, the first carrying `txs`; the old blocks stay known as
		/// stale.
		pub(crate) fn reorg(&mut self, height: u32, len: u32, txs: Vec<Transaction>) {
			let old = self.best.split_off(height as usize);
			for (i, block) in old.into_iter().enumerate() {
				self.stale.push((height + i as u32, block));
			}
			let mut txs = Some(txs);
			for i in 0..len {
				let h = height + i;
				let prev = self.best.last().unwrap().block_hash();
				// A different miner script, so the branch's blocks differ.
				let block = make_block(prev, h, &script(0xdd), txs.take().unwrap_or_default());
				self.record_outputs(&block);
				self.best.push(block);
			}
		}

		pub(crate) fn tip(&self) -> BlockId {
			let h = self.best.len() as u32 - 1;
			BlockId { height: h, hash: self.best[h as usize].block_hash() }
		}

		pub(crate) fn id(&self, height: u32) -> BlockId {
			BlockId { height, hash: self.best[height as usize].block_hash() }
		}

		fn find(&self, hash: &BlockHash) -> Option<(u32, &Block, bool)> {
			if let Some(h) = self.best.iter().position(|b| b.block_hash() == *hash) {
				return Some((h as u32, &self.best[h], true));
			}
			self.stale.iter().find(|(_, b)| b.block_hash() == *hash).map(|(h, b)| (*h, b, false))
		}

		fn filter_of(&self, block: &Block) -> BlockFilter {
			// An input spending an output these tests never created spends a
			// script nobody watches.
			BlockFilter::new_script_filter(block, |op| {
				Ok::<_, bitcoin::bip158::Error>(
					self.outputs.get(op).cloned().unwrap_or_else(|| script(0xfe)),
				)
			})
			.unwrap()
		}
	}

	#[async_trait]
	impl ScanSource for MemChain {
		async fn scan_tip(&self) -> Result<(BlockId, Header), SourceError> {
			let tip = self.tip();
			Ok((tip, self.best[tip.height as usize].header))
		}

		async fn hash_at(&self, height: u32) -> Result<Option<BlockHash>, SourceError> {
			Ok(self.best.get(height as usize).map(|b| b.block_hash()))
		}

		async fn best_hashes(&self, from: u32, count: u32) -> Result<Vec<BlockHash>, SourceError> {
			Ok(self
				.best
				.iter()
				.skip(from as usize)
				.take(count as usize)
				.map(|b| b.block_hash())
				.collect())
		}

		async fn header_state(&self, hash: &BlockHash) -> Result<Option<HeaderState>, SourceError> {
			Ok(self.find(hash).map(|(height, block, in_best_chain)| HeaderState {
				height,
				in_best_chain,
				prev: (height > 0).then_some(block.header.prev_blockhash),
			}))
		}

		async fn block_header(&self, hash: &BlockHash) -> Result<Header, SourceError> {
			self.find(hash)
				.map(|(_, b, _)| b.header)
				.ok_or_else(|| SourceError::NotFound(hash.to_string()))
		}

		async fn block_filters(
			&self, hashes: &[BlockHash],
		) -> Result<Vec<BlockFilter>, SourceError> {
			if !self.filter_index {
				return Err(SourceError::unavailable(format!(
					"{} (Index is not enabled for filtertype basic)",
					NO_FILTER_INDEX_REASON
				)));
			}
			if !self.filter_delay.is_zero() {
				tokio::time::sleep(self.filter_delay).await;
			}
			*self.filter_reads.lock().unwrap() += hashes.len();
			hashes
				.iter()
				.map(|h| {
					self.find(h)
						.map(|(_, b, _)| self.filter_of(b))
						.ok_or_else(|| SourceError::NotFound(h.to_string()))
				})
				.collect()
		}

		async fn full_block(&self, hash: &BlockHash) -> Result<Block, SourceError> {
			self.block_reads.lock().unwrap().push(*hash);
			let (height, block, _) =
				self.find(hash).ok_or_else(|| SourceError::NotFound(hash.to_string()))?;
			if height < self.pruned_below {
				return Err(SourceError::unavailable(
					"getblock failed (-1): Block not available (pruned data)",
				));
			}
			Ok(block.clone())
		}
	}

	fn limits() -> ScanLimits {
		ScanLimits { max_blocks: FILTER_SCAN_MAX_BLOCKS, filter_budget: Duration::from_secs(60) }
	}

	fn chain_upto(chain: &MemChain, heights: &[u32]) -> Vec<BlockId> {
		heights.iter().map(|h| chain.id(*h)).collect()
	}

	#[tokio::test]
	async fn a_wallet_scan_finds_payments_and_spends_and_connects_its_chain() {
		let mut chain = MemChain::new(10);
		let mine_spk = script(1);
		let change_spk = script(2);
		let theirs = script(9);

		// A payment to us at 11, and a spend of it at 14 that pays nothing of
		// ours: found only because the scan saw the payment first.
		let funding =
			spend(&[OutPoint { txid: Txid::all_zeros(), vout: 7 }], &[(&mine_spk, 10_000)]);
		chain.mine(Vec::new());
		chain.mine(vec![funding.clone()]);
		chain.mine(Vec::new());
		chain.mine(Vec::new());
		let sweep =
			spend(&[OutPoint { txid: funding.compute_txid(), vout: 0 }], &[(&theirs, 9_000)]);
		chain.mine(vec![sweep.clone()]);
		// And a spend of a coin the asker held before the scan.
		let old_coin = OutPoint { txid: Txid::from_byte_array([4; 32]), vout: 1 };
		chain.outputs.insert(old_coin, change_spk.clone());
		let spend_old = spend(&[old_coin], &[(&theirs, 1_000)]);
		chain.mine(vec![spend_old.clone()]);
		chain.mine(Vec::new());

		let req = WalletScan {
			chain: chain_upto(&chain, &[0, 5, 9]),
			spks: vec![mine_spk.clone(), change_spk.clone()],
			txids: HashSet::new(),
			owned: [old_coin].into_iter().collect(),
		};
		let got = scan_wallet(&chain, req, &limits()).await.unwrap();

		let txids: Vec<Txid> = got.found.iter().map(|f| f.tx.compute_txid()).collect();
		assert_eq!(
			txids,
			vec![funding.compute_txid(), sweep.compute_txid(), spend_old.compute_txid()]
		);
		assert_eq!(got.found[0].block, chain.id(11));
		assert_eq!(got.found[1].block, chain.id(14));
		assert_eq!(got.found[2].block, chain.id(15));
		assert_eq!(got.blocks_scanned, 7);
		// The asker's chain below the agreement, every anchor block, the tip.
		assert_eq!(got.checkpoints, chain_upto(&chain, &[0, 5, 9, 11, 14, 15, 16]));
		assert_eq!(got.tip, chain.tip());
		// Only the matching blocks were read in full.
		let reads = chain.block_reads.lock().unwrap().clone();
		assert_eq!(reads, vec![chain.id(11).hash, chain.id(14).hash, chain.id(15).hash]);
	}

	#[tokio::test]
	async fn a_caught_up_wallet_scan_reads_nothing() {
		let chain = MemChain::new(20);
		let req = WalletScan {
			chain: chain_upto(&chain, &[0, 19]),
			spks: vec![script(1)],
			..Default::default()
		};
		let got = scan_wallet(&chain, req, &limits()).await.unwrap();
		assert!(got.found.is_empty());
		assert_eq!(got.blocks_scanned, 0);
		assert_eq!(got.checkpoints, chain_upto(&chain, &[0, 19]));
		assert_eq!(*chain.filter_reads.lock().unwrap(), 0);
	}

	#[tokio::test]
	async fn a_wallet_scan_displaces_stale_checkpoints() {
		let mut chain = MemChain::new(10);
		let mine_spk = script(1);
		let funding =
			spend(&[OutPoint { txid: Txid::all_zeros(), vout: 3 }], &[(&mine_spk, 5_000)]);
		chain.mine(vec![funding.clone()]); // 10
		chain.mine(Vec::new()); // 11
		let old_10 = chain.id(10);
		let old_11 = chain.id(11);

		// Blocks 10 and 11 are replaced; the funding re-confirms at 12.
		chain.reorg(10, 2, Vec::new());
		chain.mine(vec![funding.clone()]); // 12
		chain.mine(Vec::new()); // 13

		let req = WalletScan {
			chain: vec![chain.id(0), chain.id(9), old_10, old_11],
			spks: vec![mine_spk],
			..Default::default()
		};
		let got = scan_wallet(&chain, req, &limits()).await.unwrap();
		assert_eq!(got.found.len(), 1);
		assert_eq!(got.found[0].block, chain.id(12));
		// Heights 10 and 11 carry this node's blocks now, so the asker drops
		// its own — and the anchor on them.
		assert_eq!(got.checkpoints, chain_upto(&chain, &[0, 9, 10, 11, 12, 13]));
		assert_ne!(chain.id(10), old_10);
	}

	#[tokio::test]
	async fn a_wallet_scan_is_capped_and_continues_from_where_it_stopped() {
		let mut chain = MemChain::new(5);
		let mine_spk = script(1);
		for i in 0..30u8 {
			let pay = spend(
				&[OutPoint { txid: Txid::from_byte_array([i; 32]), vout: 0 }],
				&[(&mine_spk, 1_000)],
			);
			chain.mine(if i % 10 == 0 { vec![pay] } else { Vec::new() });
		}
		let small = ScanLimits { max_blocks: 12, filter_budget: Duration::from_secs(60) };

		let mut asker = chain_upto(&chain, &[0, 4]);
		let mut all_found = Vec::new();
		let mut rounds = 0;
		loop {
			rounds += 1;
			let req = WalletScan {
				chain: asker.clone(),
				spks: vec![mine_spk.clone()],
				..Default::default()
			};
			let got = scan_wallet(&chain, req, &small).await.unwrap();
			assert!(got.blocks_scanned <= 12);
			all_found.extend(got.found.iter().map(|f| f.block.height));
			// The partial answer's chain ends at the last block scanned, and
			// the asker's next request carries it.
			let last = *got.checkpoints.last().unwrap();
			assert_eq!(chain.id(last.height), last);
			asker = got.checkpoints;
			if last == chain.tip() {
				break;
			}
			assert_eq!(got.blocks_scanned, 12, "only a capped answer stops short of the tip");
		}
		assert_eq!(rounds, 3);
		assert_eq!(all_found, vec![5, 15, 25]);
	}

	#[tokio::test]
	async fn a_wallet_scan_out_of_time_answers_for_what_it_read() {
		let mut chain = MemChain::new(300);
		chain.filter_delay = Duration::from_millis(100);
		let budget = ScanLimits {
			max_blocks: FILTER_SCAN_MAX_BLOCKS,
			filter_budget: Duration::from_millis(250),
		};
		let req = WalletScan {
			chain: chain_upto(&chain, &[0]),
			spks: vec![script(1)],
			..Default::default()
		};
		let got = scan_wallet(&chain, req, &budget).await.unwrap();
		// Whole batches, at least one, and not the whole span.
		let scanned = got.blocks_scanned as usize;
		assert!(scanned >= FILTER_SCAN_BATCH && scanned < 299, "{}", scanned);
		assert_eq!(scanned % FILTER_SCAN_BATCH, 0);
		assert_eq!(*got.checkpoints.last().unwrap(), chain.id(scanned as u32));
	}

	#[tokio::test]
	async fn wallet_scans_refuse_what_they_cannot_answer_correctly() {
		let mut chain = MemChain::new(10);
		let mine_spk = script(1);

		// Ahead of this node.
		let ahead =
			vec![chain.id(0), BlockId { height: 50, hash: BlockHash::from_byte_array([1; 32]) }];
		let req = WalletScan { chain: ahead, spks: vec![mine_spk.clone()], ..Default::default() };
		assert!(matches!(scan_wallet(&chain, req, &limits()).await, Err(ScanError::Refused(_))));

		// Another network: nothing agrees, not even genesis.
		let alien = vec![BlockId { height: 0, hash: BlockHash::from_byte_array([2; 32]) }];
		let req = WalletScan { chain: alien, spks: vec![mine_spk.clone()], ..Default::default() };
		assert!(matches!(scan_wallet(&chain, req, &limits()).await, Err(ScanError::Refused(_))));

		// No chain at all.
		let req =
			WalletScan { chain: Vec::new(), spks: vec![mine_spk.clone()], ..Default::default() };
		assert!(matches!(scan_wallet(&chain, req, &limits()).await, Err(ScanError::Refused(_))));

		// A pruned block the answer needs.
		let pay = spend(&[OutPoint { txid: Txid::all_zeros(), vout: 0 }], &[(&mine_spk, 1)]);
		chain.mine(vec![pay]);
		chain.pruned_below = 11;
		let req = WalletScan {
			chain: chain_upto(&chain, &[0, 3]),
			spks: vec![mine_spk.clone()],
			..Default::default()
		};
		match scan_wallet(&chain, req, &limits()).await {
			Err(ScanError::Pruned { height: 10, .. }) => {},
			other => panic!("{:?}", other.map(|s| s.checkpoints)),
		}

		// No filter index.
		chain.filter_index = false;
		let req = WalletScan {
			chain: chain_upto(&chain, &[0, 3]),
			spks: vec![mine_spk],
			..Default::default()
		};
		assert!(matches!(
			scan_wallet(&chain, req, &limits()).await,
			Err(ScanError::NoFilterIndex(_))
		));
	}

	#[tokio::test]
	async fn a_lightning_scan_reports_confirmations_spends_and_reorgs() {
		let mut chain = MemChain::new(20);
		let funding_spk = script(5);
		let funding =
			spend(&[OutPoint { txid: Txid::all_zeros(), vout: 1 }], &[(&funding_spk, 100_000)]);
		let funding_op = OutPoint { txid: funding.compute_txid(), vout: 0 };
		chain.mine(vec![funding.clone()]); // 20
		chain.mine(Vec::new()); // 21
		let close = spend(&[funding_op], &[(&script(6), 99_000)]);
		chain.mine(vec![close.clone()]); // 22
		chain.mine(Vec::new()); // 23

		// First sync from 19: the funding confirms, the output is not yet
		// watched.
		let req = LightningScan {
			txs: vec![WatchedTxScan {
				txid: funding.compute_txid(),
				known: None,
				script: Some(funding_spk.clone()),
			}],
			outputs: Vec::new(),
			scan_from: Some(chain.id(19)),
		};
		let got = scan_lightning(&chain, req, &limits()).await.unwrap();
		assert_eq!(got.tip, chain.tip());
		assert_eq!(got.confirmed.len(), 1);
		assert_eq!(got.confirmed[0].block, chain.id(20));
		assert_eq!(got.confirmed[0].pos, 1);
		assert!(got.unconfirmed.is_empty());

		// Asked again from the same block with the output watched too, and
		// the funding known: only the spend is news.
		let req = LightningScan {
			txs: vec![WatchedTxScan {
				txid: funding.compute_txid(),
				known: Some(chain.id(20).hash),
				script: Some(funding_spk.clone()),
			}],
			outputs: vec![(funding_op, funding_spk.clone())],
			scan_from: Some(chain.id(19)),
		};
		let got = scan_lightning(&chain, req.clone(), &limits()).await.unwrap();
		assert_eq!(got.confirmed.len(), 1);
		assert_eq!(got.confirmed[0].tx.compute_txid(), close.compute_txid());
		assert_eq!(got.confirmed[0].block, chain.id(22));

		// Caught up: nothing scanned, nothing said.
		let req_now = LightningScan { scan_from: Some(chain.tip()), ..req.clone() };
		let got = scan_lightning(&chain, req_now, &limits()).await.unwrap();
		assert!(got.confirmed.is_empty() && got.unconfirmed.is_empty());
		assert_eq!(got.blocks_scanned, 0);

		// Reorg from 20: the funding is gone from the best chain. The asker,
		// synced to the old 23, hears it is unconfirmed.
		let old_tip = chain.tip();
		let old_20 = chain.id(20).hash;
		chain.reorg(20, 5, Vec::new());
		let req = LightningScan {
			txs: vec![WatchedTxScan {
				txid: funding.compute_txid(),
				known: Some(old_20),
				script: Some(funding_spk.clone()),
			}],
			outputs: vec![(funding_op, funding_spk.clone())],
			scan_from: Some(old_tip),
		};
		let got = scan_lightning(&chain, req.clone(), &limits()).await.unwrap();
		assert_eq!(got.unconfirmed, vec![funding.compute_txid()]);
		assert!(got.confirmed.is_empty());
		assert_eq!(got.tip, chain.tip());

		// Re-mined on the new branch: confirmed in its new block instead.
		chain.mine(vec![funding.clone()]); // 25
		let got = scan_lightning(&chain, req, &limits()).await.unwrap();
		assert!(got.unconfirmed.is_empty());
		assert_eq!(got.confirmed.len(), 1);
		assert_eq!(got.confirmed[0].block, chain.id(25));
	}

	#[tokio::test]
	async fn a_capped_lightning_scan_reports_its_last_block_as_the_tip() {
		let mut chain = MemChain::new(10);
		let spk = script(5);
		let tx = spend(&[OutPoint { txid: Txid::all_zeros(), vout: 1 }], &[(&spk, 1)]);
		for i in 0..40 {
			chain.mine(if i == 30 { vec![tx.clone()] } else { Vec::new() });
		}
		let small = ScanLimits { max_blocks: 25, filter_budget: Duration::from_secs(60) };
		let watched =
			vec![WatchedTxScan { txid: tx.compute_txid(), known: None, script: Some(spk) }];

		let req = LightningScan {
			txs: watched.clone(),
			outputs: Vec::new(),
			scan_from: Some(chain.id(9)),
		};
		let first = scan_lightning(&chain, req, &small).await.unwrap();
		assert_eq!(first.tip, chain.id(34));
		assert_eq!(first.source_tip, chain.tip());
		assert_eq!(first.tip_header.block_hash(), chain.id(34).hash);
		assert!(first.confirmed.is_empty());

		let req = LightningScan { txs: watched, outputs: Vec::new(), scan_from: Some(first.tip) };
		let second = scan_lightning(&chain, req, &small).await.unwrap();
		assert_eq!(second.tip, chain.tip());
		assert_eq!(second.source_tip, second.tip);
		assert_eq!(second.confirmed.len(), 1);
		assert_eq!(second.confirmed[0].block, chain.id(40));
	}

	#[tokio::test]
	async fn a_lightning_scan_without_a_hint_looks_back_a_day() {
		let mut chain = MemChain::new(300);
		let spk = script(5);
		let tx = spend(&[OutPoint { txid: Txid::all_zeros(), vout: 1 }], &[(&spk, 1)]);
		chain.mine(vec![tx.clone()]);
		let req = LightningScan {
			txs: vec![WatchedTxScan { txid: tx.compute_txid(), known: None, script: Some(spk) }],
			outputs: Vec::new(),
			scan_from: None,
		};
		let got = scan_lightning(&chain, req, &limits()).await.unwrap();
		assert_eq!(got.blocks_scanned, LIGHTNING_FALLBACK_LOOKBACK);
		assert_eq!(got.confirmed.len(), 1);
	}
}
