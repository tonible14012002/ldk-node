// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Conversions between BDK's in-memory sync types and the wire contract in
//! [`crate::chain::provider`].
//!
//! Two directions, used by opposite sides of the link:
//!
//! ```text
//!   DEPENDENT   SyncRequest      -> WireSyncRequest      (drain BDK's own request)
//!               WireUpdate       -> Update               (apply to the wallet)
//!               MempoolQuery     -> WireMempoolRequest   (ask about the mempool)
//!               WireMempoolResponse -> MempoolAnswer     (apply what it holds)
//!   PRO         WireSyncRequest  -> SyncRequest          (rebuild, scan for real)
//!               SyncResponse     -> WireUpdate           (project the answer)
//!               WireMempoolRequest -> MempoolQuery       (ask the local MEMPOOL slot)
//!               MempoolAnswer    -> WireMempoolResponse  (project the answer)
//! ```
//!
//! # The request is drained, not rebuilt
//!
//! The Dependent side never decides *what* to ask about. It takes the request
//! BDK already built and drains it through BDK's own public iterators, so the
//! remote scan covers exactly the scripts, txids and outpoints a local scan
//! would have. Re-deriving that list here would be a second implementation of
//! BDK's selection logic, free to drift from the first.
//!
//! # Derivation stays local
//!
//! `last_active_indices` never crosses the wire. The Dependent node computes
//! it by matching returned transaction outputs against the scripts it sent —
//! it holds that mapping already. Address derivation decides which keys a
//! wallet considers its own, and a Dependent node that accepted a remote
//! node's opinion on that could be walked onto keys it does not control, so
//! [`WireUpdate`] gives a serving node no way to express one.

use std::collections::{BTreeMap, HashMap};

use bitcoin::bip158::{BlockFilter, FilterHeader};
use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{Block, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid};

use bdk_chain::spk_client::{FullScanRequest, SyncRequest, SyncResponse};
use bdk_chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::{KeychainKind, Update};

use crate::chain::cbf::source::{FilterHeaders, IndexedFilter};
use crate::chain::provider::{
	ChainProviderError, WireAnchor, WireBlockChunk, WireBlockId, WireChainTip, WireFilterHeaders,
	WireFilters, WireHeaders, WireIndexedFilter, WireMempoolRequest, WireMempoolResponse,
	WireOutPoint, WireSeenAt, WireSyncRequest, WireTxOut, WireUnconfirmedTx, WireUpdate,
	BLOCK_CHUNK_BYTES, CHAIN_WIRE_VERSION,
};
use crate::chain::seam::{MempoolAnswer, MempoolQuery, MempoolScope};

// ── small helpers ────────────────────────────────────────────────────────────

fn malformed(what: &str, e: impl std::fmt::Display) -> ChainProviderError {
	ChainProviderError::Malformed(format!("{}: {}", what, e))
}

pub(crate) fn check_version(got: u16) -> Result<(), ChainProviderError> {
	if got == CHAIN_WIRE_VERSION {
		Ok(())
	} else {
		Err(ChainProviderError::VersionMismatch { expected: CHAIN_WIRE_VERSION, got })
	}
}

pub(crate) fn txid_to_wire(txid: &Txid) -> String {
	txid.to_string()
}

pub(crate) fn txid_from_wire(s: &str) -> Result<Txid, ChainProviderError> {
	s.parse::<Txid>().map_err(|e| malformed("txid", e))
}

pub(crate) fn block_hash_from_wire(s: &str) -> Result<BlockHash, ChainProviderError> {
	s.parse::<BlockHash>().map_err(|e| malformed("block hash", e))
}

pub(crate) fn script_to_wire(script: &ScriptBuf) -> String {
	script.as_bytes().to_lower_hex_string()
}

pub(crate) fn script_from_wire(s: &str) -> Result<ScriptBuf, ChainProviderError> {
	let bytes = Vec::<u8>::from_hex(s).map_err(|e| malformed("script pubkey", e))?;
	Ok(ScriptBuf::from_bytes(bytes))
}

pub(crate) fn tx_to_wire(tx: &Transaction) -> String {
	serialize(tx).to_lower_hex_string()
}

pub(crate) fn tx_from_wire(s: &str) -> Result<Transaction, ChainProviderError> {
	let bytes = Vec::<u8>::from_hex(s).map_err(|e| malformed("transaction hex", e))?;
	deserialize(&bytes).map_err(|e| malformed("transaction", e))
}

pub(crate) fn header_to_wire(header: &bitcoin::block::Header) -> String {
	serialize(header).to_lower_hex_string()
}

pub(crate) fn header_from_wire(s: &str) -> Result<bitcoin::block::Header, ChainProviderError> {
	let bytes = Vec::<u8>::from_hex(s).map_err(|e| malformed("header hex", e))?;
	deserialize(&bytes).map_err(|e| malformed("block header", e))
}

pub(crate) fn outpoint_to_wire(op: &OutPoint) -> WireOutPoint {
	WireOutPoint { txid: txid_to_wire(&op.txid), vout: op.vout }
}

pub(crate) fn outpoint_from_wire(op: &WireOutPoint) -> Result<OutPoint, ChainProviderError> {
	Ok(OutPoint { txid: txid_from_wire(&op.txid)?, vout: op.vout })
}

pub(crate) fn block_id_to_wire(b: &BlockId) -> WireBlockId {
	WireBlockId { height: b.height, hash: b.hash.to_string() }
}

pub(crate) fn block_id_from_wire(b: &WireBlockId) -> Result<BlockId, ChainProviderError> {
	Ok(BlockId { height: b.height, hash: block_hash_from_wire(&b.hash)? })
}

/// A checkpoint chain, flattened oldest-first.
pub(crate) fn checkpoint_to_wire(tip: &CheckPoint) -> Vec<WireBlockId> {
	let mut blocks: Vec<WireBlockId> =
		tip.iter().map(|cp| block_id_to_wire(&cp.block_id())).collect();
	// `CheckPoint::iter` walks tip -> genesis; the wire is ascending.
	blocks.reverse();
	blocks
}

/// Rebuild a checkpoint chain from the wire.
///
/// `CheckPoint::from_block_ids` demands strictly ascending heights and rejects
/// anything else, so a malformed or reordered chain fails here rather than
/// corrupting the wallet's view of the chain.
pub(crate) fn checkpoint_from_wire(
	blocks: &[WireBlockId],
) -> Result<Option<CheckPoint>, ChainProviderError> {
	if blocks.is_empty() {
		return Ok(None);
	}
	let ids = blocks.iter().map(block_id_from_wire).collect::<Result<Vec<_>, _>>()?;
	CheckPoint::from_block_ids(ids)
		.map(Some)
		.map_err(|_| ChainProviderError::Malformed("checkpoint chain is not ascending".into()))
}

// ── DEPENDENT: outbound request ──────────────────────────────────────────────

/// Drain an incremental [`SyncRequest`] into its wire form.
///
/// Consumes the request: BDK's accessors are draining iterators, and a request
/// that has been read cannot be scanned again locally anyway.
pub(crate) fn sync_request_to_wire(mut req: SyncRequest<(KeychainKind, u32)>) -> WireSyncRequest {
	let start_time = req.start_time();
	let chain_tip = req.chain_tip().as_ref().map(checkpoint_to_wire).unwrap_or_default();

	let spks: Vec<String> =
		req.iter_spks_with_expected_txids().map(|item| script_to_wire(&item.spk)).collect();
	let txids: Vec<String> = req.iter_txids().map(|t| txid_to_wire(&t)).collect();
	let outpoints: Vec<WireOutPoint> = req.iter_outpoints().map(|o| outpoint_to_wire(&o)).collect();

	WireSyncRequest {
		version: CHAIN_WIRE_VERSION,
		start_time,
		chain_tip,
		spks,
		txids,
		outpoints,
		full_scan: false,
		stop_gap: 0,
	}
}

/// Drain one batch of a [`FullScanRequest`] into wire form.
///
/// A full scan derives addresses without bound until `stop_gap` consecutive
/// unused ones are seen. The serving node cannot derive — it has none of this
/// wallet's descriptors — so the scan is driven from here in bounded batches,
/// exactly as `bdk_esplora` drives it against a local provider. The caller
/// repeats with a fresh request while activity keeps appearing near the end of
/// a batch.
pub(crate) fn full_scan_request_batch_to_wire(
	req: &mut FullScanRequest<KeychainKind>, batch_size: u32, stop_gap: u32,
) -> WireSyncRequest {
	let start_time = req.start_time();
	let chain_tip = req.chain_tip().as_ref().map(checkpoint_to_wire).unwrap_or_default();

	let mut spks = Vec::new();
	for keychain in req.keychains() {
		let taken = req
			.iter_spks(keychain)
			.take(batch_size as usize)
			.map(|(_index, spk)| script_to_wire(&spk))
			.collect::<Vec<_>>();
		spks.extend(taken);
	}

	WireSyncRequest {
		version: CHAIN_WIRE_VERSION,
		start_time,
		chain_tip,
		spks,
		txids: Vec::new(),
		outpoints: Vec::new(),
		full_scan: true,
		stop_gap,
	}
}

// ── DEPENDENT: inbound update ────────────────────────────────────────────────

/// Turn a wire update into a BDK [`Update`] the wallet can apply.
///
/// `sent_spks` is the script → (keychain, index) mapping the Dependent node
/// used when it built the request; it is the authority for
/// `last_active_indices`. See the module docs for why that is not taken from
/// the wire.
pub(crate) fn wire_update_to_bdk(
	wire: &WireUpdate, sent_spks: &HashMap<ScriptBuf, (KeychainKind, u32)>,
) -> Result<Update, ChainProviderError> {
	check_version(wire.version)?;

	let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();

	let mut txs = Vec::with_capacity(wire.txs.len());
	for hex in &wire.txs {
		txs.push(std::sync::Arc::new(tx_from_wire(hex)?));
	}

	// Which of our own scripts showed activity, and at what index. Computed
	// from the returned transactions rather than trusted from the reply.
	let mut last_active: BTreeMap<KeychainKind, u32> = BTreeMap::new();
	for tx in &txs {
		for txout in &tx.output {
			if let Some((keychain, index)) = sent_spks.get(&txout.script_pubkey) {
				last_active
					.entry(*keychain)
					.and_modify(|cur| *cur = (*cur).max(*index))
					.or_insert(*index);
			}
		}
	}

	tx_update.txs = txs;

	for txout in &wire.txouts {
		let outpoint = outpoint_from_wire(&txout.outpoint)?;
		let script_pubkey = script_from_wire(&txout.script_hex)?;
		tx_update.txouts.insert(
			outpoint,
			TxOut { value: bitcoin::Amount::from_sat(txout.value_sat), script_pubkey },
		);
	}

	for anchor in &wire.anchors {
		let txid = txid_from_wire(&anchor.txid)?;
		let block_id = block_id_from_wire(&anchor.block)?;
		tx_update.anchors.insert((
			ConfirmationBlockTime { block_id, confirmation_time: anchor.confirmation_time },
			txid,
		));
	}

	for seen in &wire.seen_ats {
		tx_update.seen_ats.insert((txid_from_wire(&seen.txid)?, seen.seen_at));
	}

	let chain = checkpoint_from_wire(&wire.checkpoints)?;

	Ok(Update { last_active_indices: last_active, tx_update, chain })
}

// ── DEPENDENT: mempool ───────────────────────────────────────────────────────

/// Ask a provider what a [`MempoolQuery`] asks. The scope does not travel:
/// a provider remembers nothing about the asker and answers completely.
pub(crate) fn mempool_query_to_wire(query: &MempoolQuery) -> WireMempoolRequest {
	WireMempoolRequest {
		version: CHAIN_WIRE_VERSION,
		spks: query.scripts.iter().map(script_to_wire).collect(),
		known_unconfirmed: query.known_unconfirmed.iter().map(txid_to_wire).collect(),
	}
}

/// Turn a provider's answer into a [`MempoolAnswer`] and the tip it was
/// taken at.
///
/// `evicted_at` is the asker's own clock: the wire carries no eviction time,
/// and the moment this node learned of the eviction is the moment that
/// matters to its wallet.
pub(crate) fn wire_to_mempool_answer(
	wire: &WireMempoolResponse, evicted_at: u64,
) -> Result<(MempoolAnswer, BlockId), ChainProviderError> {
	check_version(wire.version)?;
	let tip = block_id_from_wire(&wire.tip)?;
	let unconfirmed = wire
		.unconfirmed
		.iter()
		.map(|entry| Ok((tx_from_wire(&entry.tx_hex)?, entry.seen_at)))
		.collect::<Result<Vec<_>, ChainProviderError>>()?;
	let evicted = wire
		.evicted
		.iter()
		.map(|txid| Ok((txid_from_wire(txid)?, evicted_at)))
		.collect::<Result<Vec<_>, ChainProviderError>>()?;
	Ok((MempoolAnswer { unconfirmed, evicted }, tip))
}

// ── PRO: mempool ─────────────────────────────────────────────────────────────

/// Rebuild another node's question as a [`MempoolQuery`] for the local
/// MEMPOOL slot. Always [`MempoolScope::Complete`]: nothing is remembered
/// about the asker, so nothing can be left out.
pub(crate) fn wire_to_mempool_query(
	wire: &WireMempoolRequest,
) -> Result<MempoolQuery, ChainProviderError> {
	check_version(wire.version)?;
	let scripts = wire.spks.iter().map(|s| script_from_wire(s)).collect::<Result<Vec<_>, _>>()?;
	let known_unconfirmed =
		wire.known_unconfirmed.iter().map(|t| txid_from_wire(t)).collect::<Result<Vec<_>, _>>()?;
	Ok(MempoolQuery { scripts, known_unconfirmed, scope: MempoolScope::Complete })
}

/// Project the local slot's answer, taken at `tip`, onto the wire. Eviction
/// times stay behind; see [`WireMempoolResponse::evicted`].
pub(crate) fn mempool_answer_to_wire(answer: &MempoolAnswer, tip: &BlockId) -> WireMempoolResponse {
	WireMempoolResponse {
		version: CHAIN_WIRE_VERSION,
		tip: block_id_to_wire(tip),
		unconfirmed: answer
			.unconfirmed
			.iter()
			.map(|(tx, seen_at)| WireUnconfirmedTx { tx_hex: tx_to_wire(tx), seen_at: *seen_at })
			.collect(),
		evicted: answer.evicted.iter().map(|(txid, _)| txid_to_wire(txid)).collect(),
	}
}

// ── PRO: inbound request ─────────────────────────────────────────────────────

/// Rebuild a real [`SyncRequest`] from the wire so the serving node can run an
/// ordinary scan against its own chain source.
///
/// Indexed by the caller's own `(keychain, index)` pair so nothing about the
/// requesting wallet has to be inferred here.
pub(crate) fn wire_to_sync_request(
	wire: &WireSyncRequest,
) -> Result<SyncRequest<()>, ChainProviderError> {
	check_version(wire.version)?;

	let mut builder = SyncRequest::<()>::builder_at(wire.start_time);

	// The whole chain, not a lone block: the scan below inserts blocks beneath
	// the tip, and a checkpoint that cannot be walked back to genesis panics
	// rather than return an error.
	if let Some(tip) = checkpoint_from_wire(&wire.chain_tip)? {
		builder = builder.chain_tip(tip);
	}

	let spks = wire.spks.iter().map(|s| script_from_wire(s)).collect::<Result<Vec<_>, _>>()?;
	builder = builder.spks(spks);

	let txids = wire.txids.iter().map(|t| txid_from_wire(t)).collect::<Result<Vec<_>, _>>()?;
	builder = builder.txids(txids);

	let outpoints = wire.outpoints.iter().map(outpoint_from_wire).collect::<Result<Vec<_>, _>>()?;
	builder = builder.outpoints(outpoints);

	Ok(builder.build())
}

// ── PRO: outbound update ─────────────────────────────────────────────────────

/// Project a completed scan into wire form.
pub(crate) fn sync_response_to_wire(resp: SyncResponse) -> WireUpdate {
	let SyncResponse { tx_update, chain_update, .. } = resp;
	tx_update_to_wire(tx_update, chain_update)
}

/// Shared projection of a `TxUpdate` plus a chain tip.
pub(crate) fn tx_update_to_wire(
	tx_update: TxUpdate<ConfirmationBlockTime>, chain_update: Option<CheckPoint>,
) -> WireUpdate {
	let txs = tx_update.txs.iter().map(|tx| tx_to_wire(tx)).collect();

	let txouts = tx_update
		.txouts
		.iter()
		.map(|(outpoint, txout)| WireTxOut {
			outpoint: outpoint_to_wire(outpoint),
			value_sat: txout.value.to_sat(),
			script_hex: script_to_wire(&txout.script_pubkey),
		})
		.collect();

	let anchors = tx_update
		.anchors
		.iter()
		.map(|(anchor, txid)| WireAnchor {
			txid: txid_to_wire(txid),
			block: block_id_to_wire(&anchor.block_id),
			confirmation_time: anchor.confirmation_time,
		})
		.collect();

	let seen_ats = tx_update
		.seen_ats
		.iter()
		.map(|(txid, seen_at)| WireSeenAt { txid: txid_to_wire(txid), seen_at: *seen_at })
		.collect();

	let checkpoints = chain_update.as_ref().map(checkpoint_to_wire).unwrap_or_default();

	WireUpdate { version: CHAIN_WIRE_VERSION, txs, txouts, anchors, seen_ats, checkpoints }
}

// ── RAW BIP157 DATA (both sides) ─────────────────────────────────────────────
//
// Public, unlike the rest of this module: an app implementing a network-backed
// `FilterSource` decodes these replies itself. Decoding checks shape only —
// that a header is 80 bytes, a hash parses, a block's bytes hash to the block
// asked for. Whether the data is *true* is for the verifying client.

fn filter_header_from_wire(s: &str) -> Result<FilterHeader, ChainProviderError> {
	s.parse::<FilterHeader>().map_err(|e| malformed("filter header", e))
}

/// A raw source's tip, projected onto the wire.
pub fn chain_tip_to_wire(tip: &BlockId) -> WireChainTip {
	WireChainTip { version: CHAIN_WIRE_VERSION, tip: block_id_to_wire(tip) }
}

/// A raw source's tip, decoded from the wire.
pub fn chain_tip_from_wire(wire: &WireChainTip) -> Result<BlockId, ChainProviderError> {
	check_version(wire.version)?;
	block_id_from_wire(&wire.tip)
}

/// Headers, projected onto the wire.
pub fn headers_to_wire(headers: &[Header]) -> WireHeaders {
	WireHeaders {
		version: CHAIN_WIRE_VERSION,
		headers: headers.iter().map(header_to_wire).collect(),
	}
}

/// Headers, decoded from the wire.
pub fn headers_from_wire(wire: &WireHeaders) -> Result<Vec<Header>, ChainProviderError> {
	check_version(wire.version)?;
	wire.headers.iter().map(|h| header_from_wire(h)).collect()
}

/// A span's filter headers, projected onto the wire.
pub fn filter_headers_to_wire(filter_headers: &FilterHeaders) -> WireFilterHeaders {
	WireFilterHeaders {
		version: CHAIN_WIRE_VERSION,
		previous: filter_headers.previous.to_string(),
		headers: filter_headers.headers.iter().map(|h| h.to_string()).collect(),
	}
}

/// A span's filter headers, decoded from the wire.
pub fn filter_headers_from_wire(
	wire: &WireFilterHeaders,
) -> Result<FilterHeaders, ChainProviderError> {
	check_version(wire.version)?;
	Ok(FilterHeaders {
		previous: filter_header_from_wire(&wire.previous)?,
		headers: wire
			.headers
			.iter()
			.map(|h| filter_header_from_wire(h))
			.collect::<Result<_, _>>()?,
	})
}

/// Filters, projected onto the wire.
pub fn filters_to_wire(filters: &[IndexedFilter]) -> WireFilters {
	WireFilters {
		version: CHAIN_WIRE_VERSION,
		filters: filters
			.iter()
			.map(|f| WireIndexedFilter {
				height: f.height,
				block_hash: f.block_hash.to_string(),
				filter_hex: f.filter.content.to_lower_hex_string(),
			})
			.collect(),
	}
}

/// Filters, decoded from the wire.
pub fn filters_from_wire(wire: &WireFilters) -> Result<Vec<IndexedFilter>, ChainProviderError> {
	check_version(wire.version)?;
	wire.filters
		.iter()
		.map(|f| {
			let content = Vec::<u8>::from_hex(&f.filter_hex).map_err(|e| malformed("filter", e))?;
			Ok(IndexedFilter {
				height: f.height,
				block_hash: block_hash_from_wire(&f.block_hash)?,
				filter: BlockFilter { content },
			})
		})
		.collect()
}

/// How many [`BLOCK_CHUNK_BYTES`] chunks a block of `len` bytes takes; at
/// least one, so even an empty answer has a chunk 0.
pub fn block_chunk_count(len: usize) -> u32 {
	(len.div_ceil(BLOCK_CHUNK_BYTES)).max(1) as u32
}

/// Chunk `chunk` of the consensus-encoded block `block_bytes`, or `None` when
/// the block has no such chunk.
pub fn block_chunk_to_wire(
	hash: &BlockHash, block_bytes: &[u8], chunk: u32,
) -> Option<WireBlockChunk> {
	let total_chunks = block_chunk_count(block_bytes.len());
	if chunk >= total_chunks {
		return None;
	}
	let start = chunk as usize * BLOCK_CHUNK_BYTES;
	let end = (start + BLOCK_CHUNK_BYTES).min(block_bytes.len());
	Some(WireBlockChunk {
		version: CHAIN_WIRE_VERSION,
		hash: hash.to_string(),
		chunk,
		total_chunks,
		bytes_hex: block_bytes[start..end].to_lower_hex_string(),
	})
}

/// The most chunks a block may claim: a consensus-valid block serialises to
/// at most 4 MB (every byte weighs at least one unit), so anything claiming
/// more is refused before it is buffered.
const MAX_BLOCK_CHUNKS: u32 = (4_000_000usize.div_ceil(BLOCK_CHUNK_BYTES)) as u32;

/// Reassembles a block from its [`WireBlockChunk`]s, in order.
///
/// Refuses — [`ChainProviderError::Malformed`] — a chunk for another block,
/// out of order, of the wrong size, claiming a different or implausible
/// chunk count, or a finished block whose bytes do not hash to the block
/// asked for.
#[derive(Debug)]
pub struct BlockChunkAssembler {
	hash: BlockHash,
	total_chunks: Option<u32>,
	next_chunk: u32,
	bytes: Vec<u8>,
}

impl BlockChunkAssembler {
	/// Start assembling block `hash`.
	pub fn new(hash: BlockHash) -> Self {
		Self { hash, total_chunks: None, next_chunk: 0, bytes: Vec::new() }
	}

	/// The chunk index to ask for next.
	pub fn next_chunk(&self) -> u32 {
		self.next_chunk
	}

	/// Add the next chunk. `Ok(Some(block))` once the last one is in.
	pub fn push(&mut self, wire: &WireBlockChunk) -> Result<Option<Block>, ChainProviderError> {
		check_version(wire.version)?;
		if block_hash_from_wire(&wire.hash)? != self.hash {
			return Err(ChainProviderError::Malformed("block chunk for another block".into()));
		}
		if wire.chunk != self.next_chunk {
			return Err(ChainProviderError::Malformed(format!(
				"block chunk {} out of order, expected {}",
				wire.chunk, self.next_chunk
			)));
		}
		if wire.total_chunks == 0 || wire.total_chunks > MAX_BLOCK_CHUNKS {
			return Err(ChainProviderError::Malformed(format!(
				"implausible block chunk count {}",
				wire.total_chunks
			)));
		}
		if *self.total_chunks.get_or_insert(wire.total_chunks) != wire.total_chunks {
			return Err(ChainProviderError::Malformed("block chunk count changed".into()));
		}
		let bytes =
			Vec::<u8>::from_hex(&wire.bytes_hex).map_err(|e| malformed("block chunk", e))?;
		let last = wire.chunk + 1 == wire.total_chunks;
		let size_ok = if last {
			!bytes.is_empty() && bytes.len() <= BLOCK_CHUNK_BYTES
		} else {
			bytes.len() == BLOCK_CHUNK_BYTES
		};
		if !size_ok {
			return Err(ChainProviderError::Malformed(format!(
				"block chunk {} has {} bytes",
				wire.chunk,
				bytes.len()
			)));
		}
		self.bytes.extend_from_slice(&bytes);
		self.next_chunk += 1;
		if !last {
			return Ok(None);
		}
		let block: Block = deserialize(&self.bytes).map_err(|e| malformed("block", e))?;
		if block.block_hash() != self.hash {
			return Err(ChainProviderError::Malformed("block bytes hash to another block".into()));
		}
		Ok(Some(block))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hashes::Hash;
	use bitcoin::{absolute, transaction, Amount, TxOut};

	use crate::chain::provider::WireTxStatusResponse;

	/// N4: a mempool question and its answer survive the wire in both
	/// directions, and the answer comes back stamped on the asker's clock.
	#[test]
	fn mempool_request_response_roundtrip() {
		let script = ScriptBuf::from_bytes(vec![0x00, 0x14, 0xde, 0xad, 0xbe, 0xef]);
		let known = Txid::from_byte_array([7u8; 32]);
		let query = MempoolQuery {
			scripts: vec![script.clone()],
			known_unconfirmed: vec![known],
			scope: MempoolScope::Incremental { best_processed_height: 100 },
		};

		let wire = mempool_query_to_wire(&query);
		let json = serde_json::to_string(&wire).unwrap();
		let decoded: WireMempoolRequest = serde_json::from_str(&json).unwrap();
		assert_eq!(decoded, wire);
		assert_eq!(decoded.version, CHAIN_WIRE_VERSION);

		let rebuilt = wire_to_mempool_query(&decoded).unwrap();
		assert_eq!(rebuilt.scripts, vec![script.clone()]);
		assert_eq!(rebuilt.known_unconfirmed, vec![known]);
		assert_eq!(rebuilt.scope, MempoolScope::Complete, "the scope does not travel");

		let tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: Vec::new(),
			output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: script }],
		};
		let tip = BlockId { height: 101, hash: BlockHash::from_byte_array([1u8; 32]) };
		let answer = MempoolAnswer {
			unconfirmed: vec![(tx.clone(), 1_700_000_000)],
			evicted: vec![(known, 1_700_000_001)],
		};

		let wire = mempool_answer_to_wire(&answer, &tip);
		let json = serde_json::to_string(&wire).unwrap();
		let decoded: WireMempoolResponse = serde_json::from_str(&json).unwrap();
		assert_eq!(decoded, wire);

		let (rebuilt, rebuilt_tip) = wire_to_mempool_answer(&decoded, 42).unwrap();
		assert_eq!(rebuilt_tip, tip);
		assert_eq!(rebuilt.unconfirmed, vec![(tx, 1_700_000_000)]);
		assert_eq!(
			rebuilt.evicted,
			vec![(known, 42)],
			"evictions are stamped on the asker's clock"
		);

		let mut stale = decoded;
		stale.version += 1;
		assert!(matches!(
			wire_to_mempool_answer(&stale, 42),
			Err(ChainProviderError::VersionMismatch { .. })
		));
	}

	/// N4: `tip_hash` was added after the port shipped, so an answer written
	/// without it — by a serving node running the older crate — still decodes.
	#[test]
	fn tx_status_response_without_tip_hash_still_decodes() {
		let json = r#"{"version":1,"confirmed":true,"in_mempool":false,"confirmation_height":10,"tip_height":12}"#;
		let decoded: WireTxStatusResponse = serde_json::from_str(json).unwrap();
		assert_eq!(decoded.tip_hash, None);
		assert_eq!(decoded.confirmation_height, Some(10));
		assert_eq!(decoded.tip_height, Some(12));

		let json = r#"{"version":1,"confirmed":true,"in_mempool":false,"confirmation_height":10,"tip_height":12,"tip_hash":"ab"}"#;
		let decoded: WireTxStatusResponse = serde_json::from_str(json).unwrap();
		assert_eq!(decoded.tip_hash.as_deref(), Some("ab"));
	}

	#[test]
	fn version_mismatch_is_rejected() {
		assert!(check_version(CHAIN_WIRE_VERSION).is_ok());
		match check_version(CHAIN_WIRE_VERSION + 1) {
			Err(ChainProviderError::VersionMismatch { expected, got }) => {
				assert_eq!(expected, CHAIN_WIRE_VERSION);
				assert_eq!(got, CHAIN_WIRE_VERSION + 1);
			},
			other => panic!("expected a version mismatch, got {:?}", other),
		}
	}

	#[test]
	fn script_round_trips() {
		let script = ScriptBuf::from_bytes(vec![0x00, 0x14, 0xde, 0xad, 0xbe, 0xef]);
		assert_eq!(script_from_wire(&script_to_wire(&script)).unwrap(), script);
	}

	#[test]
	fn non_ascending_checkpoints_are_rejected() {
		let hash = BlockHash::all_zeros();
		let blocks = vec![
			WireBlockId { height: 10, hash: hash.to_string() },
			WireBlockId { height: 5, hash: hash.to_string() },
		];
		assert!(checkpoint_from_wire(&blocks).is_err());
	}

	#[test]
	fn empty_checkpoints_mean_no_chain_update() {
		assert!(checkpoint_from_wire(&[]).unwrap().is_none());
	}

	/// Build a wire chain whose heights ascend from genesis.
	fn wire_chain(heights: &[u32]) -> Vec<WireBlockId> {
		heights
			.iter()
			.map(|h| {
				let mut bytes = [0u8; 32];
				bytes[0..4].copy_from_slice(&h.to_le_bytes());
				WireBlockId { height: *h, hash: BlockHash::from_byte_array(bytes).to_string() }
			})
			.collect()
	}

	/// The reason the whole chain travels instead of only its tip.
	///
	/// A scan on the serving node inserts blocks *beneath* the tip — one per
	/// confirmation it found. `CheckPoint::insert` walks backwards expecting
	/// to reach genesis, so a request carrying a lone block panics there
	/// rather than returning an error. Carrying the chain is what makes the
	/// insert land.
	#[test]
	fn a_request_chain_survives_an_insert_below_its_tip() {
		let wire = WireSyncRequest {
			version: CHAIN_WIRE_VERSION,
			start_time: 0,
			chain_tip: wire_chain(&[0, 100, 200]),
			spks: Vec::new(),
			txids: Vec::new(),
			outpoints: Vec::new(),
			full_scan: false,
			stop_gap: 0,
		};

		let req = wire_to_sync_request(&wire).unwrap();
		let tip = req.chain_tip().expect("the chain tip survived the wire");
		assert_eq!(tip.height(), 200);

		// Height 150 sits below the tip and is not yet in the chain — exactly
		// the shape that used to panic.
		let widened =
			tip.insert(BlockId { height: 150, hash: BlockHash::from_byte_array([9u8; 32]) });
		assert_eq!(widened.height(), 200);
		assert!(widened.get(150).is_some());
		assert!(widened.get(0).is_some(), "the chain still reaches genesis");
	}
}

/// A block of about `payload` bytes — one transaction with one output whose
/// script is `payload` bytes — for exercising chunking. Not consensus-valid;
/// it only has to round-trip.
#[cfg(test)]
pub(crate) fn synthetic_block(payload: usize, nonce: u32) -> Block {
	use bitcoin::block::Version as BlockVersion;
	use bitcoin::hashes::Hash;
	use bitcoin::{absolute, transaction, Amount, CompactTarget, TxIn, TxMerkleNode};
	Block {
		header: Header {
			version: BlockVersion::ONE,
			prev_blockhash: BlockHash::all_zeros(),
			merkle_root: TxMerkleNode::all_zeros(),
			time: 0,
			bits: CompactTarget::from_consensus(0x207fffff),
			nonce,
		},
		txdata: vec![Transaction {
			version: transaction::Version::ONE,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn::default()],
			output: vec![TxOut {
				value: Amount::ZERO,
				script_pubkey: ScriptBuf::from_bytes(vec![0x6a; payload]),
			}],
		}],
	}
}

#[cfg(test)]
mod raw_tests {
	use super::*;
	use bitcoin::hashes::Hash;

	fn chained_headers(n: u32) -> Vec<Header> {
		let mut headers: Vec<Header> = Vec::new();
		for i in 0..n {
			let mut header = synthetic_block(1, i).header;
			if let Some(prev) = headers.last() {
				header.prev_blockhash = prev.block_hash();
			}
			headers.push(header);
		}
		headers
	}

	#[test]
	fn raw_wire_types_round_trip() {
		let headers = chained_headers(5);
		let wire = headers_to_wire(&headers);
		assert_eq!(wire.headers[0].len(), 160, "80 bytes, hex");
		assert_eq!(headers_from_wire(&wire).unwrap(), headers);

		let tip = BlockId { height: 812_345, hash: headers[4].block_hash() };
		assert_eq!(chain_tip_from_wire(&chain_tip_to_wire(&tip)).unwrap(), tip);

		let filters: Vec<IndexedFilter> = headers
			.iter()
			.enumerate()
			.map(|(i, h)| IndexedFilter {
				height: 100 + i as u32,
				block_hash: h.block_hash(),
				filter: BlockFilter::new(&[1, 2, 3, i as u8]),
			})
			.collect();
		assert_eq!(filters_from_wire(&filters_to_wire(&filters)).unwrap(), filters);

		let mut prev = FilterHeader::all_zeros();
		let chain: Vec<FilterHeader> = filters
			.iter()
			.map(|f| {
				prev = f.filter.filter_header(&prev);
				prev
			})
			.collect();
		let filter_headers =
			FilterHeaders { previous: FilterHeader::from_byte_array([3u8; 32]), headers: chain };
		let wire = filter_headers_to_wire(&filter_headers);
		assert_eq!(filter_headers_from_wire(&wire).unwrap(), filter_headers);

		// The JSON form round-trips too: this is what crosses the network.
		let json = serde_json::to_string(&wire).unwrap();
		assert_eq!(serde_json::from_str::<WireFilterHeaders>(&json).unwrap(), wire);
	}

	#[test]
	fn raw_wire_refuses_other_versions_and_garbage() {
		let mut wire = headers_to_wire(&chained_headers(1));
		wire.version = CHAIN_WIRE_VERSION + 1;
		assert!(matches!(
			headers_from_wire(&wire),
			Err(ChainProviderError::VersionMismatch { .. })
		));

		let wire = WireHeaders { version: CHAIN_WIRE_VERSION, headers: vec!["00ff".into()] };
		assert!(matches!(headers_from_wire(&wire), Err(ChainProviderError::Malformed(_))));

		let wire = WireFilters {
			version: CHAIN_WIRE_VERSION,
			filters: vec![WireIndexedFilter {
				height: 1,
				block_hash: "not a hash".into(),
				filter_hex: "00".into(),
			}],
		};
		assert!(matches!(filters_from_wire(&wire), Err(ChainProviderError::Malformed(_))));
	}

	#[test]
	fn chunk_math() {
		assert_eq!(block_chunk_count(0), 1);
		assert_eq!(block_chunk_count(1), 1);
		assert_eq!(block_chunk_count(BLOCK_CHUNK_BYTES), 1);
		assert_eq!(block_chunk_count(BLOCK_CHUNK_BYTES + 1), 2);
		assert_eq!(block_chunk_count(4_000_000), MAX_BLOCK_CHUNKS);
		// A full chunk, hex, with its JSON envelope, stays well under the
		// 2 MiB a relayed message may carry.
		let hash = BlockHash::all_zeros();
		let chunk = block_chunk_to_wire(&hash, &vec![0u8; BLOCK_CHUNK_BYTES], 0).unwrap();
		assert!(serde_json::to_vec(&chunk).unwrap().len() < 1_700_000);
	}

	/// A block over 1 MiB is served in more than one chunk and reassembles to
	/// exactly the original bytes.
	#[test]
	fn a_large_block_reassembles_from_its_chunks() {
		let block = synthetic_block(1_300_000, 7);
		let bytes = serialize(&block);
		let hash = block.block_hash();
		let total = block_chunk_count(bytes.len());
		assert_eq!(total, 2);
		assert!(block_chunk_to_wire(&hash, &bytes, total).is_none(), "no chunk past the end");

		let mut assembler = BlockChunkAssembler::new(hash);
		let mut rebuilt = None;
		while rebuilt.is_none() {
			let chunk = block_chunk_to_wire(&hash, &bytes, assembler.next_chunk()).unwrap();
			assert_eq!(chunk.total_chunks, total);
			rebuilt = assembler.push(&chunk).unwrap();
		}
		let rebuilt = rebuilt.unwrap();
		assert_eq!(serialize(&rebuilt), bytes);
		assert_eq!(rebuilt, block);
	}

	#[test]
	fn the_assembler_refuses_what_does_not_add_up() {
		let block = synthetic_block(1_300_000, 7);
		let bytes = serialize(&block);
		let hash = block.block_hash();
		let first = block_chunk_to_wire(&hash, &bytes, 0).unwrap();
		let second = block_chunk_to_wire(&hash, &bytes, 1).unwrap();

		// Out of order.
		assert!(BlockChunkAssembler::new(hash).push(&second).is_err());
		// Another block's assembler.
		let other = synthetic_block(10, 8).block_hash();
		assert!(BlockChunkAssembler::new(other).push(&first).is_err());
		// A chunk count that changes midway, or is implausible.
		let mut assembler = BlockChunkAssembler::new(hash);
		assembler.push(&first).unwrap();
		assert!(assembler.push(&WireBlockChunk { total_chunks: 3, ..second.clone() }).is_err());
		assert!(BlockChunkAssembler::new(hash)
			.push(&WireBlockChunk { total_chunks: 1_000, ..first.clone() })
			.is_err());
		// A short middle chunk.
		let short = WireBlockChunk { bytes_hex: "00".into(), ..first.clone() };
		assert!(BlockChunkAssembler::new(hash).push(&short).is_err());
		// Tampered bytes: the block no longer hashes to what was asked.
		let tampered = synthetic_block(1_300_000, 9);
		let tampered_bytes = serialize(&tampered);
		let mut assembler = BlockChunkAssembler::new(hash);
		assembler.push(&block_chunk_to_wire(&hash, &tampered_bytes, 0).unwrap()).unwrap();
		assert!(assembler.push(&block_chunk_to_wire(&hash, &tampered_bytes, 1).unwrap()).is_err());
	}
}
