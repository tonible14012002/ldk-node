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
//!   PRO         WireSyncRequest  -> SyncRequest          (rebuild, scan for real)
//!               SyncResponse     -> WireUpdate           (project the answer)
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

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid};

use bdk_chain::spk_client::{FullScanRequest, SyncRequest, SyncResponse};
use bdk_chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::{KeychainKind, Update};

use crate::chain::provider::{
	ChainProviderError, WireAnchor, WireBlockId, WireOutPoint, WireSeenAt, WireSyncRequest,
	WireTxOut, WireUpdate, CHAIN_WIRE_VERSION,
};

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

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hashes::Hash;

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
				WireBlockId {
					height: *h,
					hash: BlockHash::from_byte_array(bytes).to_string(),
				}
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
		let widened = tip.insert(BlockId {
			height: 150,
			hash: BlockHash::from_byte_array([9u8; 32]),
		});
		assert_eq!(widened.height(), 200);
		assert!(widened.get(150).is_some());
		assert!(widened.get(0).is_some(), "the chain still reaches genesis");
	}
}
