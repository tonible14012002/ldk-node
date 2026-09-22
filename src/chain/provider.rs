// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The **remote chain provider** port and its wire contract.
//!
//! This is the one public seam a Dependent node is built on. A Dependent node
//! has no chain provider of its own; it asks another node — a Pro node — and
//! believes the answer. The transport is deliberately *not* described here:
//! implementors of [`ChainDataProvider`] own it entirely, which is what keeps
//! this crate free of any knowledge of peers, routes or capabilities.
//!
//! ```text
//!   node-app-ldk-node          ldk-node
//!   ─────────────────          ────────
//!   impl ChainDataProvider  ->  DependentChainAdapter   fills FEE/LOOKUP/BROADCAST
//!     core.network.send         DependentSyncEngine     fills the sync axis
//! ```
//!
//! # Why the wire types live here
//!
//! BDK's own sync types cannot cross a process boundary: [`SyncRequest`] holds
//! a boxed closure behind private fields, and `TxUpdate` is `#[non_exhaustive]`
//! with no `serde` derives. So the projection has to exist somewhere, and it
//! belongs on the side that owns the semantics — here — rather than being
//! reinvented per transport.
//!
//! Every type below is built from primitives and hex strings only. That is
//! deliberate: it costs a little conversion code and buys a format that does
//! not shift when a dependency enables or disables a `serde` feature, and that
//! stays readable on the wire while we are debugging two nodes against each
//! other.
//!
//! [`SyncRequest`]: bdk_chain::spk_client::SyncRequest
//!
//! # Versioning
//!
//! Every message carries [`CHAIN_WIRE_VERSION`]. A Dependent node must reject a
//! reply it cannot parse rather than half-apply it, because a half-applied
//! wallet update is indistinguishable from a chain reorg. Adapters check this
//! on the way in; see [`ChainProviderError::VersionMismatch`].

use std::fmt;

use serde::{Deserialize, Serialize};

use async_trait::async_trait;

/// The version stamped into, and demanded of, every message in this module.
///
/// Bump this whenever a field's *meaning* changes — adding an optional field
/// does not require it, removing or reinterpreting one does. Pro and Dependent
/// nodes running different versions must fail loudly, not silently disagree.
pub const CHAIN_WIRE_VERSION: u16 = 1;

/// Why a [`ChainDataProvider`] call did not produce an answer.
///
/// The distinction between these is load-bearing, not cosmetic: a Dependent
/// node must be able to tell "I could not reach anyone" from "I was told no".
/// Conflating them is how a node ends up treating an unreachable provider as
/// evidence that a transaction is not confirmed.
#[derive(Debug, Clone)]
pub enum ChainProviderError {
	/// The provider could not be reached at all: no route, no response, or a
	/// timeout. Nothing is known about the chain as a result of this call.
	Unreachable(String),
	/// The provider was reached and declined to answer — not serving this
	/// ability, not permitted, or out of budget.
	Refused(String),
	/// A reply arrived but could not be understood.
	Malformed(String),
	/// A reply arrived stamped with a wire version this build cannot honour.
	VersionMismatch {
		/// The wire version this build speaks.
		expected: u16,
		/// The wire version the reply carried.
		got: u16,
	},
}

impl fmt::Display for ChainProviderError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Unreachable(e) => write!(f, "chain provider unreachable: {}", e),
			Self::Refused(e) => write!(f, "chain provider refused: {}", e),
			Self::Malformed(e) => write!(f, "chain provider reply malformed: {}", e),
			Self::VersionMismatch { expected, got } => {
				write!(f, "chain wire version mismatch: expected {}, got {}", expected, got)
			},
		}
	}
}

impl std::error::Error for ChainProviderError {}

/// A block, identified the only two ways that matter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireBlockId {
	/// Height of the block.
	pub height: u32,
	/// Block hash, hex, RPC byte order (as `BlockHash::to_string` renders it).
	pub hash: String,
}

/// One output point.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WireOutPoint {
	/// Txid, hex, RPC byte order.
	pub txid: String,
	/// Index of the output within that transaction.
	pub vout: u32,
}

/// A transaction output, carried when only the output matters and pulling the
/// whole transaction would be wasteful.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireTxOut {
	/// The output being described.
	pub outpoint: WireOutPoint,
	/// Value of the output, in satoshis.
	pub value_sat: u64,
	/// Script pubkey, hex.
	pub script_hex: String,
}

/// Where a transaction sits in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAnchor {
	/// Txid, hex.
	pub txid: String,
	/// The block the transaction was confirmed in.
	pub block: WireBlockId,
	/// The confirming block's timestamp, as BDK's `ConfirmationBlockTime`
	/// wants it.
	pub confirmation_time: u64,
}

/// When an unconfirmed transaction was first seen.
///
/// BDK will not treat an unanchored transaction as canonical without one of
/// these, so dropping them silently loses unconfirmed balance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSeenAt {
	/// Txid, hex.
	pub txid: String,
	/// Unix timestamp at which it was first seen.
	pub seen_at: u64,
}

// ── FEE ──────────────────────────────────────────────────────────────────────

/// One confirmation target's estimate.
///
/// Keyed by the target's stable *name*, not by a block count. A block count
/// loses information: a Pro node backed by bitcoind picks conservative versus
/// economical estimation per target, and two targets that share a block count
/// can legitimately carry different rates. Serving the Pro node's own
/// per-target cache verbatim preserves whatever policy it applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireFeeTarget {
	/// Stable target name — see `ldk_node::chain::provider` wire names, emitted
	/// by the serving side and matched by the consuming side.
	pub target: String,
	/// The estimate, in satoshis per 1000 weight units.
	pub sat_per_kwu: u64,
}

/// A full fee-rate cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireFeeEstimates {
	/// Wire contract version; see [`CHAIN_WIRE_VERSION`].
	pub version: u16,
	/// One entry per confirmation target the serving node knows.
	pub targets: Vec<WireFeeTarget>,
}

// ── BROADCAST ────────────────────────────────────────────────────────────────

/// A transaction to put on the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireBroadcastRequest {
	/// Wire contract version; see [`CHAIN_WIRE_VERSION`].
	pub version: u16,
	/// Consensus-encoded transaction, hex.
	pub tx_hex: String,
}

// ── LOOKUP ───────────────────────────────────────────────────────────────────

/// Ask about an arbitrary transaction — one the asking wallet need not own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireTxStatusRequest {
	/// Wire contract version; see [`CHAIN_WIRE_VERSION`].
	pub version: u16,
	/// Txid, hex.
	pub txid: String,
	/// Script pubkey, hex. Required by Electrum-backed servers, which look up
	/// by script hash rather than by txid.
	pub script_hex: Option<String>,
}

/// What the serving node observed.
///
/// Note there is no "unreachable" here on purpose: an unreachable provider
/// produces a [`ChainProviderError`], never a `WireTxStatusResponse`. A
/// response means somebody looked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireTxStatusResponse {
	/// Wire contract version; see [`CHAIN_WIRE_VERSION`].
	pub version: u16,
	/// `true` when the serving node found the transaction in a best-chain
	/// block.
	pub confirmed: bool,
	/// `true` when the serving node knows the transaction but it is
	/// unconfirmed. Mutually exclusive with `confirmed`; both `false` means
	/// the serving node has never heard of it.
	pub in_mempool: bool,
	/// Height of the confirming block, when confirmed.
	pub confirmation_height: Option<u32>,
	/// The serving node's tip height at the moment it answered. Carried so the
	/// consumer can compute depth itself rather than trusting a count that
	/// might have been derived against a different tip.
	pub tip_height: Option<u32>,
}

// ── ON-CHAIN WALLET SYNC ─────────────────────────────────────────────────────

/// "Here is everything I watch — tell me what happened to it."
///
/// This is the wide route. It replaces what `bdk_esplora`'s `sync`/`full_scan`
/// would have done against a provider the Dependent node does not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSyncRequest {
	/// Wire contract version; see [`CHAIN_WIRE_VERSION`].
	pub version: u16,
	/// Timestamp the serving node should stamp onto unconfirmed transactions
	/// it returns. Supplied by the caller so that "when did I first see this"
	/// stays anchored to the *asking* node's clock.
	pub start_time: u64,
	/// The asking wallet's checkpoint chain, ascending, genesis first, so the
	/// answer can be built as a connected extension of it rather than a
	/// replacement.
	///
	/// The whole chain travels, not just its tip. The serving node runs an
	/// ordinary BDK scan against this, and that scan walks the chain looking
	/// for a block both nodes agree on, then inserts blocks *below* the tip —
	/// one per confirmation it found, plus the provider's own recent blocks.
	/// Inserting into a chain that does not reach genesis has no defined
	/// answer, and BDK panics rather than guess. A lone tip is therefore not
	/// enough; an empty vector means "no opinion yet", and the scan returns a
	/// fresh chain instead of an extension.
	pub chain_tip: Vec<WireBlockId>,
	/// Scripts to scan, hex. Empty on a pure txid/outpoint refresh.
	///
	/// Carries scripts only — no keychain, no derivation index. The serving
	/// node needs neither to run the scan, and withholding them means a Pro
	/// node learns which scripts a Dependent node watches but not how that
	/// wallet is structured.
	pub spks: Vec<String>,
	/// Specific transactions to re-check, hex txids.
	pub txids: Vec<String>,
	/// Specific outpoints to check for spends.
	pub outpoints: Vec<WireOutPoint>,
	/// `true` asks for a gap-limited derivation scan rather than a check of
	/// exactly the scripts listed. The serving node derives nothing itself —
	/// it cannot, it has no access to the asking wallet's descriptors — so a
	/// full scan still sends its scripts; the flag only tells the server to
	/// honour `stop_gap` semantics when reporting last-active indices.
	pub full_scan: bool,
	/// Gap limit for a full scan.
	pub stop_gap: u32,
}

/// Everything needed to advance a BDK wallet one sync forward.
///
/// Mirrors the parts of `bdk_wallet::Update` that describe the *chain*: its
/// `tx_update` (flattened here into `txs`/`txouts`/`anchors`/`seen_ats`) and
/// its checkpoint.
///
/// It deliberately does **not** carry `last_active_indices`. That field says
/// which keys a wallet should consider its own, which is a statement about the
/// asking node's wallet rather than about the chain — the asking node derives
/// it locally from the transactions returned here. A serving node has no
/// business having an opinion on it, so the wire gives it no way to express
/// one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireUpdate {
	/// Wire contract version; see [`CHAIN_WIRE_VERSION`].
	pub version: u16,
	/// Full transactions, consensus-encoded hex.
	pub txs: Vec<String>,
	/// Floating outputs whose parent transaction was not worth sending.
	pub txouts: Vec<WireTxOut>,
	/// Confirmations.
	pub anchors: Vec<WireAnchor>,
	/// First-seen times for unconfirmed transactions.
	pub seen_ats: Vec<WireSeenAt>,
	/// The checkpoint chain, **ascending by height**. Must connect to the
	/// requesting wallet's existing chain; a gap makes the update
	/// unapplicable.
	pub checkpoints: Vec<WireBlockId>,
}

// ── LIGHTNING SYNC ───────────────────────────────────────────────────────────

/// One output LDK asked to have watched, via `Filter::register_output`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireWatchedOutput {
	/// The output being watched.
	pub outpoint: WireOutPoint,
	/// Script pubkey, hex.
	pub script_hex: String,
	/// The block the output was created in, when known — lets the serving node
	/// bound its search.
	pub block_hash: Option<String>,
}

/// One transaction the asking node is tracking, with what it currently
/// believes about it.
///
/// Carrying `known_block_hash` is what makes reorg detection possible without
/// the serving node holding any per-peer state: it can compare its own view
/// against the caller's and report only the difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireWatchedTx {
	/// Txid, hex.
	pub txid: String,
	/// The block the asking node last saw it confirmed in, hex. `None` means
	/// it has never seen it confirmed.
	pub known_block_hash: Option<String>,
}

/// The registered set, sent so the serving node can answer for all of it at
/// once rather than one round trip per transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLightningSyncRequest {
	/// Wire contract version; see [`CHAIN_WIRE_VERSION`].
	pub version: u16,
	/// Transactions to report on: everything registered through
	/// `Filter::register_tx` plus everything LDK still considers relevant.
	pub txids: Vec<WireWatchedTx>,
	/// Outputs registered through `Filter::register_output`.
	pub outputs: Vec<WireWatchedOutput>,
}

/// A transaction found in a block, with everything LDK's
/// [`Confirm::transactions_confirmed`] needs.
///
/// [`Confirm::transactions_confirmed`]: lightning::chain::Confirm::transactions_confirmed
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireConfirmedTx {
	/// Consensus-encoded transaction, hex.
	pub tx_hex: String,
	/// The block it was found in.
	pub block: WireBlockId,
	/// Index of this transaction within its block. LDK requires the real
	/// position, not a placeholder.
	pub pos_in_block: u32,
	/// Consensus-encoded 80-byte block header, hex.
	pub header_hex: String,
}

/// The serving node's answer for the whole registered set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLightningSyncResponse {
	/// Wire contract version; see [`CHAIN_WIRE_VERSION`].
	pub version: u16,
	/// The serving node's chain tip at the moment it answered.
	pub tip: WireBlockId,
	/// Consensus-encoded 80-byte tip header, hex.
	pub tip_header_hex: String,
	/// Registered transactions now confirmed, plus transactions spending a
	/// registered output.
	pub confirmed: Vec<WireConfirmedTx>,
	/// Registered transactions the serving node no longer finds in the best
	/// chain — a reorg, or a dropped transaction. Hex txids.
	pub unconfirmed: Vec<String>,
}

// ── THE PORT ─────────────────────────────────────────────────────────────────

/// A remote source of chain data.
///
/// One implementation of this trait, plus a transport, is the whole of what a
/// Dependent node needs. The crate builds all four chain slots on top of it.
///
/// # Contract
///
/// * **Answer or error — never invent.** Returning a "nothing found" shaped
///   answer because a request failed is the one thing that must not happen
///   here: callers arm CSV timeouts and claim deadlines off these replies.
///   When in doubt return [`ChainProviderError::Unreachable`].
/// * **Errors are cheap; silence is not.** Implementations should apply their
///   own timeout. A call that hangs stalls wallet sync.
/// * **Idempotent.** Every call may be retried.
#[async_trait]
pub trait ChainDataProvider: Send + Sync {
	/// Identifies the provider in logs — conventionally the serving node's id.
	fn name(&self) -> String;

	/// The serving node's current fee-rate cache.
	async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError>;

	/// Hand a transaction to the serving node to put on the network.
	///
	/// Returning `Ok` means the serving node accepted it for broadcast, not
	/// that it reached a miner.
	async fn broadcast(&self, req: WireBroadcastRequest) -> Result<(), ChainProviderError>;

	/// Status of an arbitrary transaction.
	async fn tx_status(
		&self, req: WireTxStatusRequest,
	) -> Result<WireTxStatusResponse, ChainProviderError>;

	/// Advance the on-chain (BDK) wallet.
	async fn wallet_sync(&self, req: WireSyncRequest) -> Result<WireUpdate, ChainProviderError>;

	/// Advance the Lightning (LDK `Confirm`) state.
	async fn lightning_sync(
		&self, req: WireLightningSyncRequest,
	) -> Result<WireLightningSyncResponse, ChainProviderError>;
}
