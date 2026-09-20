// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The pluggable chain abilities.
//!
//! Each ability is one slot on [`crate::chain::ChainLayer`], filled by one
//! adapter. A node functions identically whichever adapter occupies a slot, and
//! no code outside slot construction branches on which one it is.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::{FeeRate, Transaction};

use lightning_block_sync::gossip::UtxoSource;

use crate::fee_estimator::ConfirmationTarget;
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

/// The outcome of asking a [`FeeAdapter`] for a fee-rate update.
///
/// Richer than a plain map because the pre-seam implementations had two
/// non-obvious outcomes that must be preserved exactly:
///
/// * a source may decide to **skip** a round — keeping the previous cache and
///   deliberately *not* advancing the fee-rate-cache metrics timestamp;
/// * a source may only want the "update finished" line logged when the cache
///   actually changed, because it refreshes often enough to be spammy.
pub(crate) enum FeeUpdate {
	/// Leave the existing cache and the metrics timestamp untouched.
	Skip,
	/// Install this cache.
	Apply {
		cache: HashMap<ConfirmationTarget, FeeRate>,
		/// Log the completion line even when the cache is unchanged.
		log_unchanged: bool,
	},
}

/// Produces fee-rate estimates.
///
/// The adapter owns its own per-target strategy, its own network policy and its
/// own wire timeout — these differ materially between sources and cannot be
/// hoisted without changing behaviour. The seam owns only installing the result
/// and recording that it happened.
#[async_trait]
pub(crate) trait FeeAdapter: Send + Sync {
	/// Stable identifier, for logs and for answering "which adapter served this".
	fn name(&self) -> &'static str;

	async fn fee_rate_update(&self) -> Result<FeeUpdate, Error>;
}

/// Sends transactions to the Bitcoin network.
///
/// Broadcast is deliberately **lossy**: a failure is logged and dropped, never
/// returned to the caller. That is the pre-seam contract and the queue has no
/// retry semantics to build on, so adapters must not propagate errors. An
/// ordered fallback across several adapters is a later change, not this one.
#[async_trait]
pub(crate) trait BroadcastAdapter: Send + Sync {
	/// Stable identifier, for logs and for answering "which adapter served this".
	fn name(&self) -> &'static str;

	/// Whether the backend can broadcast right now.
	///
	/// `false` abandons this drain pass entirely; the queue is drained again on
	/// the next tick (once per second), so this is a skip, not a shutdown.
	async fn ready(&self) -> bool {
		true
	}

	/// Broadcast one transaction, logging its own outcome.
	///
	/// Each backend classifies its own errors — an Esplora HTTP 400 usually
	/// just means bitcoind already knows the transaction and is logged far more
	/// quietly than a genuine failure — so log level belongs to the adapter.
	async fn broadcast_tx(&self, tx: &Transaction);
}

/// Answers questions about the chain that the wallet's own sync does not cover.
///
/// This is deliberately a **narrow query** ability, not a sync engine. The two
/// sync architectures (transaction-based and block-polling) share no interface
/// and are selected as an explicit separate axis; what belongs here are the
/// point lookups their consumers need — the status of an arbitrary transaction,
/// and whether channel announcements can be verified against the UTXO set.
#[async_trait]
pub(crate) trait LookupAdapter: Send + Sync {
	/// Stable identifier, for logs and for answering "which adapter served this".
	fn name(&self) -> &'static str;

	/// Reorg-aware status of an ARBITRARY transaction — one the local wallet
	/// need not own, such as a counterparty's swap opening tx.
	///
	/// FAIL-CLOSED (E6): an adapter that cannot answer — unstarted client,
	/// transport error, missing scriptPubKey, or an inconsistent
	/// tip/confirming-height pair — MUST return
	/// [`RawTxObservation::Unreachable`]. It must never report a result that
	/// could be folded into "confirmed", because callers arm CSV and claim
	/// deadlines off this answer.
	#[cfg(feature = "swaps")]
	async fn tx_status(&self, txid: Txid, script_pubkey: Option<&ScriptBuf>) -> RawTxObservation;

	/// The UTXO source used to verify BOLT-7 `channel_announcement`s.
	///
	/// `None` declares that this adapter **cannot** verify announcements, in
	/// which case they are accepted unverified and the routing graph carries
	/// capacities nobody checked.
	fn utxo_source(&self) -> Option<Arc<dyn UtxoSource>>;
}
