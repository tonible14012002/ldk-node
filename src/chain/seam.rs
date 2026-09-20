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

use bitcoin::{FeeRate, Transaction};

use crate::fee_estimator::ConfirmationTarget;
use crate::Error;

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
