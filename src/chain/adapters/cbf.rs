// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Chain ability adapters over the filter-driven engine.
//!
//! A CBF node has peers, headers, filters and the blocks it chose to download — and nothing
//! else. Each adapter here fills one slot from exactly that, and says `Unavailable` for
//! everything it cannot see, so the chain moves on to a provider or an external source:
//!
//! * [`CbfDerivedFee`] — FEE from the coinbase of recent blocks. A block's coinbase pays its
//!   subsidy plus every fee it collected, so a window of recent blocks is a fee market seen
//!   after the fact. Coarse, and last in every preset; it is what a node has when nobody
//!   mempool-aware answers.
//! * [`CbfP2pBroadcast`] — BROADCAST straight to the node's own peers over P2P.
//! * [`CbfWatchTxStatus`] — TX_STATUS for a transaction the node was told to watch *before*
//!   it confirmed, answered from the blocks the applicator went through. Forward-only: a
//!   filter node has no history to look back into and never claims one.
//! * [`CbfUtxoSource`] — UTXO verification of channel announcements at the existence-only
//!   level the filters allow, opted into by `CbfConfig::utxo_source`.
//!
//! The fee window, the P2P handoff and its bound are DatPham's (`cycles-cbf-828`), lifted
//! out of the upstream chain source and onto the slots.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bip157::{Package, Requester};

use bitcoin::{BlockHash, FeeRate, OutPoint, Transaction, Txid};

use lightning_block_sync::gossip::UtxoSource;
use lightning_block_sync::{
	AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, BlockSourceError,
};

use crate::chain::cbf::fee::{
	cbf_percentile_for_target, percentile_of_sorted, CBF_MIN_FEERATE_SAT_PER_KWU, FEE_WINDOW_BLOCKS,
};
use crate::chain::cbf::{CBF_BLOCK_FETCH_TIMEOUT_SECS, CBF_HEADER_LOOKUP_TIMEOUT_SECS};
use crate::chain::engine::cbf::CbfSyncEngine;
use crate::chain::seam::{
	ActionResult, BroadcastAction, BroadcastRejection, ChainActionError, FeeAction, FeeUpdate,
	PackageOutcomes, TxBroadcastOutcome, UtxoCapability, UtxoVerification, ADAPTER_BUDGET_MARGIN,
	MAX_BROADCAST_PACKAGE_TXS,
};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, ConfirmationTarget,
};
use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};

#[cfg(feature = "swaps")]
use crate::chain::cbf::WatchLedger;
#[cfg(feature = "swaps")]
use crate::chain::seam::{Anchored, TxStatusAction};
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::ScriptBuf;

use async_trait::async_trait;

/// Per-transaction timeout on the kyoto P2P broadcast handoff.
///
/// [`Requester::submit_package`] resolves only once a peer has actually PULLED the transaction:
/// kyoto announces the wtxid in an `inv` and completes the caller's oneshot when it answers the
/// peer's `getdata`. A peer that already knows the transaction never sends `getdata` — Bitcoin
/// Core logs `got inv: wtx <id> have peer=N` and drops it — so that future NEVER resolves, and
/// kyoto attaches no timeout of its own.
///
/// Re-broadcasting a transaction the network already has is routine, not exceptional: both sides
/// of a cooperative close broadcast the same closing transaction, both sides of a force close may
/// broadcast the same commitment, and LDK re-broadcasts unconfirmed transactions on a timer. Since
/// the broadcast queue drains SERIALLY, a single unresolvable handoff would wedge every LATER
/// broadcast for the lifetime of the node — including the force-close sweeps that recover a
/// channel balance. Hence the bound, matching the engine's other kyoto-request timeout
/// ([`CBF_BLOCK_FETCH_TIMEOUT_SECS`]).
///
/// Timing out does not retract the announcement: the transaction stays in kyoto's broadcast queue
/// and is still served if a peer asks for it later, and is re-announced to every peer that
/// completes a handshake afterwards.
pub(crate) const CBF_P2P_BROADCAST_TIMEOUT_SECS: u64 = 10;

/// FEE budget: one chain-tip lookup, then for every height of the window a header lookup
/// and — for a block not sampled yet, or sampled on a branch that was reorged out — a block
/// fetch, each under its own bound. Sized for the worst case, a window with nothing cached:
/// `1 + FEE_WINDOW_BLOCKS` header lookups and `FEE_WINDOW_BLOCKS` block fetches, plus the
/// margin. The steady state is a tip lookup, the header lookups and one block fetch per new
/// block since the last tick; the applicator's own downloads are reused and cost nothing.
const CBF_DERIVED_FEE_BUDGET: Duration = Duration::from_secs(
	(1 + FEE_WINDOW_BLOCKS as u64) * CBF_HEADER_LOOKUP_TIMEOUT_SECS
		+ FEE_WINDOW_BLOCKS as u64 * CBF_BLOCK_FETCH_TIMEOUT_SECS
		+ ADAPTER_BUDGET_MARGIN.as_secs(),
);

/// BROADCAST budget: a package of one or two transactions is one handoff; a longer one, or a
/// pair kyoto will not take as a package, is one handoff per transaction, serially, each under
/// [`CBF_P2P_BROADCAST_TIMEOUT_SECS`]. The largest package worth of those, plus the margin, so
/// the handoff's own timeout and its log line always fire before the seam's.
const CBF_P2P_BROADCAST_BUDGET: Duration = Duration::from_secs(
	MAX_BROADCAST_PACKAGE_TXS * CBF_P2P_BROADCAST_TIMEOUT_SECS + ADAPTER_BUDGET_MARGIN.as_secs(),
);

/// Runs a kyoto request under `secs`, so a request the node never answers cannot park an
/// adapter past its budget with nothing logged.
async fn bounded<T>(
	secs: u64, request: impl Future<Output = T>,
) -> Result<T, tokio::time::error::Elapsed> {
	tokio::time::timeout(Duration::from_secs(secs), request).await
}

// ── FEE ─────────────────────────────────────────────────────────────────────

/// Per-target fee estimates derived from the coinbase of recent blocks.
///
/// Reads the [`BlockFeeCache`] the applicator fills with every block it downloads, tops it
/// up with the blocks of the window it has not seen, and reads one percentile per target
/// out of the sorted window: a higher percentile for an urgent target, a lower one for a
/// relaxed one. `Unavailable` while kyoto is not running, and while the window holds no
/// sample at all — a chain that has just resumed and downloaded nothing yet has no fee
/// market to report, and the estimator's own per-target fallbacks stand until it does.
///
/// [`BlockFeeCache`]: crate::chain::cbf::fee::BlockFeeCache
pub(crate) struct CbfDerivedFee {
	engine: Arc<CbfSyncEngine>,
	logger: Arc<Logger>,
}

impl CbfDerivedFee {
	pub(crate) fn new(engine: Arc<CbfSyncEngine>, logger: Arc<Logger>) -> Self {
		Self { engine, logger }
	}

	/// Reconciles the block-fee cache against the canonical chain and returns the per-block
	/// fee rates of the most recent [`FEE_WINDOW_BLOCKS`] blocks.
	///
	/// For each height in the window the canonical block hash is fetched; if the cached entry
	/// still matches, its rate is reused, otherwise (a new block, or one that was reorged out)
	/// the block is downloaded via [`Requester::average_fee_rate`]. Heights that fell out of
	/// the window are evicted; entries the applicator recorded above the tip this pass saw are
	/// kept, so a block that arrived mid-pass is not thrown away and downloaded again.
	///
	/// Best-effort within the window: a height whose header or block cannot be fetched is
	/// skipped, so a slow or unresponsive peer can only thin the sample, not void the pass —
	/// the window fills incrementally over successive ticks. Only the tip lookup is fatal:
	/// without it there is no window to reconcile.
	async fn refresh_block_fee_window(&self, requester: &Requester) -> ActionResult<Vec<FeeRate>> {
		let tip_height = match bounded(CBF_HEADER_LOOKUP_TIMEOUT_SECS, requester.chain_tip()).await
		{
			Ok(Ok(tip)) => tip.height,
			Ok(Err(e)) => {
				log_error!(self.logger, "CBF fee update: failed to fetch the chain tip: {}", e);
				return Err(ChainActionError::unavailable(format!(
					"chain tip lookup failed: {}",
					e
				)));
			},
			Err(_elapsed) => {
				log_error!(
					self.logger,
					"CBF fee update: the chain tip lookup timed out after {}s",
					CBF_HEADER_LOOKUP_TIMEOUT_SECS
				);
				return Err(ChainActionError::timed_out("chain tip lookup timed out"));
			},
		};
		let lo = tip_height.saturating_sub(FEE_WINDOW_BLOCKS - 1);

		let cache = self.engine.block_fee_cache();
		// Snapshot the cache so the std `Mutex` is never held across an `.await`.
		let cached = cache.lock().unwrap_or_else(|e| e.into_inner()).clone();

		let mut window = BTreeMap::new();
		for height in lo..=tip_height {
			let canonical_hash =
				match bounded(CBF_HEADER_LOOKUP_TIMEOUT_SECS, requester.get_header(height)).await {
					Ok(Ok(Some(indexed))) => indexed.header.block_hash(),
					// Height not available (yet); skip it.
					Ok(Ok(None)) => continue,
					Ok(Err(e)) => {
						log_debug!(
							self.logger,
							"CBF fee update: failed to fetch the header at height {}, skipping: {}",
							height,
							e
						);
						continue;
					},
					Err(_elapsed) => {
						log_debug!(
							self.logger,
							"CBF fee update: the header lookup at height {} timed out, skipping",
							height
						);
						continue;
					},
				};

			// Reuse the cached rate while the block is still canonical; otherwise download it.
			if let Some(fee_rate) = cached_rate(&cached, height, canonical_hash) {
				window.insert(height, (canonical_hash, fee_rate));
				continue;
			}

			// The sample downloads a full block, so it counts against the same
			// `CBF_FULL_BLOCK_PERMITS` bound the applicator's matched blocks do: a fee window
			// refilled after a restart is fourteen blocks, and on a small device those must
			// not be held in memory next to the applicator's. The wait for a permit is inside
			// the per-block bound, so the budget above still covers it.
			let permits = self.engine.full_block_permits();
			let sample = bounded(CBF_BLOCK_FETCH_TIMEOUT_SECS, async {
				let _permit = permits
					.acquire()
					.await
					.map_err(|_closed| "the full-block permits were closed".to_string())?;
				requester.average_fee_rate(canonical_hash).await.map_err(|e| e.to_string())
			})
			.await;
			match sample {
				Ok(Ok(fee_rate)) => {
					window.insert(height, (canonical_hash, fee_rate));
				},
				Ok(Err(e)) => {
					log_debug!(
						self.logger,
						"CBF fee update: failed to fetch the fee rate of block {}, skipping: {}",
						canonical_hash,
						e
					);
				},
				Err(_elapsed) => {
					log_debug!(
						self.logger,
						"CBF fee update: timed out fetching block {} for fee estimation, skipping",
						canonical_hash
					);
				},
			}
		}

		let samples = window.values().map(|(_, fee_rate)| *fee_rate).collect();
		{
			let mut current = cache.lock().unwrap_or_else(|e| e.into_inner());
			// Blocks the applicator recorded above this pass's tip arrived while the window
			// was being built; they are the next pass's newest samples, not stale entries.
			for (height, entry) in current.iter() {
				if *height > tip_height {
					window.insert(*height, *entry);
				}
			}
			// Replacing the rest wholesale evicts every entry that fell out of the window.
			*current = window;
		}
		Ok(samples)
	}
}

/// The cached rate for `height`, if the block cached there is still the canonical one.
///
/// A height whose cached hash differs was reorged out: its rate belongs to a block that is
/// no longer in the chain, and the canonical block must be downloaded instead.
fn cached_rate(
	cached: &BTreeMap<u32, (BlockHash, FeeRate)>, height: u32, canonical_hash: BlockHash,
) -> Option<FeeRate> {
	cached.get(&height).filter(|(hash, _)| *hash == canonical_hash).map(|(_, fee_rate)| *fee_rate)
}

/// The per-target cache read out of a window of per-block fee rates, or `None` for an empty
/// window.
///
/// Every target reads its own percentile ([`cbf_percentile_for_target`]) of the same sorted
/// window, floored at [`CBF_MIN_FEERATE_SAT_PER_KWU`] (1 sat/vB: coinbase-derived rates are
/// routinely zero on regtest and signet) and post-adjusted like every other source. The
/// answer is therefore all targets or nothing: there is no sample from which some targets
/// could be read and others not.
pub(crate) fn fee_cache_from_samples(
	samples: &[FeeRate],
) -> Option<HashMap<ConfirmationTarget, FeeRate>> {
	if samples.is_empty() {
		return None;
	}
	let mut samples_sat_per_kwu: Vec<u64> =
		samples.iter().map(|fee_rate| fee_rate.to_sat_per_kwu()).collect();
	samples_sat_per_kwu.sort_unstable();

	let mut cache = HashMap::with_capacity(10);
	for target in get_all_conf_targets() {
		let percentile = cbf_percentile_for_target(target);
		let sat_per_kwu =
			percentile_of_sorted(&samples_sat_per_kwu, percentile).max(CBF_MIN_FEERATE_SAT_PER_KWU);
		let fee_rate = FeeRate::from_sat_per_kwu(sat_per_kwu);
		cache.insert(target, apply_post_estimation_adjustments(target, fee_rate));
	}
	Some(cache)
}

#[async_trait]
impl FeeAction for CbfDerivedFee {
	fn name(&self) -> &'static str {
		"cbf_derived"
	}

	fn budget(&self) -> Option<Duration> {
		Some(CBF_DERIVED_FEE_BUDGET)
	}

	async fn fee_rate_update(&self) -> ActionResult<FeeUpdate> {
		let Some(requester) = self.engine.requester() else {
			return Err(ChainActionError::unavailable("CBF node is not running"));
		};
		let samples = self.refresh_block_fee_window(&requester).await?;
		match fee_cache_from_samples(&samples) {
			Some(cache) => {
				log_debug!(
					self.logger,
					"CBF fee update: derived estimates from the coinbase of {} recent block(s)",
					samples.len()
				);
				Ok(FeeUpdate::Apply { cache, log_unchanged: false })
			},
			None => {
				log_info!(
					self.logger,
					"CBF fee update: no block in the fee window could be sampled yet; the \
					 previous estimates stand"
				);
				Err(ChainActionError::unavailable("no block samples in the fee window yet"))
			},
		}
	}
}

// ── BROADCAST ───────────────────────────────────────────────────────────────

/// How one kyoto handoff ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Handoff {
	/// A peer pulled the transaction inside the budget.
	Relayed,
	/// Kyoto refused the submission: the node has stopped.
	Refused(String),
	/// Kyoto took the transaction and announced it, but no peer asked for it inside the
	/// budget. Usually benign — a peer that already has a transaction never asks for it — and
	/// the announcement stands.
	Unanswered,
}

#[cfg(test)]
impl Handoff {
	fn relayed(&self) -> bool {
		matches!(self, Self::Relayed)
	}
}

/// Awaits ONE kyoto broadcast handoff under `hold_timeout`, never propagating a failure.
///
/// `submit` is a [`Requester::submit_package`] future; `what` names the transaction (or package)
/// for the log.
///
/// The timeout is the whole point — see [`CBF_P2P_BROADCAST_TIMEOUT_SECS`] for why an unbounded
/// await here wedges the entire serial broadcast queue. Expiring is logged at INFO rather than
/// ERROR because the overwhelmingly common cause is benign (the peer already has the transaction);
/// a genuine relay failure shows up as the transaction never confirming, which the caller's own
/// re-broadcast timer keeps retrying.
///
/// A free function, generic over the future, so it is unit-testable without a live kyoto node.
async fn bounded_p2p_handoff<T, E, Fut>(
	logger: &Logger, hold_timeout: Duration, what: &str, submit: Fut,
) -> Handoff
where
	Fut: Future<Output = Result<T, E>>,
	E: std::fmt::Display,
{
	match tokio::time::timeout(hold_timeout, submit).await {
		Ok(Ok(_)) => Handoff::Relayed,
		Ok(Err(e)) => {
			log_error!(logger, "Failed to broadcast {}: {}", what, e);
			Handoff::Refused(e.to_string())
		},
		Err(_elapsed) => {
			log_info!(
				logger,
				"No peer requested {} within {:?}; it stays queued for relay in the CBF client \
				 (a peer that already has a transaction never asks for it) and the broadcast \
				 queue moves on.",
				what,
				hold_timeout,
			);
			Handoff::Unanswered
		},
	}
}

/// Hands `package` to the network through `submit`, one kyoto package where kyoto takes
/// one — a single transaction, or a parent and the child that spends it — and one
/// transaction at a time otherwise, each handoff bounded by `hold_timeout`.
///
/// One outcome per transaction, in package order. A pulled transaction is `Accepted`. One
/// kyoto took but no peer pulled inside the bound is `AlreadyKnown`: it was announced, it
/// stays in kyoto's queue to be served to any peer that asks and re-announced to every peer
/// that connects, and a peer that already has a transaction never asks for it. It has been
/// handed to the network, and the wallet must hear so — reporting it `Unavailable` would
/// exhaust the chain, leave the wallet unaware of the spend, and have it offer the same
/// inputs to the next send, which the network then refuses as a conflict. The handoff has
/// already logged that nobody pulled it. Only a submission kyoto refused — its node has
/// stopped — is `Unavailable`: that transaction was handed to nobody.
///
/// Never `Rejected`. Kyoto learns of a peer's verdict, if at all, from a `reject` message it
/// reports on its warning channel, asynchronously, keyed by wtxid, and only from peers that
/// still send one — Bitcoin Core stopped in 0.20. That cannot be tied to a handoff with any
/// reliability, so no P2P answer is ever a verdict on the transaction, and on a hybrid node the
/// provider after this adapter is not asked for one: an announced package ends the chain here. A
/// transaction the network refuses is found out late, by the borrowed mempool view no longer
/// holding it once the own-broadcast grace window has passed.
///
/// A free function, generic over `submit`, so it is unit-testable without a live kyoto node.
async fn relay_package<F, Fut, T, E>(
	logger: &Logger, hold_timeout: Duration, package: &[Transaction], submit: F,
) -> PackageOutcomes
where
	F: Fn(Package) -> Fut,
	Fut: Future<Output = Result<T, E>>,
	E: std::fmt::Display,
{
	let txids: Vec<Txid> = package.iter().map(|tx| tx.compute_txid()).collect();
	let handoffs: Vec<Handoff> = match Package::from_vec(package.to_vec()) {
		Ok(kyoto_package) => {
			let handoff = bounded_p2p_handoff(
				logger,
				hold_timeout,
				"the transaction package",
				submit(kyoto_package),
			)
			.await;
			vec![handoff; package.len()]
		},
		Err(_) => {
			let mut handoffs = Vec::with_capacity(package.len());
			for (tx, txid) in package.iter().zip(&txids) {
				let what = format!("transaction {}", txid);
				let handoff = bounded_p2p_handoff(
					logger,
					hold_timeout,
					&what,
					submit(Package::from(tx.clone())),
				)
				.await;
				handoffs.push(handoff);
			}
			handoffs
		},
	};

	txids
		.into_iter()
		.zip(handoffs)
		.map(|(txid, handoff)| {
			let outcome = match handoff {
				Handoff::Relayed => TxBroadcastOutcome::Accepted,
				Handoff::Unanswered => TxBroadcastOutcome::AlreadyKnown,
				Handoff::Refused(reason) => {
					TxBroadcastOutcome::Unavailable { reason, timed_out: false }
				},
			};
			(txid, outcome)
		})
		.collect()
}

/// Broadcast over the node's own P2P connections, through kyoto.
pub(crate) struct CbfP2pBroadcast {
	engine: Arc<CbfSyncEngine>,
	logger: Arc<Logger>,
}

impl CbfP2pBroadcast {
	pub(crate) fn new(engine: Arc<CbfSyncEngine>, logger: Arc<Logger>) -> Self {
		Self { engine, logger }
	}
}

#[async_trait]
impl BroadcastAction for CbfP2pBroadcast {
	fn name(&self) -> &'static str {
		"cbf_p2p"
	}

	fn budget(&self) -> Option<Duration> {
		Some(CBF_P2P_BROADCAST_BUDGET)
	}

	/// Kyoto running. Nothing can be handed to a peer without it, and a drain pass in which no
	/// adapter is ready leaves the queue for the next tick rather than dropping its packages.
	async fn ready(&self) -> bool {
		self.engine.requester().is_some()
	}

	async fn broadcast_package(
		&self, txs: &[Transaction],
	) -> ActionResult<PackageOutcomes, BroadcastRejection> {
		let Some(requester) = self.engine.requester() else {
			return Err(ChainActionError::unavailable("CBF node is not running"));
		};
		let hold_timeout = Duration::from_secs(CBF_P2P_BROADCAST_TIMEOUT_SECS);
		let outcomes = relay_package(&self.logger, hold_timeout, txs, |package| {
			let requester = requester.clone();
			async move { requester.submit_package(package).await }
		})
		.await;
		Ok(outcomes)
	}
}

// ── TX_STATUS ───────────────────────────────────────────────────────────────

/// Forward-only status of a watched transaction, from the blocks the applicator applied.
///
/// Answers exactly one thing: that a transaction watched *before* it confirmed was seen in a
/// block still on the applied chain — `Confirmed`, at that block's height, with the depth
/// measured against the applied tip the answer is anchored to. A reorg that disconnects the
/// block drops the sighting from the ledger, and the answer with it.
///
/// Everything else is `Unavailable`, so the chain falls through to a provider that can look:
/// a transaction nobody asked this node to watch; one watched but not seen since the watch
/// began, which a filter node cannot tell apart from "confirmed before I looked", "in a
/// mempool I do not have" and "never broadcast"; and one whose sighting a reorg took back.
/// On a node with no provider the chain is then exhausted and the caller fails closed, which
/// is the honest answer a node with no history can give.
#[cfg(feature = "swaps")]
pub(crate) struct CbfWatchTxStatus {
	ledger: Arc<WatchLedger>,
}

#[cfg(feature = "swaps")]
impl CbfWatchTxStatus {
	pub(crate) fn new(ledger: Arc<WatchLedger>) -> Self {
		Self { ledger }
	}
}

#[cfg(feature = "swaps")]
#[async_trait]
impl TxStatusAction for CbfWatchTxStatus {
	fn name(&self) -> &'static str {
		"cbf_watch"
	}

	/// Answered from memory; the slot default is more than enough.
	fn budget(&self) -> Option<Duration> {
		None
	}

	async fn tx_status(
		&self, txid: Txid, _script_pubkey: Option<&ScriptBuf>,
	) -> ActionResult<Anchored<RawTxObservation>> {
		if !self.ledger.is_watched(&txid) {
			return Err(ChainActionError::unavailable("not watched by the filter sync"));
		}
		let Some(block) = self.ledger.confirmation(&txid) else {
			return Err(ChainActionError::unavailable(
				"watched, but not seen confirmed in any block applied since the watch began",
			));
		};
		let Some(tip) = self.ledger.tip() else {
			// A sighting implies an applied block, so this cannot happen; refusing beats
			// inventing a depth if it ever does.
			return Err(ChainActionError::unavailable("no block applied yet"));
		};
		if tip.height < block.height {
			// A disconnect at or below the block drops the sighting, so neither can this.
			return Err(ChainActionError::unavailable(format!(
				"applied tip {} below the confirming block {}",
				tip.height, block.height
			)));
		}
		let confirmations = tip.height - block.height + 1;
		Ok(Anchored {
			value: RawTxObservation::Confirmed { height: Some(block.height), confirmations },
			tip: Some(tip),
		})
	}
}

// ── UTXO ────────────────────────────────────────────────────────────────────

/// The block source behind [`CbfUtxoSource`]: blocks by hash and hashes by height, from
/// kyoto, for the gossip verifier.
///
/// The verifier asks for the announced channel's funding block by height, fetches the block,
/// reads the funding output from it and asks whether that output is unspent. The first
/// three come from kyoto's header chain and its peers; the last a filter node cannot answer,
/// and this source says so by its verification level rather than by pretending: see
/// [`UtxoSource::is_output_unspent`] below.
pub(crate) struct CbfBlockSource {
	engine: Arc<CbfSyncEngine>,
	logger: Arc<Logger>,
}

impl CbfBlockSource {
	fn requester(&self) -> Result<Requester, BlockSourceError> {
		self.engine
			.requester()
			.ok_or_else(|| BlockSourceError::transient("CBF node is not running"))
	}
}

impl BlockSource for CbfBlockSource {
	/// Kyoto keeps no chain work, and a `BlockHeaderData` without its `chainwork` would be a
	/// lie by type, so headers are not served: the verifier never asks for one, and a poller
	/// that would is not this engine. Persistent, because retrying cannot change that.
	fn get_header<'a>(
		&'a self, _header_hash: &'a BlockHash, _height_hint: Option<u32>,
	) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			Err(BlockSourceError::persistent(
				"the CBF block source serves blocks by hash and hashes by height for gossip \
				 verification; it does not track chain work and serves no headers",
			))
		})
	}

	fn get_block<'a>(
		&'a self, header_hash: &'a BlockHash,
	) -> AsyncBlockSourceResult<'a, BlockData> {
		Box::pin(async move {
			let requester = self.requester()?;
			let handle = requester.request_block(*header_hash).map_err(|e| {
				BlockSourceError::transient(format!(
					"could not request block {}: {}",
					header_hash, e
				))
			})?;
			match bounded(CBF_BLOCK_FETCH_TIMEOUT_SECS, handle).await {
				Ok(Ok(Ok(indexed))) => Ok(BlockData::FullBlock(indexed.block)),
				Ok(Ok(Err(bip157::error::FetchBlockError::UnknownHash))) => {
					Err(BlockSourceError::persistent(format!(
						"block {} is not on the chain of most work",
						header_hash
					)))
				},
				Ok(Ok(Err(e))) => Err(BlockSourceError::transient(format!(
					"could not fetch block {}: {}",
					header_hash, e
				))),
				Ok(Err(_dropped)) => Err(BlockSourceError::transient(format!(
					"the CBF node dropped the request for block {}",
					header_hash
				))),
				Err(_elapsed) => {
					log_debug!(
						self.logger,
						"CBF block source: fetching block {} timed out after {}s",
						header_hash,
						CBF_BLOCK_FETCH_TIMEOUT_SECS
					);
					Err(BlockSourceError::transient(format!(
						"fetching block {} timed out after {}s",
						header_hash, CBF_BLOCK_FETCH_TIMEOUT_SECS
					)))
				},
			}
		})
	}

	fn get_best_block(&self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
		Box::pin(async move {
			let requester = self.requester()?;
			match bounded(CBF_HEADER_LOOKUP_TIMEOUT_SECS, requester.chain_tip()).await {
				Ok(Ok(tip)) => Ok((tip.hash, Some(tip.height))),
				Ok(Err(e)) => {
					Err(BlockSourceError::transient(format!("could not read the chain tip: {}", e)))
				},
				Err(_elapsed) => Err(BlockSourceError::transient(format!(
					"the chain tip lookup timed out after {}s",
					CBF_HEADER_LOOKUP_TIMEOUT_SECS
				))),
			}
		})
	}
}

impl UtxoSource for CbfBlockSource {
	/// From kyoto's header chain. A height it does not hold yet is transient: the
	/// announcement may be ahead of this node's tip, and a later attempt may find it.
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> AsyncBlockSourceResult<'a, BlockHash> {
		Box::pin(async move {
			let requester = self.requester()?;
			match bounded(CBF_HEADER_LOOKUP_TIMEOUT_SECS, requester.get_header(block_height)).await
			{
				Ok(Ok(Some(indexed))) => Ok(indexed.header.block_hash()),
				Ok(Ok(None)) => Err(BlockSourceError::transient(format!(
					"height {} is not in the header chain",
					block_height
				))),
				Ok(Err(e)) => Err(BlockSourceError::transient(format!(
					"could not look up the header at height {}: {}",
					block_height, e
				))),
				Err(_elapsed) => Err(BlockSourceError::transient(format!(
					"the header lookup at height {} timed out after {}s",
					block_height, CBF_HEADER_LOOKUP_TIMEOUT_SECS
				))),
			}
		})
	}

	/// Taken on trust. A filter node holds no UTXO set, and the filters it streams cannot be
	/// searched backwards for a spend of one output; what it *has* verified by the time this
	/// is asked is that the funding output exists, in the block the announcement names — the
	/// verifier fetched that block through [`BlockSource::get_block`] and read the output from
	/// it. That is the [`UtxoVerification::ExistenceOnly`] level this source declares, and
	/// the startup log says so.
	fn is_output_unspent<'a>(&'a self, _outpoint: OutPoint) -> AsyncBlockSourceResult<'a, bool> {
		Box::pin(async move { Ok(true) })
	}
}

/// Existence-only verification of BOLT-7 channel announcements over the filters, opted into
/// by `CbfConfig::utxo_source`.
pub(crate) struct CbfUtxoSource {
	source: Arc<CbfBlockSource>,
}

impl CbfUtxoSource {
	pub(crate) fn new(engine: Arc<CbfSyncEngine>, logger: Arc<Logger>) -> Self {
		Self { source: Arc::new(CbfBlockSource { engine, logger }) }
	}
}

impl UtxoCapability for CbfUtxoSource {
	fn name(&self) -> &'static str {
		"cbf"
	}

	fn utxo_source(&self) -> Option<(Arc<dyn UtxoSource>, UtxoVerification)> {
		Some((Arc::clone(&self.source) as Arc<dyn UtxoSource>, UtxoVerification::ExistenceOnly))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::sync::Mutex;

	use bitcoin::hashes::Hash;
	use bitcoin::{
		absolute, transaction, Amount, ScriptBuf, Sequence, TxIn, TxOut, WPubkeyHash, Witness,
	};

	fn test_logger() -> Logger {
		Logger::new_log_facade()
	}

	/// Long enough that the pulled cases below are never mistaken for a timeout.
	fn generous_test_timeout() -> Duration {
		Duration::from_secs(5)
	}

	/// Stand-in for `Requester::submit_package` against a peer that already knows the
	/// transaction: kyoto queued the announcement, Bitcoin Core answered the `inv` with silence
	/// (`got inv: wtx <id> have peer=N`), and the oneshot is therefore never completed.
	fn never_pulled_by_a_peer() -> impl std::future::Future<Output = Result<(), &'static str>> {
		std::future::pending()
	}

	/// Short enough that the never-pulled cases cost the suite nothing, long enough that the
	/// pulled cases below are never mistaken for one.
	fn short_handoff_timeout() -> Duration {
		Duration::from_millis(50)
	}

	// ------------------------------------------------------------------------------------------
	// P2P broadcast handoff (DatPham's defect P2). `Requester::submit_package` completes only
	// when a peer PULLS the transaction, so it never completes for a transaction the peer
	// already has — and the broadcast queue drains serially, so one such handoff used to wedge
	// every broadcast behind it (measured live: a cooperative-close re-broadcast stalled the
	// queue, and NONE of the force-close sweeps generated over the next nine minutes ever
	// reached the network).
	// ------------------------------------------------------------------------------------------

	#[tokio::test]
	async fn a_handoff_no_peer_pulls_is_abandoned_rather_than_awaited_forever() {
		let logger = test_logger();

		// The outer timeout is what makes this a test rather than a hang: without the bound
		// inside `bounded_p2p_handoff` the inner future is `Pending` forever.
		let handoff = tokio::time::timeout(
			Duration::from_secs(5),
			bounded_p2p_handoff(
				&logger,
				short_handoff_timeout(),
				"the transaction under test",
				never_pulled_by_a_peer(),
			),
		)
		.await
		.expect(
			"the P2P handoff must return on its own; an unbounded await here is the P2 wedge \
			 that stops every later broadcast, force-close sweeps included",
		);

		assert_eq!(handoff, Handoff::Unanswered, "a transaction no peer asked for was not relayed");
		assert!(!handoff.relayed());
	}

	#[tokio::test]
	async fn a_handoff_a_peer_does_pull_is_awaited_to_completion() {
		// Non-vacuity for the bound: it must not turn every handoff into a timeout.
		let logger = test_logger();

		let handoff = bounded_p2p_handoff(
			&logger,
			generous_test_timeout(),
			"the transaction under test",
			async {
				tokio::time::sleep(Duration::from_millis(5)).await;
				Ok::<(), &str>(())
			},
		)
		.await;

		assert!(handoff.relayed(), "a transaction a peer pulled must be reported as relayed");
	}

	#[tokio::test]
	async fn a_handoff_rejected_by_the_cbf_client_reports_failure_without_stalling() {
		// `submit_package` errors when the kyoto node has stopped. That is a fast, honest
		// failure and must stay distinct from the timeout path.
		let logger = test_logger();

		let handoff = bounded_p2p_handoff(
			&logger,
			generous_test_timeout(),
			"the transaction under test",
			async { Err::<(), &str>("the CBF node has stopped") },
		)
		.await;

		assert_eq!(handoff, Handoff::Refused("the CBF node has stopped".into()));
		assert!(!handoff.relayed(), "a submit error must not be reported as a relay");
	}

	#[tokio::test]
	async fn a_handoff_no_peer_pulls_does_not_wedge_the_broadcasts_behind_it() {
		// The scenario-10 shape in miniature: the node re-broadcasts a cooperative-close
		// transaction its counterparty already relayed (so no peer ever pulls it), and the
		// force-close sweeps queued behind it must still go out. This is the property that
		// makes the bound load-bearing, because the real drain loop is serial.
		let logger = test_logger();
		let relayed: Arc<Mutex<Vec<&str>>> = Arc::new(Mutex::new(Vec::new()));

		// (what, will a peer pull it?)
		let queue = vec![
			("the duplicate cooperative-close tx", false),
			("force-close sweep #1", true),
			("force-close sweep #2", true),
		];

		let drained = tokio::time::timeout(Duration::from_secs(5), async {
			for (what, pulled) in queue {
				let handoff = if pulled {
					bounded_p2p_handoff(&logger, short_handoff_timeout(), what, async {
						Ok::<(), &str>(())
					})
					.await
				} else {
					bounded_p2p_handoff(
						&logger,
						short_handoff_timeout(),
						what,
						never_pulled_by_a_peer(),
					)
					.await
				};
				if handoff.relayed() {
					relayed.lock().expect("lock").push(what);
				}
			}
		})
		.await;

		assert!(
			drained.is_ok(),
			"the serial broadcast drain must finish; hanging here is exactly the fund-safety \
			 defect (sweeps generated forever, none relayed)"
		);
		assert_eq!(
			*relayed.lock().expect("lock"),
			vec!["force-close sweep #1", "force-close sweep #2"],
			"every broadcast queued behind an un-pulled one must still reach a peer"
		);
	}

	// ------------------------------------------------------------------------------------------
	// N3: the package shape and the per-transaction outcomes over the handoff.
	// ------------------------------------------------------------------------------------------

	fn script(seed: u8) -> ScriptBuf {
		ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&[seed; 33]))
	}

	fn tx_spending(previous_output: OutPoint, pays: ScriptBuf) -> Transaction {
		Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: pays }],
		}
	}

	/// A parent and the child that spends it: the one pair kyoto takes as a package.
	fn parent_and_child() -> (Transaction, Transaction) {
		let parent =
			tx_spending(OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 }, script(1));
		let child = tx_spending(OutPoint { txid: parent.compute_txid(), vout: 0 }, script(2));
		(parent, child)
	}

	fn unrelated(seed: u8) -> Transaction {
		tx_spending(OutPoint { txid: Txid::from_byte_array([seed; 32]), vout: 0 }, script(seed))
	}

	/// What a fake peer does with each handoff, in submission order.
	#[derive(Clone, Copy)]
	enum Peer {
		Pulls,
		Ignores,
		/// The CBF node has stopped: the submission itself fails.
		NodeStopped,
	}

	/// A fake `submit_package` scripted per call, counting the calls.
	fn scripted_submit(
		script: Vec<Peer>,
	) -> (
		Arc<Mutex<usize>>,
		impl Fn(Package) -> std::pin::Pin<Box<dyn Future<Output = Result<(), &'static str>> + Send>>,
	) {
		let calls = Arc::new(Mutex::new(0usize));
		let counter = Arc::clone(&calls);
		let submit = move |_package: Package| {
			let mut n = counter.lock().expect("lock");
			let behaviour = script[*n];
			*n += 1;
			let fut: std::pin::Pin<Box<dyn Future<Output = Result<(), &'static str>> + Send>> =
				match behaviour {
					Peer::Pulls => Box::pin(async { Ok(()) }),
					Peer::Ignores => Box::pin(std::future::pending()),
					Peer::NodeStopped => Box::pin(async { Err("the CBF node has stopped") }),
				};
			fut
		};
		(calls, submit)
	}

	fn outcomes_of(outcomes: &PackageOutcomes) -> Vec<&TxBroadcastOutcome> {
		outcomes.iter().map(|(_, outcome)| outcome).collect()
	}

	#[tokio::test]
	async fn relay_package_hands_a_pair_over_as_one_package_and_the_rest_one_at_a_time() {
		let logger = test_logger();
		let (parent, child) = parent_and_child();

		// A parent and its child: one kyoto package, one handoff, both accepted.
		let (calls, submit) = scripted_submit(vec![Peer::Pulls]);
		let outcomes = relay_package(
			&logger,
			short_handoff_timeout(),
			&[parent.clone(), child.clone()],
			submit,
		)
		.await;
		assert_eq!(*calls.lock().unwrap(), 1, "a related pair is one package");
		assert_eq!(
			outcomes,
			vec![
				(parent.compute_txid(), TxBroadcastOutcome::Accepted),
				(child.compute_txid(), TxBroadcastOutcome::Accepted)
			]
		);

		// Two unrelated transactions are not a package kyoto takes: one handoff each.
		let (calls, submit) = scripted_submit(vec![Peer::Pulls, Peer::Pulls]);
		let outcomes =
			relay_package(&logger, short_handoff_timeout(), &[unrelated(1), unrelated(2)], submit)
				.await;
		assert_eq!(*calls.lock().unwrap(), 2, "an unrelated pair goes one at a time");
		assert!(outcomes.iter().all(|(_, o)| *o == TxBroadcastOutcome::Accepted));

		// Three transactions exceed kyoto's package size: one handoff each, in order.
		let (calls, submit) = scripted_submit(vec![Peer::Pulls, Peer::Pulls, Peer::Pulls]);
		let package = [unrelated(1), unrelated(2), unrelated(3)];
		let outcomes = relay_package(&logger, short_handoff_timeout(), &package, submit).await;
		assert_eq!(*calls.lock().unwrap(), 3);
		let txids: Vec<Txid> = outcomes.iter().map(|(txid, _)| *txid).collect();
		assert_eq!(txids, package.iter().map(|tx| tx.compute_txid()).collect::<Vec<_>>());
	}

	#[tokio::test]
	async fn relay_package_outcomes_count_every_announced_transaction_as_on_the_network() {
		let logger = test_logger();
		let package = [unrelated(1), unrelated(2), unrelated(3)];

		// One pulled: the ones nobody asked for were announced alongside it and are known.
		let (_, submit) = scripted_submit(vec![Peer::Ignores, Peer::Pulls, Peer::Ignores]);
		let outcomes = relay_package(&logger, short_handoff_timeout(), &package, submit).await;
		assert_eq!(
			outcomes_of(&outcomes),
			vec![
				&TxBroadcastOutcome::AlreadyKnown,
				&TxBroadcastOutcome::Accepted,
				&TxBroadcastOutcome::AlreadyKnown
			]
		);

		// None pulled: kyoto took and announced every one, so every one was handed to the
		// network. Reporting them unavailable would leave the wallet offering their inputs again.
		let (_, submit) = scripted_submit(vec![Peer::Ignores, Peer::Ignores, Peer::Ignores]);
		let outcomes = relay_package(&logger, short_handoff_timeout(), &package, submit).await;
		assert!(outcomes.iter().all(|(_, o)| *o == TxBroadcastOutcome::AlreadyKnown));
		assert_eq!(
			crate::chain::seam::package_result(outcomes),
			Ok(()),
			"an announced package is on the network: the chain stops, and the tail records it"
		);

		// A single transaction nobody pulled: the same.
		let (_, submit) = scripted_submit(vec![Peer::Ignores]);
		let outcomes =
			relay_package(&logger, short_handoff_timeout(), &[unrelated(4)], submit).await;
		assert_eq!(outcomes_of(&outcomes), vec![&TxBroadcastOutcome::AlreadyKnown]);

		// Kyoto refused the only transaction: handed to nobody, so unavailable.
		let (_, submit) = scripted_submit(vec![Peer::NodeStopped]);
		let outcomes =
			relay_package(&logger, short_handoff_timeout(), &[unrelated(5)], submit).await;
		assert!(matches!(outcomes[0].1, TxBroadcastOutcome::Unavailable { timed_out: false, .. }));

		// The node stopped mid-package: the refused sends are unavailable and not a timeout,
		// even though an earlier one was pulled.
		let (_, submit) = scripted_submit(vec![Peer::Pulls, Peer::NodeStopped, Peer::Ignores]);
		let outcomes = relay_package(&logger, short_handoff_timeout(), &package, submit).await;
		assert_eq!(outcomes[0].1, TxBroadcastOutcome::Accepted);
		assert!(matches!(outcomes[1].1, TxBroadcastOutcome::Unavailable { timed_out: false, .. }));
		assert_eq!(outcomes[2].1, TxBroadcastOutcome::AlreadyKnown);

		// Never a verdict: no outcome of a P2P relay is `Rejected`.
		assert!(!outcomes.iter().any(|(_, o)| matches!(o, TxBroadcastOutcome::Rejected(_))));
	}

	// ------------------------------------------------------------------------------------------
	// N3: the coinbase-derived fee window.
	// ------------------------------------------------------------------------------------------

	#[test]
	fn fee_cache_from_samples_fills_every_target_or_none() {
		// A window of ascending rates: every target reads its own percentile, so an urgent
		// target never reads below a relaxed one.
		let samples: Vec<FeeRate> =
			(1..=14u64).map(|n| FeeRate::from_sat_per_kwu(n * 1_000)).collect();
		let cache = fee_cache_from_samples(&samples).expect("a non-empty window has an answer");
		for target in get_all_conf_targets() {
			assert!(cache.contains_key(&target), "{:?} is missing from the cache", target);
		}
		assert_eq!(cache.len(), get_all_conf_targets().len(), "all targets, never partial");

		// Regtest coinbases pay no fees at all: the floor keeps every target relayable.
		let free: Vec<FeeRate> = vec![FeeRate::ZERO; 5];
		let cache = fee_cache_from_samples(&free).expect("zero samples are still samples");
		for (target, rate) in &cache {
			assert!(
				rate.to_sat_per_kwu() >= CBF_MIN_FEERATE_SAT_PER_KWU,
				"{:?} read {} sat/kwu, below the floor",
				target,
				rate.to_sat_per_kwu()
			);
		}

		// No sample: no answer, rather than an invented one.
		assert!(fee_cache_from_samples(&[]).is_none());
	}

	#[test]
	fn cached_rate_is_reused_only_while_the_block_is_canonical() {
		let canonical = BlockHash::from_byte_array([0xaa; 32]);
		let reorged_out = BlockHash::from_byte_array([0xbb; 32]);
		let rate = FeeRate::from_sat_per_kwu(1_234);
		let mut cached = BTreeMap::new();
		cached.insert(100, (canonical, rate));
		cached.insert(101, (reorged_out, rate));

		assert_eq!(cached_rate(&cached, 100, canonical), Some(rate), "still canonical: reused");
		assert_eq!(cached_rate(&cached, 101, canonical), None, "reorged out: downloaded again");
		assert_eq!(cached_rate(&cached, 102, canonical), None, "never sampled: downloaded");
	}

	#[test]
	fn budgets_cover_the_worst_case_of_their_bounded_requests() {
		// 15 header lookups and 14 block fetches of 10 s each, plus the margin.
		assert_eq!(CBF_DERIVED_FEE_BUDGET, Duration::from_secs(15 * 10 + 14 * 10 + 1));
		// The largest package, one 10 s handoff per transaction, plus the margin.
		assert_eq!(CBF_P2P_BROADCAST_BUDGET, Duration::from_secs(25 * 10 + 1));
	}

	// ------------------------------------------------------------------------------------------
	// N3: the forward-only watch.
	// ------------------------------------------------------------------------------------------

	#[cfg(feature = "swaps")]
	#[tokio::test]
	async fn watch_tx_status_answers_only_a_confirmation_it_saw() {
		use bdk_chain::BlockId;

		let ledger = Arc::new(WatchLedger::new());
		let adapter = CbfWatchTxStatus::new(Arc::clone(&ledger));
		let (watched, unwatched) =
			(Txid::from_byte_array([1u8; 32]), Txid::from_byte_array([2u8; 32]));
		let block = |height: u32, seed: u8| BlockId {
			height,
			hash: BlockHash::from_byte_array([seed; 32]),
		};
		let unavailable = |r: ActionResult<Anchored<RawTxObservation>>| {
			matches!(r, Err(ChainActionError::Unavailable { timed_out: false, .. }))
		};

		// Nobody asked: the chain falls through.
		assert!(unavailable(adapter.tx_status(unwatched, None).await));

		// Watched but not seen yet: a filter node cannot tell the cases apart, so no answer.
		ledger.watch_swap(watched);
		assert!(unavailable(adapter.tx_status(watched, None).await));

		// Seen at 100, tip at 102: three confirmations, anchored to the applied tip.
		ledger.note_connected(block(100, 0xa0), [watched]);
		ledger.note_connected(block(101, 0xa1), []);
		ledger.note_connected(block(102, 0xa2), []);
		let answer = adapter.tx_status(watched, None).await.unwrap();
		assert_eq!(
			answer.value,
			RawTxObservation::Confirmed { height: Some(100), confirmations: 3 }
		);
		assert_eq!(answer.tip, Some(block(102, 0xa2)));

		// A reorg that takes the block back takes the answer with it.
		let header = bitcoin::block::Header {
			version: bitcoin::block::Version::TWO,
			prev_blockhash: block(99, 0x99).hash,
			merkle_root: bitcoin::TxMerkleNode::all_zeros(),
			time: 0,
			bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
			nonce: 0,
		};
		ledger.note_disconnected(&header, 100);
		assert!(unavailable(adapter.tx_status(watched, None).await));

		// Seen again on the new branch: answered again, at the new depth.
		ledger.note_connected(block(100, 0xb0), [watched]);
		let answer = adapter.tx_status(watched, None).await.unwrap();
		assert_eq!(
			answer.value,
			RawTxObservation::Confirmed { height: Some(100), confirmations: 1 }
		);

		// Let go: never asked again.
		ledger.unwatch_swap(&watched);
		assert!(unavailable(adapter.tx_status(watched, None).await));
	}

	// ------------------------------------------------------------------------------------------
	// N3: every adapter over an engine whose kyoto is not running says so.
	// ------------------------------------------------------------------------------------------

	fn stopped_engine() -> (Arc<CbfSyncEngine>, Arc<Logger>) {
		use std::sync::RwLock;

		use lightning::util::test_utils::TestStore;

		use crate::chain::test_wallet::fresh_regtest_wallet;
		use crate::config::Config;
		use crate::fee_estimator::OnchainFeeEstimator;
		use crate::tx_broadcaster::TransactionBroadcaster;
		use crate::types::DynStore;
		use crate::NodeMetrics;

		let logger = Arc::new(test_logger());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let broadcaster = Arc::new(TransactionBroadcaster::new(Arc::clone(&logger)));
		let fee_estimator = Arc::new(OnchainFeeEstimator::new());
		let wallet = fresh_regtest_wallet(&kv_store, &broadcaster, &fee_estimator, &logger);
		let config = Arc::new(Config { network: bitcoin::Network::Regtest, ..Config::default() });
		let engine = CbfSyncEngine::new(
			Vec::new(),
			1,
			None,
			None,
			wallet,
			kv_store,
			config,
			Arc::clone(&logger),
			Arc::new(RwLock::new(NodeMetrics::default())),
		)
		.expect("an engine that connects to nothing");
		(Arc::new(engine), logger)
	}

	#[tokio::test]
	async fn adapters_over_a_stopped_kyoto_are_unavailable_not_wrong() {
		let (engine, logger) = stopped_engine();

		let fee = CbfDerivedFee::new(Arc::clone(&engine), Arc::clone(&logger));
		assert!(matches!(
			fee.fee_rate_update().await,
			Err(ChainActionError::Unavailable { timed_out: false, .. })
		));

		let broadcast = CbfP2pBroadcast::new(Arc::clone(&engine), Arc::clone(&logger));
		assert!(!broadcast.ready().await, "nothing to hand a peer without kyoto");
		assert!(matches!(
			broadcast.broadcast_package(&[unrelated(1)]).await,
			Err(ChainActionError::Unavailable { timed_out: false, .. })
		));

		let utxo = CbfUtxoSource::new(Arc::clone(&engine), Arc::clone(&logger));
		let (source, verification) = utxo.utxo_source().expect("declared once enabled");
		assert_eq!(verification, UtxoVerification::ExistenceOnly);
		assert_eq!(UtxoCapability::name(&utxo), "cbf");
		let hash = BlockHash::all_zeros();
		let transient =
			|e: BlockSourceError| e.kind() == lightning_block_sync::BlockSourceErrorKind::Transient;
		assert!(source.get_block_hash_by_height(1).await.is_err_and(transient));
		assert!(source.get_block(&hash).await.is_err_and(transient));
		assert!(source.get_best_block().await.is_err_and(transient));
		// Headers are never served, running or not.
		let header = source.get_header(&hash, Some(1)).await.unwrap_err();
		assert_eq!(header.kind(), lightning_block_sync::BlockSourceErrorKind::Persistent);
		// The one answer that needs no node: spent-ness is taken on trust, by declaration.
		assert_eq!(source.is_output_unspent(OutPoint::null()).await.unwrap(), true);
	}
}
