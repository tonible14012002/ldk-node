// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The pluggable chain abilities.
//!
//! Each ability is one slot on [`crate::chain::ChainLayer`]. A slot is an
//! **ordered chain of adapters** — an [`ActionChain`] — not a single adapter.
//! A node functions identically whichever adapters occupy a slot, and no code
//! outside slot construction branches on which ones they are.
//!
//! # The per-action slots
//!
//! | Slot             | Trait                   | Default budget           |
//! |------------------|-------------------------|--------------------------|
//! | FEE              | [`FeeAction`]           | [`FEE_BUDGET`]           |
//! | BROADCAST        | [`BroadcastAction`]     | [`BROADCAST_BUDGET`]     |
//! | TX_STATUS        | `TxStatusAction`        | [`TX_STATUS_BUDGET`]     |
//! | MEMPOOL          | [`MempoolAction`]       | [`MEMPOOL_BUDGET`]       |
//! | SCRIPT_HISTORY   | [`ScriptHistoryAction`] | [`SCRIPT_HISTORY_BUDGET`]|
//! | UTXO             | [`UtxoCapability`]      | — (not an action)        |
//!
//! The slot default applies to an adapter that declares no budget of its own
//! (`budget() == None`). An adapter whose backend already bounds itself
//! declares a budget sitting just above that bound, so its own timeout fires
//! first and the error it logs is the one an operator sees.
//!
//! Headers, blocks and filter matches are deliberately **not** slots: their
//! only consumers are a `Listen`-driven sync engine and its `UtxoSource`, and a
//! block fetched from a different adapter than the headers came from would fail
//! reorg consistency anyway. They stay engine-internal.
//!
//! # Error taxonomy
//!
//! Every action answers with an [`ActionResult`], whose error is
//! [`ChainActionError`]:
//!
//! ```text
//!   Unavailable   the adapter could not answer
//!                 -> the chain advances to the next adapter
//!                    timeout and transport failure both map here
//!
//!   Rejected      the adapter answered, and the answer is NO
//!                 -> terminal; the chain does NOT advance
//!                    a tx the network refuses is refused by every adapter
//!
//!   Ok            answer accepted; the chain stops here
//! ```
//!
//! The split is load-bearing. A Dependent node must be able to tell "nobody
//! could answer" from "I was told no": conflating the two is how a node treats
//! an unreachable provider as evidence that a transaction was refused, or —
//! worse — keeps trying the next adapter with a transaction the network has
//! already rejected.
//!
//! # Rules the combinator enforces
//!
//! * **Every call runs under a budget the seam enforces.** [`ActionChain`]
//!   wraps each adapter call in [`tokio::time::timeout`] — the adapter's
//!   declared budget, else the slot default — and an adapter that overruns it
//!   is `Unavailable` with `timed_out` set. An adapter may say how long it
//!   legitimately takes; it may not run unbounded.
//! * **Exhaustion is an honest failure.** When no adapter answers, the slot
//!   fails with `Unavailable`. The seam never fabricates an answer and never
//!   serves a stale value a caller would act on.
//! * **A chain of length one is legal.** That is how "no fallback" is spelled.
//!   An empty chain is legal to construct and always `Unavailable`.
//!
//! FEE, BROADCAST and TX_STATUS run on chains; MEMPOOL and SCRIPT_HISTORY
//! follow.
//!
//! # BROADCAST is package-shaped
//!
//! The queue hands the slot every transaction LDK asked to broadcast together
//! (a commitment tx and its anchor CPFP, say), and the adapter answers for the
//! package. Each backend still sends one transaction at a time and keeps its
//! own error classification and log levels; it folds each send into a
//! [`TxBroadcastOutcome`] and [`package_result`] turns the package's worth of
//! those into the slot's answer. `Ok` means every transaction was handed to
//! the network — accepted, or already known to it. `Rejected` lists the
//! transactions the network refused, and the layer's shared tail evicts them
//! from the on-chain wallet so their inputs are spendable again.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::{FeeRate, ScriptBuf, Transaction, Txid};

use bdk_chain::BlockId;

use lightning_block_sync::gossip::UtxoSource;

use crate::chain::provider::{ChainProviderError, WireSyncRequest};
use crate::config::TX_BROADCAST_TIMEOUT_SECS;
use crate::fee_estimator::ConfirmationTarget;
use crate::logger::{log_debug, log_info, LdkLogger, Logger};
use crate::Error;

#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;

use async_trait::async_trait;

/// The outcome of asking a [`FeeAction`] for a fee-rate update.
///
/// Richer than a plain map because the pre-seam implementations had two
/// non-obvious outcomes that must be preserved exactly:
///
/// * a source may decide to **skip** a round — keeping the previous cache and
///   deliberately *not* advancing the fee-rate-cache metrics timestamp;
/// * a source may only want the "update finished" line logged when the cache
///   actually changed, because it refreshes often enough to be spammy.
#[derive(Debug)]
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

// ── PER-ACTION SEAM ──────────────────────────────────────────────────────────
//
// Everything below is the per-action shape of the seam: one result type, one
// trait per action, and the combinator that runs an ordered adapter chain
// under a budget. FEE, BROADCAST and TX_STATUS are wired into `ChainLayer`;
// the items belonging to slots not yet moved carry `dead_code` allowances
// that are removed as each slot lands.

/// Default budget for a FEE adapter that declares none of its own.
pub(crate) const FEE_BUDGET: Duration = Duration::from_secs(5);
/// Default budget for a BROADCAST adapter that declares none of its own.
pub(crate) const BROADCAST_BUDGET: Duration = Duration::from_secs(15);
/// Default budget for a TX_STATUS adapter that declares none of its own.
#[cfg(feature = "swaps")]
pub(crate) const TX_STATUS_BUDGET: Duration = Duration::from_secs(10);
/// Default budget for a MEMPOOL adapter that declares none of its own.
#[allow(dead_code)] // consumed once the MEMPOOL slot runs on an `ActionChain`
pub(crate) const MEMPOOL_BUDGET: Duration = Duration::from_secs(30);
/// Default budget for a SCRIPT_HISTORY adapter that declares none of its own.
#[allow(dead_code)] // consumed once the SCRIPT_HISTORY slot runs on an `ActionChain`
pub(crate) const SCRIPT_HISTORY_BUDGET: Duration = Duration::from_secs(90);

/// Headroom an adapter adds above the timeout its backend already enforces
/// when declaring its budget, so the backend's own timeout fires first and the
/// error it logs — not a bare seam timeout — is what an operator sees.
pub(crate) const ADAPTER_BUDGET_MARGIN: Duration = Duration::from_secs(1);

/// The most transactions one broadcast package is sized for when an adapter
/// that sends them one at a time declares its budget: Bitcoin Core's own
/// package limit (`MAX_PACKAGE_COUNT`), which nothing LDK hands the
/// broadcaster exceeds.
pub(crate) const MAX_BROADCAST_PACKAGE_TXS: u64 = 25;

/// BROADCAST budget for an adapter that sends a package one transaction at a
/// time, each under its backend's own [`TX_BROADCAST_TIMEOUT_SECS`] — the
/// pre-seam per-transaction bound, which nothing here shortens. The largest
/// package worth of those, plus the margin, so the backend's per-transaction
/// timeout and its log line always fire before the seam's.
pub(crate) const PER_TX_BROADCAST_BUDGET: Duration = Duration::from_secs(
	TX_BROADCAST_TIMEOUT_SECS * MAX_BROADCAST_PACKAGE_TXS + ADAPTER_BUDGET_MARGIN.as_secs(),
);

/// Why an adapter did not produce an accepted answer.
///
/// See the module docs for the taxonomy. `R` is the slot's rejection payload:
/// a plain reason for most slots, a per-transaction list for BROADCAST
/// ([`BroadcastRejection`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainActionError<R = String> {
	/// The adapter could not answer: unstarted, unreachable, timed out, or
	/// handed back something it could not parse. The chain advances.
	Unavailable {
		reason: String,
		/// Whether running out of time is why: the seam's budget, the
		/// backend's own wire timeout, or — for an exhausted chain — any
		/// adapter that timed out. A chain of one reports exactly what its
		/// adapter did; a longer chain reports a timeout when a timeout is
		/// part of why it was exhausted, because a reachable-but-slow source
		/// is the thing an operator can act on. Callers that distinguish
		/// "timed out" from "failed" read this, never the reason text.
		timed_out: bool,
	},
	/// The adapter answered, and the answer is no. Terminal for the chain.
	Rejected(R),
}

impl<R> ChainActionError<R> {
	/// An `Unavailable` that did not run out of time.
	pub(crate) fn unavailable(reason: impl Into<String>) -> Self {
		Self::Unavailable { reason: reason.into(), timed_out: false }
	}

	/// An `Unavailable` whose cause is running out of time.
	pub(crate) fn timed_out(reason: impl Into<String>) -> Self {
		Self::Unavailable { reason: reason.into(), timed_out: true }
	}

	/// An `Unavailable` recording that the call overran `budget`.
	fn budget_exceeded(budget: Duration) -> Self {
		Self::timed_out(format!("timed out after {}ms", budget.as_millis()))
	}
}

impl<R: std::fmt::Debug> std::fmt::Display for ChainActionError<R> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Unavailable { reason, .. } => write!(f, "unavailable: {}", reason),
			Self::Rejected(reason) => write!(f, "rejected: {:?}", reason),
		}
	}
}

/// A remote provider that could not be used is never a rejection: whether it
/// was unreachable, refused to serve, replied garbage or spoke the wrong wire
/// version, nothing is known about the chain as a result, and the next
/// adapter must get its turn. The variant's own `Display` text is kept as the
/// reason so the fall-through log still says which of the four it was.
///
/// `Unreachable` covers "no response" as well as "no route", and the
/// pre-chain Dependent adapter already reported it as a timeout; that rule
/// lives here now.
impl<R> From<ChainProviderError> for ChainActionError<R> {
	fn from(e: ChainProviderError) -> Self {
		let timed_out = matches!(e, ChainProviderError::Unreachable(_));
		Self::Unavailable { reason: e.to_string(), timed_out }
	}
}

/// A backend's own [`Error`] is never a rejection either: the pre-chain
/// adapters reported every failure to answer as an `Error`, and none of those
/// is the network saying no. The `*Timeout` variants set `timed_out`, which is
/// what lets the FEE slot tell [`Error::FeerateEstimationUpdateTimeout`] from
/// [`Error::FeerateEstimationUpdateFailed`] after the chain has run.
impl<R> From<Error> for ChainActionError<R> {
	fn from(e: Error) -> Self {
		let timed_out = matches!(
			e,
			Error::FeerateEstimationUpdateTimeout
				| Error::WalletOperationTimeout
				| Error::TxSyncTimeout
				| Error::GossipUpdateTimeout
		);
		Self::Unavailable { reason: e.to_string(), timed_out }
	}
}

/// What a BROADCAST adapter says no to: each refused txid with its reason.
pub(crate) type BroadcastRejection = Vec<(Txid, String)>;

/// What one backend said about one transaction of a package.
///
/// The shared vocabulary every BROADCAST adapter folds its own error
/// classification into, one transaction at a time; [`package_result`] turns a
/// package's worth into the slot's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TxBroadcastOutcome {
	/// The backend took it.
	Accepted,
	/// The backend already had it, in its mempool or in a block. As good as
	/// accepted: the network has the transaction.
	AlreadyKnown,
	/// The backend gave a verdict against the transaction itself — a mempool
	/// policy or verification failure — with the reason it gave.
	Rejected(String),
	/// The backend could not be asked, or did not answer.
	Unavailable { reason: String, timed_out: bool },
}

/// A failure to *answer* is `Unavailable`; a verdict is `Rejected`. Lets an
/// adapter reuse the [`Error`] and [`ChainProviderError`] rules above for a
/// single transaction.
impl From<ChainActionError> for TxBroadcastOutcome {
	fn from(e: ChainActionError) -> Self {
		match e {
			ChainActionError::Unavailable { reason, timed_out } => {
				Self::Unavailable { reason, timed_out }
			},
			ChainActionError::Rejected(reason) => Self::Rejected(reason),
		}
	}
}

/// Fold a package's per-transaction outcomes into the slot's answer.
///
/// `Ok` only when every transaction was handed to the network — accepted, or
/// already known to it. Otherwise, in order of precedence:
///
/// * any `Unavailable` makes the package `Unavailable` (`timed_out` if any
///   send was), even if another transaction was rejected. A package with one
///   unsent transaction was not handed to the network; the chain advances and
///   the next adapter resends the whole package — already-known sends are
///   `Ok`, and the rejection surfaces again there, or on the next drain pass,
///   from whichever adapter is up. Reporting `Rejected` here would claim the
///   unsent transactions were accepted, a claim the shared tail acts on.
/// * else any `Rejected` makes the package `Rejected`, listing every refused
///   transaction with its reason. Transactions not listed were accepted.
pub(crate) fn package_result(
	outcomes: impl IntoIterator<Item = (Txid, TxBroadcastOutcome)>,
) -> ActionResult<(), BroadcastRejection> {
	let mut rejected: BroadcastRejection = Vec::new();
	let mut unavailable: Vec<String> = Vec::new();
	let mut any_timed_out = false;

	for (txid, outcome) in outcomes {
		match outcome {
			TxBroadcastOutcome::Accepted | TxBroadcastOutcome::AlreadyKnown => {},
			TxBroadcastOutcome::Rejected(reason) => rejected.push((txid, reason)),
			TxBroadcastOutcome::Unavailable { reason, timed_out } => {
				any_timed_out |= timed_out;
				unavailable.push(format!("{}: {}", txid, reason));
			},
		}
	}

	if !unavailable.is_empty() {
		return Err(ChainActionError::Unavailable {
			reason: unavailable.join("; "),
			timed_out: any_timed_out,
		});
	}
	if !rejected.is_empty() {
		return Err(ChainActionError::Rejected(rejected));
	}
	Ok(())
}

/// The result of one adapter answering one action.
pub(crate) type ActionResult<T, R = String> = Result<T, ChainActionError<R>>;

/// An answer together with the chain tip it was derived against.
///
/// Carried so a hybrid node can refuse an answer computed on a chain it does
/// not consider best: a provider's `tip` that is not on our chain makes the
/// answer `Unavailable` and the chain advances. `None` means the adapter has
/// no notion of a tip to report (a fee cache, for instance).
// Without `swaps` only MEMPOOL and SCRIPT_HISTORY carry a tip, and neither
// runs on a chain yet.
#[cfg_attr(not(feature = "swaps"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Anchored<T> {
	pub value: T,
	pub tip: Option<BlockId>,
}

/// An accepted answer, tagged with the adapter that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answered<T> {
	pub value: T,
	/// [`FeeAction::name`] (and friends) of the adapter that answered.
	pub by: &'static str,
}

/// FEE — produces a fee-rate cache update.
#[async_trait]
pub(crate) trait FeeAction: Send + Sync {
	/// Stable identifier, for logs and for [`Answered::by`].
	fn name(&self) -> &'static str;

	/// How long one call may legitimately take, when the backend already
	/// bounds itself; `None` takes the slot default. Declared just above the
	/// backend's own timeout so that timeout — and its log line — fires first.
	fn budget(&self) -> Option<Duration> {
		None
	}

	async fn fee_rate_update(&self) -> ActionResult<FeeUpdate>;
}

/// BROADCAST — puts a package of transactions on the network.
///
/// Package semantics: the adapter is handed every transaction the queue
/// produced together (a commitment tx and its anchor CPFP, say), and answers
/// for the package. `Rejected` lists the txids the network refused; a
/// rejected package is never retried on the next adapter, because the network
/// that refused it is the same network.
#[async_trait]
pub(crate) trait BroadcastAction: Send + Sync {
	/// Stable identifier, for logs and for [`Answered::by`].
	fn name(&self) -> &'static str;

	/// How long one call may legitimately take, when the backend already
	/// bounds itself; `None` takes the slot default. Declared just above the
	/// backend's own timeout so that timeout — and its log line — fires first.
	fn budget(&self) -> Option<Duration> {
		None
	}

	/// Whether the backend can broadcast right now.
	///
	/// `false` is `Unavailable` without the round trip. A drain pass in which
	/// no adapter of the chain is ready is abandoned before anything is
	/// pulled from the queue, so the packages wait for the next tick rather
	/// than being lost to an exhausted chain.
	async fn ready(&self) -> bool {
		true
	}

	/// Send `txs` and answer for the package; see [`package_result`] for what
	/// the answer means.
	async fn broadcast_package(&self, txs: &[Transaction]) -> ActionResult<(), BroadcastRejection>;
}

/// TX_STATUS — reorg-aware status of an ARBITRARY transaction, one the local
/// wallet need not own.
///
/// FAIL-CLOSED (E6): an adapter that cannot answer returns `Unavailable`, so
/// the chain advances; when the chain is exhausted the caller sees an error,
/// never an observation it could fold into "confirmed". The observation is
/// [`Anchored`] to the tip it was derived against.
#[cfg(feature = "swaps")]
#[async_trait]
pub(crate) trait TxStatusAction: Send + Sync {
	/// Stable identifier, for logs and for [`Answered::by`].
	fn name(&self) -> &'static str;

	/// How long one call may legitimately take, when the backend already
	/// bounds itself; `None` takes the slot default. Declared just above the
	/// backend's own timeout so that timeout — and its log line — fires first.
	fn budget(&self) -> Option<Duration> {
		None
	}

	async fn tx_status(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> ActionResult<Anchored<RawTxObservation>>;
}

/// What the wallet wants to know about the mempool.
#[allow(dead_code)] // consumed once the MEMPOOL slot runs on an `ActionChain`
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MempoolQuery {
	/// Scripts the wallet watches.
	pub scripts: Vec<ScriptBuf>,
	/// Unconfirmed transactions the wallet already knows, so the adapter can
	/// report evictions.
	pub known_unconfirmed: Vec<Txid>,
	/// The wallet's current height, so the adapter can bound its answer.
	pub height_hint: u32,
}

/// What the mempool said.
#[allow(dead_code)] // consumed once the MEMPOOL slot runs on an `ActionChain`
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MempoolAnswer {
	/// Relevant unconfirmed transactions with the time they were first seen.
	pub unconfirmed: Vec<(Transaction, u64)>,
	/// Known-unconfirmed txids no longer in the mempool, with the eviction
	/// time.
	pub evicted: Vec<(Txid, u64)>,
}

/// MEMPOOL — relevant unconfirmed transactions and evictions.
#[allow(dead_code)] // consumed once the MEMPOOL slot runs on an `ActionChain`
#[async_trait]
pub(crate) trait MempoolAction: Send + Sync {
	/// Stable identifier, for logs and for [`Answered::by`].
	fn name(&self) -> &'static str;

	/// How long one call may legitimately take, when the backend already
	/// bounds itself; `None` takes the slot default. Declared just above the
	/// backend's own timeout so that timeout — and its log line — fires first.
	fn budget(&self) -> Option<Duration> {
		None
	}

	async fn mempool(&self, query: MempoolQuery) -> ActionResult<Anchored<MempoolAnswer>>;
}

/// SCRIPT_HISTORY — the wide wallet scan, phrased on the wire type because
/// BDK's own request holds a closure and cannot be handed to a remote adapter.
#[allow(dead_code)] // consumed once the SCRIPT_HISTORY slot runs on an `ActionChain`
#[async_trait]
pub(crate) trait ScriptHistoryAction: Send + Sync {
	/// Stable identifier, for logs and for [`Answered::by`].
	fn name(&self) -> &'static str;

	/// How long one call may legitimately take, when the backend already
	/// bounds itself; `None` takes the slot default. Declared just above the
	/// backend's own timeout so that timeout — and its log line — fires first.
	fn budget(&self) -> Option<Duration> {
		None
	}

	async fn script_history(
		&self, req: WireSyncRequest,
	) -> ActionResult<Anchored<bdk_wallet::Update>>;
}

/// How far a [`UtxoSource`] actually checks a `channel_announcement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UtxoVerification {
	/// The output is fetched and its value and script are checked.
	Full,
	/// Only that the output exists unspent is checked; value and script are
	/// taken on trust.
	#[allow(dead_code)] // declared by the CBF UTXO source once it exists
	ExistenceOnly,
}

impl UtxoVerification {
	/// For the startup log.
	pub(crate) fn as_str(self) -> &'static str {
		match self {
			Self::Full => "full",
			Self::ExistenceOnly => "existence-only",
		}
	}
}

/// UTXO — the source used to verify BOLT-7 `channel_announcement`s.
///
/// Not an action: it is a capability the layer asks for once at startup. `None`
/// declares that announcements are accepted unverified.
pub(crate) trait UtxoCapability: Send + Sync {
	/// Stable identifier, for logs.
	fn name(&self) -> &'static str;

	fn utxo_source(&self) -> Option<(Arc<dyn UtxoSource>, UtxoVerification)>;
}

/// An ordered chain of adapters for one slot, each call run under a budget.
///
/// `A` is the slot's action trait object (`dyn FeeAction`, ...). The chain
/// owns the fallback rules described in the module docs; adapters own only
/// their answer and, optionally, how long it may take.
pub(crate) struct ActionChain<A: ?Sized> {
	slot: &'static str,
	budget: Duration,
	adapters: Vec<Arc<A>>,
	last_answered: Mutex<Option<&'static str>>,
	logger: Arc<Logger>,
}

impl<A: ?Sized + Send + Sync + SlotAdapter> ActionChain<A> {
	/// A chain for `slot`, trying `adapters` in order, each under its own
	/// declared budget or, failing that, `budget`.
	pub(crate) fn new(
		slot: &'static str, budget: Duration, adapters: Vec<Arc<A>>, logger: Arc<Logger>,
	) -> Self {
		Self { slot, budget, adapters, last_answered: Mutex::new(None), logger }
	}

	/// The adapter names in chain order, for the startup log.
	pub(crate) fn names(&self) -> Vec<&'static str> {
		self.adapters.iter().map(|a| Self::adapter_name(a)).collect()
	}

	/// The adapters in chain order, for a slot whose drain needs to ask them
	/// something before running the chain (BROADCAST asks who is ready).
	pub(crate) fn adapters(&self) -> &[Arc<A>] {
		&self.adapters
	}

	/// Which adapter answered most recently, if any has.
	///
	/// A poisoned lock holds a plain `Option<&'static str>` that no panic can
	/// leave half-written, so the value is taken as is.
	#[allow(dead_code)] // read by diagnostics once every slot runs on a chain
	pub(crate) fn last_answered(&self) -> Option<&'static str> {
		*self.last_answered.lock().unwrap_or_else(|e| e.into_inner())
	}

	#[allow(dead_code)] // read once every slot runs on a chain
	pub(crate) fn is_empty(&self) -> bool {
		self.adapters.is_empty()
	}

	/// Run `action` against each adapter in order until one answers.
	///
	/// Each call runs under the adapter's declared budget, or the slot default
	/// when it declares none. `Unavailable` (including a budget timeout)
	/// advances to the next adapter; `Rejected` returns at once and no later
	/// adapter is tried; `Ok` stops the chain, records the answerer and
	/// returns it. An empty or exhausted chain is `Unavailable` — never a
	/// stale or invented value — and an exhausted one reports every adapter's
	/// reason, in order, and is `timed_out` if any of them was.
	///
	/// `action` receives an owned `Arc` so the future it builds borrows nothing
	/// from the chain: that is what lets a single `Fut` type serve every
	/// adapter without a higher-ranked lifetime on the closure.
	pub(crate) async fn run<T, R, F, Fut>(&self, action: F) -> ActionResult<Answered<T>, R>
	where
		F: Fn(Arc<A>) -> Fut,
		Fut: Future<Output = ActionResult<T, R>>,
	{
		let mut reasons: Vec<String> = Vec::with_capacity(self.adapters.len());
		let mut any_timed_out = false;

		for (idx, adapter) in self.adapters.iter().enumerate() {
			let name = Self::adapter_name(adapter);
			let next = self.adapters.get(idx + 1).map(Self::adapter_name);
			let budget = SlotAdapter::budget(&**adapter).unwrap_or(self.budget);

			let outcome = match tokio::time::timeout(budget, action(Arc::clone(adapter))).await {
				Ok(outcome) => outcome,
				Err(_elapsed) => Err(ChainActionError::budget_exceeded(budget)),
			};

			match outcome {
				Ok(value) => {
					*self.last_answered.lock().unwrap_or_else(|e| e.into_inner()) = Some(name);
					log_debug!(self.logger, "slot={} answered_by={}", self.slot, name);
					return Ok(Answered { value, by: name });
				},
				Err(ChainActionError::Rejected(reason)) => {
					log_info!(
						self.logger,
						"slot={} adapter={} rejected; not trying the remaining adapters",
						self.slot,
						name
					);
					return Err(ChainActionError::Rejected(reason));
				},
				Err(ChainActionError::Unavailable { reason, timed_out }) => {
					any_timed_out |= timed_out;
					match next {
						Some(next) => log_debug!(
							self.logger,
							"slot={} adapter={} unavailable ({}); falling through to adapter={}",
							self.slot,
							name,
							reason,
							next
						),
						None => log_info!(
							self.logger,
							"slot={} adapter={} unavailable ({}); chain exhausted",
							self.slot,
							name,
							reason
						),
					}
					reasons.push(format!("{}: {}", name, reason));
				},
			}
		}

		let reason = if reasons.is_empty() {
			String::from("no adapters configured")
		} else {
			reasons.join("; ")
		};
		Err(ChainActionError::Unavailable {
			reason: format!("{}: exhausted: {}", self.slot, reason),
			timed_out: any_timed_out,
		})
	}

	fn adapter_name(adapter: &Arc<A>) -> &'static str {
		SlotAdapter::name(&**adapter)
	}
}

/// What every action trait shares: a stable name and an optional budget.
/// Implemented for each action trait object so [`ActionChain`] can log, tag
/// answers and bound calls without knowing which slot it is running.
pub(crate) trait SlotAdapter {
	fn name(&self) -> &'static str;
	fn budget(&self) -> Option<Duration>;
}

impl SlotAdapter for dyn FeeAction {
	fn name(&self) -> &'static str {
		FeeAction::name(self)
	}
	fn budget(&self) -> Option<Duration> {
		FeeAction::budget(self)
	}
}

impl SlotAdapter for dyn BroadcastAction {
	fn name(&self) -> &'static str {
		BroadcastAction::name(self)
	}
	fn budget(&self) -> Option<Duration> {
		BroadcastAction::budget(self)
	}
}

#[cfg(feature = "swaps")]
impl SlotAdapter for dyn TxStatusAction {
	fn name(&self) -> &'static str {
		TxStatusAction::name(self)
	}
	fn budget(&self) -> Option<Duration> {
		TxStatusAction::budget(self)
	}
}

impl SlotAdapter for dyn MempoolAction {
	fn name(&self) -> &'static str {
		MempoolAction::name(self)
	}
	fn budget(&self) -> Option<Duration> {
		MempoolAction::budget(self)
	}
}

impl SlotAdapter for dyn ScriptHistoryAction {
	fn name(&self) -> &'static str {
		ScriptHistoryAction::name(self)
	}
	fn budget(&self) -> Option<Duration> {
		ScriptHistoryAction::budget(self)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::time::Instant;

	use bitcoin::hashes::Hash;

	/// What one fake adapter does when asked.
	enum Behaviour {
		Ok(u64),
		/// Answers `Ok` only after sleeping this long.
		SlowOk(Duration, u64),
		Unavailable,
		/// Unavailable because its own backend timed out.
		UnavailableTimedOut,
		Rejected,
		/// Never answers; only the seam's budget ends the call.
		Hang,
	}

	struct FakeFee {
		name: &'static str,
		behaviour: Behaviour,
		/// The budget the fake declares, if any.
		budget: Option<Duration>,
		calls: AtomicUsize,
	}

	impl FakeFee {
		fn new(name: &'static str, behaviour: Behaviour) -> Arc<Self> {
			Arc::new(Self { name, behaviour, budget: None, calls: AtomicUsize::new(0) })
		}

		fn with_budget(name: &'static str, behaviour: Behaviour, budget: Duration) -> Arc<Self> {
			Arc::new(Self { name, behaviour, budget: Some(budget), calls: AtomicUsize::new(0) })
		}

		fn calls(&self) -> usize {
			self.calls.load(Ordering::SeqCst)
		}
	}

	fn applied(rate: u64) -> FeeUpdate {
		let mut cache = HashMap::new();
		cache.insert(ConfirmationTarget::OnchainPayment, FeeRate::from_sat_per_kwu(rate));
		FeeUpdate::Apply { cache, log_unchanged: false }
	}

	#[async_trait]
	impl FeeAction for FakeFee {
		fn name(&self) -> &'static str {
			self.name
		}

		fn budget(&self) -> Option<Duration> {
			self.budget
		}

		async fn fee_rate_update(&self) -> ActionResult<FeeUpdate> {
			self.calls.fetch_add(1, Ordering::SeqCst);
			match self.behaviour {
				Behaviour::Ok(rate) => Ok(applied(rate)),
				Behaviour::SlowOk(delay, rate) => {
					tokio::time::sleep(delay).await;
					Ok(applied(rate))
				},
				Behaviour::Unavailable => {
					Err(ChainActionError::unavailable(format!("{} is down", self.name)))
				},
				Behaviour::UnavailableTimedOut => {
					Err(ChainActionError::timed_out(format!("{} wire timeout", self.name)))
				},
				Behaviour::Rejected => {
					Err(ChainActionError::Rejected(format!("{} says no", self.name)))
				},
				Behaviour::Hang => std::future::pending().await,
			}
		}
	}

	fn chain(budget: Duration, adapters: &[Arc<FakeFee>]) -> ActionChain<dyn FeeAction> {
		ActionChain::new(
			"fee",
			budget,
			adapters.iter().map(|a| Arc::clone(a) as Arc<dyn FeeAction>).collect(),
			Arc::new(Logger::new_log_facade()),
		)
	}

	/// The rate the fake applied, so tests can tell answers apart.
	fn applied_rate(update: FeeUpdate) -> u64 {
		match update {
			FeeUpdate::Apply { cache, .. } => {
				cache.get(&ConfirmationTarget::OnchainPayment).unwrap().to_sat_per_kwu()
			},
			FeeUpdate::Skip => panic!("fakes never skip"),
		}
	}

	async fn run(chain: &ActionChain<dyn FeeAction>) -> ActionResult<Answered<FeeUpdate>> {
		chain.run(|a| async move { a.fee_rate_update().await }).await
	}

	#[tokio::test]
	async fn unavailable_advances_to_next() {
		let first = FakeFee::new("first", Behaviour::Unavailable);
		let second = FakeFee::new("second", Behaviour::Ok(250));
		let chain = chain(Duration::from_secs(1), &[Arc::clone(&first), Arc::clone(&second)]);

		let answered = run(&chain).await.unwrap();

		assert_eq!(answered.by, "second");
		assert_eq!(applied_rate(answered.value), 250);
		assert_eq!(first.calls(), 1);
		assert_eq!(second.calls(), 1);
		assert_eq!(chain.last_answered(), Some("second"));
	}

	#[tokio::test]
	async fn rejected_is_terminal_and_skips_rest() {
		let first = FakeFee::new("first", Behaviour::Rejected);
		let second = FakeFee::new("second", Behaviour::Ok(250));
		let chain = chain(Duration::from_secs(1), &[Arc::clone(&first), Arc::clone(&second)]);

		let err = run(&chain).await.unwrap_err();

		assert_eq!(err, ChainActionError::Rejected("first says no".to_string()));
		assert_eq!(second.calls(), 0, "a rejection must not be retried on the next adapter");
		assert_eq!(chain.last_answered(), None);
	}

	#[tokio::test]
	async fn ok_stops_chain_and_records_answerer() {
		let first = FakeFee::new("first", Behaviour::Ok(100));
		let second = FakeFee::new("second", Behaviour::Ok(250));
		let chain = chain(Duration::from_secs(1), &[Arc::clone(&first), Arc::clone(&second)]);

		let answered = run(&chain).await.unwrap();

		assert_eq!(answered.by, "first");
		assert_eq!(applied_rate(answered.value), 100);
		assert_eq!(second.calls(), 0, "the chain stops at the first answer");
		assert_eq!(chain.last_answered(), Some("first"));
		assert_eq!(chain.names(), vec!["first", "second"]);
	}

	#[tokio::test]
	async fn timeout_counts_as_unavailable() {
		let hung = FakeFee::new("hung", Behaviour::Hang);
		let second = FakeFee::new("second", Behaviour::Ok(250));
		let chain = chain(Duration::from_millis(20), &[Arc::clone(&hung), Arc::clone(&second)]);

		let answered = run(&chain).await.unwrap();

		assert_eq!(answered.by, "second", "the seam's budget, not the adapter, ended the call");
		assert_eq!(hung.calls(), 1);
	}

	#[tokio::test]
	async fn exhausted_chain_is_honest_failure_not_stale_value() {
		let first = FakeFee::new("first", Behaviour::Ok(100));
		let chain = chain(Duration::from_secs(1), &[Arc::clone(&first)]);

		// A good answer first, so a stale value exists to be tempted by.
		assert_eq!(run(&chain).await.unwrap().by, "first");
		assert_eq!(chain.last_answered(), Some("first"));

		let down_a = FakeFee::new("down-a", Behaviour::Unavailable);
		let down_b = FakeFee::new("down-b", Behaviour::Unavailable);
		let chain = chain_with_history(&chain, &[down_a, down_b]);

		let err = run(&chain).await.unwrap_err();

		assert_eq!(
			err,
			ChainActionError::Unavailable {
				reason: "fee: exhausted: down-a: down-a is down; down-b: down-b is down"
					.to_string(),
				timed_out: false,
			},
			"every adapter's reason is reported, in order"
		);
		assert_eq!(chain.last_answered(), Some("first"), "history is kept, but never served");
	}

	#[tokio::test]
	async fn exhaustion_by_budget_sets_timed_out() {
		let hung = FakeFee::new("hung", Behaviour::Hang);
		let chain = chain(Duration::from_millis(20), &[Arc::clone(&hung)]);

		let err = run(&chain).await.unwrap_err();

		assert!(matches!(err, ChainActionError::Unavailable { timed_out: true, .. }), "{}", err);

		let down = FakeFee::new("down", Behaviour::Unavailable);
		let chain = self::chain(Duration::from_millis(20), &[down]);
		let err = run(&chain).await.unwrap_err();
		assert!(matches!(err, ChainActionError::Unavailable { timed_out: false, .. }), "{}", err);
	}

	/// A longer chain is `timed_out` when a timeout is part of why it was
	/// exhausted, whichever adapter it was.
	#[tokio::test]
	async fn exhaustion_is_timed_out_if_any_adapter_was() {
		let down = FakeFee::new("down", Behaviour::Unavailable);
		let slow = FakeFee::new("slow", Behaviour::UnavailableTimedOut);
		let chain = chain(Duration::from_secs(1), &[Arc::clone(&down), Arc::clone(&slow)]);

		let err = run(&chain).await.unwrap_err();

		assert!(matches!(err, ChainActionError::Unavailable { timed_out: true, .. }), "{}", err);
		assert_eq!(slow.calls(), 1);
	}

	/// The FEE slot maps exhaustion back onto the two `Error` variants its
	/// callers already distinguish, so a backend's own timeout must survive
	/// the round trip as the typed flag.
	#[test]
	fn backend_errors_keep_their_timeout_identity() {
		let timeout: ChainActionError = Error::FeerateEstimationUpdateTimeout.into();
		assert!(matches!(timeout, ChainActionError::Unavailable { timed_out: true, .. }));

		let failed: ChainActionError = Error::FeerateEstimationUpdateFailed.into();
		assert!(matches!(failed, ChainActionError::Unavailable { timed_out: false, .. }));
	}

	/// An adapter that declares a budget longer than the slot default gets it:
	/// the seam does not cut a legitimately slow backend at the slot default.
	#[tokio::test]
	async fn adapter_budget_longer_than_slot_is_honoured() {
		let slot_budget = Duration::from_millis(20);
		let adapter_budget = Duration::from_millis(500);
		let slow = FakeFee::with_budget(
			"slow",
			Behaviour::SlowOk(Duration::from_millis(100), 250),
			adapter_budget,
		);
		let chain = chain(slot_budget, &[Arc::clone(&slow)]);

		let answered = run(&chain).await.unwrap();

		assert_eq!(answered.by, "slow");
		assert_eq!(applied_rate(answered.value), 250);
		assert_eq!(slow.calls(), 1);
	}

	/// An adapter that declares a budget shorter than the slot default is cut
	/// at its own budget, not the slot's.
	#[tokio::test]
	async fn adapter_budget_shorter_than_slot_cuts_earlier() {
		let slot_budget = Duration::from_secs(5);
		let adapter_budget = Duration::from_millis(20);
		let hung = FakeFee::with_budget("hung", Behaviour::Hang, adapter_budget);
		let second = FakeFee::new("second", Behaviour::Ok(250));
		let chain = chain(slot_budget, &[Arc::clone(&hung), Arc::clone(&second)]);

		let started = Instant::now();
		let answered = run(&chain).await.unwrap();
		let elapsed = started.elapsed();

		assert_eq!(answered.by, "second");
		assert_eq!(hung.calls(), 1);
		assert!(
			elapsed < Duration::from_secs(1),
			"the adapter's {:?} budget must cut the call, not the slot's {:?}; took {:?}",
			adapter_budget,
			slot_budget,
			elapsed
		);
	}

	/// A new chain over `adapters` that carries `previous`'s answer history —
	/// the shape of a slot whose adapters all went down after having worked.
	fn chain_with_history(
		previous: &ActionChain<dyn FeeAction>, adapters: &[Arc<FakeFee>],
	) -> ActionChain<dyn FeeAction> {
		let chain = self::chain(previous.budget, adapters);
		*chain.last_answered.lock().unwrap() = previous.last_answered();
		chain
	}

	#[tokio::test]
	async fn chain_of_one_is_legal() {
		let only = FakeFee::new("only", Behaviour::Ok(100));
		let chain = chain(Duration::from_secs(1), &[Arc::clone(&only)]);

		assert!(!chain.is_empty());
		assert_eq!(run(&chain).await.unwrap().by, "only");

		let only_down = FakeFee::new("only", Behaviour::Unavailable);
		let chain = self::chain(Duration::from_secs(1), &[only_down]);
		assert!(matches!(run(&chain).await, Err(ChainActionError::Unavailable { .. })));
	}

	#[tokio::test]
	async fn empty_chain_is_unavailable() {
		let chain = chain(Duration::from_secs(1), &[]);

		assert!(chain.is_empty());
		assert!(chain.names().is_empty());
		let err = run(&chain).await.unwrap_err();

		assert_eq!(
			err,
			ChainActionError::Unavailable {
				reason: "fee: exhausted: no adapters configured".to_string(),
				timed_out: false,
			}
		);
		assert_eq!(chain.last_answered(), None);
	}

	/// A package is `Ok` only when every transaction reached the network;
	/// one unsent transaction outranks another's rejection, because the
	/// chain must resend the whole package, and a rejection lists exactly
	/// the refused transactions.
	#[test]
	fn package_result_precedence() {
		let a = Txid::from_slice(&[1u8; 32]).unwrap();
		let b = Txid::from_slice(&[2u8; 32]).unwrap();
		let c = Txid::from_slice(&[3u8; 32]).unwrap();

		assert_eq!(
			package_result([
				(a, TxBroadcastOutcome::Accepted),
				(b, TxBroadcastOutcome::AlreadyKnown)
			]),
			Ok(()),
			"already known is as good as accepted"
		);
		assert_eq!(package_result(Vec::new()), Ok(()), "an empty package has nothing to refuse");

		assert_eq!(
			package_result([
				(a, TxBroadcastOutcome::Accepted),
				(b, TxBroadcastOutcome::Rejected("insufficient fee".into())),
				(c, TxBroadcastOutcome::Rejected("missing inputs".into())),
			]),
			Err(ChainActionError::Rejected(vec![
				(b, "insufficient fee".to_string()),
				(c, "missing inputs".to_string()),
			])),
			"every refused transaction is listed; the accepted one is not"
		);

		let err = package_result([
			(a, TxBroadcastOutcome::Rejected("insufficient fee".into())),
			(
				b,
				TxBroadcastOutcome::Unavailable {
					reason: "connection reset".into(),
					timed_out: false,
				},
			),
			(c, TxBroadcastOutcome::Unavailable { reason: "5s".into(), timed_out: true }),
		])
		.unwrap_err();
		assert!(
			matches!(err, ChainActionError::Unavailable { timed_out: true, .. }),
			"an unsent transaction outranks a rejection, and any timeout marks it: {}",
			err
		);
	}

	/// Every provider failure is `Unavailable`; only `Unreachable` — no route
	/// or no response — is a timeout, as the pre-chain Dependent adapter ruled.
	#[test]
	fn provider_errors_are_all_unavailable() {
		let cases = vec![
			(ChainProviderError::Unreachable("no route".into()), true),
			(ChainProviderError::Refused("not serving".into()), false),
			(ChainProviderError::Malformed("bad hex".into()), false),
			(ChainProviderError::VersionMismatch { expected: 1, got: 2 }, false),
		];
		for (case, timed_out) in cases {
			let reason = case.to_string();
			let err: ChainActionError = case.into();
			assert_eq!(err, ChainActionError::Unavailable { reason, timed_out });
		}
	}
}
