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
//! | Slot             | Trait                   | Budget                   |
//! |------------------|-------------------------|--------------------------|
//! | FEE              | [`FeeAction`]           | [`FEE_BUDGET`]           |
//! | BROADCAST        | [`BroadcastAction`]     | [`BROADCAST_BUDGET`]     |
//! | TX_STATUS        | `TxStatusAction`        | [`TX_STATUS_BUDGET`]     |
//! | MEMPOOL          | [`MempoolAction`]       | [`MEMPOOL_BUDGET`]       |
//! | SCRIPT_HISTORY   | [`ScriptHistoryAction`] | [`SCRIPT_HISTORY_BUDGET`]|
//! | UTXO             | [`UtxoCapability`]      | — (not an action)        |
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
//! * **Timeout ownership sits with the seam.** [`ActionChain`] imposes a
//!   per-slot budget on every adapter call with [`tokio::time::timeout`]; an
//!   adapter that overruns it is `Unavailable`. Adapters are not trusted to
//!   bound themselves.
//! * **Exhaustion is an honest failure.** When no adapter answers, the slot
//!   fails with `Unavailable`. The seam never fabricates an answer and never
//!   serves a stale value a caller would act on.
//! * **A chain of length one is legal.** That is how "no fallback" is spelled.
//!   An empty chain is legal to construct and always `Unavailable`.
//!
//! FEE and TX_STATUS run on chains. The pre-chain single-adapter
//! [`BroadcastAdapter`] still fills the BROADCAST slot and is replaced when
//! that slot moves onto its chain; MEMPOOL and SCRIPT_HISTORY follow.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::{FeeRate, ScriptBuf, Transaction, Txid};

use bdk_chain::BlockId;

use lightning_block_sync::gossip::UtxoSource;

use crate::chain::provider::{ChainProviderError, WireSyncRequest};
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

// ── PER-ACTION SEAM ──────────────────────────────────────────────────────────
//
// Everything below is the per-action shape of the seam: one result type, one
// trait per action, and the combinator that runs an ordered adapter chain
// under a budget. FEE and TX_STATUS are wired into `ChainLayer`; the items
// belonging to slots not yet moved carry `dead_code` allowances that are
// removed as each slot lands.

/// Per-slot budget the seam imposes on every FEE adapter call.
pub(crate) const FEE_BUDGET: Duration = Duration::from_secs(5);
/// Per-slot budget the seam imposes on every BROADCAST adapter call.
#[allow(dead_code)] // consumed once the BROADCAST slot runs on an `ActionChain`
pub(crate) const BROADCAST_BUDGET: Duration = Duration::from_secs(15);
/// Per-slot budget the seam imposes on every TX_STATUS adapter call.
#[cfg(feature = "swaps")]
pub(crate) const TX_STATUS_BUDGET: Duration = Duration::from_secs(10);
/// Per-slot budget the seam imposes on every MEMPOOL adapter call.
#[allow(dead_code)] // consumed once the MEMPOOL slot runs on an `ActionChain`
pub(crate) const MEMPOOL_BUDGET: Duration = Duration::from_secs(30);
/// Per-slot budget the seam imposes on every SCRIPT_HISTORY adapter call.
#[allow(dead_code)] // consumed once the SCRIPT_HISTORY slot runs on an `ActionChain`
pub(crate) const SCRIPT_HISTORY_BUDGET: Duration = Duration::from_secs(90);

/// Why an adapter did not produce an accepted answer.
///
/// See the module docs for the taxonomy. `R` is the slot's rejection payload:
/// a plain reason for most slots, a per-transaction list for BROADCAST
/// ([`BroadcastRejection`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainActionError<R = String> {
	/// The adapter could not answer: unstarted, unreachable, timed out, or
	/// handed back something it could not parse. The chain advances.
	Unavailable(String),
	/// The adapter answered, and the answer is no. Terminal for the chain.
	#[allow(dead_code)] // built by the BROADCAST adapters once that slot runs on an `ActionChain`
	Rejected(R),
}

/// The words every timeout reason carries, whether the seam's budget or an
/// adapter's own wire timeout produced it. [`ChainActionError::is_timeout`]
/// keys off this so a slot can report "timed out" and "failed" as the
/// distinct errors its callers already distinguish.
const TIMEOUT_MARKER: &str = "timed out";

impl<R> ChainActionError<R> {
	/// An `Unavailable` whose reason is that the call overran a budget.
	fn timed_out(budget: Duration) -> Self {
		Self::Unavailable(format!("{} after {}ms", TIMEOUT_MARKER, budget.as_millis()))
	}

	/// Whether this reason records a timeout — the seam's budget, an adapter's
	/// own wire timeout, or, for an exhausted chain, any adapter that timed
	/// out. A chain of one reports exactly what its adapter did; a longer
	/// chain reports a timeout when a timeout is part of why it failed,
	/// because a reachable-but-slow source is the thing an operator can act on.
	pub(crate) fn is_timeout(&self) -> bool {
		match self {
			Self::Unavailable(reason) => reason.contains(TIMEOUT_MARKER),
			Self::Rejected(_) => false,
		}
	}
}

impl<R: std::fmt::Debug> std::fmt::Display for ChainActionError<R> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Unavailable(reason) => write!(f, "unavailable: {}", reason),
			Self::Rejected(reason) => write!(f, "rejected: {:?}", reason),
		}
	}
}

/// A remote provider that could not be used is never a rejection: whether it
/// was unreachable, refused to serve, replied garbage or spoke the wrong wire
/// version, nothing is known about the chain as a result, and the next
/// adapter must get its turn. The variant's own `Display` text is kept as the
/// reason so the fall-through log still says which of the four it was.
impl<R> From<ChainProviderError> for ChainActionError<R> {
	fn from(e: ChainProviderError) -> Self {
		Self::Unavailable(e.to_string())
	}
}

/// A backend's own [`Error`] is never a rejection either: the pre-chain
/// adapters reported every failure to answer as an `Error`, and none of those
/// is the network saying no. The variant's `Display` text is the reason, which
/// is what lets [`ChainActionError::is_timeout`] tell
/// [`Error::FeerateEstimationUpdateTimeout`] from
/// [`Error::FeerateEstimationUpdateFailed`] after the chain has run.
impl<R> From<Error> for ChainActionError<R> {
	fn from(e: Error) -> Self {
		Self::Unavailable(e.to_string())
	}
}

/// What a BROADCAST adapter says no to: each refused txid with its reason.
#[allow(dead_code)] // consumed once the BROADCAST slot runs on an `ActionChain`
pub(crate) type BroadcastRejection = Vec<(Txid, String)>;

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

	async fn fee_rate_update(&self) -> ActionResult<FeeUpdate>;
}

/// BROADCAST — puts a package of transactions on the network.
///
/// Package semantics: the adapter is handed every transaction the queue
/// produced together (a commitment tx and its anchor CPFP, say), and answers
/// for the package. `Rejected` lists the txids the network refused; a
/// rejected package is never retried on the next adapter, because the network
/// that refused it is the same network.
#[allow(dead_code)] // consumed once the BROADCAST slot runs on an `ActionChain`
#[async_trait]
pub(crate) trait BroadcastAction: Send + Sync {
	/// Stable identifier, for logs and for [`Answered::by`].
	fn name(&self) -> &'static str;

	/// Whether the backend can broadcast right now. `false` is `Unavailable`
	/// without the round trip.
	async fn ready(&self) -> bool {
		true
	}

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

	async fn mempool(&self, query: MempoolQuery) -> ActionResult<Anchored<MempoolAnswer>>;
}

/// SCRIPT_HISTORY — the wide wallet scan, phrased on the wire type because
/// BDK's own request holds a closure and cannot be handed to a remote adapter.
#[allow(dead_code)] // consumed once the SCRIPT_HISTORY slot runs on an `ActionChain`
#[async_trait]
pub(crate) trait ScriptHistoryAction: Send + Sync {
	/// Stable identifier, for logs and for [`Answered::by`].
	fn name(&self) -> &'static str;

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

/// An ordered chain of adapters for one slot, run under the slot's budget.
///
/// `A` is the slot's action trait object (`dyn FeeAction`, ...). The chain
/// owns the fallback rules described in the module docs; adapters own only
/// their answer.
pub(crate) struct ActionChain<A: ?Sized> {
	slot: &'static str,
	budget: Duration,
	adapters: Vec<Arc<A>>,
	last_answered: Mutex<Option<&'static str>>,
	logger: Arc<Logger>,
}

impl<A: ?Sized + Send + Sync + SlotAdapter> ActionChain<A> {
	/// A chain for `slot`, trying `adapters` in order, each under `budget`.
	pub(crate) fn new(
		slot: &'static str, budget: Duration, adapters: Vec<Arc<A>>, logger: Arc<Logger>,
	) -> Self {
		Self { slot, budget, adapters, last_answered: Mutex::new(None), logger }
	}

	/// The adapter names in chain order, for the startup log.
	pub(crate) fn names(&self) -> Vec<&'static str> {
		self.adapters.iter().map(|a| Self::adapter_name(a)).collect()
	}

	/// The adapters in chain order, for a slot whose tail needs to address
	/// them individually (the BROADCAST own-package echo).
	#[allow(dead_code)] // read by the BROADCAST tail once that slot runs on an `ActionChain`
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
	/// `Unavailable` (including a budget timeout) advances to the next adapter;
	/// `Rejected` returns at once and no later adapter is tried; `Ok` stops the
	/// chain, records the answerer and returns it. An empty or exhausted chain
	/// is `Unavailable` — never a stale or invented value — and an exhausted
	/// one reports every adapter's reason, in order.
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

		for (idx, adapter) in self.adapters.iter().enumerate() {
			let name = Self::adapter_name(adapter);
			let next = self.adapters.get(idx + 1).map(Self::adapter_name);

			let outcome = match tokio::time::timeout(self.budget, action(Arc::clone(adapter))).await
			{
				Ok(outcome) => outcome,
				Err(_elapsed) => Err(ChainActionError::timed_out(self.budget)),
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
				Err(ChainActionError::Unavailable(reason)) => {
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
		Err(ChainActionError::Unavailable(format!("{}: exhausted: {}", self.slot, reason)))
	}

	fn adapter_name(adapter: &Arc<A>) -> &'static str {
		SlotAdapter::name(&**adapter)
	}
}

/// The one thing every action trait shares: a stable name. Implemented for
/// each action trait object so [`ActionChain`] can log and tag answers
/// without knowing which slot it is running.
pub(crate) trait SlotAdapter {
	fn name(&self) -> &'static str;
}

impl SlotAdapter for dyn FeeAction {
	fn name(&self) -> &'static str {
		FeeAction::name(self)
	}
}

impl SlotAdapter for dyn BroadcastAction {
	fn name(&self) -> &'static str {
		BroadcastAction::name(self)
	}
}

#[cfg(feature = "swaps")]
impl SlotAdapter for dyn TxStatusAction {
	fn name(&self) -> &'static str {
		TxStatusAction::name(self)
	}
}

impl SlotAdapter for dyn MempoolAction {
	fn name(&self) -> &'static str {
		MempoolAction::name(self)
	}
}

impl SlotAdapter for dyn ScriptHistoryAction {
	fn name(&self) -> &'static str {
		ScriptHistoryAction::name(self)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::sync::atomic::{AtomicUsize, Ordering};

	/// What one fake adapter does when asked.
	enum Behaviour {
		Ok(u64),
		Unavailable,
		Rejected,
		/// Never answers; only the seam's budget ends the call.
		Hang,
	}

	struct FakeFee {
		name: &'static str,
		behaviour: Behaviour,
		calls: AtomicUsize,
	}

	impl FakeFee {
		fn new(name: &'static str, behaviour: Behaviour) -> Arc<Self> {
			Arc::new(Self { name, behaviour, calls: AtomicUsize::new(0) })
		}

		fn calls(&self) -> usize {
			self.calls.load(Ordering::SeqCst)
		}
	}

	#[async_trait]
	impl FeeAction for FakeFee {
		fn name(&self) -> &'static str {
			self.name
		}

		async fn fee_rate_update(&self) -> ActionResult<FeeUpdate> {
			self.calls.fetch_add(1, Ordering::SeqCst);
			match self.behaviour {
				Behaviour::Ok(rate) => {
					let mut cache = HashMap::new();
					cache.insert(
						ConfirmationTarget::OnchainPayment,
						FeeRate::from_sat_per_kwu(rate),
					);
					Ok(FeeUpdate::Apply { cache, log_unchanged: false })
				},
				Behaviour::Unavailable => {
					Err(ChainActionError::Unavailable(format!("{} is down", self.name)))
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

		match err {
			ChainActionError::Unavailable(reason) => {
				assert_eq!(
					reason, "fee: exhausted: down-a: down-a is down; down-b: down-b is down",
					"every adapter's reason is reported, in order"
				);
			},
			other => panic!("exhaustion must be Unavailable, got {:?}", other),
		}
		assert_eq!(chain.last_answered(), Some("first"), "history is kept, but never served");
	}

	#[tokio::test]
	async fn exhaustion_by_budget_reads_as_timeout() {
		let hung = FakeFee::new("hung", Behaviour::Hang);
		let chain = chain(Duration::from_millis(20), &[Arc::clone(&hung)]);

		let err = run(&chain).await.unwrap_err();

		assert!(err.is_timeout(), "{}", err);

		let down = FakeFee::new("down", Behaviour::Unavailable);
		let chain = self::chain(Duration::from_millis(20), &[down]);
		let err = run(&chain).await.unwrap_err();
		assert!(!err.is_timeout(), "{}", err);
	}

	/// The FEE slot maps exhaustion back onto the two `Error` variants its
	/// callers already distinguish, so a backend's own timeout must survive
	/// the round trip through the reason text.
	#[test]
	fn backend_errors_keep_their_timeout_identity() {
		let timeout: ChainActionError = Error::FeerateEstimationUpdateTimeout.into();
		assert!(matches!(timeout, ChainActionError::Unavailable(_)));
		assert!(timeout.is_timeout());

		let failed: ChainActionError = Error::FeerateEstimationUpdateFailed.into();
		assert!(matches!(failed, ChainActionError::Unavailable(_)));
		assert!(!failed.is_timeout());

		let rejected: ChainActionError = ChainActionError::Rejected("no".to_string());
		assert!(!rejected.is_timeout());
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
		assert!(matches!(run(&chain).await, Err(ChainActionError::Unavailable(_))));
	}

	#[tokio::test]
	async fn empty_chain_is_unavailable() {
		let chain = chain(Duration::from_secs(1), &[]);

		assert!(chain.is_empty());
		assert!(chain.names().is_empty());
		let err = run(&chain).await.unwrap_err();

		assert_eq!(
			err,
			ChainActionError::Unavailable("fee: exhausted: no adapters configured".to_string())
		);
		assert_eq!(chain.last_answered(), None);
	}

	#[test]
	fn provider_errors_are_all_unavailable() {
		let cases = vec![
			ChainProviderError::Unreachable("no route".into()),
			ChainProviderError::Refused("not serving".into()),
			ChainProviderError::Malformed("bad hex".into()),
			ChainProviderError::VersionMismatch { expected: 1, got: 2 },
		];
		for case in cases {
			let display = case.to_string();
			let err: ChainActionError = case.into();
			assert_eq!(err, ChainActionError::Unavailable(display));
		}
	}
}
