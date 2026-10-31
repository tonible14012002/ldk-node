// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Per-transaction broadcast policies, and the queue of transactions held for a rebroadcast.
//!
//! LDK's [`BroadcasterInterface`] carries no metadata, and LDK hands each channel funding to it
//! on its own, whenever that channel's peer answers `funding_signed`. Two opens funded from one
//! coin therefore race: the second funding spends the change of the first, and when the second
//! peer answers first the child reaches the network before its parent and is refused with
//! `bad-txns-inputs-missingorspent`. LDK never broadcasts a funding again, so before this module
//! that refusal left the channel waiting for confirmations forever.
//!
//! Whoever builds a transaction says what should happen to it, by txid, before it is broadcast:
//! [`BroadcastPolicy::QueueUntilParents`] — the default for every transaction this node's
//! on-chain wallet builds — or [`BroadcastPolicy::DropOnReject`], the behaviour every other
//! transaction (LDK's own claims and commitments, which LDK rebroadcasts itself) keeps. The
//! BROADCAST tail of the chain layer looks the policy up:
//!
//! * a queued transaction the network refuses because an input is missing, or that no backend
//!   could be asked about, is **held**: its inputs stay reserved in the on-chain wallet, and it
//!   is sent again as soon as a parent is broadcast or confirms, and otherwise on a bounded
//!   backoff;
//! * it is **given up** — its inputs released exactly as a refused transaction's always were —
//!   only on a definitive answer: an input spent by a different confirmed transaction, a parent
//!   this node gave up on, a refusal for any reason other than a missing input, or its
//!   `max_age` passing.
//!
//! The given-up transactions are remembered for a while, so the dead-funding reaper can close a
//! channel whose funding, or one of its parents, this node gave up on
//! ([`crate::dead_funding`]). Everything here is persisted on every change: a node that
//! restarts keeps holding, and keeps retrying, what it held.
//!
//! [`BroadcasterInterface`]: lightning::chain::chaininterface::BroadcasterInterface

use crate::io::{
	BROADCAST_QUEUE_PERSISTENCE_KEY, BROADCAST_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
	BROADCAST_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::logger::{log_error, LdkLogger, Logger};
use crate::types::DynStore;
use crate::Error;

use lightning::util::ser::{Readable, Writeable};
use lightning::{impl_writeable_tlv_based, impl_writeable_tlv_based_enum};

use bitcoin::{Transaction, Txid};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// How long a queued transaction is held, by default, before it is given up: two days. Long
/// enough for a parent stuck behind a fee spike or a node that restarts all day; short enough
/// that coins reserved for a transaction whose parent never appears come back.
pub const DEFAULT_BROADCAST_QUEUE_MAX_AGE_SECS: u64 = 48 * 60 * 60;

/// The first retry of a held transaction comes this long after the refusal; each further one
/// waits twice as long as the last, up to [`RETRY_BACKOFF_CAP_SECS`].
const RETRY_BACKOFF_BASE_SECS: u64 = 15;
const RETRY_BACKOFF_CAP_SECS: u64 = 10 * 60;

/// How long a transaction this node put on the network is remembered as sent, so a child
/// registered later with it in [`BroadcastPolicy::QueueUntilParents::depends_on`] knows the
/// dependency is met. Only transactions some entry depends on, or that were registered
/// themselves, are remembered at all.
const SENT_MEMORY_SECS: u64 = 72 * 60 * 60;
const SENT_MEMORY_CAP: usize = 512;

/// How long, and how many, given-up transactions are remembered for the dead-funding reaper and
/// for [`BroadcastQueue::list`].
const ABANDONED_MEMORY_SECS: u64 = 30 * 24 * 60 * 60;
const ABANDONED_MEMORY_CAP: usize = 128;

/// What the broadcast path does with a transaction the network does not take.
///
/// Registered per txid before the transaction is broadcast (see
/// [`crate::Node::register_broadcast_policy`]); a transaction nobody registered is
/// [`BroadcastPolicy::DropOnReject`]. [`BroadcastPolicy::default`] is the policy the node gives
/// every transaction its own on-chain wallet builds — channel fundings, on-chain sends and swap
/// fundings — unless the caller chose otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BroadcastPolicy {
	/// A refusal is final: the transaction is dropped and the inputs it spent are offered to
	/// coin selection again. A transaction no backend could be asked about is dropped as well.
	DropOnReject,
	/// A refusal because an input is missing, or a broadcast no backend could answer, keeps the
	/// transaction queued — its inputs reserved — and it is broadcast again once a parent is
	/// on the network, and otherwise on a bounded backoff.
	QueueUntilParents {
		/// Seconds after registration after which a transaction still not on the network is
		/// given up and its inputs released.
		max_age_secs: u64,
		/// Transactions that must be on the network before this one is broadcast at all, on
		/// top of the parents whose outputs it spends — which are always waited for. For a
		/// batch of dependent operations whose order is not visible in their inputs.
		depends_on: Vec<Txid>,
	},
}

impl Default for BroadcastPolicy {
	fn default() -> Self {
		Self::QueueUntilParents {
			max_age_secs: DEFAULT_BROADCAST_QUEUE_MAX_AGE_SECS,
			depends_on: Vec::new(),
		}
	}
}

impl_writeable_tlv_based_enum!(BroadcastPolicy,
	(0, DropOnReject) => {},
	(2, QueueUntilParents) => {
		(0, max_age_secs, required),
		(2, depends_on, required_vec),
	}
);

/// Where an entry of the broadcast queue stands; see [`BroadcastQueueEntry`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BroadcastQueueState {
	/// A policy was registered and the transaction has not been broadcast yet — a channel
	/// funding waiting for its peer's `funding_signed`, say.
	Registered,
	/// The network refused the transaction because an input is missing, or no backend could be
	/// asked: it is held, its inputs reserved, and broadcast again.
	Waiting,
	/// The node gave the transaction up and released its inputs.
	Abandoned {
		/// Why, in words.
		reason: String,
	},
}

/// One transaction of the broadcast queue, as [`crate::Node::list_broadcast_queue`] lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcastQueueEntry {
	/// The transaction.
	pub txid: Txid,
	/// Where it stands.
	pub state: BroadcastQueueState,
	/// The explicit dependencies its policy named.
	pub depends_on: Vec<Txid>,
	/// The parents — explicit dependencies and the transactions whose outputs it spends — not
	/// yet broadcast by this node nor confirmed. Empty for an abandoned entry.
	pub waiting_on: Vec<Txid>,
	/// When its policy was registered (abandoned: when it was given up), in seconds since the
	/// UNIX epoch.
	pub created_at_secs: u64,
	/// When it is given up if still not on the network; `None` for an abandoned entry.
	pub expires_at_secs: Option<u64>,
	/// How many times it was held: refused, unanswered, or waiting for its dependencies.
	pub attempts: u32,
	/// When it is broadcast again at the latest, while [`BroadcastQueueState::Waiting`].
	pub next_attempt_at_secs: Option<u64>,
	/// What the network, or the chain, said the last time it was tried.
	pub last_error: Option<String>,
}

/// What [`BroadcastQueue::hold`] did with a transaction.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hold {
	/// Held; it is broadcast again at `next_attempt_at` at the latest.
	Held { attempts: u32, next_attempt_at: u64 },
	/// Its policy does not queue it: the caller does what it always did.
	NotQueued,
	/// Past its `max_age`: the caller gives it up.
	Expired,
}

/// The time before the retry following `attempts` refusals.
fn backoff_secs(attempts: u32) -> u64 {
	let doublings = attempts.saturating_sub(1).min(16);
	RETRY_BACKOFF_BASE_SECS.saturating_mul(1u64 << doublings).min(RETRY_BACKOFF_CAP_SECS)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
	txid: Txid,
	max_age_secs: u64,
	depends_on: Vec<Txid>,
	registered_at: u64,
	/// The transaction, once it was refused and is held.
	tx: Option<Transaction>,
	attempts: u32,
	next_attempt_at: u64,
	last_error: Option<String>,
	/// Whether the last refusal was a verdict of the network, rather than no backend answering.
	/// Only a transaction the network refused counts as dead once it expires.
	last_was_verdict: bool,
}

impl_writeable_tlv_based!(Entry, {
	(0, txid, required),
	(2, max_age_secs, required),
	(4, depends_on, required_vec),
	(6, registered_at, required),
	(8, tx, option),
	(10, attempts, required),
	(12, next_attempt_at, required),
	(14, last_error, option),
	(16, last_was_verdict, required),
});

impl Entry {
	fn expires_at(&self) -> u64 {
		self.registered_at.saturating_add(self.max_age_secs)
	}

	/// The explicit dependencies, then the transactions whose outputs it spends, each once.
	fn parents(&self) -> Vec<Txid> {
		let mut parents: Vec<Txid> = Vec::new();
		let inputs = self.tx.iter().flat_map(|tx| tx.input.iter().map(|i| i.previous_output.txid));
		for txid in self.depends_on.iter().copied().chain(inputs) {
			if txid != self.txid && !parents.contains(&txid) {
				parents.push(txid);
			}
		}
		parents
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SentTx {
	txid: Txid,
	at: u64,
}

impl_writeable_tlv_based!(SentTx, {
	(0, txid, required),
	(2, at, required),
});

#[derive(Clone, Debug, PartialEq, Eq)]
struct AbandonedTx {
	txid: Txid,
	at: u64,
	reason: String,
	/// Whether giving it up proves it can never confirm, so the dead-funding reaper may act on
	/// it: everything but a transaction that expired without the network ever saying no.
	definitive: bool,
}

impl_writeable_tlv_based!(AbandonedTx, {
	(0, txid, required),
	(2, at, required),
	(4, reason, required),
	(6, definitive, required),
});

#[derive(Default)]
struct QueueState {
	entries: HashMap<Txid, Entry>,
	sent: HashMap<Txid, u64>,
	abandoned: Vec<AbandonedTx>,
	/// The policy an open asked for, by user channel id, until LDK asks for the funding.
	/// In memory only: LDK does not persist a channel before it is funded.
	pending_opens: HashMap<u128, BroadcastPolicy>,
	/// How many of an entry's parents were known to be on the network when it was last looked
	/// at; one more known parent makes it due at once. In memory only: after a restart the
	/// first look takes the baseline again, and the persisted backoff runs as before.
	parents_known: HashMap<Txid, usize>,
}

/// The persisted form.
struct QueueSnapshot {
	entries: Vec<Entry>,
	sent: Vec<SentTx>,
	abandoned: Vec<AbandonedTx>,
}

impl_writeable_tlv_based!(QueueSnapshot, {
	(0, entries, required_vec),
	(2, sent, required_vec),
	(4, abandoned, required_vec),
});

/// The broadcast policies registered per txid, the transactions held for a rebroadcast, and the
/// ones given up; see the module docs.
pub(crate) struct BroadcastQueue {
	state: Mutex<QueueState>,
	kv_store: Arc<DynStore>,
	logger: Arc<Logger>,
}

impl BroadcastQueue {
	/// Reads the persisted queue; none persisted yet is an empty queue, and an unreadable one is
	/// logged and treated as empty — the held transactions are then given up by nobody, and
	/// their reservations end as the wallet's sync finds them in neither mempool nor chain.
	pub(crate) fn read_or_empty(kv_store: Arc<DynStore>, logger: Arc<Logger>) -> Self {
		let mut state = QueueState::default();
		match kv_store.read(
			BROADCAST_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
			BROADCAST_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
			BROADCAST_QUEUE_PERSISTENCE_KEY,
		) {
			Ok(bytes) => match QueueSnapshot::read(&mut &bytes[..]) {
				Ok(snapshot) => {
					state.entries = snapshot.entries.into_iter().map(|e| (e.txid, e)).collect();
					state.sent = snapshot.sent.into_iter().map(|s| (s.txid, s.at)).collect();
					state.abandoned = snapshot.abandoned;
				},
				Err(e) => {
					log_error!(
						logger,
						"Failed to deserialize the broadcast queue; starting from an empty one: {}",
						e
					);
				},
			},
			Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => {},
			Err(e) => {
				log_error!(
					logger,
					"Failed to read the broadcast queue; starting from an empty one: {}",
					e
				);
			},
		}
		Self { state: Mutex::new(state), kv_store, logger }
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	fn persist(&self, state: &QueueState) -> Result<(), Error> {
		let mut entries: Vec<Entry> = state.entries.values().cloned().collect();
		entries.sort_unstable_by_key(|e| e.txid);
		let mut sent: Vec<SentTx> =
			state.sent.iter().map(|(txid, at)| SentTx { txid: *txid, at: *at }).collect();
		sent.sort_unstable_by_key(|s| s.txid);
		let data = QueueSnapshot { entries, sent, abandoned: state.abandoned.clone() }.encode();
		self.kv_store
			.write(
				BROADCAST_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
				BROADCAST_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
				BROADCAST_QUEUE_PERSISTENCE_KEY,
				&data,
			)
			.map_err(|e| {
				log_error!(
					self.logger,
					"Write for key {}/{}/{} failed due to: {}",
					BROADCAST_QUEUE_PERSISTENCE_PRIMARY_NAMESPACE,
					BROADCAST_QUEUE_PERSISTENCE_SECONDARY_NAMESPACE,
					BROADCAST_QUEUE_PERSISTENCE_KEY,
					e
				);
				Error::PersistenceFailed
			})
	}

	/// Persists, logging a failure: the in-memory queue stays authoritative for this run, and
	/// the next change writes it again.
	fn persist_logged(&self, state: &QueueState) {
		let _ = self.persist(state);
	}

	/// Registers what should happen to `txid` when the network does not take it. A
	/// [`BroadcastPolicy::DropOnReject`] registration removes any earlier one, since that is
	/// what an unregistered transaction gets. A transaction already held keeps its place and
	/// retry state; only its policy changes.
	pub(crate) fn register(&self, txid: Txid, policy: BroadcastPolicy, now: u64) {
		let mut state = self.lock();
		match policy {
			BroadcastPolicy::DropOnReject => {
				if state.entries.remove(&txid).is_none() {
					return;
				}
			},
			BroadcastPolicy::QueueUntilParents { max_age_secs, depends_on } => {
				let entry = state.entries.entry(txid).or_insert_with(|| Entry {
					txid,
					max_age_secs,
					depends_on: Vec::new(),
					registered_at: now,
					tx: None,
					attempts: 0,
					next_attempt_at: now,
					last_error: None,
					last_was_verdict: false,
				});
				entry.max_age_secs = max_age_secs;
				entry.depends_on = depends_on;
			},
		}
		self.persist_logged(&state);
	}

	/// The policy registered for `txid`; [`BroadcastPolicy::DropOnReject`] when none was.
	pub(crate) fn policy(&self, txid: &Txid) -> BroadcastPolicy {
		match self.lock().entries.get(txid) {
			Some(entry) => BroadcastPolicy::QueueUntilParents {
				max_age_secs: entry.max_age_secs,
				depends_on: entry.depends_on.clone(),
			},
			None => BroadcastPolicy::DropOnReject,
		}
	}

	/// Remembers the policy a channel open asked for its funding transaction, which LDK asks the
	/// node to build only after the peer accepted the channel.
	pub(crate) fn set_pending_open(&self, user_channel_id: u128, policy: BroadcastPolicy) {
		self.lock().pending_opens.insert(user_channel_id, policy);
	}

	/// The policy the open with `user_channel_id` asked for, forgetting it; the default when it
	/// asked for none.
	pub(crate) fn take_pending_open(&self, user_channel_id: u128) -> BroadcastPolicy {
		self.lock().pending_opens.remove(&user_channel_id).unwrap_or_default()
	}

	/// Forgets the policy of an open that never got as far as a funding transaction.
	pub(crate) fn forget_pending_open(&self, user_channel_id: u128) {
		self.lock().pending_opens.remove(&user_channel_id);
	}

	/// Whether `txid` is held for a rebroadcast. The on-chain wallet keeps such a transaction's
	/// inputs reserved whatever a sync says about its absence from the mempool.
	pub(crate) fn is_held(&self, txid: &Txid) -> bool {
		self.lock().entries.get(txid).map_or(false, |e| e.tx.is_some())
	}

	/// The txids given up for good, for the dead-funding reaper.
	pub(crate) fn definitively_abandoned(&self) -> HashSet<Txid> {
		self.lock().abandoned.iter().filter(|a| a.definitive).map(|a| a.txid).collect()
	}

	/// Whether `txid` was given up, definitively or not.
	#[cfg(test)]
	pub(crate) fn is_abandoned(&self, txid: &Txid) -> bool {
		self.lock().abandoned.iter().any(|a| a.txid == *txid)
	}

	/// Whether a queued `tx` must wait before its first broadcast: an explicit dependency of
	/// its policy is neither sent by this node nor confirmed.
	pub(crate) fn awaits_dependencies(
		&self, tx: &Transaction, is_confirmed: impl Fn(&Txid) -> bool,
	) -> bool {
		let state = self.lock();
		let Some(entry) = state.entries.get(&tx.compute_txid()) else {
			return false;
		};
		entry.depends_on.iter().any(|dep| !state.sent.contains_key(dep) && !is_confirmed(dep))
	}

	/// The parents of the held `txid` this node gave up on, if any.
	pub(crate) fn abandoned_parent(&self, tx: &Transaction) -> Option<Txid> {
		let state = self.lock();
		let txid = tx.compute_txid();
		let depends_on = state.entries.get(&txid).map(|e| e.depends_on.clone()).unwrap_or_default();
		depends_on
			.into_iter()
			.chain(tx.input.iter().map(|i| i.previous_output.txid))
			.find(|parent| state.abandoned.iter().any(|a| a.txid == *parent))
	}

	/// Holds `tx` after a refusal (`verdict`) or a broadcast nobody answered, with `reason`.
	pub(crate) fn hold(&self, tx: &Transaction, reason: String, verdict: bool, now: u64) -> Hold {
		let mut state = self.lock();
		let txid = tx.compute_txid();
		let Some(entry) = state.entries.get_mut(&txid) else {
			return Hold::NotQueued;
		};
		if now >= entry.expires_at() {
			return Hold::Expired;
		}
		entry.tx = Some(tx.clone());
		entry.attempts = entry.attempts.saturating_add(1);
		entry.next_attempt_at = now.saturating_add(backoff_secs(entry.attempts));
		entry.last_error = Some(reason);
		entry.last_was_verdict = verdict;
		let held = Hold::Held { attempts: entry.attempts, next_attempt_at: entry.next_attempt_at };
		self.persist_logged(&state);
		held
	}

	/// Records that `txids` are on the network: their entries are done, and every held entry
	/// with one of them as a parent is due at once.
	pub(crate) fn mark_sent(&self, txids: &[Txid], now: u64) {
		let mut state = self.lock();
		let mut changed = false;
		let parents: HashSet<Txid> = state.entries.values().flat_map(|e| e.parents()).collect();
		for txid in txids {
			let registered = state.entries.remove(txid).is_some();
			state.parents_known.remove(txid);
			if registered || parents.contains(txid) {
				state.sent.insert(*txid, now);
				changed = true;
			}
		}
		if !changed {
			return;
		}
		let sent: HashSet<Txid> = txids.iter().copied().collect();
		for entry in state.entries.values_mut() {
			if entry.tx.is_some() && entry.parents().iter().any(|p| sent.contains(p)) {
				entry.next_attempt_at = now;
			}
		}
		prune_sent(&mut state.sent, now);
		self.persist_logged(&state);
	}

	/// The held transactions due for a rebroadcast at `now`, parents first: those whose backoff
	/// ran out, and those with a parent that became known — sent by this node or confirmed —
	/// since they were last tried. An entry whose explicit dependencies are not all known yet is
	/// not due.
	pub(crate) fn due(&self, now: u64, is_confirmed: impl Fn(&Txid) -> bool) -> Vec<Transaction> {
		let mut state = self.lock();
		let QueueState { entries, sent, parents_known, .. } = &mut *state;
		let mut due = Vec::new();
		for entry in entries.values() {
			let Some(tx) = entry.tx.as_ref() else {
				continue;
			};
			let known = |p: &Txid| sent.contains_key(p) || is_confirmed(p);
			if entry.depends_on.iter().any(|dep| !known(dep)) {
				continue;
			}
			let known_now = entry.parents().iter().filter(|p| known(p)).count();
			// The first look only takes the baseline: a parent confirmed long ago is no news.
			let known_before = *parents_known.entry(entry.txid).or_insert(known_now);
			if entry.next_attempt_at <= now || known_now > known_before {
				parents_known.insert(entry.txid, known_now);
				due.push(tx.clone());
			}
		}
		parents_first(due)
	}

	/// The held entries past their `max_age`, each with the reason and whether giving it up is
	/// definitive — only if the network refused it, rather than no backend answering — for the
	/// caller to give up ([`crate::wallet::Wallet::give_up_transaction`]). A registration whose
	/// transaction never reached the broadcast path is forgotten here, silently.
	pub(crate) fn expire(&self, now: u64) -> Vec<(Txid, String, bool)> {
		let mut state = self.lock();
		let before = state.entries.len();
		state.entries.retain(|_, e| e.tx.is_some() || now < e.expires_at());
		let forgot = state.entries.len() != before;
		let expired = state
			.entries
			.values()
			.filter(|e| now >= e.expires_at())
			.map(|e| {
				let reason = format!(
					"not on the network {}s after it was queued; last: {}",
					e.max_age_secs,
					e.last_error.as_deref().unwrap_or("no answer")
				);
				(e.txid, reason, e.last_was_verdict)
			})
			.collect();
		if forgot {
			self.persist_logged(&state);
		}
		expired
	}

	/// Gives `txid` up with `reason` — `definitive` when that proves it can never confirm — and
	/// with it every entry depending on it, directly or not. Returns every txid given up, `txid`
	/// first. The caller releases their inputs.
	pub(crate) fn abandon(
		&self, txid: Txid, reason: String, definitive: bool, now: u64,
	) -> Vec<Txid> {
		let mut state = self.lock();
		let given_up = abandon_locked(&mut state, txid, reason, definitive, now);
		self.persist_logged(&state);
		given_up.into_iter().map(|(txid, _)| txid).collect()
	}

	/// Whether any transaction is held for a rebroadcast.
	pub(crate) fn has_held(&self) -> bool {
		self.lock().entries.values().any(|e| e.tx.is_some())
	}

	/// Every entry — registered, held and given up — for the node's operator.
	pub(crate) fn list(&self, is_confirmed: impl Fn(&Txid) -> bool) -> Vec<BroadcastQueueEntry> {
		let state = self.lock();
		let mut listed: Vec<BroadcastQueueEntry> = state
			.entries
			.values()
			.map(|entry| {
				let waiting = entry.tx.is_some();
				BroadcastQueueEntry {
					txid: entry.txid,
					state: if waiting {
						BroadcastQueueState::Waiting
					} else {
						BroadcastQueueState::Registered
					},
					depends_on: entry.depends_on.clone(),
					waiting_on: entry
						.parents()
						.into_iter()
						.filter(|p| !state.sent.contains_key(p) && !is_confirmed(p))
						.collect(),
					created_at_secs: entry.registered_at,
					expires_at_secs: Some(entry.expires_at()),
					attempts: entry.attempts,
					next_attempt_at_secs: waiting.then_some(entry.next_attempt_at),
					last_error: entry.last_error.clone(),
				}
			})
			.collect();
		listed.sort_unstable_by_key(|e| (e.created_at_secs, e.txid));
		listed.extend(state.abandoned.iter().rev().map(|a| BroadcastQueueEntry {
			txid: a.txid,
			state: BroadcastQueueState::Abandoned { reason: a.reason.clone() },
			depends_on: Vec::new(),
			waiting_on: Vec::new(),
			created_at_secs: a.at,
			expires_at_secs: None,
			attempts: 0,
			next_attempt_at_secs: None,
			last_error: None,
		}));
		listed
	}
}

/// Gives `txid` up and, after it, every entry depending on it, directly or not; returns each
/// with the reason it was given up. A descendant's give-up is always definitive: its parent
/// will never be broadcast by this node.
fn abandon_locked(
	state: &mut QueueState, txid: Txid, reason: String, definitive: bool, now: u64,
) -> Vec<(Txid, String)> {
	state.entries.remove(&txid);
	state.parents_known.remove(&txid);
	record_abandoned(state, txid, reason.clone(), definitive, now);
	let mut given_up = vec![(txid, reason)];
	let mut frontier = vec![txid];
	while let Some(parent) = frontier.pop() {
		let children: Vec<Txid> = state
			.entries
			.values()
			.filter(|e| e.parents().contains(&parent))
			.map(|e| e.txid)
			.collect();
		for child in children {
			let reason = format!("it depends on {}, which was given up", parent);
			state.entries.remove(&child);
			state.parents_known.remove(&child);
			record_abandoned(state, child, reason.clone(), true, now);
			given_up.push((child, reason));
			frontier.push(child);
		}
	}
	given_up
}

fn record_abandoned(
	state: &mut QueueState, txid: Txid, reason: String, definitive: bool, now: u64,
) {
	state.abandoned.retain(|a| a.txid != txid && now.saturating_sub(a.at) <= ABANDONED_MEMORY_SECS);
	state.abandoned.push(AbandonedTx { txid, at: now, reason, definitive });
	if state.abandoned.len() > ABANDONED_MEMORY_CAP {
		let excess = state.abandoned.len() - ABANDONED_MEMORY_CAP;
		state.abandoned.drain(..excess);
	}
}

fn prune_sent(sent: &mut HashMap<Txid, u64>, now: u64) {
	sent.retain(|_, at| now.saturating_sub(*at) <= SENT_MEMORY_SECS);
	if sent.len() > SENT_MEMORY_CAP {
		let mut by_age: Vec<(u64, Txid)> = sent.iter().map(|(txid, at)| (*at, *txid)).collect();
		by_age.sort_unstable();
		let excess = sent.len() - SENT_MEMORY_CAP;
		for (_, txid) in by_age.into_iter().take(excess) {
			sent.remove(&txid);
		}
	}
}

/// `txs` reordered so that every transaction comes after the ones of `txs` whose outputs it
/// spends, otherwise keeping their order. A backend sends a package one transaction at a time,
/// and a child sent before its parent is refused for a missing input. A dependency cycle cannot
/// exist between valid transactions; should one be handed in, its members keep their order at
/// the end.
pub(crate) fn parents_first(txs: Vec<Transaction>) -> Vec<Transaction> {
	if txs.len() < 2 {
		return txs;
	}
	let txids: Vec<Txid> = txs.iter().map(|tx| tx.compute_txid()).collect();
	let index: HashMap<Txid, usize> = txids.iter().enumerate().map(|(i, t)| (*t, i)).collect();
	let parents: Vec<HashSet<usize>> = txs
		.iter()
		.enumerate()
		.map(|(i, tx)| {
			tx.input
				.iter()
				.filter_map(|input| index.get(&input.previous_output.txid).copied())
				.filter(|p| *p != i)
				.collect()
		})
		.collect();

	let mut placed = vec![false; txs.len()];
	let mut order = Vec::with_capacity(txs.len());
	loop {
		let next = (0..txs.len()).find(|&i| !placed[i] && parents[i].iter().all(|p| placed[*p]));
		match next {
			Some(i) => {
				placed[i] = true;
				order.push(i);
			},
			None => break,
		}
	}
	order.extend((0..txs.len()).filter(|i| !placed[*i]));

	let mut slots: Vec<Option<Transaction>> = txs.into_iter().map(Some).collect();
	order.into_iter().filter_map(|i| slots[i].take()).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::hashes::Hash;
	use bitcoin::{
		absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness,
	};
	use lightning::util::test_utils::TestStore;

	fn spending(previous: &[OutPoint], value: u64) -> Transaction {
		Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: previous
				.iter()
				.map(|previous_output| TxIn {
					previous_output: *previous_output,
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
					witness: Witness::new(),
				})
				.collect(),
			output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::new() }],
		}
	}

	fn coin(seed: u8) -> OutPoint {
		OutPoint { txid: Txid::from_byte_array([seed; 32]), vout: 0 }
	}

	fn out_of(tx: &Transaction) -> OutPoint {
		OutPoint { txid: tx.compute_txid(), vout: 0 }
	}

	fn queue_on(kv_store: &Arc<DynStore>) -> BroadcastQueue {
		BroadcastQueue::read_or_empty(Arc::clone(kv_store), Arc::new(Logger::new_log_facade()))
	}

	fn store() -> Arc<DynStore> {
		Arc::new(TestStore::new(false))
	}

	fn never_confirmed(_: &Txid) -> bool {
		false
	}

	#[test]
	fn parents_first_puts_every_parent_before_its_children() {
		let parent = spending(&[coin(1)], 10_000);
		let child = spending(&[out_of(&parent)], 9_000);
		let grandchild = spending(&[out_of(&child)], 8_000);
		let unrelated = spending(&[coin(2)], 5_000);

		let ordered = parents_first(vec![
			grandchild.clone(),
			unrelated.clone(),
			child.clone(),
			parent.clone(),
		]);

		assert_eq!(ordered, vec![unrelated, parent, child, grandchild]);
		let single = vec![spending(&[coin(3)], 1_000)];
		assert_eq!(parents_first(single.clone()), single);
	}

	#[test]
	fn an_unregistered_transaction_is_drop_on_reject_and_never_held() {
		let queue = queue_on(&store());
		let tx = spending(&[coin(1)], 1_000);

		assert_eq!(queue.policy(&tx.compute_txid()), BroadcastPolicy::DropOnReject);
		assert_eq!(queue.hold(&tx, "missing inputs".into(), true, 10), Hold::NotQueued);
		assert!(!queue.is_held(&tx.compute_txid()));

		// Registering DropOnReject over a queued policy restores the default.
		queue.register(tx.compute_txid(), BroadcastPolicy::default(), 10);
		queue.register(tx.compute_txid(), BroadcastPolicy::DropOnReject, 11);
		assert_eq!(queue.policy(&tx.compute_txid()), BroadcastPolicy::DropOnReject);
	}

	#[test]
	fn a_held_child_is_due_at_once_when_its_parent_is_sent_and_on_backoff_otherwise() {
		let queue = queue_on(&store());
		let parent = spending(&[coin(1)], 10_000);
		let child = spending(&[out_of(&parent)], 9_000);
		queue.register(parent.compute_txid(), BroadcastPolicy::default(), 100);
		queue.register(child.compute_txid(), BroadcastPolicy::default(), 100);

		assert_eq!(
			queue.hold(&child, "bad-txns-inputs-missingorspent (-25)".into(), true, 100),
			Hold::Held { attempts: 1, next_attempt_at: 100 + RETRY_BACKOFF_BASE_SECS }
		);
		assert!(queue.is_held(&child.compute_txid()));
		assert!(queue.due(101, never_confirmed).is_empty(), "inside its backoff");

		queue.mark_sent(&[parent.compute_txid()], 102);
		assert_eq!(queue.due(102, never_confirmed), vec![child.clone()], "its parent is out");

		queue.mark_sent(&[child.compute_txid()], 103);
		assert!(!queue.is_held(&child.compute_txid()));
		assert!(queue.due(10_000, never_confirmed).is_empty());
	}

	#[test]
	fn a_parent_that_confirms_makes_its_held_child_due() {
		let queue = queue_on(&store());
		let parent = spending(&[coin(1)], 10_000);
		let child = spending(&[out_of(&parent)], 9_000);
		queue.register(child.compute_txid(), BroadcastPolicy::default(), 100);
		queue.hold(&child, "Missing inputs (-25)".into(), true, 100);
		assert!(queue.due(101, never_confirmed).is_empty());

		let parent_txid = parent.compute_txid();
		let due = queue.due(101, |txid| *txid == parent_txid);
		assert_eq!(due, vec![child.clone()]);
		assert!(queue.due(102, |txid| *txid == parent_txid).is_empty(), "once per new parent");
	}

	#[test]
	fn the_backoff_doubles_up_to_its_cap() {
		assert_eq!(backoff_secs(1), 15);
		assert_eq!(backoff_secs(2), 30);
		assert_eq!(backoff_secs(3), 60);
		assert_eq!(backoff_secs(7), RETRY_BACKOFF_CAP_SECS);
		assert_eq!(backoff_secs(u32::MAX), RETRY_BACKOFF_CAP_SECS);
	}

	#[test]
	fn explicit_dependencies_gate_the_first_broadcast_and_every_retry() {
		let queue = queue_on(&store());
		let first = spending(&[coin(1)], 10_000);
		let second = spending(&[coin(2)], 10_000);
		let policy = BroadcastPolicy::QueueUntilParents {
			max_age_secs: 3_600,
			depends_on: vec![first.compute_txid()],
		};
		queue.register(second.compute_txid(), policy.clone(), 100);
		assert_eq!(queue.policy(&second.compute_txid()), policy);

		assert!(queue.awaits_dependencies(&second, never_confirmed));
		queue.hold(&second, "waiting for its dependencies".into(), false, 100);
		assert!(queue.due(10_000, never_confirmed).is_empty(), "never before `first` is out");

		queue.mark_sent(&[first.compute_txid()], 200);
		assert!(!queue.awaits_dependencies(&second, never_confirmed));
		assert_eq!(queue.due(200, never_confirmed), vec![second]);
	}

	#[test]
	fn expiry_names_held_entries_and_forgets_registrations() {
		let queue = queue_on(&store());
		let held = spending(&[coin(1)], 1_000);
		let registered = spending(&[coin(2)], 1_000);
		let unanswered = spending(&[coin(3)], 1_000);
		let policy = BroadcastPolicy::QueueUntilParents { max_age_secs: 50, depends_on: vec![] };
		for tx in [&held, &registered, &unanswered] {
			queue.register(tx.compute_txid(), policy.clone(), 100);
		}
		queue.hold(&held, "Missing inputs (-25)".into(), true, 100);
		queue.hold(&unanswered, "electrum: timed out".into(), false, 100);

		assert!(queue.expire(149).is_empty());
		assert_eq!(queue.hold(&held, "again".into(), true, 150), Hold::Expired);
		let mut expired: Vec<(Txid, bool)> =
			queue.expire(150).into_iter().map(|(txid, _, definitive)| (txid, definitive)).collect();
		expired.sort();
		let mut expected = vec![(held.compute_txid(), true), (unanswered.compute_txid(), false)];
		expected.sort();
		assert_eq!(expired, expected, "definitive only where the network said no");
		assert_eq!(
			queue.policy(&registered.compute_txid()),
			BroadcastPolicy::DropOnReject,
			"a registration never broadcast is forgotten"
		);
		assert!(!queue.is_abandoned(&registered.compute_txid()), "and is not a give-up");

		queue.abandon(held.compute_txid(), "expired".into(), true, 150);
		queue.abandon(unanswered.compute_txid(), "expired".into(), false, 150);
		let dead = queue.definitively_abandoned();
		assert!(dead.contains(&held.compute_txid()));
		assert!(!dead.contains(&unanswered.compute_txid()), "nobody ever said no: not proof");
		assert!(queue.is_abandoned(&unanswered.compute_txid()));
	}

	#[test]
	fn abandoning_a_parent_abandons_every_descendant() {
		let queue = queue_on(&store());
		let parent = spending(&[coin(1)], 10_000);
		let child = spending(&[out_of(&parent)], 9_000);
		let grandchild = spending(&[out_of(&child)], 8_000);
		let unrelated = spending(&[coin(2)], 5_000);
		for tx in [&parent, &child, &grandchild, &unrelated] {
			queue.register(tx.compute_txid(), BroadcastPolicy::default(), 100);
		}
		queue.hold(&child, "Missing inputs (-25)".into(), true, 100);
		queue.hold(&grandchild, "Missing inputs (-25)".into(), true, 100);

		let given_up = queue.abandon(parent.compute_txid(), "discarded".into(), true, 120);

		assert_eq!(
			given_up,
			vec![parent.compute_txid(), child.compute_txid(), grandchild.compute_txid()]
		);
		assert!(!queue.is_held(&child.compute_txid()));
		assert_eq!(queue.policy(&unrelated.compute_txid()), BroadcastPolicy::default());
		assert_eq!(queue.abandoned_parent(&child), Some(parent.compute_txid()));
		let listed = queue.list(never_confirmed);
		assert_eq!(listed.len(), 4);
		assert_eq!(listed[0].state, BroadcastQueueState::Registered);
		assert!(matches!(listed[1].state, BroadcastQueueState::Abandoned { .. }));
	}

	#[test]
	fn the_queue_survives_a_restart() {
		let kv_store = store();
		let parent = spending(&[coin(1)], 10_000);
		let child = spending(&[out_of(&parent)], 9_000);
		let gone = spending(&[coin(9)], 1_000);
		{
			let queue = queue_on(&kv_store);
			queue.register(child.compute_txid(), BroadcastPolicy::default(), 100);
			queue.register(parent.compute_txid(), BroadcastPolicy::default(), 100);
			queue.hold(&child, "bad-txns-inputs-missingorspent (-25)".into(), true, 100);
			queue.register(gone.compute_txid(), BroadcastPolicy::default(), 100);
			queue.abandon(gone.compute_txid(), "conflict".into(), true, 101);
			queue.set_pending_open(7, BroadcastPolicy::DropOnReject);
		}

		let queue = queue_on(&kv_store);

		assert!(queue.is_held(&child.compute_txid()));
		assert_eq!(queue.policy(&parent.compute_txid()), BroadcastPolicy::default());
		assert!(queue.definitively_abandoned().contains(&gone.compute_txid()));
		assert_eq!(
			queue.due(100, never_confirmed),
			Vec::<Transaction>::new(),
			"the backoff is persisted too"
		);
		queue.mark_sent(&[parent.compute_txid()], 105);
		assert_eq!(queue.due(105, never_confirmed), vec![child]);
		assert_eq!(
			queue.take_pending_open(7),
			BroadcastPolicy::default(),
			"an open's pending policy does not outlive the run: LDK forgets the unfunded channel"
		);
	}
}
