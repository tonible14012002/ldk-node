// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Chain-proven dead channel fundings.
//!
//! A funding transaction this node built can lose the chain for good: the coin it spends is
//! taken by another transaction that confirms (two opens raced for one coin, and the loser's
//! funding was rejected by every mempool), or it spends the change of such a loser and so can
//! never confirm either. LDK has no notion of this. The `ChannelMonitor` of such a channel
//! lives forever: its holder commitment is rebroadcast every 30 seconds and rejected with
//! `bad-txns-inputs-missingorspent`, its holder balance keeps counting in
//! [`Node::list_balances`] on top of the on-chain coin that was never spent, and
//! `archive_fully_resolved_channel_monitors` never archives it because its claimable balance
//! never resolves.
//!
//! The on-chain wallet reserves the inputs of every funding it builds and hands them back when
//! the funding is discarded, rejected or evicted — after which a later spend reuses the coin
//! while LDK still waits on the old channel. This module closes that gap with proof, not a
//! heuristic: a funding is **dead** when its transaction is in the wallet's graph (we built it)
//! and, by the wallet's own view of the chain, one of its inputs is spent by a *different*
//! transaction buried [`ANTI_REORG_DELAY`] deep, or one of its inputs comes from a parent that
//! is itself dead. A transaction this node gave up for good — a funding LDK discarded before
//! broadcasting it, or one the broadcast queue gave up on a definitive answer
//! ([`crate::broadcast_queue`]) — is dead by this node's own word: nothing will ever broadcast
//! it, and its inputs are offered to other spends. A legitimately pending funding is never dead, and a funding the peer built
//! (an inbound channel) is not in the wallet's graph and is left alone.
//!
//! What happens to a dead funding, in order:
//!
//! 1. While the `ChannelManager` still lists the channel it is force-closed without
//!    broadcasting — there is nothing to broadcast; a commitment spending a dead funding is
//!    rejected like the funding was.
//! 2. On a later pass — one that finds the channel already gone when it starts, so the
//!    background processor has had at least a sync interval to persist the `ChannelManager`
//!    without it — the manager is persisted once more and the funding outpoint recorded in a
//!    small persisted set ([`DeadFundingStore`]). From then on [`Node::list_balances`] leaves
//!    the monitor's balances out of the Lightning total and reports them as
//!    [`BalanceDetails::dead_funding_balance_sats`].
//! 3. At the next start the recorded monitors are archived exactly as LDK archives a resolved
//!    one — moved to the `archived_monitors` namespace — before the `ChannelManager` is read,
//!    and never loaded into the `ChainMonitor`. That ends the rebroadcast loop. A monitor
//!    cannot be removed from a running `ChainMonitor`, which is why this waits for a restart.
//!    Should the persisted manager still need one of them, the start puts the monitors back,
//!    forgets the outpoints (a later pass proves and records them again) and reads the
//!    manager once more with every monitor, so no recorded outpoint can keep a node down.
//!
//! Detection runs after every successful on-chain wallet sync. It walks the node's own
//! monitors only — a handful — and costs a few hash lookups per funding input.
//!
//! [`Node::list_balances`]: crate::Node::list_balances
//! [`BalanceDetails::dead_funding_balance_sats`]: crate::BalanceDetails::dead_funding_balance_sats

use crate::io::{
	DEAD_FUNDING_PERSISTENCE_KEY, DEAD_FUNDING_PERSISTENCE_PRIMARY_NAMESPACE,
	DEAD_FUNDING_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Wallet};
use crate::Error;

use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
use lightning::chain::transaction::OutPoint as FundingOutPoint;
use lightning::impl_writeable_tlv_based;
use lightning::ln::types::ChannelId;
use lightning::util::persist::{
	ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
	ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_KEY,
	CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
	CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::ser::{Readable, Writeable};

use bdk_chain::local_chain::LocalChain;
use bdk_chain::tx_graph::TxGraph;
use bdk_chain::{BlockId, ChainOracle, ConfirmationBlockTime};

use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Txid};

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};

/// Why a funding can never confirm. Each variant names the chain fact that proves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeadFundingProof {
	/// `input` is spent by `conflicting_txid`, confirmed at `confirmation_height` and buried
	/// at least [`ANTI_REORG_DELAY`] blocks deep by the wallet's chain tip.
	ConflictingSpend { input: OutPoint, conflicting_txid: Txid, confirmation_height: u32 },
	/// An input comes from `parent_txid`, which is itself dead.
	DeadParent { parent_txid: Txid },
	/// This node gave the transaction up for good and released its inputs.
	Abandoned,
}

impl fmt::Display for DeadFundingProof {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ConflictingSpend { input, conflicting_txid, confirmation_height } => write!(
				f,
				"input {} is spent by {} confirmed at height {}",
				input, conflicting_txid, confirmation_height
			),
			Self::DeadParent { parent_txid } => {
				write!(f, "it spends an output of dead transaction {}", parent_txid)
			},
			Self::Abandoned => write!(f, "this node gave it up and released its inputs"),
		}
	}
}

/// Which of `candidates` are dead, by the wallet's chain view (`graph`, `chain`, `tip`), each
/// with its proof.
///
/// `known_dead` are transactions already proven dead earlier — recorded fundings whose
/// monitors may be archived by now — so a child of one is still caught. `abandoned` are the
/// transactions this node gave up for good. A candidate not in `graph` is never dead: the
/// wallet did not build it, so nothing here can speak for it.
pub(crate) fn find_dead_fundings(
	graph: &TxGraph<ConfirmationBlockTime>, chain: &LocalChain, tip: BlockId,
	candidates: impl IntoIterator<Item = Txid>, known_dead: &HashSet<Txid>,
	abandoned: &HashSet<Txid>,
) -> HashMap<Txid, DeadFundingProof> {
	let mut finder =
		DeadTxFinder { graph, chain, tip, known_dead, abandoned, memo: HashMap::new() };
	candidates
		.into_iter()
		.filter_map(|txid| finder.proof(txid).map(|proof| (txid, proof)))
		.collect()
}

struct DeadTxFinder<'a> {
	graph: &'a TxGraph<ConfirmationBlockTime>,
	chain: &'a LocalChain,
	tip: BlockId,
	known_dead: &'a HashSet<Txid>,
	abandoned: &'a HashSet<Txid>,
	/// Every transaction classified so far, dead or not, so the parent walk visits each once.
	memo: HashMap<Txid, Option<DeadFundingProof>>,
}

impl DeadTxFinder<'_> {
	/// The height `txid` is confirmed at on the wallet's best chain, if it is.
	fn confirmation_height(&self, txid: Txid) -> Option<u32> {
		self.graph
			.all_anchors()
			.get(&txid)?
			.iter()
			.find(|anchor| {
				matches!(self.chain.is_block_in_chain(anchor.block_id, self.tip), Ok(Some(true)))
			})
			.map(|anchor| anchor.block_id.height)
	}

	/// Whether a transaction confirmed at `height` is [`ANTI_REORG_DELAY`] deep at the tip —
	/// the same depth at which the wallet calls an on-chain payment settled.
	fn is_buried(&self, height: u32) -> bool {
		self.tip.height >= height.saturating_add(ANTI_REORG_DELAY - 1)
	}

	fn proof(&mut self, txid: Txid) -> Option<DeadFundingProof> {
		if let Some(known) = self.memo.get(&txid) {
			return known.clone();
		}
		// Marked before the parent walk, so a malformed graph cannot send it in circles.
		self.memo.insert(txid, None);
		let proof = self.classify(txid);
		self.memo.insert(txid, proof.clone());
		proof
	}

	fn classify(&mut self, txid: Txid) -> Option<DeadFundingProof> {
		let tx = self.graph.get_tx(txid)?;
		if self.confirmation_height(txid).is_some() {
			// On the chain, whatever else spends its inputs on a branch we are not on.
			return None;
		}

		for input in &tx.input {
			let outpoint = input.previous_output;
			for spender in self.graph.outspends(outpoint) {
				if *spender == txid {
					continue;
				}
				if let Some(height) = self.confirmation_height(*spender) {
					if self.is_buried(height) {
						return Some(DeadFundingProof::ConflictingSpend {
							input: outpoint,
							conflicting_txid: *spender,
							confirmation_height: height,
						});
					}
				}
			}
		}

		for input in &tx.input {
			let parent_txid = input.previous_output.txid;
			if self.known_dead.contains(&parent_txid)
				|| self.abandoned.contains(&parent_txid)
				|| self.proof(parent_txid).is_some()
			{
				return Some(DeadFundingProof::DeadParent { parent_txid });
			}
		}

		// Last, so a chain proof is named whenever there is one.
		if self.abandoned.contains(&txid) {
			return Some(DeadFundingProof::Abandoned);
		}

		None
	}
}

/// The funding outpoints proven dead whose channels are gone, persisted so the next start
/// archives their monitors and so [`crate::Node::list_balances`] can leave them out meanwhile.
///
/// The set only grows. It is a cache of a fact the reaper re-proves from the chain on every
/// pass, so a missing or unreadable entry costs nothing but a re-detection.
pub(crate) struct DeadFundingStore {
	outpoints: RwLock<HashSet<FundingOutPoint>>,
	kv_store: Arc<DynStore>,
	logger: Arc<Logger>,
}

impl DeadFundingStore {
	/// Reads the persisted set; none persisted yet is an empty set, and an unreadable one is
	/// logged and treated as empty.
	pub(crate) fn read_or_empty(kv_store: Arc<DynStore>, logger: Arc<Logger>) -> Self {
		let outpoints = match kv_store.read(
			DEAD_FUNDING_PERSISTENCE_PRIMARY_NAMESPACE,
			DEAD_FUNDING_PERSISTENCE_SECONDARY_NAMESPACE,
			DEAD_FUNDING_PERSISTENCE_KEY,
		) {
			Ok(bytes) => match DeadFundingSet::read(&mut &bytes[..]) {
				Ok(set) => set.outpoints.into_iter().collect(),
				Err(e) => {
					log_error!(
						logger,
						"Failed to deserialize the dead funding set; starting from an empty one: {}",
						e
					);
					HashSet::new()
				},
			},
			Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => HashSet::new(),
			Err(e) => {
				log_error!(
					logger,
					"Failed to read the dead funding set; starting from an empty one: {}",
					e
				);
				HashSet::new()
			},
		};
		Self { outpoints: RwLock::new(outpoints), kv_store, logger }
	}

	pub(crate) fn contains(&self, funding_txo: &FundingOutPoint) -> bool {
		self.outpoints.read().unwrap().contains(funding_txo)
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.outpoints.read().unwrap().is_empty()
	}

	/// The funding transactions recorded, for the parent walk of a later detection.
	pub(crate) fn txids(&self) -> HashSet<Txid> {
		self.outpoints.read().unwrap().iter().map(|txo| txo.txid).collect()
	}

	/// Records `funding_txo` and persists the set. Recording an outpoint twice is a no-op.
	pub(crate) fn insert(&self, funding_txo: FundingOutPoint) -> Result<(), Error> {
		let mut locked_outpoints = self.outpoints.write().unwrap();
		if !locked_outpoints.insert(funding_txo) {
			return Ok(());
		}
		self.persist(&locked_outpoints).map_err(|e| {
			// Keep memory and disk in step: the next pass re-proves and retries.
			locked_outpoints.remove(&funding_txo);
			e
		})
	}

	/// Forgets every outpoint in `funding_txos` and persists the set. A start that had to put
	/// archived monitors back calls this: a later pass proves and records them again.
	pub(crate) fn remove_all(&self, funding_txos: &HashSet<FundingOutPoint>) -> Result<(), Error> {
		let mut locked_outpoints = self.outpoints.write().unwrap();
		let before = locked_outpoints.len();
		locked_outpoints.retain(|txo| !funding_txos.contains(txo));
		if locked_outpoints.len() == before {
			return Ok(());
		}
		self.persist(&locked_outpoints)
	}

	fn persist(&self, outpoints: &HashSet<FundingOutPoint>) -> Result<(), Error> {
		let mut outpoints: Vec<FundingOutPoint> = outpoints.iter().copied().collect();
		outpoints.sort_unstable_by_key(|txo| (txo.txid, txo.index));
		let data = DeadFundingSet { outpoints }.encode();
		self.kv_store
			.write(
				DEAD_FUNDING_PERSISTENCE_PRIMARY_NAMESPACE,
				DEAD_FUNDING_PERSISTENCE_SECONDARY_NAMESPACE,
				DEAD_FUNDING_PERSISTENCE_KEY,
				&data,
			)
			.map_err(|e| {
				log_error!(
					self.logger,
					"Write for key {}/{}/{} failed due to: {}",
					DEAD_FUNDING_PERSISTENCE_PRIMARY_NAMESPACE,
					DEAD_FUNDING_PERSISTENCE_SECONDARY_NAMESPACE,
					DEAD_FUNDING_PERSISTENCE_KEY,
					e
				);
				Error::PersistenceFailed
			})
	}
}

struct DeadFundingSet {
	outpoints: Vec<FundingOutPoint>,
}

impl_writeable_tlv_based!(DeadFundingSet, {
	(0, outpoints, required_vec),
});

/// What one pass does about a dead funding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PassAction {
	/// The `ChannelManager` still lists the channel: close it. Nothing is recorded on this
	/// pass, whatever the close does.
	ForceClose {
		funding_txo: FundingOutPoint,
		channel_id: ChannelId,
		counterparty_node_id: PublicKey,
		proof: DeadFundingProof,
	},
	/// The channel was already gone when the pass started — at least a sync interval after
	/// its close, time enough for the background processor to have persisted the manager
	/// without it: record the funding.
	Record { funding_txo: FundingOutPoint, channel_id: ChannelId, proof: DeadFundingProof },
}

/// Decides a pass from what it found: the monitors not yet recorded (`candidates`), the
/// fundings proven dead among them, and the channels the `ChannelManager` listed when the
/// pass started. Recording waits for a pass that starts with the channel gone, so a close
/// and its record are never on the same pass.
pub(crate) fn plan_pass(
	candidates: &[(FundingOutPoint, ChannelId)], dead: &HashMap<Txid, DeadFundingProof>,
	listed: &[(FundingOutPoint, ChannelId, PublicKey)],
) -> Vec<PassAction> {
	candidates
		.iter()
		.filter_map(|(funding_txo, channel_id)| {
			let proof = dead.get(&funding_txo.txid)?.clone();
			let action = match listed.iter().find(|(txo, _, _)| txo == funding_txo) {
				Some((_, channel_id, counterparty_node_id)) => PassAction::ForceClose {
					funding_txo: *funding_txo,
					channel_id: *channel_id,
					counterparty_node_id: *counterparty_node_id,
					proof,
				},
				None => {
					PassAction::Record { funding_txo: *funding_txo, channel_id: *channel_id, proof }
				},
			};
			Some(action)
		})
		.collect()
}

/// One detection pass over the node's own channel monitors; see the module docs.
///
/// Cheap by construction — a handful of monitors, a few lookups each — so every successful
/// on-chain wallet sync runs it. Nothing here propagates: a step that fails is logged and
/// retried on the next pass, which proves the same facts again.
pub(crate) fn reap_dead_fundings(
	wallet: &Wallet, channel_manager: &ChannelManager, chain_monitor: &ChainMonitor,
	store: &DeadFundingStore, kv_store: &DynStore, logger: &Logger,
) {
	let candidates: Vec<(FundingOutPoint, ChannelId)> = chain_monitor
		.list_monitors()
		.into_iter()
		.filter(|(funding_txo, _)| !store.contains(funding_txo))
		.collect();
	if candidates.is_empty() {
		return;
	}

	let known_dead = store.txids();
	let dead = wallet.find_dead_fundings(candidates.iter().map(|(txo, _)| txo.txid), &known_dead);
	if dead.is_empty() {
		return;
	}

	let listed: Vec<(FundingOutPoint, ChannelId, PublicKey)> = channel_manager
		.list_channels()
		.into_iter()
		.filter_map(|c| c.funding_txo.map(|txo| (txo, c.channel_id, c.counterparty.node_id)))
		.collect();

	for action in plan_pass(&candidates, &dead, &listed) {
		match action {
			PassAction::ForceClose { funding_txo, channel_id, counterparty_node_id, proof } => {
				log_info!(
					logger,
					"Funding transaction {} of channel {} is dead: {}. Force-closing the channel without broadcasting.",
					funding_txo.txid,
					channel_id,
					proof
				);
				let reason = format!(
					"funding transaction {} can never confirm: {}",
					funding_txo.txid, proof
				);
				if let Err(e) = channel_manager.force_close_without_broadcasting_txn(
					&channel_id,
					&counterparty_node_id,
					reason,
				) {
					log_error!(
						logger,
						"Failed to force-close channel {} over its dead funding {}: {:?}",
						channel_id,
						funding_txo.txid,
						e
					);
				}
			},
			PassAction::Record { funding_txo, channel_id, proof } => {
				// Persist the `ChannelManager` without the channel once more before
				// recording, so a start that archives the monitor can never meet a manager
				// that still needs it.
				if let Err(e) = kv_store.write(
					CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
					CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
					CHANNEL_MANAGER_PERSISTENCE_KEY,
					&channel_manager.encode(),
				) {
					log_error!(
						logger,
						"Failed to persist the channel manager before recording dead funding {}: {}",
						funding_txo.txid,
						e
					);
					continue;
				}
				match store.insert(funding_txo) {
					Ok(()) => {
						log_info!(
							logger,
							"Recorded dead funding {} of channel {} ({}); its balances no longer count and its ChannelMonitor is archived at the next start.",
							funding_txo,
							channel_id,
							proof
						);
					},
					Err(e) => {
						log_error!(
							logger,
							"Failed to record dead funding {} of channel {}: {}",
							funding_txo,
							channel_id,
							e
						);
					},
				}
			},
		}
	}
}

/// The key a `ChannelMonitor` is persisted under, as LDK's `MonitorName` forms it.
fn monitor_key(funding_txo: &FundingOutPoint) -> String {
	format!("{}_{}", funding_txo.txid, funding_txo.index)
}

/// Moves the persisted monitor of each of `dead` from the live to the archived namespace —
/// what LDK's own `archive_persisted_channel` does for a resolved monitor — and returns the
/// outpoints moved. A monitor no longer persisted is skipped; a move that fails is logged and
/// left where it was, so that monitor loads as before.
pub(crate) fn archive_dead_monitors(
	kv_store: &DynStore, dead: &[FundingOutPoint], logger: &Logger,
) -> HashSet<FundingOutPoint> {
	let mut archived = HashSet::new();
	for funding_txo in dead {
		match move_monitor(
			kv_store,
			funding_txo,
			(
				CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			),
			(
				ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			),
		) {
			Ok(true) => {
				log_info!(
					logger,
					"Archived the ChannelMonitor of dead funding {}; it is not loaded again.",
					funding_txo
				);
				archived.insert(*funding_txo);
			},
			Ok(false) => {
				log_debug!(logger, "No ChannelMonitor persisted for dead funding {}.", funding_txo);
			},
			Err(e) => {
				log_error!(
					logger,
					"Failed to archive the ChannelMonitor of dead funding {}; loading it as before: {}",
					funding_txo,
					e
				);
			},
		}
	}
	archived
}

/// Undoes [`archive_dead_monitors`] for `archived`: the start that archived them could not
/// read the `ChannelManager` without them, so they go back where the next start finds them.
pub(crate) fn restore_archived_monitors(
	kv_store: &DynStore, archived: &HashSet<FundingOutPoint>, logger: &Logger,
) {
	for funding_txo in archived {
		match move_monitor(
			kv_store,
			funding_txo,
			(
				ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			),
			(
				CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			),
		) {
			Ok(_) => {
				log_info!(
					logger,
					"Restored the ChannelMonitor of dead funding {} from the archive.",
					funding_txo
				);
			},
			Err(e) => {
				log_error!(
					logger,
					"Failed to restore the ChannelMonitor of dead funding {} from the archive: {}",
					funding_txo,
					e
				);
			},
		}
	}
}

/// A start that archived `archived` could not read the `ChannelManager` without them: puts
/// the monitors back and forgets the outpoints, so the next read sees every monitor and the
/// recorded set can never keep the node from starting. A later pass proves them again.
pub(crate) fn undo_dead_monitor_archive(
	kv_store: &DynStore, store: &DeadFundingStore, archived: &HashSet<FundingOutPoint>,
	logger: &Logger,
) {
	restore_archived_monitors(kv_store, archived, logger);
	if let Err(e) = store.remove_all(archived) {
		log_error!(
			logger,
			"Failed to forget {} restored dead funding(s); they are proven again later: {}",
			archived.len(),
			e
		);
	}
}

/// Copies the monitor of `funding_txo` from `from` to `to` and removes the original.
/// `Ok(false)` means nothing was persisted under `from`.
fn move_monitor(
	kv_store: &DynStore, funding_txo: &FundingOutPoint, from: (&str, &str), to: (&str, &str),
) -> Result<bool, lightning::io::Error> {
	let key = monitor_key(funding_txo);
	let monitor = match kv_store.read(from.0, from.1, &key) {
		Ok(monitor) => monitor,
		Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => return Ok(false),
		Err(e) => return Err(e),
	};
	kv_store.write(to.0, to.1, &key, &monitor)?;
	kv_store.remove(from.0, from.1, &key, true)?;
	Ok(true)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::logger::Logger;

	use lightning::util::test_utils::TestStore;

	use bitcoin::hashes::Hash;

	fn store_and_logger() -> (Arc<DynStore>, Arc<Logger>) {
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let logger = Arc::new(Logger::new_log_facade());
		(kv_store, logger)
	}

	fn funding(seed: u8, index: u16) -> FundingOutPoint {
		FundingOutPoint { txid: Txid::from_byte_array([seed; 32]), index }
	}

	#[test]
	fn the_dead_set_survives_a_restart() {
		let (kv_store, logger) = store_and_logger();
		let store = DeadFundingStore::read_or_empty(Arc::clone(&kv_store), Arc::clone(&logger));
		assert!(store.is_empty(), "nothing persisted yet");

		store.insert(funding(1, 0)).expect("persists");
		store.insert(funding(2, 3)).expect("persists");
		store.insert(funding(1, 0)).expect("a repeat is a no-op");

		let reread = DeadFundingStore::read_or_empty(kv_store, logger);
		assert!(reread.contains(&funding(1, 0)));
		assert!(reread.contains(&funding(2, 3)));
		assert!(!reread.contains(&funding(2, 0)), "the index is part of the outpoint");
		assert_eq!(
			reread.txids(),
			[funding(1, 0).txid, funding(2, 3).txid].into_iter().collect::<HashSet<_>>()
		);
	}

	#[test]
	fn an_unreadable_dead_set_starts_empty() {
		let (kv_store, logger) = store_and_logger();
		kv_store
			.write(
				DEAD_FUNDING_PERSISTENCE_PRIMARY_NAMESPACE,
				DEAD_FUNDING_PERSISTENCE_SECONDARY_NAMESPACE,
				DEAD_FUNDING_PERSISTENCE_KEY,
				&[0xffu8; 7],
			)
			.unwrap();
		let store = DeadFundingStore::read_or_empty(kv_store, logger);
		assert!(store.is_empty());
	}

	fn proof(seed: u8) -> DeadFundingProof {
		DeadFundingProof::DeadParent { parent_txid: Txid::from_byte_array([seed; 32]) }
	}

	fn channel(seed: u8) -> ChannelId {
		ChannelId::from_bytes([seed; 32])
	}

	fn peer() -> PublicKey {
		use std::str::FromStr;
		PublicKey::from_str("0276607124ebe6a6c9338517b6f485825b27c2dcc0b9fc2aa6a4c0df91194e5993")
			.unwrap()
	}

	#[test]
	fn a_pass_closes_a_listed_dead_channel_and_records_only_one_already_gone() {
		let listed_dead = funding(1, 0);
		let gone_dead = funding(2, 0);
		let listed_live = funding(3, 0);
		let candidates =
			[(listed_dead, channel(1)), (gone_dead, channel(2)), (listed_live, channel(3))];
		let dead: HashMap<_, _> =
			[(listed_dead.txid, proof(1)), (gone_dead.txid, proof(2))].into_iter().collect();
		let listed = [(listed_dead, channel(1), peer()), (listed_live, channel(3), peer())];

		let actions = plan_pass(&candidates, &dead, &listed);
		assert_eq!(
			actions,
			vec![
				PassAction::ForceClose {
					funding_txo: listed_dead,
					channel_id: channel(1),
					counterparty_node_id: peer(),
					proof: proof(1),
				},
				PassAction::Record { funding_txo: gone_dead, channel_id: channel(2), proof: proof(2) },
			],
			"the listed one is closed, not recorded; the gone one is recorded; the live one is left"
		);

		// The next pass starts with the closed channel gone: now it is recorded.
		let listed = [(listed_live, channel(3), peer())];
		let actions = plan_pass(&candidates[..1], &dead, &listed);
		assert_eq!(
			actions,
			vec![PassAction::Record {
				funding_txo: listed_dead,
				channel_id: channel(1),
				proof: proof(1)
			}]
		);
	}

	#[test]
	fn undoing_an_archive_puts_the_monitor_back_and_forgets_the_outpoint() {
		let (kv_store, logger) = store_and_logger();
		let store = DeadFundingStore::read_or_empty(Arc::clone(&kv_store), Arc::clone(&logger));
		let dead = funding(4, 0);
		let other = funding(5, 1);
		store.insert(dead).unwrap();
		store.insert(other).unwrap();
		kv_store
			.write(
				CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
				&monitor_key(&dead),
				&[4u8; 8],
			)
			.unwrap();
		let archived = archive_dead_monitors(&*kv_store, &[dead], &logger);
		assert_eq!(archived, [dead].into_iter().collect());

		// The manager could not be read without it.
		undo_dead_monitor_archive(&*kv_store, &store, &archived, &logger);

		assert_eq!(
			kv_store
				.read(
					CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
					CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
					&monitor_key(&dead)
				)
				.unwrap(),
			vec![4u8; 8],
			"the monitor is back where the next start reads it"
		);
		assert!(!store.contains(&dead), "forgotten in memory");
		assert!(store.contains(&other), "the rest of the set is untouched");
		let reread = DeadFundingStore::read_or_empty(kv_store, logger);
		assert!(!reread.contains(&dead), "forgotten on disk");
		assert!(reread.contains(&other));
	}

	#[test]
	fn archiving_moves_the_monitor_and_only_the_dead_ones() {
		let (kv_store, logger) = store_and_logger();
		let dead = funding(7, 1);
		let live = funding(8, 0);
		for txo in [&dead, &live] {
			kv_store
				.write(
					CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
					CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
					&monitor_key(txo),
					&[txo.index as u8; 16],
				)
				.unwrap();
		}

		let archived = archive_dead_monitors(&*kv_store, &[dead, funding(9, 0)], &logger);
		assert_eq!(archived, [dead].into_iter().collect(), "an unknown outpoint is skipped");

		let live_keys = kv_store
			.list(
				CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			)
			.unwrap();
		assert_eq!(live_keys, vec![monitor_key(&live)]);
		let archived_bytes = kv_store
			.read(
				ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
				&monitor_key(&dead),
			)
			.unwrap();
		assert_eq!(archived_bytes, vec![1u8; 16], "the archived copy is the persisted monitor");

		restore_archived_monitors(&*kv_store, &archived, &logger);
		let mut live_keys = kv_store
			.list(
				CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
			)
			.unwrap();
		live_keys.sort();
		assert_eq!(live_keys, vec![monitor_key(&dead), monitor_key(&live)]);
		assert!(kv_store
			.list(
				ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
				ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE
			)
			.unwrap()
			.is_empty());
	}
}
