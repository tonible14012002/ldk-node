// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The pieces of a BIP157/158 compact-block-filter chain source that are not the engine.
//!
//! Ported from the upstream CBF chain source (DatPham, `cycles-cbf-828`) onto LDK 0.1 and
//! bdk_wallet 2.x, and split along the seam: the sync engine lives in
//! [`crate::chain::engine::cbf`], the block applicator that fans kyoto's output out to the
//! listeners in [`applicator`], the coinbase fee maths in [`fee`], the wallet birthday in
//! [`birthday`]. What is here is shared by more than one of them: the sync state the engine
//! publishes and the applicator advances, the trusted-peer parser, the resume checkpoint
//! derivation, and the [`WatchLedger`] the applicator feeds for the T8 TX_STATUS adapter.

pub(crate) mod applicator;
pub(crate) mod birthday;
pub(crate) mod fee;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Mutex;

use bip157::{HashCheckpoint, TrustedPeer};

use bdk_chain::local_chain::CheckPoint;
use bdk_chain::BlockId;

use bitcoin::block::Header;
use bitcoin::Txid;

use lightning::chain::BestBlock;

use tokio::sync::watch;

use crate::chain::bitcoind::ChainListener;
use crate::chain::CbfSyncStatus;
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::Error;

/// Walk back this many blocks from the wallet's persisted tip when deriving the kyoto resume
/// checkpoint, so a recent reorg cannot strand the node above the new best chain.
pub(crate) const REORG_SAFETY_BLOCKS: u32 = 7;

/// Where the engine is between "started" and "caught up", as the applicator advances it.
///
/// Published through a `watch` channel: `wait_until_synced` blocks on it, and
/// [`simplify_sync_state`] projects it onto the public [`CbfSyncStatus`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum CbfSyncState {
	Active {
		/// Highest tip whose preceding chain updates have been applied to all listeners.
		applied_tip: Option<u32>,
		/// Whether kyoto has reported catching up to the network tip (via `FiltersSynced`) and
		/// the resulting blocks have been applied. `wait_until_synced` blocks until this is set.
		///
		/// This must not be derived from a locally-sampled chain tip: kyoto does not persist, so a
		/// freshly (re)started node's local header chain sits at genesis until it syncs from peers.
		/// Comparing against that would make `wait_until_synced` return before any sync happens.
		synced_to_tip: bool,
	},
	Failed(Error),
}

/// Pure mapping from the internal, error-carrying [`CbfSyncState`] to the
/// externally-consumable [`CbfSyncStatus`] — extracted so the mapping is
/// unit-testable without a live kyoto node or `watch` channel.
pub(crate) fn simplify_sync_state(state: CbfSyncState) -> CbfSyncStatus {
	match state {
		CbfSyncState::Active { synced_to_tip: true, .. } => CbfSyncStatus::Synced,
		CbfSyncState::Active { synced_to_tip: false, .. } => CbfSyncStatus::Syncing,
		CbfSyncState::Failed(_) => CbfSyncStatus::Failed,
	}
}

/// Marks that we are applying a block past the last `FiltersSynced` tip, so a `sync_wallets` call
/// issued after new blocks are mined waits for the next `FiltersSynced` rather than returning on a
/// stale `synced_to_tip`. Only flips (and notifies waiters) when currently set.
///
/// Called both when a new block's filter is received (before it is fetched and applied) and after
/// it is applied, so `synced_to_tip` reflects "behind by an unapplied block" as soon as we learn
/// that block exists, not only once we've finished catching up to it.
pub(crate) fn mark_syncing(sync_state_tx: &watch::Sender<CbfSyncState>) {
	// Copy the current state out and drop the `watch` read guard before calling `send_replace`:
	// `borrow()` holds a read lock for the lifetime of its temporary, and `send_replace` takes
	// the write lock, so holding the borrow across it deadlocks. `CbfSyncState` is `Copy`, so the
	// deref copies and the guard is released at the end of this statement.
	let current = *sync_state_tx.borrow();
	if let CbfSyncState::Active { applied_tip, synced_to_tip: true } = current {
		sync_state_tx.send_replace(CbfSyncState::Active { applied_tip, synced_to_tip: false });
	}
}

/// Result of parsing a single configured trusted-peer entry (`ip:port` or `host:port`).
///
/// Kept distinct from [`TrustedPeer`] so the parse step is unit-testable without depending on
/// kyoto's internal representation; [`ParsedPeer::into_trusted_peer`] converts to the real type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedPeer {
	/// A literal IPv4/IPv6 socket address.
	Addr(SocketAddr),
	/// A hostname/port pair. Resolution happens at kyoto connect time, not here.
	Hostname { host: String, port: u16 },
}

impl ParsedPeer {
	pub(crate) fn into_trusted_peer(self) -> TrustedPeer {
		match self {
			ParsedPeer::Addr(addr) => TrustedPeer::from_socket_addr(addr),
			ParsedPeer::Hostname { host, port } => TrustedPeer::from_hostname(host, port),
		}
	}
}

/// Parses a single configured CBF trusted-peer entry.
///
/// Tries a literal `SocketAddr` first (covers IPv4/IPv6). On failure, splits on the last `:`
/// and treats the left side as a hostname to be resolved at kyoto connect time via
/// [`TrustedPeer::from_hostname`] (backed by [`tokio::net::lookup_host`]). Returns `Err` for
/// entries with no parseable port, rather than silently dropping them — a mistyped peer should
/// surface as a startup error, not vanish from the trusted-peer list.
pub(crate) fn parse_trusted_peer(peer_str: &str) -> Result<ParsedPeer, Error> {
	if let Ok(addr) = peer_str.parse::<SocketAddr>() {
		return Ok(ParsedPeer::Addr(addr));
	}

	let (host, port_str) = peer_str.rsplit_once(':').ok_or(Error::InvalidSocketAddress)?;
	if host.is_empty() {
		return Err(Error::InvalidSocketAddress);
	}
	let port: u16 = port_str.parse().map_err(|_| Error::InvalidSocketAddress)?;

	Ok(ParsedPeer::Hostname { host: host.to_string(), port })
}

/// Why kyoto cannot be given a checkpoint to resume from.
///
/// A filter scan from genesis is never the fallback: on a small device it takes days, and
/// the wallets this engine takes over — synced until now by a transaction-based engine, whose
/// BDK checkpoint chain holds only the tip and the anchors of its own transactions — would hit
/// it on their very first CBF start. The engine fails closed on either variant instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeRefusal {
	/// The wallet's checkpoint chain offers no anchor at or below the furthest-behind listener,
	/// and no wallet birthday is configured to stand in.
	NoAnchor { listener_height: u32 },
	/// The configured birthday sits above the furthest-behind listener — kyoto would start
	/// strictly after it and the listener would never see the blocks it is waiting for — and the
	/// wallet's checkpoint chain offers nothing usable either.
	BirthdayAboveListener { birthday_height: u32, listener_height: u32 },
}

impl std::fmt::Display for ResumeRefusal {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::NoAnchor { listener_height } => write!(
				f,
				"the wallet's checkpoint chain has no usable anchor at or below the \
				 furthest-behind listener (height {}) and no wallet birthday is configured; \
				 refusing to scan from genesis — configure `wallet_birthday_height`",
				listener_height
			),
			Self::BirthdayAboveListener { birthday_height, listener_height } => write!(
				f,
				"the configured wallet birthday resolves to height {}, above the \
				 furthest-behind listener (height {}), and the wallet's checkpoint chain has no \
				 usable anchor either; refusing to scan from genesis — lower \
				 `wallet_birthday_height` to at most the listener height",
				birthday_height, listener_height
			),
		}
	}
}

/// The anchor the wallet's own checkpoint chain offers, walked back [`REORG_SAFETY_BLOCKS`]
/// from the furthest-behind listener, or `None` when the chain offers nothing usable.
///
/// Nothing usable means genesis (a fresh, unscanned wallet) or a checkpoint *above* the
/// listener: a wallet anchored at its birthday next to Lightning state persisted below it, or
/// a transaction-less wallet whose only checkpoint is its own tip while the `ChannelManager`
/// sits a few blocks behind. Anchoring kyoto above a listener would make it emit only blocks
/// the applicator refuses — `next_height` derives from the *minimum* listener — stalling sync
/// forever without ever tripping the divergence gate.
pub(crate) fn derived_resume_anchor(
	logger: &Logger, bdk_cp: CheckPoint, min_best_block: &BestBlock,
) -> Option<HashCheckpoint> {
	if let Some(bdk_at_height) = bdk_cp.get(min_best_block.height) {
		if bdk_at_height.hash() != min_best_block.block_hash {
			log_error!(
				logger,
				"CBF resume: listener best block at height {} has hash {} but BDK has {}; \
				 a component may be on a stale fork. Anchoring on BDK's chain.",
				min_best_block.height,
				min_best_block.block_hash,
				bdk_at_height.hash(),
			);
		}
	}

	// Walk BDK's checkpoint chain back to the reorg-safe anchor height.
	let target_height = min_best_block.height.saturating_sub(REORG_SAFETY_BLOCKS);
	let cursor = resume_anchor(bdk_cp, target_height);

	if cursor.height() > min_best_block.height {
		log_error!(
			logger,
			"CBF resume: the wallet's lowest usable checkpoint (height {}) is above the \
			 furthest-behind listener (height {}); it cannot anchor the resume.",
			cursor.height(),
			min_best_block.height,
		);
		return None;
	}

	(cursor.height() > 0).then(|| HashCheckpoint::new(cursor.height(), cursor.hash()))
}

/// Picks the checkpoint kyoto resumes from, given what the wallet's chain offers and the
/// configured birthday, for listeners whose furthest-behind tip is `listener_height`.
///
/// The birthday wins over a derived anchor below it: everything before the birthday is by
/// definition not the wallet's, and the derived anchor of a sparse checkpoint chain can sit
/// hundreds of thousands of blocks back. Either anchor is usable only at or below the
/// furthest-behind listener, for the reason [`derived_resume_anchor`] gives. Nothing usable
/// is a refusal, never genesis.
pub(crate) fn choose_resume_anchor(
	derived: Option<HashCheckpoint>, birthday: Option<HashCheckpoint>, listener_height: u32,
) -> Result<HashCheckpoint, ResumeRefusal> {
	let usable_derived = derived.filter(|cp| cp.height <= listener_height);
	let usable_birthday = birthday.filter(|cp| cp.height <= listener_height);
	match (usable_derived, usable_birthday) {
		(Some(anchor), Some(birthday)) if anchor.height < birthday.height => Ok(birthday),
		(Some(anchor), _) => Ok(anchor),
		(None, Some(birthday)) => Ok(birthday),
		(None, None) => Err(match birthday {
			Some(birthday) => ResumeRefusal::BirthdayAboveListener {
				birthday_height: birthday.height,
				listener_height,
			},
			None => ResumeRefusal::NoAnchor { listener_height },
		}),
	}
}

/// The checkpoint kyoto resumes from: the wallet's own anchor, lifted to the birthday when
/// that is higher, and never genesis — see [`choose_resume_anchor`].
pub(crate) fn resume_checkpoint(
	logger: &Logger, chain_listener: &ChainListener, birthday: Option<HashCheckpoint>,
) -> Result<HashCheckpoint, ResumeRefusal> {
	let min_best_block = chain_listener.get_best_block();
	let bdk_cp = chain_listener.onchain_wallet.latest_checkpoint();
	let derived = derived_resume_anchor(logger, bdk_cp, &min_best_block);
	let chosen = choose_resume_anchor(derived, birthday, min_best_block.height)?;
	if derived != Some(chosen) {
		log_info!(
			logger,
			"CBF resume: anchoring on the wallet birthday at height {} (the wallet's own chain \
			 offered {}).",
			chosen.height,
			derived.map_or("no usable anchor".to_string(), |d| format!("height {}", d.height)),
		);
	}
	Ok(chosen)
}

/// Walks `bdk_cp` back toward `target_height` without ever stepping onto genesis.
///
/// On a dense chain this lands on the checkpoint at `target_height`, exactly like a plain
/// walk. The genesis guard matters for sparse chains — most importantly a fresh wallet whose
/// only real anchor is its birthday checkpoint (`[genesis, birthday]`): stepping onto genesis
/// there would make [`resume_checkpoint`] return `None` and silently demote the node to a full
/// filter scan from block 1, with every block below the birthday discarded on arrival.
pub(crate) fn resume_anchor(bdk_cp: CheckPoint, target_height: u32) -> CheckPoint {
	let mut cursor = bdk_cp;
	while cursor.height() > target_height {
		match cursor.prev() {
			Some(prev) if prev.height() > 0 => cursor = prev,
			_ => break,
		}
	}
	cursor
}

/// Where the transactions this node was asked to watch were seen confirmed, as the applicator
/// saw the blocks go by, together with the block it most recently applied.
///
/// Forward-only by construction: a watch registered after its transaction confirmed is never
/// matched, because the applicator only checks the blocks it applies from then on. That is what
/// lets the CBF TX_STATUS adapter (T8) answer "not seen" honestly rather than claim a
/// confirmation it never observed — a filter-driven node has no history to look back into.
/// Disconnects drop every confirmation at or above the rewound height, so an answer never
/// outlives the branch it was seen on.
pub(crate) struct WatchLedger {
	inner: Mutex<WatchLedgerInner>,
}

#[derive(Default)]
struct WatchLedgerInner {
	watched: HashSet<Txid>,
	confirmed: HashMap<Txid, BlockId>,
	/// The block the applicator most recently connected, rewound to the parent on disconnect.
	tip: Option<BlockId>,
}

impl WatchLedger {
	pub(crate) fn new() -> Self {
		Self { inner: Mutex::new(WatchLedgerInner::default()) }
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, WatchLedgerInner> {
		self.inner.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// Start watching `txid` in every block applied from now on.
	pub(crate) fn watch(&self, txid: Txid) {
		self.lock().watched.insert(txid);
	}

	/// The block most recently applied by the applicator, if any block has been.
	pub(crate) fn tip(&self) -> Option<BlockId> {
		self.lock().tip
	}

	/// The applicator connected `block`: it is the tip now, and any watched transaction among
	/// `txids` confirmed in it.
	pub(crate) fn note_connected(&self, block: BlockId, txids: impl IntoIterator<Item = Txid>) {
		let mut inner = self.lock();
		inner.tip = Some(block);
		if inner.watched.is_empty() {
			return;
		}
		for txid in txids {
			if inner.watched.contains(&txid) {
				inner.confirmed.insert(txid, block);
			}
		}
	}

	/// The applicator disconnected the block `header` at `height`: nothing seen at or above
	/// `height` is confirmed any more, and if the applied tip had reached `height` it is the
	/// header's parent now.
	///
	/// A tip below `height` is left where it is. During a catch-up kyoto header-syncs to the
	/// network tip before it streams filters, so a reorg it reports can sit above every block the
	/// applicator has applied; moving the tip *forward* to the fork point would claim blocks that
	/// were never applied.
	pub(crate) fn note_disconnected(&self, header: &Header, height: u32) {
		let mut inner = self.lock();
		if inner.tip.is_some_and(|tip| tip.height >= height) {
			inner.tip =
				Some(BlockId { height: height.saturating_sub(1), hash: header.prev_blockhash });
		}
		inner.confirmed.retain(|_, block| block.height < height);
	}
}

// Wired by T8: the forward-only TX_STATUS adapter reads answers out of the ledger and lets a
// settled watch go.
#[allow(dead_code)]
impl WatchLedger {
	/// Stop watching `txid` and forget where it was seen.
	pub(crate) fn unwatch(&self, txid: &Txid) {
		let mut inner = self.lock();
		inner.watched.remove(txid);
		inner.confirmed.remove(txid);
	}

	/// Whether `txid` is watched at all — the difference between "not seen yet" and "never
	/// asked", which the adapter must not conflate.
	pub(crate) fn is_watched(&self, txid: &Txid) -> bool {
		self.lock().watched.contains(txid)
	}

	/// The block `txid` was seen confirmed in, if the applicator saw it since the watch began.
	pub(crate) fn confirmation(&self, txid: &Txid) -> Option<BlockId> {
		self.lock().confirmed.get(txid).copied()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::hashes::Hash;

	#[test]
	fn simplify_sync_state_active_not_synced_is_syncing() {
		let state = CbfSyncState::Active { applied_tip: Some(100), synced_to_tip: false };
		assert_eq!(simplify_sync_state(state), CbfSyncStatus::Syncing);
	}

	#[test]
	fn simplify_sync_state_active_no_applied_tip_is_syncing() {
		// Freshly constructed state before the engine ever launched kyoto.
		let state = CbfSyncState::Active { applied_tip: None, synced_to_tip: false };
		assert_eq!(simplify_sync_state(state), CbfSyncStatus::Syncing);
	}

	#[test]
	fn simplify_sync_state_active_synced_to_tip_is_synced() {
		let state = CbfSyncState::Active { applied_tip: Some(900_000), synced_to_tip: true };
		assert_eq!(simplify_sync_state(state), CbfSyncStatus::Synced);
	}

	#[test]
	fn simplify_sync_state_failed_is_failed_regardless_of_error_variant() {
		assert_eq!(
			simplify_sync_state(CbfSyncState::Failed(Error::NotRunning)),
			CbfSyncStatus::Failed
		);
		assert_eq!(
			simplify_sync_state(CbfSyncState::Failed(Error::TxSyncFailed)),
			CbfSyncStatus::Failed
		);
	}

	#[test]
	fn parse_peer_accepts_hostname() {
		let p = parse_trusted_peer("bitcoind.local:18444").expect("hostname peer");
		// shape assertion only — resolution happens at connect time
		assert!(
			matches!(p, ParsedPeer::Hostname { ref host, port } if host == "bitcoind.local" && port == 18444)
		);
		let p2 = parse_trusted_peer("127.0.0.1:18444").expect("socketaddr peer");
		assert!(matches!(p2, ParsedPeer::Addr(_)));
		assert!(parse_trusted_peer("no-port-here").is_err());
		assert!(parse_trusted_peer(":18444").is_err(), "an empty host is not a peer");
		assert!(parse_trusted_peer("host:notaport").is_err());
	}

	fn chain_of(heights: &[u32]) -> CheckPoint {
		CheckPoint::from_block_ids(
			heights.iter().map(|h| BlockId { height: *h, hash: bitcoin::BlockHash::all_zeros() }),
		)
		.expect("strictly increasing heights")
	}

	#[test]
	fn resume_anchor_walks_dense_chains_to_the_target() {
		let heights: Vec<u32> = (0..=10).collect();
		let cp = chain_of(&heights);
		assert_eq!(resume_anchor(cp.clone(), 3).height(), 3);
		assert_eq!(resume_anchor(cp.clone(), 10).height(), 10);
		// Target 0 stops at height 1: the anchor never falls onto genesis.
		assert_eq!(resume_anchor(cp, 0).height(), 1);
	}

	fn cp(height: u32) -> HashCheckpoint {
		HashCheckpoint::new(height, bitcoin::BlockHash::from_byte_array([height as u8; 32]))
	}

	#[test]
	fn resume_falls_back_to_the_birthday_instead_of_genesis() {
		// Dat's `None` — a fresh wallet, or one whose only checkpoint sits above a listener —
		// used to mean a full scan from genesis. It now means the birthday.
		let birthday = HashCheckpoint::taproot_activation();
		assert_eq!(choose_resume_anchor(None, Some(birthday), 900_000), Ok(birthday));
	}

	#[test]
	fn resume_refuses_without_an_anchor_or_a_birthday() {
		assert_eq!(
			choose_resume_anchor(None, None, 900_000),
			Err(ResumeRefusal::NoAnchor { listener_height: 900_000 })
		);
	}

	#[test]
	fn resume_lifts_an_anchor_below_the_birthday_up_to_it() {
		// A sparse checkpoint chain (tip + the anchors of the wallet's own transactions) walks
		// back onto an anchor far below the birthday; nothing before the birthday is the
		// wallet's, so the birthday is where the scan starts.
		let birthday = HashCheckpoint::taproot_activation();
		assert_eq!(choose_resume_anchor(Some(cp(500_000)), Some(birthday), 900_000), Ok(birthday));
		// An anchor above the birthday is the wallet's own progress and is kept.
		assert_eq!(
			choose_resume_anchor(Some(cp(800_000)), Some(birthday), 900_000),
			Ok(cp(800_000))
		);
		// No birthday: the derived anchor stands, however far back it is.
		assert_eq!(choose_resume_anchor(Some(cp(500_000)), None, 900_000), Ok(cp(500_000)));
	}

	#[test]
	fn resume_never_anchors_above_the_furthest_behind_listener() {
		// Either anchor above the listener would make kyoto start where the applicator never
		// catches up. The derived one is dropped in favour of the birthday...
		let birthday = HashCheckpoint::taproot_activation();
		assert_eq!(choose_resume_anchor(Some(cp(950_000)), Some(birthday), 940_000), Ok(birthday));
		// ...and a birthday above the listener is refused outright, with the derived anchor
		// standing in when there is one.
		assert_eq!(
			choose_resume_anchor(None, Some(cp(950_000)), 940_000),
			Err(ResumeRefusal::BirthdayAboveListener {
				birthday_height: 950_000,
				listener_height: 940_000
			})
		);
		assert_eq!(
			choose_resume_anchor(Some(cp(930_000)), Some(cp(950_000)), 940_000),
			Ok(cp(930_000))
		);
	}

	#[test]
	fn a_sparse_wallet_chain_derives_no_anchor_above_a_lagging_listener() {
		// The transaction-less wallet handed over from a transaction-based engine: its chain is
		// [genesis, tip] and the ChannelManager is a few blocks behind the tip. The tip is
		// above the listener, so the wallet offers nothing and the birthday must carry it.
		let logger = Logger::new_log_facade();
		let listener = BestBlock::new(bitcoin::BlockHash::all_zeros(), 949_990);
		assert_eq!(derived_resume_anchor(&logger, chain_of(&[0, 950_000]), &listener), None);
		// A wallet with one old transaction anchor walks back onto it.
		let derived = derived_resume_anchor(&logger, chain_of(&[0, 700_000, 950_000]), &listener);
		assert_eq!(derived.map(|cp| cp.height), Some(700_000));
		// Dense chains land on the reorg-safe height as before.
		let heights: Vec<u32> = (949_980..=950_000).collect();
		let listener = BestBlock::new(bitcoin::BlockHash::all_zeros(), 950_000);
		let derived = derived_resume_anchor(&logger, chain_of(&heights), &listener);
		assert_eq!(derived.map(|cp| cp.height), Some(950_000 - REORG_SAFETY_BLOCKS));
	}

	#[test]
	fn resume_anchor_never_falls_onto_genesis_on_sparse_chains() {
		// A fresh wallet with a birthday checkpoint: [genesis, birthday]. The reorg-safety
		// walk-back must anchor on the birthday, not slide onto genesis and force a full
		// scan from block 1.
		let cp = chain_of(&[0, 709_631]);
		assert_eq!(resume_anchor(cp, 709_624).height(), 709_631);

		let genesis_only = chain_of(&[0]);
		assert_eq!(resume_anchor(genesis_only, 0).height(), 0);
	}

	fn txid(seed: u8) -> Txid {
		Txid::from_byte_array([seed; 32])
	}

	fn block(height: u32, seed: u8) -> BlockId {
		BlockId { height, hash: bitcoin::BlockHash::from_byte_array([seed; 32]) }
	}

	#[test]
	fn watch_ledger_is_forward_only_and_rewinds_on_disconnect() {
		let ledger = WatchLedger::new();
		let (early, late, never) = (txid(1), txid(2), txid(3));

		// Seen before the watch began: never matched, even though it was in an applied block.
		ledger.note_connected(block(100, 0xa0), [early]);
		ledger.watch(early);
		ledger.watch(late);
		assert_eq!(ledger.confirmation(&early), None, "a confirmation before the watch is unseen");
		assert_eq!(ledger.tip(), Some(block(100, 0xa0)));

		ledger.note_connected(block(101, 0xa1), [late, never]);
		assert_eq!(ledger.confirmation(&late), Some(block(101, 0xa1)));
		assert_eq!(ledger.confirmation(&never), None, "an unwatched txid is not recorded");
		assert!(!ledger.is_watched(&never));

		// A disconnect of 101 drops what was seen there and rewinds the tip to the parent.
		let header = Header {
			version: bitcoin::block::Version::TWO,
			prev_blockhash: block(100, 0xa0).hash,
			merkle_root: bitcoin::TxMerkleNode::all_zeros(),
			time: 0,
			bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
			nonce: 0,
		};
		ledger.note_disconnected(&header, 101);
		assert_eq!(ledger.confirmation(&late), None);
		assert_eq!(ledger.tip(), Some(block(100, 0xa0)));
		assert!(ledger.is_watched(&late), "the watch survives the reorg; only the sighting goes");

		ledger.unwatch(&late);
		assert!(!ledger.is_watched(&late));
	}

	#[test]
	fn watch_ledger_never_moves_the_applied_tip_forward_on_disconnect() {
		let ledger = WatchLedger::new();
		let seen = txid(1);
		ledger.watch(seen);
		let above = Header {
			version: bitcoin::block::Version::TWO,
			prev_blockhash: block(104, 0xa4).hash,
			merkle_root: bitcoin::TxMerkleNode::all_zeros(),
			time: 0,
			bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
			nonce: 0,
		};

		// Nothing applied yet: a reorg kyoto reports during the header sync leaves it that way.
		ledger.note_disconnected(&above, 105);
		assert_eq!(ledger.tip(), None, "no block was applied, so none is the tip");

		// Applied through 100, then 105 is reorganised out before the replay reaches it: the tip
		// stays at 100 rather than jumping to the fork point 104, and the sighting at 100 stands.
		ledger.note_connected(block(100, 0xa0), [seen]);
		ledger.note_disconnected(&above, 105);
		assert_eq!(ledger.tip(), Some(block(100, 0xa0)));
		assert_eq!(ledger.confirmation(&seen), Some(block(100, 0xa0)));

		// A disconnect the tip has reached still rewinds it.
		let at_tip = Header { prev_blockhash: block(99, 0x99).hash, ..above };
		ledger.note_disconnected(&at_tip, 100);
		assert_eq!(ledger.tip(), Some(block(99, 0x99)));
		assert_eq!(ledger.confirmation(&seen), None);
	}
}
