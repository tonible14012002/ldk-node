// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

pub(crate) mod adapters;
pub(crate) mod bitcoind;
pub(crate) mod electrum;
pub(crate) mod engine;
mod layer;
pub mod provider;
pub(crate) mod seam;
pub(crate) mod wire_convert;

pub(crate) use layer::ChainLayer;

use crate::chain::electrum::ElectrumRuntimeClient;
use crate::config::{Config, RESOLVED_CHANNEL_MONITOR_ARCHIVAL_INTERVAL};
use crate::io::utils::write_node_metrics;
use crate::logger::Logger;
use crate::types::{ChainMonitor, ChannelManager, DynStore};
use crate::{Error, NodeMetrics};

use lightning::chain::{Filter, WatchedOutput};

use bitcoin::{Script, ScriptBuf, Txid};

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

// The default Esplora server we're using.
pub(crate) const DEFAULT_ESPLORA_SERVER_URL: &str = "https://blockstream.info/api";

// The default Esplora client timeout we're using.
pub(crate) const DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS: u64 = 10;

pub(crate) const CHAIN_POLLING_INTERVAL_SECS: u64 = 2;

pub(crate) enum WalletSyncStatus {
	Completed,
	InProgress { subscribers: tokio::sync::broadcast::Sender<Result<(), Error>> },
}

impl WalletSyncStatus {
	fn register_or_subscribe_pending_sync(
		&mut self,
	) -> Option<tokio::sync::broadcast::Receiver<Result<(), Error>>> {
		match self {
			WalletSyncStatus::Completed => {
				// We're first to register for a sync.
				let (tx, _) = tokio::sync::broadcast::channel(1);
				*self = WalletSyncStatus::InProgress { subscribers: tx };
				None
			},
			WalletSyncStatus::InProgress { subscribers } => {
				// A sync is in-progress, we subscribe.
				let rx = subscribers.subscribe();
				Some(rx)
			},
		}
	}

	fn propagate_result_to_subscribers(&mut self, res: Result<(), Error>) {
		// Send the notification to any other tasks that might be waiting on it by now.
		{
			match self {
				WalletSyncStatus::Completed => {
					// No sync in-progress, do nothing.
					return;
				},
				WalletSyncStatus::InProgress { subscribers } => {
					// A sync is in-progress, we notify subscribers.
					if subscribers.receiver_count() > 0 {
						match subscribers.send(res) {
							Ok(_) => (),
							Err(e) => {
								debug_assert!(
									false,
									"Failed to send wallet sync result to subscribers: {:?}",
									e
								);
							},
						}
					}
					*self = WalletSyncStatus::Completed;
				},
			}
		}
	}
}

pub(crate) enum ElectrumRuntimeStatus {
	Started(Arc<ElectrumRuntimeClient>),
	Stopped {
		pending_registered_txs: Vec<(Txid, ScriptBuf)>,
		pending_registered_outputs: Vec<WatchedOutput>,
	},
}

impl ElectrumRuntimeStatus {
	pub(crate) fn new() -> Self {
		let pending_registered_txs = Vec::new();
		let pending_registered_outputs = Vec::new();
		Self::Stopped { pending_registered_txs, pending_registered_outputs }
	}

	pub(crate) fn start(
		&mut self, server_url: String, runtime: Arc<tokio::runtime::Runtime>, config: Arc<Config>,
		logger: Arc<Logger>,
	) -> Result<(), Error> {
		match self {
			Self::Stopped { pending_registered_txs, pending_registered_outputs } => {
				let client = Arc::new(ElectrumRuntimeClient::new(
					server_url.clone(),
					runtime,
					config,
					logger,
				)?);

				// Apply any pending `Filter` entries
				for (txid, script_pubkey) in pending_registered_txs.drain(..) {
					client.register_tx(&txid, &script_pubkey);
				}

				for output in pending_registered_outputs.drain(..) {
					client.register_output(output)
				}

				*self = Self::Started(client);
			},
			Self::Started(_) => {
				debug_assert!(false, "We shouldn't call start if we're already started")
			},
		}
		Ok(())
	}

	pub(crate) fn stop(&mut self) {
		*self = Self::new()
	}

	pub(crate) fn client(&self) -> Option<Arc<ElectrumRuntimeClient>> {
		match self {
			Self::Started(client) => Some(Arc::clone(&client)),
			Self::Stopped { .. } => None,
		}
	}

	fn register_tx(&mut self, txid: &Txid, script_pubkey: &Script) {
		match self {
			Self::Started(client) => client.register_tx(txid, script_pubkey),
			Self::Stopped { pending_registered_txs, .. } => {
				pending_registered_txs.push((*txid, script_pubkey.to_owned()))
			},
		}
	}

	fn register_output(&mut self, output: lightning::chain::WatchedOutput) {
		match self {
			Self::Started(client) => client.register_output(output),
			Self::Stopped { pending_registered_outputs, .. } => {
				pending_registered_outputs.push(output)
			},
		}
	}
}

pub(crate) fn periodically_archive_fully_resolved_monitors(
	channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
	kv_store: Arc<DynStore>, logger: Arc<Logger>, node_metrics: Arc<RwLock<NodeMetrics>>,
) -> Result<(), Error> {
	let mut locked_node_metrics = node_metrics.write().unwrap();
	let cur_height = channel_manager.current_best_block().height;
	let should_archive = locked_node_metrics
		.latest_channel_monitor_archival_height
		.as_ref()
		.map_or(true, |h| cur_height >= h + RESOLVED_CHANNEL_MONITOR_ARCHIVAL_INTERVAL);

	if should_archive {
		chain_monitor.archive_fully_resolved_channel_monitors();
		locked_node_metrics.latest_channel_monitor_archival_height = Some(cur_height);
		write_node_metrics(&*locked_node_metrics, kv_store, logger)?;
	}
	Ok(())
}

// ============================================================================
// Peerswap native primitive B5 — reorg-aware per-txid confirmation tracking.
//
// `register_tx`/`onchain_tx_confirmations` only cover wallet-owned txids; a
// swap taker must verify the *counterparty's* opening tx, which the wallet does
// not own. The types and helpers below add a brand-new, reorg-aware, per-txid
// chain query over whichever chain source the deployment configured
// (Esplora/Electrum/Bitcoind), and FAIL CLOSED (never a falsely-confirmed
// result) when that source cannot answer (E6). Everything here is gated behind
// the `swaps` cargo feature so the default build is byte-for-byte unaffected.
// ============================================================================

/// Reorg-aware chain status of a watched transaction (Peerswap native
/// primitive B5).
///
/// [`ChainStatus::NoChainSource`] is the fail-closed sentinel returned when the
/// configured chain source cannot answer — it is never conflated with a
/// confirmed result (E6). [`ChainStatus::Reorged`] is reported when a tx that
/// was previously observed confirmed is no longer in the best chain, so the
/// caller can re-anchor CSV/claim deadlines (F4).
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStatus {
	/// Included in a block on the current best chain.
	Confirmed,
	/// Known to the chain source but still unconfirmed (in the mempool).
	Mempool,
	/// Previously observed confirmed, but no longer in the best chain (re-orged
	/// back to the mempool or evicted). Deadlines must be re-anchored.
	Reorged,
	/// Unknown to the chain source and never observed confirmed (never broadcast
	/// or evicted from the mempool before confirming).
	Dropped,
	/// The chain source is unconfigured/unreachable and could not answer. The
	/// caller MUST treat this as "unverifiable", never as confirmed
	/// (fail-closed, E6).
	NoChainSource,
}

#[cfg(feature = "swaps")]
impl ChainStatus {
	/// Stable lowercase string form for capability payloads and logs.
	pub fn as_str(&self) -> &'static str {
		match self {
			ChainStatus::Confirmed => "confirmed",
			ChainStatus::Mempool => "mempool",
			ChainStatus::Reorged => "reorged",
			ChainStatus::Dropped => "dropped",
			ChainStatus::NoChainSource => "no_chain_source",
		}
	}
}

/// Reorg-aware confirmation/eviction status of a watched transaction
/// (Peerswap native primitive B5).
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxStatus {
	/// Confirmation depth on the current best chain (`0` when unconfirmed,
	/// reorged, dropped, or unverifiable).
	pub confirmations: u32,
	/// Height of the confirming block, re-derived from the current best chain
	/// (`None` when unconfirmed/reorged/dropped/unverifiable).
	pub height: Option<u32>,
	/// Reorg-aware chain status.
	pub status: ChainStatus,
}

/// Backend-agnostic raw observation of a `txid` against a chain source, before
/// the previously-observed confirmation anchor is folded in (Peerswap B5).
#[cfg(feature = "swaps")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawTxObservation {
	/// Included in a best-chain block at the given height/depth.
	Confirmed { height: Option<u32>, confirmations: u32 },
	/// Known to the chain source but unconfirmed.
	InMempool,
	/// Unknown to the chain source.
	NotFound,
	/// The chain source could not answer (fail-closed sentinel, E6).
	Unreachable,
}

/// Fold a raw observation together with whether the tx was previously observed
/// confirmed into the reorg-aware [`TxStatus`] (Peerswap B5).
///
/// Pure function — unit-tested independently of any live chain source. The
/// load-bearing invariant: a [`RawTxObservation::Unreachable`] can never become
/// [`ChainStatus::Confirmed`], regardless of prior confirmation history.
#[cfg(feature = "swaps")]
pub(crate) fn derive_tx_status(
	observation: RawTxObservation, previously_confirmed: bool,
) -> TxStatus {
	match observation {
		RawTxObservation::Confirmed { height, confirmations } => TxStatus {
			// A tx in the tip block is 1 confirmation deep, never 0.
			confirmations: confirmations.max(1),
			height,
			status: ChainStatus::Confirmed,
		},
		RawTxObservation::InMempool => TxStatus {
			confirmations: 0,
			height: None,
			status: if previously_confirmed { ChainStatus::Reorged } else { ChainStatus::Mempool },
		},
		RawTxObservation::NotFound => TxStatus {
			confirmations: 0,
			height: None,
			status: if previously_confirmed { ChainStatus::Reorged } else { ChainStatus::Dropped },
		},
		RawTxObservation::Unreachable => {
			TxStatus { confirmations: 0, height: None, status: ChainStatus::NoChainSource }
		},
	}
}

/// In-memory registry of swap txids being watched (Peerswap B5).
///
/// Stores the scriptPubKey (required by the Electrum scriptHash lookup) and the
/// last observed confirmation height, which lets
/// [`crate::Node::get_tx_confirmations`] distinguish a first unconfirmed
/// sighting from a reorg-induced un-confirmation. Durable reorg state
/// additionally lives in the native `swap.db` on the consumer side; this cache
/// is best-effort and is rebuilt by re-registering after a restart.
#[cfg(feature = "swaps")]
pub(crate) struct SwapTxWatch {
	entries: Mutex<HashMap<Txid, SwapWatchEntry>>,
}

#[cfg(feature = "swaps")]
#[derive(Clone)]
struct SwapWatchEntry {
	script_pubkey: ScriptBuf,
	last_confirmed_height: Option<u32>,
}

#[cfg(feature = "swaps")]
impl SwapTxWatch {
	pub(crate) fn new() -> Self {
		Self { entries: Mutex::new(HashMap::new()) }
	}

	/// Register (idempotently) a txid + its scriptPubKey for watching. A repeat
	/// registration refreshes the scriptPubKey but preserves the prior
	/// confirmation anchor, so reorg detection survives a re-arm.
	pub(crate) fn register(&self, txid: Txid, script_pubkey: ScriptBuf) {
		let mut entries = self.entries.lock().unwrap();
		entries
			.entry(txid)
			.and_modify(|entry| entry.script_pubkey = script_pubkey.clone())
			.or_insert(SwapWatchEntry { script_pubkey, last_confirmed_height: None });
	}

	/// Drop the watch entry for `txid` (B5 LOW-1). Without this the map grows
	/// unbounded for the process lifetime — every distinct watched txid (each
	/// swap's opening + spend txs) accumulates forever. The consumer calls this
	/// once a swap reaches a terminal, settled state and no longer needs reorg
	/// tracking. A no-op if `txid` was never registered.
	pub(crate) fn unregister(&self, txid: &Txid) {
		self.entries.lock().unwrap().remove(txid);
	}

	/// Number of currently-watched txids (test/observability only).
	#[cfg(test)]
	pub(crate) fn len(&self) -> usize {
		self.entries.lock().unwrap().len()
	}

	/// The watched scriptPubKey for `txid`, if registered.
	pub(crate) fn script_pubkey(&self, txid: &Txid) -> Option<ScriptBuf> {
		self.entries.lock().unwrap().get(txid).map(|entry| entry.script_pubkey.clone())
	}

	/// Whether `txid` was ever observed confirmed (arms reorg detection).
	pub(crate) fn previously_confirmed(&self, txid: &Txid) -> bool {
		self.entries
			.lock()
			.unwrap()
			.get(txid)
			.map_or(false, |entry| entry.last_confirmed_height.is_some())
	}

	/// Persist the latest confirmation anchor after a query so subsequent
	/// queries can detect a reorg/un-confirmation. Only a fresh confirmation
	/// advances the anchor; a non-confirmed status never disarms it.
	pub(crate) fn record(&self, txid: &Txid, status: &TxStatus) {
		if status.status == ChainStatus::Confirmed {
			if let Some(entry) = self.entries.lock().unwrap().get_mut(txid) {
				entry.last_confirmed_height = status.height;
			}
		}
	}
}

#[cfg(all(test, feature = "swaps"))]
mod swap_b5_tests {
	use super::{derive_tx_status, ChainStatus, RawTxObservation, SwapTxWatch};
	use bitcoin::hashes::Hash;
	use bitcoin::{ScriptBuf, Txid};

	fn dummy_txid(byte: u8) -> Txid {
		Txid::from_byte_array([byte; 32])
	}

	#[test]
	fn confirmed_reports_depth_and_height() {
		let status = derive_tx_status(
			RawTxObservation::Confirmed { height: Some(100), confirmations: 6 },
			false,
		);
		assert_eq!(status.status, ChainStatus::Confirmed);
		assert_eq!(status.confirmations, 6);
		assert_eq!(status.height, Some(100));
	}

	#[test]
	fn confirmed_depth_is_floored_to_one() {
		// A tx in the tip block is 1 confirmation deep, never 0.
		let status = derive_tx_status(
			RawTxObservation::Confirmed { height: Some(100), confirmations: 0 },
			false,
		);
		assert_eq!(status.status, ChainStatus::Confirmed);
		assert_eq!(status.confirmations, 1);
	}

	#[test]
	fn first_sighting_distinguishes_mempool_from_dropped() {
		let mempool = derive_tx_status(RawTxObservation::InMempool, false);
		assert_eq!(mempool.status, ChainStatus::Mempool);
		assert_eq!(mempool.confirmations, 0);
		assert_eq!(mempool.height, None);

		let dropped = derive_tx_status(RawTxObservation::NotFound, false);
		assert_eq!(dropped.status, ChainStatus::Dropped);
		assert_eq!(dropped.confirmations, 0);
		assert_eq!(dropped.height, None);
	}

	#[test]
	fn unconfirmation_after_confirm_is_reorg() {
		// Previously confirmed, now back to the mempool or gone => Reorged,
		// not Mempool/Dropped, so the caller re-anchors deadlines (F4).
		let back_to_mempool = derive_tx_status(RawTxObservation::InMempool, true);
		assert_eq!(back_to_mempool.status, ChainStatus::Reorged);
		assert_eq!(back_to_mempool.confirmations, 0);

		let evicted = derive_tx_status(RawTxObservation::NotFound, true);
		assert_eq!(evicted.status, ChainStatus::Reorged);
		assert_eq!(evicted.confirmations, 0);
	}

	#[test]
	fn unreachable_fails_closed_and_is_never_confirmed() {
		// The load-bearing E6 invariant: an unanswerable chain source is never
		// reported as confirmed, regardless of prior confirmation history.
		for previously_confirmed in [false, true] {
			let status = derive_tx_status(RawTxObservation::Unreachable, previously_confirmed);
			assert_eq!(status.status, ChainStatus::NoChainSource);
			assert_ne!(status.status, ChainStatus::Confirmed);
			assert_eq!(status.confirmations, 0);
			assert_eq!(status.height, None);
		}
	}

	#[test]
	fn unreachable_status_string_is_stable() {
		assert_eq!(ChainStatus::NoChainSource.as_str(), "no_chain_source");
		assert_eq!(ChainStatus::Confirmed.as_str(), "confirmed");
		assert_eq!(ChainStatus::Reorged.as_str(), "reorged");
		assert_eq!(ChainStatus::Dropped.as_str(), "dropped");
		assert_eq!(ChainStatus::Mempool.as_str(), "mempool");
	}

	#[test]
	fn watch_registry_tracks_spk_and_reorg_anchor() {
		let watch = SwapTxWatch::new();
		let txid = dummy_txid(7);
		let spk = ScriptBuf::from_bytes(vec![0x00, 0x14, 0x11, 0x22, 0x33]);

		// Unregistered: no scriptPubKey, not previously confirmed.
		assert!(watch.script_pubkey(&txid).is_none());
		assert!(!watch.previously_confirmed(&txid));

		watch.register(txid, spk.clone());
		assert_eq!(watch.script_pubkey(&txid), Some(spk));
		assert!(!watch.previously_confirmed(&txid));

		// Recording a confirmation arms the reorg anchor.
		let confirmed = derive_tx_status(
			RawTxObservation::Confirmed { height: Some(200), confirmations: 3 },
			false,
		);
		watch.record(&txid, &confirmed);
		assert!(watch.previously_confirmed(&txid));

		// A later mempool sighting for the now-armed txid derives Reorged.
		let reorged =
			derive_tx_status(RawTxObservation::InMempool, watch.previously_confirmed(&txid));
		assert_eq!(reorged.status, ChainStatus::Reorged);

		// Recording a non-confirmed status does not disarm the anchor.
		watch.record(&txid, &reorged);
		assert!(watch.previously_confirmed(&txid));
	}

	#[test]
	fn unregister_drops_the_watch_entry_and_is_idempotent() {
		// B5 LOW-1: the watch map must not grow unbounded — a terminalized swap's
		// entry is dropped, and unregistering an unknown txid is a harmless no-op.
		let watch = SwapTxWatch::new();
		let a = dummy_txid(1);
		let b = dummy_txid(2);
		let spk = ScriptBuf::from_bytes(vec![0x00, 0x14, 0xaa, 0xbb]);

		watch.register(a, spk.clone());
		watch.register(b, spk.clone());
		assert_eq!(watch.len(), 2);

		watch.unregister(&a);
		assert_eq!(watch.len(), 1, "the terminalized txid's entry is dropped");
		assert!(watch.script_pubkey(&a).is_none());
		assert!(watch.script_pubkey(&b).is_some(), "unrelated entry untouched");

		// Idempotent: dropping the same (or an unknown) txid again is a no-op.
		watch.unregister(&a);
		watch.unregister(&dummy_txid(99));
		assert_eq!(watch.len(), 1);

		watch.unregister(&b);
		assert_eq!(watch.len(), 0);
	}
}
