// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The block applicator: the single task that hands kyoto's chain to the listeners.
//!
//! Kyoto's event loop decides *what* happened — a filter matched and the block was fetched, a
//! filter did not match, headers were reorganised out, the filters caught up to the tip — and
//! queues it as a [`ChainOp`]. The applicator decides, in order and one at a time, what each
//! op means for the listeners: whether the block is the next one expected, whether a listener
//! diverged while taking it, when the deferred wallet chain state is flushed, and when the
//! node may be called synced. Keeping the two apart is what lets the fetch run ahead of the
//! (persisting, slower) application under a bounded queue.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bip157::IndexedBlock;

use bitcoin::block::Header;
use bitcoin::Block;

use bdk_chain::BlockId;

use tokio::sync::{mpsc, watch, OwnedSemaphorePermit};

use crate::chain::bitcoind::ChainListener;
use crate::chain::cbf::fee::{coinbase_fee_rate, record_block_fee, BlockFeeCache};
use crate::chain::cbf::{mark_syncing, CbfSyncState, WatchLedger};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::types::DynStore;
use crate::{Error, NodeMetrics};

/// Bound on the queue between the kyoto event loop and [`BlockApplicator`].
///
/// During a bulk sync, filter processing outruns listener application (each applied block costs
/// a BDK persist), so an unbounded queue would let hundreds of thousands of `ChainOp` values
/// accumulate with no backpressure — a concrete OOM risk on a 512 MiB device. A bound makes the
/// event loop wait for the applicator instead.
///
/// Most ops are `ConnectFiltered`, which carries only an 80-byte header, so this depth is ample
/// for pipelining in the common case. It is NOT the bound on full blocks: a `ConnectFull` op
/// carries an entire block, and 64 of them would be ~256 MiB at the 4 MiB block size, more than
/// half the memory of a 512 MiB device. Full blocks are bounded separately by
/// [`CBF_FULL_BLOCK_PERMITS`].
///
/// This queue is the only backpressure between kyoto and the listeners. Kyoto's own event
/// channel (`Client::event_rx`) is unbounded, so while the event loop waits on this queue or on
/// a full-block permit, the filters kyoto keeps streaming accumulate there — an `IndexedFilter`
/// is a few hundred bytes to a few kilobytes, which is why the wait here is short and the
/// full-block bound is what matters.
pub(crate) const CBF_CHAIN_OP_QUEUE_DEPTH: usize = 64;

/// How many full blocks may exist at once between kyoto's event loop and the listeners: being
/// downloaded, queued in a `ConnectFull` op, or being applied.
///
/// The event loop takes a permit before it asks kyoto for a matched block, and the permit rides
/// in the op until the applicator drops it, so the worst case is this many blocks in memory —
/// 16 MiB at the block size limit — whatever the queue depth. Four is enough to keep one block
/// applying while the next downloads (the fetch is network-bound, the apply persist-bound) and
/// matched blocks are rare next to filtered ones, so a deeper pipeline would buy nothing on a
/// device that cannot afford it.
pub(crate) const CBF_FULL_BLOCK_PERMITS: usize = 4;

/// How many applied blocks may accumulate before the deferred on-chain chain tip is written.
///
/// While catching up, the wallet's `local_chain` write is deferred (see
/// `Wallet::set_bulk_chain_persistence`) so the growing full-chain map is not re-serialized on
/// every block. Flushing every retarget period bounds how many blocks a crash can force us to
/// replay, while collapsing ~2016 full-map writes into one. Once caught up, every block is
/// followed by a `Synced` op, which flushes — so at the tip this reverts to one write per block.
pub(crate) const CBF_CHAIN_FLUSH_INTERVAL_BLOCKS: u32 = 2016;

/// One unit of chain change, as kyoto's event loop reports it and the applicator applies it.
#[derive(Debug)]
pub(crate) enum ChainOp {
	/// A block whose filter matched a watched script, fetched in full. The permit is one of
	/// [`CBF_FULL_BLOCK_PERMITS`], taken before the fetch and released when this op is dropped —
	/// applied or skipped.
	ConnectFull { block: IndexedBlock, permit: OwnedSemaphorePermit },
	/// A block whose filter did not match: only its header is handed over.
	ConnectFiltered { header: Header, height: u32 },
	/// Headers kyoto removed from the chain of most work, tip first — strictly DESCENDING
	/// height, because `ChannelManager` and `OutputSweeper` assert that each disconnected header
	/// is their current tip. The lowest header's parent is the fork point; kyoto re-delivers the
	/// new branch's filters after this.
	Disconnect { headers: Vec<(Header, u32)> },
	/// Kyoto's filters caught up to the network tip it reports (`FiltersSynced`). Only this
	/// height is a true tip; the applicator judges stranded listeners against it and nothing
	/// else.
	Synced { tip_height: u32 },
}

/// Everything the applicator asks of the listeners, as one seam.
///
/// [`ChainListener`] is the production implementation; a test can stand in a fake to drive
/// the applicator without a `ChannelManager`. Every method mirrors one of the listener's gated
/// entry points or the wallet's chain-persistence hooks, so the seam adds no policy of its own.
pub(crate) trait ChainFanout: Send + Sync {
	/// A full block, delivered to every listener that can take it.
	fn connect_block(&self, block: &Block, height: u32);
	/// A header whose filter did not match: an empty block for every listener.
	fn connect_filtered(&self, header: &Header, height: u32);
	/// One disconnected header, applied tip-first down to the fork point.
	fn disconnect(&self, header: &Header, height: u32);
	/// The first divergence any listener recorded since the last drain.
	fn take_divergence(&self) -> Option<String>;
	/// Judge the replay batch against the tip it ended at; `true` if a listener is stranded.
	fn record_stranded_listeners(&self, tip_height: u32) -> bool;
	/// Defer (or resume) the wallet's chain-tip persistence.
	fn set_bulk_chain_persistence(&self, enabled: bool);
	/// Write any deferred chain state.
	fn flush_chain_persistence(&self) -> Result<(), Error>;
}

impl ChainFanout for ChainListener {
	fn connect_block(&self, block: &Block, height: u32) {
		self.gated_block_connected(block, height)
	}

	fn connect_filtered(&self, header: &Header, height: u32) {
		self.gated_filtered_block_connected(header, &[], height)
	}

	fn disconnect(&self, header: &Header, height: u32) {
		self.gated_block_disconnected(header, height)
	}

	fn take_divergence(&self) -> Option<String> {
		ChainListener::take_divergence(self)
	}

	fn record_stranded_listeners(&self, tip_height: u32) -> bool {
		ChainListener::record_stranded_listeners(self, tip_height)
	}

	fn set_bulk_chain_persistence(&self, enabled: bool) {
		self.onchain_wallet.set_bulk_chain_persistence(enabled)
	}

	fn flush_chain_persistence(&self) -> Result<(), Error> {
		self.onchain_wallet.flush_chain_persistence()
	}
}

/// Applies [`ChainOp`]s to the listeners, in order, one at a time.
pub(crate) struct BlockApplicator<F: ChainFanout> {
	fanout: Arc<F>,
	ops_rx: mpsc::Receiver<ChainOp>,
	/// The height the next connected block must have; anything else is out of sequence.
	next_height: u32,
	/// Blocks applied since the last deferred-chain-state flush.
	blocks_since_flush: u32,
	sync_state_tx: watch::Sender<CbfSyncState>,
	/// Every full block applied here has its coinbase-derived fee rate cached, so the fee
	/// estimator does not have to re-download it.
	block_fee_cache: BlockFeeCache,
	watch_ledger: Arc<WatchLedger>,
	kv_store: Arc<DynStore>,
	node_metrics: Arc<RwLock<NodeMetrics>>,
	logger: Arc<Logger>,
}

impl<F: ChainFanout> BlockApplicator<F> {
	/// An applicator expecting `next_height` as its first block.
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new(
		fanout: Arc<F>, ops_rx: mpsc::Receiver<ChainOp>, next_height: u32,
		sync_state_tx: watch::Sender<CbfSyncState>, block_fee_cache: BlockFeeCache,
		watch_ledger: Arc<WatchLedger>, kv_store: Arc<DynStore>,
		node_metrics: Arc<RwLock<NodeMetrics>>, logger: Arc<Logger>,
	) -> Self {
		Self {
			fanout,
			ops_rx,
			next_height,
			blocks_since_flush: 0,
			sync_state_tx,
			block_fee_cache,
			watch_ledger,
			kv_store,
			node_metrics,
			logger,
		}
	}

	/// Writes the deferred on-chain chain tip, logging (but not propagating) a failure: the chain
	/// state is reconstructible by replay, so a failed flush must not abort block application.
	fn flush_chain_state(&mut self) {
		match self.fanout.flush_chain_persistence() {
			Ok(()) => self.blocks_since_flush = 0,
			Err(e) => {
				// Deliberately do NOT reset the counter: the chain state is still unwritten, so the
				// next applied block should retry promptly rather than wait another full interval.
				// The persister keeps its pending set, so no state is dropped on the floor.
				log_error!(
					self.logger,
					"Failed to flush deferred CBF chain state ({}); will retry on the next block.",
					e
				);
			},
		}
	}

	/// Drains any listener divergence recorded during the last op.
	///
	/// Returns `true` when the applicator must stop. A diverged listener is sitting on a chain we
	/// cannot extend, so advancing `next_height` would march past it and eventually publish a
	/// "synced" tip while that listener is stale — silent, and unrecoverable without a reorg whose
	/// fork point happens to fall below it. Failing loudly instead surfaces the condition to
	/// `wait_until_synced` and stops further damage.
	fn fail_on_divergence(&mut self) -> bool {
		let Some(reason) = self.fanout.take_divergence() else {
			return false;
		};
		log_error!(
			self.logger,
			"Halting CBF block application: {}. The node must be restarted to re-derive a common \
			 chain state from the persisted listener heights.",
			reason
		);
		// Publish the failure BEFORE flushing. The flush is an unbounded KV write; if it hangs, a
		// `wait_until_synced` caller would otherwise block forever waiting for a state that is
		// already decided. Signalling first makes the failure observable regardless.
		self.sync_state_tx.send_replace(CbfSyncState::Failed(Error::TxSyncFailed));
		// Persist what was applied before the divergence so the resume floor reflects it.
		self.flush_chain_state();
		true
	}

	/// Counts an applied block and flushes once the interval has elapsed.
	fn note_block_applied(&mut self) {
		self.blocks_since_flush += 1;
		if self.blocks_since_flush >= CBF_CHAIN_FLUSH_INTERVAL_BLOCKS {
			self.flush_chain_state();
		}
	}

	/// Runs until the op channel closes (the event loop's senders are gone) or a listener
	/// diverges.
	pub(crate) async fn run(mut self) {
		// Defer the wallet's full-chain map write for as long as this applicator runs. Every path
		// that leaves the catching-up state (`Synced`, the channel closing on the event loop's
		// exit, and the periodic interval) flushes, so deferral never outlives a sync boundary.
		self.fanout.set_bulk_chain_persistence(true);

		while let Some(op) = self.ops_rx.recv().await {
			match op {
				// The permit is dropped with the op at the end of this arm, applied or skipped.
				ChainOp::ConnectFull { block: ib, permit: _permit } => {
					if ib.height != self.next_height {
						log_debug!(
							self.logger,
							"CBF skipping out-of-sequence block at height {} (expected {})",
							ib.height,
							self.next_height
						);
						continue;
					}
					self.fanout.connect_block(&ib.block, ib.height);
					if self.fail_on_divergence() {
						return;
					}
					self.next_height += 1;
					self.note_block_applied();
					mark_syncing(&self.sync_state_tx);
					let block_hash = ib.block.block_hash();
					record_block_fee(
						&self.block_fee_cache,
						ib.height,
						block_hash,
						coinbase_fee_rate(&ib.block, ib.height),
					);
					self.watch_ledger.note_connected(
						BlockId { height: ib.height, hash: block_hash },
						ib.block.txdata.iter().map(|tx| tx.compute_txid()),
					);
				},
				ChainOp::ConnectFiltered { header, height } => {
					if height != self.next_height {
						log_debug!(
							self.logger,
							"CBF skipping out-of-sequence block at height {} (expected {})",
							height,
							self.next_height
						);
						continue;
					}
					self.fanout.connect_filtered(&header, height);
					if self.fail_on_divergence() {
						return;
					}
					self.next_height += 1;
					self.note_block_applied();
					mark_syncing(&self.sync_state_tx);
					self.watch_ledger
						.note_connected(BlockId { height, hash: header.block_hash() }, []);
				},
				ChainOp::Disconnect { headers } => {
					let Some(fork_height) = self.disconnect(&headers) else {
						continue;
					};
					if self.fail_on_divergence() {
						return;
					}
					// Rewind the frontier to the fork point, but never advance it. During a
					// catch-up kyoto header-syncs to the network tip before it streams filters, so
					// a reorg it reports can sit entirely above the blocks still waiting in this
					// queue; the listeners were `NotReached` by it, and jumping the frontier up to
					// the fork point would drop every one of those blocks as out of sequence — and
					// make the first block of the new branch a gap the listeners refuse.
					if fork_height >= self.next_height {
						log_debug!(
							self.logger,
							"CBF reorg with fork height {} is at or above the next height {}; the \
							 blocks below it are still to be applied in order",
							fork_height,
							self.next_height
						);
					}
					self.next_height = self.next_height.min(fork_height + 1);
					self.sync_state_tx.send_replace(CbfSyncState::Active {
						applied_tip: Some(self.next_height.saturating_sub(1)),
						synced_to_tip: false,
					});
				},
				ChainOp::Synced { tip_height } => {
					log_info!(self.logger, "CBF caught up to tip {}", tip_height);
					if self.next_height > tip_height {
						// The last chance a listener gets to be proven on this chain: the replay
						// ends here and is not coming back. A listener the replay never reached is
						// stranded, not lagging, and must not be left silently on its own chain
						// while we advertise this one as synced. Only kyoto's reported tip may be
						// judged against — an intermediate batch boundary proves nothing.
						if self.fanout.record_stranded_listeners(tip_height)
							&& self.fail_on_divergence()
						{
							return;
						}
						// Reaching the tip is the durability boundary: write the deferred chain state
						// before publishing, so the tip we advertise as applied is also persisted.
						self.flush_chain_state();
						self.publish_synced_tip(tip_height);
					} else {
						log_debug!(
							self.logger,
							"CBF waiting to apply blocks through tip {} (next height {})",
							tip_height,
							self.next_height
						);
					}
				},
			}
		}

		// The channel closed, which is how every end of the event loop reaches us — a clean stop
		// or the restart loop giving up. Deferred chain state lives only in memory, so without this
		// flush the blocks applied since the last interval flush would be silently discarded and
		// re-synced on the next start.
		self.flush_chain_state();
	}

	/// Hands every disconnected header to the listeners, tip first, and returns the fork
	/// height — the parent of the lowest header — or `None` for an empty list.
	///
	/// The order is load-bearing: `ChannelManager` and `OutputSweeper` assert that the header
	/// being disconnected IS their tip, so the highest must go first. The event loop sorts;
	/// this asserts.
	fn disconnect(&self, headers: &[(Header, u32)]) -> Option<u32> {
		debug_assert!(
			headers.windows(2).all(|pair| pair[0].1 > pair[1].1),
			"disconnected headers must be strictly descending by height: {:?}",
			headers.iter().map(|(_, h)| *h).collect::<Vec<_>>()
		);
		let (_, lowest) = headers.last()?;
		for (header, height) in headers {
			self.fanout.disconnect(header, *height);
			self.watch_ledger.note_disconnected(header, *height);
		}
		Some(lowest.saturating_sub(1))
	}

	fn publish_synced_tip(&self, tip_height: u32) {
		let already_published = {
			let sync_state = *self.sync_state_tx.borrow();
			match sync_state {
				CbfSyncState::Active { applied_tip, .. } => applied_tip,
				CbfSyncState::Failed(_) => None,
			}
		};
		if already_published.map_or(false, |published_height| published_height >= tip_height) {
			// Even if the applied tip is unchanged, we have now confirmed we are caught up to the
			// network tip, so ensure the synced flag is set for any `wait_until_synced` waiter.
			self.sync_state_tx.send_replace(CbfSyncState::Active {
				applied_tip: already_published,
				synced_to_tip: true,
			});
			return;
		}
		self.sync_state_tx.send_replace(CbfSyncState::Active {
			applied_tip: Some(tip_height),
			synced_to_tip: true,
		});
		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		let mut locked_node_metrics = self.node_metrics.write().unwrap();
		locked_node_metrics.latest_lightning_wallet_sync_timestamp = unix_time_secs_opt;
		locked_node_metrics.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
		if let Err(e) = write_node_metrics(
			&*locked_node_metrics,
			Arc::clone(&self.kv_store),
			Arc::clone(&self.logger),
		) {
			log_error!(self.logger, "Failed to persist CBF sync metrics: {:?}", e);
		}
	}
}

#[cfg(test)]
mod tests {
	//! The applicator driven through a fake fan-out: one Lightning-shaped listener that keeps a
	//! `BestBlock` and applies the same gates the real listeners do, plus channel monitors
	//! handled the way the real fan-out handles the `ChainMonitor` — through the real
	//! `MonitorGate` and the real per-monitor decision functions — so the ops the applicator
	//! emits can be checked for order and for what they did to each tip.
	use super::*;

	use std::collections::BTreeMap;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Mutex;
	use std::time::Duration;

	use bitcoin::hashes::Hash;
	use bitcoin::{BlockHash, Txid};
	use lightning::chain::transaction::OutPoint;
	use lightning::chain::BestBlock;
	use lightning::util::test_utils::TestStore;

	use crate::chain::bitcoind::{
		disconnect_action, listener_action, DisconnectAction, ListenerAction, MonitorGate,
	};
	use crate::chain::cbf::fee::new_block_fee_cache;

	fn hash(byte: u8) -> BlockHash {
		BlockHash::from_byte_array([byte; 32])
	}

	fn funding(seed: u8) -> OutPoint {
		OutPoint { txid: Txid::from_byte_array([seed; 32]), index: 0 }
	}

	fn header_with(prev_blockhash: BlockHash, nonce: u32) -> Header {
		Header {
			version: bitcoin::block::Version::TWO,
			prev_blockhash,
			merkle_root: bitcoin::TxMerkleNode::all_zeros(),
			time: 0,
			bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
			nonce,
		}
	}

	/// A single Lightning-shaped listener behind the fan-out seam, plus channel monitors.
	///
	/// The monitors are modelled as the `ChainMonitor` holds them: one delivery lands on every
	/// monitor and overwrites its tip, whatever it was (`ChannelMonitor::block_connected`), while
	/// a rewind is applied per monitor on its own tip. The start-of-replay snapshots in `gate`
	/// are the real [`MonitorGate`].
	struct FakeFanout {
		tip: Mutex<BestBlock>,
		monitors: Mutex<BTreeMap<OutPoint, BestBlock>>,
		gate: Mutex<MonitorGate>,
		/// The heights handed to the single `ChainMonitor` delivery, in order.
		monitor_deliveries: Mutex<Vec<u32>>,
		/// Snapshots the replay refuted, by name.
		refuted: Mutex<Vec<String>>,
		disconnects: Mutex<Vec<(BlockHash, u32)>>,
		divergence: Mutex<Option<String>>,
		flushes: AtomicUsize,
	}

	impl FakeFanout {
		fn at(tip: BestBlock) -> Arc<Self> {
			Self::with_monitors(tip, [])
		}

		/// A fan-out whose monitors were persisted at the given tips, snapshotted the way
		/// `ChainListener::new_gated` snapshots them: before any block is delivered.
		fn with_monitors(
			tip: BestBlock, monitors: impl IntoIterator<Item = (OutPoint, BestBlock)>,
		) -> Arc<Self> {
			let monitors: BTreeMap<_, _> = monitors.into_iter().collect();
			Arc::new(Self {
				tip: Mutex::new(tip),
				gate: Mutex::new(MonitorGate::new(monitors.clone())),
				monitors: Mutex::new(monitors),
				monitor_deliveries: Mutex::new(Vec::new()),
				refuted: Mutex::new(Vec::new()),
				disconnects: Mutex::new(Vec::new()),
				divergence: Mutex::new(None),
				flushes: AtomicUsize::new(0),
			})
		}

		fn tip(&self) -> BestBlock {
			*self.tip.lock().unwrap()
		}

		fn monitor_tip(&self, funding_txo: OutPoint) -> BestBlock {
			self.monitors.lock().unwrap()[&funding_txo]
		}

		fn monitor_deliveries(&self) -> Vec<u32> {
			self.monitor_deliveries.lock().unwrap().clone()
		}

		fn live_snapshots(&self) -> usize {
			self.gate.lock().unwrap().live()
		}

		/// The height the engine resumes from: the furthest-behind listener, monitors included,
		/// as `ChainListener::get_best_block` computes it.
		fn resume_height(&self) -> u32 {
			let monitors = self.monitors.lock().unwrap();
			monitors
				.values()
				.map(|b| b.height)
				.min()
				.map_or(self.tip().height, |monitor_min| monitor_min.min(self.tip().height))
		}
	}

	impl ChainFanout for FakeFanout {
		fn connect_block(&self, block: &Block, height: u32) {
			self.connect_filtered(&block.header, height)
		}

		fn connect_filtered(&self, header: &Header, height: u32) {
			let block_hash = header.block_hash();
			{
				let mut tip = self.tip.lock().unwrap();
				if tip.height + 1 == height && tip.block_hash == header.prev_blockhash {
					*tip = BestBlock::new(block_hash, height);
				} else {
					*self.divergence.lock().unwrap() = Some(format!("connect at {}", height));
				}
			}

			// The monitors, as `ChainListener::gated_lightning_block_connected` treats them:
			// every live snapshot is judged first, a refutation withholds the block from the
			// whole `ChainMonitor`, and otherwise the furthest-behind monitor's gate decides.
			let decisions =
				self.gate.lock().unwrap().judge_block(block_hash, header.prev_blockhash, height);
			let mut refuted = false;
			for decision in decisions {
				if decision.action == ListenerAction::Diverged {
					refuted = true;
					self.refuted.lock().unwrap().push(decision.snapshot.name.clone());
					*self.divergence.lock().unwrap() =
						Some(format!("{} refuted the block at {}", decision.snapshot.name, height));
				}
			}
			if refuted {
				return;
			}
			let mut monitors = self.monitors.lock().unwrap();
			let deliver = match monitors.values().min_by_key(|b| b.height) {
				Some(min) => matches!(
					listener_action(min, block_hash, header.prev_blockhash, height),
					ListenerAction::Deliver | ListenerAction::AlreadyApplied
				),
				None => true,
			};
			if deliver {
				self.monitor_deliveries.lock().unwrap().push(height);
				for best in monitors.values_mut() {
					*best = BestBlock::new(block_hash, height);
				}
			}
		}

		fn disconnect(&self, header: &Header, height: u32) {
			self.disconnects.lock().unwrap().push((header.block_hash(), height));
			{
				let mut tip = self.tip.lock().unwrap();
				// The real listeners' gate, verbatim: rewind only while this header IS the tip.
				match disconnect_action(&tip, header, height) {
					DisconnectAction::Rewind => {
						*tip = BestBlock::new(header.prev_blockhash, height - 1)
					},
					DisconnectAction::NotReached => {},
					DisconnectAction::Diverged => {
						*self.divergence.lock().unwrap() =
							Some(format!("disconnect at {} is not the tip", height));
					},
				}
			}
			// Each monitor on its own tip, as `ChainListener::gated_block_disconnected` does.
			let mut monitors = self.monitors.lock().unwrap();
			for (funding_txo, best) in monitors.iter_mut() {
				match disconnect_action(best, header, height) {
					DisconnectAction::Rewind => {
						*best = BestBlock::new(header.prev_blockhash, height - 1);
						self.gate.lock().unwrap().note_rewound(funding_txo, height);
					},
					DisconnectAction::NotReached => {},
					DisconnectAction::Diverged => {
						*self.divergence.lock().unwrap() = Some(format!(
							"ChannelMonitor {} cannot be rewound at {}",
							funding_txo, height
						));
					},
				}
			}
		}

		fn take_divergence(&self) -> Option<String> {
			self.divergence.lock().unwrap().take()
		}

		fn record_stranded_listeners(&self, _tip_height: u32) -> bool {
			false
		}

		fn set_bulk_chain_persistence(&self, _enabled: bool) {}

		fn flush_chain_persistence(&self) -> Result<(), Error> {
			self.flushes.fetch_add(1, Ordering::SeqCst);
			Ok(())
		}
	}

	struct Harness {
		fanout: Arc<FakeFanout>,
		ops_tx: mpsc::Sender<ChainOp>,
		sync_state_tx: watch::Sender<CbfSyncState>,
		ledger: Arc<WatchLedger>,
		task: tokio::task::JoinHandle<()>,
	}

	fn spawn(fanout: Arc<FakeFanout>) -> Harness {
		let (ops_tx, ops_rx) = mpsc::channel(CBF_CHAIN_OP_QUEUE_DEPTH);
		let resume_height = fanout.resume_height();
		let (sync_state_tx, _) = watch::channel(CbfSyncState::Active {
			applied_tip: Some(resume_height),
			synced_to_tip: false,
		});
		let ledger = Arc::new(WatchLedger::new());
		let applicator = BlockApplicator::new(
			Arc::clone(&fanout),
			ops_rx,
			resume_height + 1,
			sync_state_tx.clone(),
			new_block_fee_cache(),
			Arc::clone(&ledger),
			Arc::new(TestStore::new(false)),
			Arc::new(RwLock::new(NodeMetrics::default())),
			Arc::new(Logger::new_log_facade()),
		);
		let task = tokio::spawn(applicator.run());
		Harness { fanout, ops_tx, sync_state_tx, ledger, task }
	}

	/// How long any single wait on the applicator may take before the test fails.
	const WAIT: Duration = Duration::from_secs(10);

	/// Waits for the sync state to satisfy `pred`, bounded.
	///
	/// The harness keeps a clone of the state sender, so a receiver never errors when the
	/// applicator has stopped, or when the ops sent will never publish the awaited state: without
	/// a bound such a test would sit forever instead of failing.
	async fn wait_for_state(h: &Harness, pred: impl FnMut(&CbfSyncState) -> bool) -> CbfSyncState {
		let mut rx = h.sync_state_tx.subscribe();
		let state = tokio::time::timeout(WAIT, rx.wait_for(pred))
			.await
			.expect("the applicator did not publish the awaited sync state in time")
			.expect("the sync state channel is open");
		*state
	}

	/// Joins the applicator task, bounded, and propagates its panic if it had one.
	async fn join(task: tokio::task::JoinHandle<()>) {
		tokio::time::timeout(WAIT, task)
			.await
			.expect("the applicator did not stop in time")
			.expect("the applicator panicked");
	}

	/// The headers of blocks 101..=103 on top of `prev` at 100, built ahead of time so a monitor
	/// can be persisted at one of them.
	fn headers_101_to_103(prev: BlockHash) -> Vec<Header> {
		let mut prev = prev;
		let mut headers = Vec::new();
		for height in 101..=103u32 {
			let header = header_with(prev, height);
			prev = header.block_hash();
			headers.push(header);
		}
		headers
	}

	/// Three blocks 101..=103 on top of the fan-out's tip at 100, connected through the
	/// applicator so the listener's tip and the ledger agree on the chain before a reorg.
	async fn connect_101_to_103(h: &Harness) -> Vec<Header> {
		let headers = headers_101_to_103(h.fanout.tip().block_hash);
		assert!(connect_and_sync(h, 101, &headers, 103).await);
		assert_eq!(h.fanout.tip().height, 103);
		assert_eq!(h.ledger.tip().map(|b| b.height), Some(103));
		headers
	}

	/// Connects `headers` at consecutive heights from `first_height` and waits for the `Synced`
	/// at `tip_height` to publish: `Synced` is the observable boundary, so once it is published
	/// the ops before it landed. Returns `false` if the applicator failed instead.
	async fn connect_and_sync(
		h: &Harness, first_height: u32, headers: &[Header], tip_height: u32,
	) -> bool {
		for (i, header) in headers.iter().enumerate() {
			let height = first_height + i as u32;
			h.ops_tx.send(ChainOp::ConnectFiltered { header: *header, height }).await.unwrap();
		}
		h.ops_tx.send(ChainOp::Synced { tip_height }).await.unwrap();
		let state = wait_for_state(h, |s| match s {
			CbfSyncState::Active { applied_tip, synced_to_tip } => {
				*synced_to_tip && *applied_tip == Some(tip_height)
			},
			CbfSyncState::Failed(_) => true,
		})
		.await;
		matches!(state, CbfSyncState::Active { .. })
	}

	#[tokio::test]
	async fn disconnect_ops_gate_on_listener_tip_hash() {
		let h = spawn(FakeFanout::at(BestBlock::new(hash(100), 100)));
		let headers = connect_101_to_103(&h).await;

		// Kyoto reorganises 102 and 103 out. The event loop hands them over tip first.
		let reorg = vec![(headers[2], 103), (headers[1], 102)];
		h.ops_tx.send(ChainOp::Disconnect { headers: reorg }).await.unwrap();
		let state =
			wait_for_state(&h, |s| matches!(s, CbfSyncState::Active { synced_to_tip: false, .. }))
				.await;

		// Each header was the listener's tip when it arrived, so each one rewound it: 103 first,
		// then 102, landing on the fork point 101.
		assert_eq!(
			*h.fanout.disconnects.lock().unwrap(),
			vec![(headers[2].block_hash(), 103), (headers[1].block_hash(), 102)],
			"descending, tip first"
		);
		assert_eq!(h.fanout.tip(), BestBlock::new(headers[0].block_hash(), 101));
		assert!(matches!(state, CbfSyncState::Active { applied_tip: Some(101), .. }));
		assert_eq!(h.ledger.tip(), Some(BlockId { height: 101, hash: headers[0].block_hash() }));

		// The applicator now expects 102 again: the new branch connects, and a `Synced` at
		// its tip publishes.
		let new_102 = header_with(headers[0].block_hash(), 0xbeef);
		h.ops_tx.send(ChainOp::ConnectFiltered { header: new_102, height: 102 }).await.unwrap();
		h.ops_tx.send(ChainOp::Synced { tip_height: 102 }).await.unwrap();
		let state =
			wait_for_state(&h, |s| matches!(s, CbfSyncState::Active { synced_to_tip: true, .. }))
				.await;
		assert!(matches!(state, CbfSyncState::Active { applied_tip: Some(102), .. }));
		assert_eq!(h.fanout.tip(), BestBlock::new(new_102.block_hash(), 102));

		drop(h.ops_tx);
		join(h.task).await;
		assert!(h.fanout.flushes.load(Ordering::SeqCst) >= 1, "a clean stop flushes");
	}

	#[tokio::test]
	async fn a_disconnect_that_is_not_the_listener_tip_halts_the_applicator() {
		let h = spawn(FakeFanout::at(BestBlock::new(hash(100), 100)));
		let headers = connect_101_to_103(&h).await;

		// A header at the listener's height with a different hash: the listener is on a chain
		// this reorg cannot rewind it along. The gate refuses, records divergence, and the
		// applicator must halt rather than march `next_height` past a stale listener.
		let other_103 = header_with(headers[1].block_hash(), 0xdead);
		assert_ne!(other_103.block_hash(), headers[2].block_hash());
		h.ops_tx.send(ChainOp::Disconnect { headers: vec![(other_103, 103)] }).await.unwrap();

		wait_for_state(&h, |s| matches!(s, CbfSyncState::Failed(Error::TxSyncFailed))).await;
		join(h.task).await;
		assert_eq!(h.fanout.tip().height, 103, "the listener was left untouched");
		assert!(
			h.ops_tx.send(ChainOp::Synced { tip_height: 103 }).await.is_err(),
			"nothing is applied after a halt"
		);
	}

	#[tokio::test]
	async fn a_reorg_rewinds_only_the_monitor_that_reached_it() {
		// The crash-skew geometry: monitor A was persisted at 104, monitor B at 105, and the
		// block at 105 is reorganised out before the replay (which resumes from A's 104) gets to
		// re-deliver it. Gated on the furthest-behind monitor the reorg was `NotReached` for the
		// whole `ChainMonitor`, so B kept the abandoned block and its events matured on the new
		// branch. Per monitor, B is rewound and A — which never reached 105 — is left alone.
		let block_105 = header_with(hash(104), 105);
		let (a, b) = (funding(1), funding(2));
		let h = spawn(FakeFanout::with_monitors(
			BestBlock::new(hash(104), 104),
			[(a, BestBlock::new(hash(104), 104)), (b, BestBlock::new(block_105.block_hash(), 105))],
		));
		assert_eq!(h.fanout.resume_height(), 104);

		h.ops_tx.send(ChainOp::Disconnect { headers: vec![(block_105, 105)] }).await.unwrap();
		// A `Synced` at the fork point is the observable boundary: the applicator processes it
		// after the disconnect and publishes 104 as the synced tip.
		h.ops_tx.send(ChainOp::Synced { tip_height: 104 }).await.unwrap();
		wait_for_state(&h, |s| {
			matches!(s, CbfSyncState::Active { applied_tip: Some(104), synced_to_tip: true })
		})
		.await;

		assert_eq!(h.fanout.monitor_tip(b), BestBlock::new(hash(104), 104), "B rewound to 104");
		assert_eq!(h.fanout.monitor_tip(a), BestBlock::new(hash(104), 104), "A untouched");
		assert!(h.fanout.take_divergence().is_none(), "a rewind on its own tip is not a fork");
		assert_eq!(h.fanout.live_snapshots(), 1, "B's snapshot at 105 is moot; A's at 104 stands");

		// The new branch: both monitors take 105 in lockstep, and A's snapshot is proven by it.
		let new_105 = header_with(hash(104), 0xbeef);
		assert!(connect_and_sync(&h, 105, &[new_105], 105).await);
		assert_eq!(h.fanout.monitor_deliveries(), vec![105]);
		assert_eq!(h.fanout.monitor_tip(a), BestBlock::new(new_105.block_hash(), 105));
		assert_eq!(h.fanout.monitor_tip(b), BestBlock::new(new_105.block_hash(), 105));
		assert_eq!(h.fanout.live_snapshots(), 0);

		drop(h.ops_tx);
		join(h.task).await;
	}

	#[tokio::test]
	async fn an_ahead_monitor_on_another_chain_halts_the_replay_at_its_own_height() {
		// Monitor B was persisted at 102 on a block the chain does not have. Nothing below 102
		// can tell (its live tip is overwritten by the first delivery, which is exactly why the
		// snapshot exists), but at 102 the snapshot compares by hash and refutes it: the block
		// is withheld from the `ChainMonitor` and the applicator halts rather than feed a
		// monitor that is on another chain.
		let (a, b) = (funding(1), funding(2));
		let h = spawn(FakeFanout::with_monitors(
			BestBlock::new(hash(100), 100),
			[(a, BestBlock::new(hash(100), 100)), (b, BestBlock::new(hash(0xbb), 102))],
		));
		let headers = headers_101_to_103(hash(100));
		assert!(!connect_and_sync(&h, 101, &headers, 103).await, "the replay failed");
		join(h.task).await;

		assert_eq!(h.fanout.monitor_deliveries(), vec![101], "102 was withheld");
		assert_eq!(
			*h.fanout.refuted.lock().unwrap(),
			vec![format!("ChannelMonitor {}", b)],
			"named by funding outpoint"
		);
		assert_eq!(h.fanout.live_snapshots(), 1, "kept as the evidence");
		assert!(
			h.ops_tx.send(ChainOp::Synced { tip_height: 103 }).await.is_err(),
			"nothing is applied after a halt"
		);
	}

	#[tokio::test]
	async fn an_ahead_monitor_on_the_same_chain_is_proven_at_its_tip_and_then_moves_in_lockstep() {
		// The same skew, but B's persisted block at 102 IS the chain's. The replay below 102
		// cannot prove it; at 102 the snapshot matches and is retired; nothing about B ever halts
		// the engine; and the `ChainMonitor` is handed each height exactly once. From then on B
		// moves with the others: the reorg of 103 rewinds both monitors on their (now common)
		// tip.
		let headers = headers_101_to_103(hash(100));
		let (a, b) = (funding(1), funding(2));
		let h = spawn(FakeFanout::with_monitors(
			BestBlock::new(hash(100), 100),
			[
				(a, BestBlock::new(hash(100), 100)),
				(b, BestBlock::new(headers[1].block_hash(), 102)),
			],
		));
		assert!(connect_and_sync(&h, 101, &headers, 103).await);
		assert_eq!(h.fanout.monitor_deliveries(), vec![101, 102, 103]);
		assert!(h.fanout.refuted.lock().unwrap().is_empty());
		assert!(h.fanout.take_divergence().is_none());
		assert_eq!(h.fanout.live_snapshots(), 0, "both proven: A by 101, B at 102");

		h.ops_tx.send(ChainOp::Disconnect { headers: vec![(headers[2], 103)] }).await.unwrap();
		wait_for_state(&h, |s| matches!(s, CbfSyncState::Active { applied_tip: Some(102), .. }))
			.await;
		assert_eq!(h.fanout.monitor_tip(a), BestBlock::new(headers[1].block_hash(), 102));
		assert_eq!(h.fanout.monitor_tip(b), BestBlock::new(headers[1].block_hash(), 102));
		assert!(h.fanout.take_divergence().is_none());

		drop(h.ops_tx);
		join(h.task).await;
	}

	#[tokio::test]
	async fn a_reorg_above_the_replay_frontier_keeps_the_blocks_below_it_applying_in_order() {
		// The catch-up geometry: the listeners are at 100 and kyoto, which header-synced to the
		// network tip before streaming a single filter, reorganises 105 out while 101..=104 are
		// still on their way through this queue. No listener has reached 105 (`NotReached`, not a
		// divergence), and the frontier must stay at 101: moving it up to the fork point would
		// drop 101..=104 as out of sequence and leave the new 105 a gap the listeners refuse.
		let h = spawn(FakeFanout::at(BestBlock::new(hash(100), 100)));
		let stale_105 = header_with(hash(104), 105);
		h.ops_tx.send(ChainOp::Disconnect { headers: vec![(stale_105, 105)] }).await.unwrap();

		// 101..=104 as kyoto already had them, then the new branch's 105.
		let mut headers = Vec::new();
		let mut prev = hash(100);
		for height in 101..=104u32 {
			let header = header_with(prev, height);
			prev = header.block_hash();
			headers.push(header);
		}
		let new_105 = header_with(prev, 0xbeef);
		headers.push(new_105);
		assert!(connect_and_sync(&h, 101, &headers, 105).await, "every block applied in order");

		assert_eq!(
			*h.fanout.disconnects.lock().unwrap(),
			vec![(stale_105.block_hash(), 105)],
			"the listeners were offered the reorg and had not reached it"
		);
		assert!(h.fanout.take_divergence().is_none());
		assert_eq!(h.fanout.tip(), BestBlock::new(new_105.block_hash(), 105));
		assert_eq!(h.ledger.tip(), Some(BlockId { height: 105, hash: new_105.block_hash() }));

		drop(h.ops_tx);
		join(h.task).await;
	}

	#[tokio::test]
	async fn a_full_block_holds_its_permit_only_until_it_is_applied_or_skipped() {
		let h = spawn(FakeFanout::at(BestBlock::new(hash(100), 100)));
		let permits = Arc::new(tokio::sync::Semaphore::new(CBF_FULL_BLOCK_PERMITS));
		let full_block = |header: Header, height: u32| IndexedBlock {
			height,
			block: Block { header, txdata: Vec::new() },
		};

		// A stray full block out of sequence is skipped, and one in sequence is applied; each
		// arrived holding a permit, as the event loop hands them over, and each gives it back.
		let stray = full_block(header_with(hash(104), 105), 105);
		let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
		h.ops_tx.send(ChainOp::ConnectFull { block: stray, permit }).await.unwrap();
		let header_101 = header_with(hash(100), 101);
		let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
		h.ops_tx
			.send(ChainOp::ConnectFull { block: full_block(header_101, 101), permit })
			.await
			.unwrap();
		h.ops_tx.send(ChainOp::Synced { tip_height: 101 }).await.unwrap();
		wait_for_state(&h, |s| {
			matches!(s, CbfSyncState::Active { applied_tip: Some(101), synced_to_tip: true })
		})
		.await;

		assert_eq!(h.fanout.tip(), BestBlock::new(header_101.block_hash(), 101));
		assert!(h.fanout.take_divergence().is_none(), "the stray block never reached a listener");
		assert_eq!(
			permits.available_permits(),
			CBF_FULL_BLOCK_PERMITS,
			"the applied and the skipped block both released their permit"
		);

		drop(h.ops_tx);
		join(h.task).await;
	}

	#[tokio::test]
	async fn out_of_sequence_blocks_are_skipped_without_touching_the_listeners() {
		let h = spawn(FakeFanout::at(BestBlock::new(hash(100), 100)));
		// 105 before 101: the listener would panic on it; the applicator drops it.
		let stray = header_with(hash(104), 105);
		h.ops_tx.send(ChainOp::ConnectFiltered { header: stray, height: 105 }).await.unwrap();
		connect_101_to_103(&h).await;
		assert_eq!(h.fanout.tip().height, 103);
		assert!(h.fanout.take_divergence().is_none());

		drop(h.ops_tx);
		join(h.task).await;
	}
}
