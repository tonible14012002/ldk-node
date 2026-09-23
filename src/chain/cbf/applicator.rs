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

use tokio::sync::{mpsc, watch};

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
/// Kept small because a `ConnectFull` op carries an entire block: at 64 slots the worst case is
/// bounded even when every queued op is a matched block. Most ops are `ConnectFiltered`, which
/// carries only an 80-byte header, so this depth is ample for pipelining in the common case.
pub(crate) const CBF_CHAIN_OP_QUEUE_DEPTH: usize = 64;

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
	/// A block whose filter matched a watched script, fetched in full.
	ConnectFull { block: IndexedBlock },
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
	/// The event loop gave up.
	Failed { error: Error },
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
		// that leaves the catching-up state (`Synced`, `Failed`, and the periodic interval) flushes,
		// so deferral never outlives a sync boundary.
		self.fanout.set_bulk_chain_persistence(true);

		while let Some(op) = self.ops_rx.recv().await {
			match op {
				ChainOp::ConnectFull { block: ib } => {
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
					self.next_height = fork_height + 1;
					self.sync_state_tx.send_replace(CbfSyncState::Active {
						applied_tip: Some(fork_height),
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
				ChainOp::Failed { error } => {
					log_error!(self.logger, "CBF sync failed: {}", error);
					// Persist whatever we applied before the failure so the resume floor reflects it.
					self.flush_chain_state();
					self.sync_state_tx.send_replace(CbfSyncState::Failed(error));
				},
			}
		}

		// The channel closed, which is how a normal shutdown reaches us. Deferred chain state lives
		// only in memory, so without this flush a clean stop would silently discard every block
		// applied since the last interval flush and force them to be re-synced on next start.
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
	//! `BestBlock` and applies the same disconnect gate the real listeners do, so the ops the
	//! applicator emits can be checked for order and for what they did to the tip.
	use super::*;

	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Mutex;

	use bitcoin::hashes::Hash;
	use bitcoin::BlockHash;
	use lightning::chain::BestBlock;
	use lightning::util::test_utils::TestStore;

	use crate::chain::bitcoind::{disconnect_action, DisconnectAction};
	use crate::chain::cbf::fee::new_block_fee_cache;

	fn hash(byte: u8) -> BlockHash {
		BlockHash::from_byte_array([byte; 32])
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

	/// A single Lightning-shaped listener behind the fan-out seam.
	struct FakeFanout {
		tip: Mutex<BestBlock>,
		disconnects: Mutex<Vec<(BlockHash, u32)>>,
		divergence: Mutex<Option<String>>,
		flushes: AtomicUsize,
	}

	impl FakeFanout {
		fn at(tip: BestBlock) -> Arc<Self> {
			Arc::new(Self {
				tip: Mutex::new(tip),
				disconnects: Mutex::new(Vec::new()),
				divergence: Mutex::new(None),
				flushes: AtomicUsize::new(0),
			})
		}

		fn tip(&self) -> BestBlock {
			*self.tip.lock().unwrap()
		}
	}

	impl ChainFanout for FakeFanout {
		fn connect_block(&self, block: &Block, height: u32) {
			self.connect_filtered(&block.header, height)
		}

		fn connect_filtered(&self, header: &Header, height: u32) {
			let mut tip = self.tip.lock().unwrap();
			if tip.height + 1 == height && tip.block_hash == header.prev_blockhash {
				*tip = BestBlock::new(header.block_hash(), height);
			} else {
				*self.divergence.lock().unwrap() = Some(format!("connect at {}", height));
			}
		}

		fn disconnect(&self, header: &Header, height: u32) {
			self.disconnects.lock().unwrap().push((header.block_hash(), height));
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
		let (sync_state_tx, _) = watch::channel(CbfSyncState::Active {
			applied_tip: Some(fanout.tip().height),
			synced_to_tip: false,
		});
		let ledger = Arc::new(WatchLedger::new());
		let applicator = BlockApplicator::new(
			Arc::clone(&fanout),
			ops_rx,
			fanout.tip().height + 1,
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

	/// Three blocks 101..=103 on top of the fan-out's tip at 100, connected through the
	/// applicator so the listener's tip and the ledger agree on the chain before a reorg.
	async fn connect_101_to_103(h: &Harness) -> Vec<Header> {
		let mut prev = h.fanout.tip().block_hash;
		let mut headers = Vec::new();
		for height in 101..=103u32 {
			let header = header_with(prev, height);
			h.ops_tx.send(ChainOp::ConnectFiltered { header, height }).await.unwrap();
			prev = header.block_hash();
			headers.push(header);
		}
		// `Synced` is the observable boundary: once it is published the ops before it landed.
		h.ops_tx.send(ChainOp::Synced { tip_height: 103 }).await.unwrap();
		let mut rx = h.sync_state_tx.subscribe();
		rx.wait_for(|s| matches!(s, CbfSyncState::Active { synced_to_tip: true, .. }))
			.await
			.unwrap();
		assert_eq!(h.fanout.tip().height, 103);
		assert_eq!(h.ledger.tip().map(|b| b.height), Some(103));
		headers
	}

	#[tokio::test]
	async fn disconnect_ops_gate_on_listener_tip_hash() {
		let h = spawn(FakeFanout::at(BestBlock::new(hash(100), 100)));
		let headers = connect_101_to_103(&h).await;

		// Kyoto reorganises 102 and 103 out. The event loop hands them over tip first.
		let reorg = vec![(headers[2], 103), (headers[1], 102)];
		h.ops_tx.send(ChainOp::Disconnect { headers: reorg }).await.unwrap();
		let mut rx = h.sync_state_tx.subscribe();
		let state = *rx
			.wait_for(|s| matches!(s, CbfSyncState::Active { synced_to_tip: false, .. }))
			.await
			.unwrap();

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
		let state = *rx
			.wait_for(|s| matches!(s, CbfSyncState::Active { synced_to_tip: true, .. }))
			.await
			.unwrap();
		assert!(matches!(state, CbfSyncState::Active { applied_tip: Some(102), .. }));
		assert_eq!(h.fanout.tip(), BestBlock::new(new_102.block_hash(), 102));

		drop(h.ops_tx);
		h.task.await.unwrap();
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

		let mut rx = h.sync_state_tx.subscribe();
		rx.wait_for(|s| matches!(s, CbfSyncState::Failed(Error::TxSyncFailed))).await.unwrap();
		h.task.await.unwrap();
		assert_eq!(h.fanout.tip().height, 103, "the listener was left untouched");
		assert!(
			h.ops_tx.send(ChainOp::Synced { tip_height: 103 }).await.is_err(),
			"nothing is applied after a halt"
		);
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
	}
}
