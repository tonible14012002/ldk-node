// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::logger::{log_error, LdkLogger};

use lightning::chain::chaininterface::BroadcasterInterface;

use bitcoin::Transaction;

use tokio::sync::mpsc;
use tokio::sync::{Mutex, MutexGuard};

use std::ops::Deref;

// Bumped from 50 to 500 because LDK's onchain claim-bump logic floods the
// queue with rebroadcasts of stuck force-close commitment TXs (each new
// block triggers another retry). Once the queue fills up, new broadcasts —
// including one-shot sweep/funding TXs the onboarding flow depends on —
// are silently dropped with `try_send` returning `Full`. 500 is generous
// enough that legitimate sweep/funding broadcasts always make it through
// even when an old monitor's commitment-tx is stuck looping against
// bitcoind's "Transaction outputs already in utxo set" rejection.
const BCAST_PACKAGE_QUEUE_SIZE: usize = 500;

pub(crate) struct TransactionBroadcaster<L: Deref>
where
	L::Target: LdkLogger,
{
	queue_sender: mpsc::Sender<Vec<Transaction>>,
	queue_receiver: Mutex<mpsc::Receiver<Vec<Transaction>>>,
	logger: L,
}

impl<L: Deref> TransactionBroadcaster<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(logger: L) -> Self {
		let (queue_sender, queue_receiver) = mpsc::channel(BCAST_PACKAGE_QUEUE_SIZE);
		Self { queue_sender, queue_receiver: Mutex::new(queue_receiver), logger }
	}

	pub(crate) async fn get_broadcast_queue(&self) -> MutexGuard<mpsc::Receiver<Vec<Transaction>>> {
		self.queue_receiver.lock().await
	}

	/// Enqueues a single fully-signed transaction for broadcast (swaps B4).
	///
	/// Thin wrapper over the [`BroadcasterInterface::broadcast_transactions`] impl below:
	/// it enqueues the transaction onto the bounded broadcast queue drained by the chain
	/// source's `process_broadcast_queue` loop. The actual network send happens there,
	/// so this returns immediately and does not confirm acceptance by the backend.
	#[cfg(feature = "swaps")]
	pub(crate) fn broadcast_tx(&self, tx: &Transaction) {
		<Self as BroadcasterInterface>::broadcast_transactions(self, &[tx]);
	}
}

impl<L: Deref> BroadcasterInterface for TransactionBroadcaster<L>
where
	L::Target: LdkLogger,
{
	fn broadcast_transactions(&self, txs: &[&Transaction]) {
		let package = txs.iter().map(|&t| t.clone()).collect::<Vec<Transaction>>();
		self.queue_sender.try_send(package).unwrap_or_else(|e| {
			log_error!(self.logger, "Failed to broadcast transactions: {}", e);
		});
	}
}
