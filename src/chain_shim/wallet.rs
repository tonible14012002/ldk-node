// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The node's on-chain wallet as the chain layer's [`ChainWallet`].
//!
//! The trait's method set is exactly what the chain layer called on the wallet when it lived in
//! this crate, under the same names, so every method is the wallet's own; this only hands them
//! across the seam and maps the errors.

use std::collections::HashMap;
use std::sync::Arc;

use bdk_chain::local_chain::CheckPoint;
use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_wallet::{KeychainKind, Update};
use bitcoin::block::Header;
use bitcoin::{Block, OutPoint, ScriptBuf, Transaction, Txid};

use lightning::chain::Listen;

use node_chain_seam::{BlockListener, BlockRef, BroadcastQueue, ChainError, ChainWallet};

use super::chain_error;
use crate::types::Wallet;

impl BlockListener for Wallet {
	fn best_block(&self) -> BlockRef {
		let best = self.current_best_block();
		BlockRef::new(best.height, best.block_hash)
	}

	fn block_connected(&self, block: &Block, height: u32) {
		Listen::block_connected(self, block, height)
	}

	fn filtered_block_connected(
		&self, header: &Header, txdata: &[(usize, &Transaction)], height: u32,
	) {
		Listen::filtered_block_connected(self, header, txdata, height)
	}

	fn block_disconnected(&self, header: &Header, height: u32) {
		Listen::block_disconnected(self, header, height)
	}
}

impl ChainWallet for Wallet {
	fn list_watched_scripts(&self) -> Vec<ScriptBuf> {
		Wallet::list_watched_scripts(self)
	}

	fn watched_script_count(&self) -> usize {
		Wallet::watched_script_count(self)
	}

	fn revealed_spk_index(&self) -> HashMap<ScriptBuf, (KeychainKind, u32)> {
		Wallet::revealed_spk_index(self)
	}

	fn outpoints_for_spend_watch(&self, reorg_depth: u32) -> Vec<OutPoint> {
		Wallet::outpoints_for_spend_watch(self, reorg_depth)
	}

	fn latest_checkpoint(&self) -> CheckPoint {
		Wallet::latest_checkpoint(self)
	}

	fn get_full_scan_request(&self) -> FullScanRequest<KeychainKind> {
		Wallet::get_full_scan_request(self)
	}

	fn get_incremental_sync_request(&self) -> SyncRequest<(KeychainKind, u32)> {
		Wallet::get_incremental_sync_request(self)
	}

	fn apply_update(&self, update: Update) -> Result<(), ChainError> {
		Wallet::apply_update(self, update).map_err(chain_error)
	}

	fn set_bulk_chain_persistence(&self, enabled: bool) {
		Wallet::set_bulk_chain_persistence(self, enabled)
	}

	fn flush_chain_persistence(&self) -> Result<(), ChainError> {
		Wallet::flush_chain_persistence(self).map_err(chain_error)
	}

	fn is_relevant_tx(&self, tx: &Transaction) -> bool {
		Wallet::is_relevant_tx(self, tx)
	}

	fn known_tx(&self, txid: &Txid) -> Option<Transaction> {
		Wallet::known_tx(self, txid)
	}

	fn knows_tx(&self, txid: &Txid) -> bool {
		Wallet::knows_tx(self, txid)
	}

	fn get_cached_txs(&self) -> Vec<Arc<Transaction>> {
		Wallet::get_cached_txs(self)
	}

	fn get_unconfirmed_txids(&self) -> Vec<Txid> {
		Wallet::get_unconfirmed_txids(self)
	}

	fn is_tx_confirmed(&self, txid: &Txid) -> bool {
		Wallet::is_tx_confirmed(self, txid)
	}

	fn confirmed_conflict(&self, tx: &Transaction) -> Option<(OutPoint, Txid)> {
		Wallet::confirmed_conflict(self, tx)
	}

	fn apply_mempool_txs(
		&self, unconfirmed_txs: Vec<(Transaction, u64)>, evicted_txids: Vec<(Txid, u64)>,
	) -> Result<(), ChainError> {
		Wallet::apply_mempool_txs(self, unconfirmed_txs, evicted_txids).map_err(chain_error)
	}

	fn apply_own_view(
		&self, unconfirmed_txs: Vec<(Transaction, u64)>, evicted_txids: Vec<(Txid, u64)>,
	) -> Result<(), ChainError> {
		Wallet::apply_own_view(self, unconfirmed_txs, evicted_txids).map_err(chain_error)
	}

	fn fail_replaced_payments(&self) -> Result<(), ChainError> {
		Wallet::fail_replaced_payments(self).map_err(chain_error)
	}

	fn give_up_transaction(
		&self, txid: Txid, reason: String, definitive: bool,
	) -> Result<Vec<Txid>, ChainError> {
		Wallet::give_up_transaction(self, txid, reason, definitive).map_err(chain_error)
	}

	fn broadcast_queue(&self) -> &dyn BroadcastQueue {
		&**Wallet::broadcast_queue(self)
	}
}
