// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::io::utils::{
	read_bdk_wallet_change_set, write_bdk_wallet_change_descriptor, write_bdk_wallet_descriptor,
	write_bdk_wallet_indexer, write_bdk_wallet_local_chain, write_bdk_wallet_network,
	write_bdk_wallet_tx_graph,
};
use crate::logger::{log_error, LdkLogger, Logger};
use crate::types::DynStore;

use bdk_chain::local_chain::ChangeSet as LocalChainChangeSet;
use bdk_chain::Merge;
use bdk_wallet::{ChangeSet, WalletPersister};

use std::sync::Arc;

pub(crate) struct KVStoreWalletPersister {
	latest_change_set: Option<ChangeSet>,
	kv_store: Arc<DynStore>,
	logger: Arc<Logger>,
	/// While set, `local_chain` changes are merged into the in-memory aggregate but not written
	/// to the KV store. See [`Self::set_defer_local_chain`].
	defer_local_chain: bool,
	/// The `local_chain` changes merged into `latest_change_set` while deferred and not yet
	/// written. Non-empty exactly when the persisted chain lags the in-memory one.
	pending_local_chain: LocalChainChangeSet,
}

impl KVStoreWalletPersister {
	pub(crate) fn new(kv_store: Arc<DynStore>, logger: Arc<Logger>) -> Self {
		Self {
			latest_change_set: None,
			kv_store,
			logger,
			defer_local_chain: false,
			pending_local_chain: LocalChainChangeSet::default(),
		}
	}

	/// Defers `local_chain` writes while a bulk block-by-block sync is in progress.
	///
	/// The persisted `local_chain` is a `BTreeMap<height, hash>` covering every checkpoint the
	/// wallet holds, re-serialized and re-written in full on every applied block. During an
	/// initial filter-driven sync that makes the bytes written quadratic in the number of blocks
	/// applied, which is the dominant cost on flash storage.
	///
	/// Deferring is safe because of the write order [`WalletPersister::persist`] keeps: `indexer`
	/// and `tx_graph` are written synchronously on every call and `local_chain` was already
	/// written last. With deferral the chain write is merely postponed, so at any crash point the
	/// persisted chain tip can only LAG the persisted transaction graph, never lead it. A lagging
	/// tip is recoverable: the sync engine resumes from the wallet's persisted checkpoint and
	/// replays the missing blocks, re-anchoring transactions the graph already holds (BDK anchor
	/// inserts are idempotent). A leading tip would not be: the engine would resume above blocks
	/// whose transactions were never persisted and the wallet would never see them, which is
	/// exactly why `indexer` and `tx_graph` are never deferred.
	///
	/// Turning deferral off does not flush. Callers pair this with [`Self::flush_local_chain`];
	/// a non-deferred write that follows also clears the backlog, because it writes the full
	/// aggregate.
	// Wired by T7: reached through `Wallet::set_bulk_chain_persistence` / `flush_chain_persistence`.
	#[allow(dead_code)]
	pub(crate) fn set_defer_local_chain(&mut self, defer: bool) {
		self.defer_local_chain = defer;
	}

	/// Whether `local_chain` changes are being held back from the KV store.
	#[cfg(test)]
	pub(crate) fn has_pending_local_chain(&self) -> bool {
		!self.pending_local_chain.is_empty()
	}

	/// Writes the in-memory `local_chain` aggregate once if any change was deferred.
	// Wired by T7: reached through `Wallet::set_bulk_chain_persistence` / `flush_chain_persistence`.
	#[allow(dead_code)]
	pub(crate) fn flush_local_chain(&mut self) -> Result<(), std::io::Error> {
		if self.pending_local_chain.is_empty() {
			return Ok(());
		}

		let latest_change_set = self.latest_change_set.as_ref().ok_or_else(|| {
			std::io::Error::new(
				std::io::ErrorKind::Other,
				"Wallet must be initialized before flushing the local chain",
			)
		})?;

		write_bdk_wallet_local_chain(
			&latest_change_set.local_chain,
			Arc::clone(&self.kv_store),
			Arc::clone(&self.logger),
		)?;
		self.pending_local_chain = LocalChainChangeSet::default();
		Ok(())
	}
}

impl WalletPersister for KVStoreWalletPersister {
	type Error = std::io::Error;

	fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
		// Return immediately if we have already been initialized.
		if let Some(latest_change_set) = persister.latest_change_set.as_ref() {
			return Ok(latest_change_set.clone());
		}

		let change_set_opt = read_bdk_wallet_change_set(
			Arc::clone(&persister.kv_store),
			Arc::clone(&persister.logger),
		)?;

		let change_set = match change_set_opt {
			Some(persisted_change_set) => persisted_change_set,
			None => {
				// BDK docs state: "The implementation must return all data currently stored in the
				// persister. If there is no data, return an empty changeset (using
				// ChangeSet::default())."
				ChangeSet::default()
			},
		};
		persister.latest_change_set = Some(change_set.clone());
		Ok(change_set)
	}

	fn persist(persister: &mut Self, change_set: &ChangeSet) -> Result<(), Self::Error> {
		if change_set.is_empty() {
			return Ok(());
		}

		// We're allowed to fail here if we're not initialized, BDK docs state: "This method can fail if the
		// persister is not initialized."
		let latest_change_set = persister.latest_change_set.as_mut().ok_or_else(|| {
			std::io::Error::new(
				std::io::ErrorKind::Other,
				"Wallet must be initialized before calling persist",
			)
		})?;

		// Check that we'd never accidentally override any persisted data if the change set doesn't
		// match our descriptor/change_descriptor/network.
		if let Some(descriptor) = change_set.descriptor.as_ref() {
			if latest_change_set.descriptor.is_some()
				&& latest_change_set.descriptor.as_ref() != Some(descriptor)
			{
				debug_assert!(false, "Wallet descriptor must never change");
				log_error!(
					persister.logger,
					"Wallet change set doesn't match persisted descriptor. This should never happen."
				);
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"Wallet change set doesn't match persisted descriptor. This should never happen."
				));
			} else {
				latest_change_set.descriptor = Some(descriptor.clone());
				write_bdk_wallet_descriptor(
					&descriptor,
					Arc::clone(&persister.kv_store),
					Arc::clone(&persister.logger),
				)?;
			}
		}

		if let Some(change_descriptor) = change_set.change_descriptor.as_ref() {
			if latest_change_set.change_descriptor.is_some()
				&& latest_change_set.change_descriptor.as_ref() != Some(change_descriptor)
			{
				debug_assert!(false, "Wallet change_descriptor must never change");
				log_error!(
					persister.logger,
					"Wallet change set doesn't match persisted change_descriptor. This should never happen."
				);
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"Wallet change set doesn't match persisted change_descriptor. This should never happen."
				));
			} else {
				latest_change_set.change_descriptor = Some(change_descriptor.clone());
				write_bdk_wallet_change_descriptor(
					&change_descriptor,
					Arc::clone(&persister.kv_store),
					Arc::clone(&persister.logger),
				)?;
			}
		}

		if let Some(network) = change_set.network {
			if latest_change_set.network.is_some() && latest_change_set.network != Some(network) {
				debug_assert!(false, "Wallet network must never change");
				log_error!(
					persister.logger,
					"Wallet change set doesn't match persisted network. This should never happen."
				);
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"Wallet change set doesn't match persisted network. This should never happen.",
				));
			} else {
				latest_change_set.network = Some(network);
				write_bdk_wallet_network(
					&network,
					Arc::clone(&persister.kv_store),
					Arc::clone(&persister.logger),
				)?;
			}
		}

		debug_assert!(
			latest_change_set.descriptor.is_some()
				&& latest_change_set.change_descriptor.is_some()
				&& latest_change_set.network.is_some(),
			"descriptor, change_descriptor, and network are mandatory ChangeSet fields"
		);

		// Merge and persist the sub-changesets individually if necessary.
		//
		// According to the BDK team the individual sub-changesets can be persisted
		// individually/non-atomically, "(h)owever, the localchain tip is used by block-by-block
		// chain sources as a reference as to where to sync from, so I would persist that last", "I
		// would write in this order: indexer, tx_graph, local_chain", which is why we follow this
		// particular order.
		if !change_set.indexer.is_empty() {
			latest_change_set.indexer.merge(change_set.indexer.clone());
			write_bdk_wallet_indexer(
				&latest_change_set.indexer,
				Arc::clone(&persister.kv_store),
				Arc::clone(&persister.logger),
			)?;
		}

		if !change_set.tx_graph.is_empty() {
			latest_change_set.tx_graph.merge(change_set.tx_graph.clone());
			write_bdk_wallet_tx_graph(
				&latest_change_set.tx_graph,
				Arc::clone(&persister.kv_store),
				Arc::clone(&persister.logger),
			)?;
		}

		if !change_set.local_chain.is_empty() {
			latest_change_set.local_chain.merge(change_set.local_chain.clone());
			if persister.defer_local_chain {
				// Merged in memory only; `flush_local_chain` writes the aggregate later. A crash
				// before that flush leaves an older persisted chain tip behind a fully persisted
				// transaction graph, which the next sync heals by replaying the missing blocks.
				persister.pending_local_chain.merge(change_set.local_chain.clone());
			} else {
				write_bdk_wallet_local_chain(
					&latest_change_set.local_chain,
					Arc::clone(&persister.kv_store),
					Arc::clone(&persister.logger),
				)?;
				// The aggregate just written includes anything deferred earlier.
				persister.pending_local_chain = LocalChainChangeSet::default();
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use bdk_wallet::{KeychainKind, Wallet as BdkWallet, WalletPersister};
	use bitcoin::block::{Header, Version};
	use bitcoin::hashes::Hash;
	use bitcoin::{
		absolute, transaction, Amount, Block, BlockHash, CompactTarget, Network, OutPoint,
		ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
	};
	use lightning::util::test_utils::TestStore;

	use super::KVStoreWalletPersister;
	use crate::io::utils::{read_bdk_wallet_local_chain, read_bdk_wallet_tx_graph};
	use crate::logger::Logger;
	use crate::types::DynStore;

	const EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
	const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

	/// Extends the wallet's chain by one empty block on top of its current tip and returns the
	/// new tip hash. `bdk_wallet` 2.x has no bare checkpoint insert; a block is how a tip moves.
	fn connect_empty_block(wallet: &mut BdkWallet, nonce: u32) -> BlockHash {
		let tip = wallet.latest_checkpoint();
		let block = Block {
			header: Header {
				version: Version::TWO,
				prev_blockhash: tip.hash(),
				merkle_root: TxMerkleNode::all_zeros(),
				time: 0,
				bits: CompactTarget::from_consensus(0x207f_ffff),
				nonce,
			},
			txdata: Vec::new(),
		};
		wallet.apply_block(&block, tip.height() + 1).expect("extends the tip");
		block.block_hash()
	}

	/// The heights the store's persisted local chain currently holds.
	fn persisted_heights(store: &Arc<DynStore>, logger: &Arc<Logger>) -> Vec<u32> {
		read_bdk_wallet_local_chain(Arc::clone(store), Arc::clone(logger))
			.expect("readable")
			.map(|chain| chain.blocks.keys().copied().collect())
			.unwrap_or_default()
	}

	fn persisted_txids(store: &Arc<DynStore>, logger: &Arc<Logger>) -> Vec<Txid> {
		read_bdk_wallet_tx_graph(Arc::clone(store), Arc::clone(logger))
			.expect("readable")
			.map(|graph| graph.txs.iter().map(|tx| tx.compute_txid()).collect())
			.unwrap_or_default()
	}

	#[test]
	fn persister_defers_local_chain_until_flush() {
		let logger = Arc::new(Logger::new_log_facade());
		let store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let mut persister = KVStoreWalletPersister::new(Arc::clone(&store), Arc::clone(&logger));
		let mut wallet = BdkWallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
			.network(Network::Regtest)
			.create_wallet(&mut persister)
			.expect("valid test descriptors");
		assert_eq!(persisted_heights(&store, &logger), vec![0], "genesis is written at creation");

		persister.set_defer_local_chain(true);
		connect_empty_block(&mut wallet, 1);
		let second = connect_empty_block(&mut wallet, 2);
		assert!(wallet.persist(&mut persister).expect("persist"), "there was something to stage");

		assert_eq!(
			persisted_heights(&store, &logger),
			vec![0],
			"while deferred the store still holds only the chain it had"
		);
		assert!(persister.has_pending_local_chain());

		// Funds-critical state keeps writing through: a transaction seen while deferred is on
		// disk before the chain tip that would anchor it is.
		let deposit = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint { txid: Txid::from_byte_array([7u8; 32]), vout: 0 },
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(10_000),
				script_pubkey: wallet.reveal_next_address(KeychainKind::External).script_pubkey(),
			}],
		};
		let deposit_txid = deposit.compute_txid();
		wallet.apply_unconfirmed_txs(vec![(deposit, 1)]);
		wallet.persist(&mut persister).expect("persist");
		assert_eq!(persisted_txids(&store, &logger), vec![deposit_txid]);
		assert_eq!(persisted_heights(&store, &logger), vec![0], "the chain is still held back");

		persister.flush_local_chain().expect("flush");
		assert_eq!(persisted_heights(&store, &logger), vec![0, 1, 2], "one write lands it all");
		assert!(!persister.has_pending_local_chain());

		// Nothing left to flush: a second flush is a no-op and the store is unchanged.
		persister.flush_local_chain().expect("flush");
		assert_eq!(persisted_heights(&store, &logger), vec![0, 1, 2]);

		// Off again: writes go straight through, and what was persisted survives a reload.
		persister.set_defer_local_chain(false);
		connect_empty_block(&mut wallet, 3);
		wallet.persist(&mut persister).expect("persist");
		assert_eq!(persisted_heights(&store, &logger), vec![0, 1, 2, 3]);

		let mut reloaded = KVStoreWalletPersister::new(store, logger);
		let change_set = WalletPersister::initialize(&mut reloaded).expect("initialize");
		assert_eq!(change_set.local_chain.blocks.len(), 4);
		assert_eq!(change_set.local_chain.blocks.get(&2), Some(&Some(second)));
	}

	#[test]
	fn a_direct_write_after_deferral_clears_the_backlog() {
		let logger = Arc::new(Logger::new_log_facade());
		let store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let mut persister = KVStoreWalletPersister::new(Arc::clone(&store), Arc::clone(&logger));
		let mut wallet = BdkWallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
			.network(Network::Regtest)
			.create_wallet(&mut persister)
			.expect("valid test descriptors");

		persister.set_defer_local_chain(true);
		connect_empty_block(&mut wallet, 1);
		wallet.persist(&mut persister).expect("persist");
		assert!(persister.has_pending_local_chain());

		// Deferral switched off without a flush: the next chain write carries the aggregate,
		// including the block that was held back, so the backlog is gone with it.
		persister.set_defer_local_chain(false);
		connect_empty_block(&mut wallet, 2);
		wallet.persist(&mut persister).expect("persist");
		assert_eq!(persisted_heights(&store, &logger), vec![0, 1, 2]);
		assert!(!persister.has_pending_local_chain());
	}
}
