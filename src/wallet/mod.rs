// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use persist::KVStoreWalletPersister;

use crate::config::Config;
use crate::logger::{log_debug, log_error, log_info, log_trace, LdkLogger};

use crate::fee_estimator::{ConfirmationTarget, FeeEstimator};
use crate::payment::store::ConfirmationStatus;
use crate::payment::{PaymentDetails, PaymentDirection, PaymentStatus};
use crate::types::PaymentStore;
use crate::Error;

use lightning::chain::chaininterface::BroadcasterInterface;
use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
use lightning::chain::{BestBlock, Listen};

use lightning::events::bump_transaction::{Utxo, WalletSource};
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::ln::msgs::{DecodeError, UnsignedGossipMessage};
use lightning::ln::script::ShutdownScript;
use lightning::sign::{
	ChangeDestinationSource, EntropySource, InMemorySigner, KeysManager, NodeSigner, OutputSpender,
	Recipient, SignerProvider, SpendableOutputDescriptor,
};

use lightning::util::message_signing;
use lightning_invoice::RawBolt11Invoice;

use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_wallet::{Balance, KeychainKind, PersistedWallet, SignOptions, Update};

use bitcoin::address::NetworkUnchecked;
use bitcoin::blockdata::constants::WITNESS_SCALE_FACTOR;
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Signing};
use bitcoin::{
	Address, Amount, FeeRate, Network, ScriptBuf, Transaction, TxOut, Txid, WPubkeyHash,
	WitnessProgram, WitnessVersion,
};

#[cfg(feature = "swaps")]
use bitcoin::bip32::{ChildNumber, Xpriv};
#[cfg(feature = "swaps")]
use bitcoin::secp256k1::Keypair;

use std::collections::HashMap;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

pub(crate) enum OnchainSendAmount {
	ExactRetainingReserve { amount_sats: u64, cur_anchor_reserve_sats: u64 },
	AllRetainingReserve { cur_anchor_reserve_sats: u64 },
	AllDrainingReserve,
}

pub(crate) mod persist;
pub(crate) mod ser;

pub(crate) struct Wallet<B: Deref, E: Deref, L: Deref>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	// A BDK on-chain wallet.
	inner: Mutex<PersistedWallet<KVStoreWalletPersister>>,
	persister: Mutex<KVStoreWalletPersister>,
	broadcaster: B,
	fee_estimator: E,
	payment_store: Arc<PaymentStore>,
	config: Arc<Config>,
	logger: L,
}

impl<B: Deref, E: Deref, L: Deref> Wallet<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	pub(crate) fn new(
		wallet: bdk_wallet::PersistedWallet<KVStoreWalletPersister>,
		wallet_persister: KVStoreWalletPersister, broadcaster: B, fee_estimator: E,
		payment_store: Arc<PaymentStore>, config: Arc<Config>, logger: L,
	) -> Self {
		let inner = Mutex::new(wallet);
		let persister = Mutex::new(wallet_persister);
		Self { inner, persister, broadcaster, fee_estimator, payment_store, config, logger }
	}

	pub(crate) fn get_full_scan_request(&self) -> FullScanRequest<KeychainKind> {
		self.inner.lock().unwrap().start_full_scan().build()
	}

	pub(crate) fn get_incremental_sync_request(&self) -> SyncRequest<(KeychainKind, u32)> {
		self.inner.lock().unwrap().start_sync_with_revealed_spks().build()
	}

	/// Every revealed script pubkey, with the keychain and index it came from.
	///
	/// Used by the Dependent sync engine to work out `last_active_indices`
	/// locally from a remote scan's results. Address derivation is the one
	/// thing a Dependent node must not outsource: accepting a remote opinion
	/// on which keys belong to this wallet would let a provider walk it onto
	/// keys it does not control.
	pub(crate) fn revealed_spk_index(&self) -> HashMap<ScriptBuf, (KeychainKind, u32)> {
		self.inner
			.lock()
			.unwrap()
			.spk_index()
			.revealed_spks(..)
			.map(|((keychain, index), spk)| (spk, (keychain, index)))
			.collect()
	}

	pub(crate) fn get_cached_txs(&self) -> Vec<Arc<Transaction>> {
		self.inner.lock().unwrap().tx_graph().full_txs().map(|tx_node| tx_node.tx).collect()
	}

	pub(crate) fn get_unconfirmed_txids(&self) -> Vec<Txid> {
		self.inner
			.lock()
			.unwrap()
			.transactions()
			.filter(|t| t.chain_position.is_unconfirmed())
			.map(|t| t.tx_node.txid)
			.collect()
	}

	pub(crate) fn current_best_block(&self) -> BestBlock {
		let checkpoint = self.inner.lock().unwrap().latest_checkpoint();
		BestBlock { block_hash: checkpoint.hash(), height: checkpoint.height() }
	}

	/// The wallet's chain tip as a BDK checkpoint, with its (possibly sparse) ancestry.
	///
	/// A filter-driven engine seeds its header chain from this instead of the bare
	/// [`Self::current_best_block`] so it can resume without re-fetching the ancestors.
	// Called by the filter-driven sync engine only.
	#[cfg_attr(not(feature = "cbf"), allow(dead_code))]
	pub(crate) fn latest_checkpoint(&self) -> bdk_chain::local_chain::CheckPoint {
		self.inner.lock().unwrap().latest_checkpoint()
	}

	/// How many script pubkeys [`Self::list_watched_scripts`] would return.
	///
	/// The set only ever grows — BDK reveals keys, it never forgets them — so a filter-driven
	/// engine matching thousands of block filters against it can keep a copy and refresh it
	/// only when this count moves, instead of cloning every script per filter.
	// Called by the filter-driven sync engine only.
	#[cfg_attr(not(feature = "cbf"), allow(dead_code))]
	pub(crate) fn watched_script_count(&self) -> usize {
		self.inner.lock().unwrap().spk_index().inner().all_spks().len()
	}

	/// Every script pubkey the wallet watches for on-chain activity: all revealed SPKs of both
	/// keychains plus the lookahead window BDK derives beyond the last revealed index.
	///
	/// A filter-driven engine matches blocks against this set. The lookahead matters there: a
	/// block may pay an address the wallet has not explicitly revealed yet (on recovery a fresh
	/// wallet has revealed nothing at all) but which is still inside the gap limit, and a
	/// filter that only carried revealed scripts would silently miss that deposit.
	// Called by the filter-driven sync engine only.
	#[cfg_attr(not(feature = "cbf"), allow(dead_code))]
	pub(crate) fn list_watched_scripts(&self) -> Vec<ScriptBuf> {
		self.inner.lock().unwrap().spk_index().inner().all_spks().values().cloned().collect()
	}

	/// Defers persistence of the wallet's chain tip while a bulk block-by-block sync is running.
	///
	/// See [`KVStoreWalletPersister::set_defer_local_chain`] for why only the chain is deferred
	/// and why a crash mid-sync stays recoverable. Callers pair this with
	/// [`Self::flush_chain_persistence`]; nothing flushes implicitly.
	// Called by the filter-driven sync engine only.
	#[cfg_attr(not(feature = "cbf"), allow(dead_code))]
	pub(crate) fn set_bulk_chain_persistence(&self, enabled: bool) {
		self.persister.lock().unwrap().set_defer_local_chain(enabled);
	}

	/// Persists any chain state deferred by [`Self::set_bulk_chain_persistence`].
	// Called by the filter-driven sync engine only.
	#[cfg_attr(not(feature = "cbf"), allow(dead_code))]
	pub(crate) fn flush_chain_persistence(&self) -> Result<(), Error> {
		self.persister.lock().unwrap().flush_local_chain().map_err(|e| {
			log_error!(self.logger, "Failed to flush deferred on-chain wallet chain state: {}", e);
			Error::PersistenceFailed
		})
	}

	pub(crate) fn apply_update(&self, update: impl Into<Update>) -> Result<(), Error> {
		let mut locked_wallet = self.inner.lock().unwrap();
		match locked_wallet.apply_update(update) {
			Ok(()) => {
				let mut locked_persister = self.persister.lock().unwrap();
				locked_wallet.persist(&mut locked_persister).map_err(|e| {
					log_error!(self.logger, "Failed to persist wallet: {}", e);
					Error::PersistenceFailed
				})?;

				self.update_payment_store(&mut *locked_wallet).map_err(|e| {
					log_error!(self.logger, "Failed to update payment store: {}", e);
					Error::PersistenceFailed
				})?;

				Ok(())
			},
			Err(e) => {
				log_error!(self.logger, "Sync failed due to chain connection error: {}", e);
				Err(Error::WalletOperationFailed)
			},
		}
	}

	pub(crate) fn apply_mempool_txs(
		&self, unconfirmed_txs: Vec<(Transaction, u64)>, evicted_txids: Vec<(Txid, u64)>,
	) -> Result<(), Error> {
		let mut locked_wallet = self.inner.lock().unwrap();
		locked_wallet.apply_unconfirmed_txs(unconfirmed_txs);
		locked_wallet.apply_evicted_txs(evicted_txids);

		let mut locked_persister = self.persister.lock().unwrap();
		locked_wallet.persist(&mut locked_persister).map_err(|e| {
			log_error!(self.logger, "Failed to persist wallet: {}", e);
			Error::PersistenceFailed
		})?;

		Ok(())
	}

	fn update_payment_store<'a>(
		&self, locked_wallet: &'a mut PersistedWallet<KVStoreWalletPersister>,
	) -> Result<(), Error> {
		for wtx in locked_wallet.transactions() {
			let id = PaymentId(wtx.tx_node.txid.to_byte_array());
			let txid = wtx.tx_node.txid;
			let (payment_status, confirmation_status) = match wtx.chain_position {
				bdk_chain::ChainPosition::Confirmed { anchor, .. } => {
					let confirmation_height = anchor.block_id.height;
					let cur_height = locked_wallet.latest_checkpoint().height();
					let payment_status = if cur_height >= confirmation_height + ANTI_REORG_DELAY - 1
					{
						PaymentStatus::Succeeded
					} else {
						PaymentStatus::Pending
					};
					let confirmation_status = ConfirmationStatus::Confirmed {
						block_hash: anchor.block_id.hash,
						height: confirmation_height,
						timestamp: anchor.confirmation_time,
					};
					(payment_status, confirmation_status)
				},
				bdk_chain::ChainPosition::Unconfirmed { .. } => {
					(PaymentStatus::Pending, ConfirmationStatus::Unconfirmed)
				},
			};
			// TODO: It would be great to introduce additional variants for
			// `ChannelFunding` and `ChannelClosing`. For the former, we could just
			// take a reference to `ChannelManager` here and check against
			// `list_channels`. But for the latter the best approach is much less
			// clear: for force-closes/HTLC spends we should be good querying
			// `OutputSweeper::tracked_spendable_outputs`, but regular channel closes
			// (i.e., `SpendableOutputDescriptor::StaticOutput` variants) are directly
			// spent to a wallet address. The only solution I can come up with is to
			// create and persist a list of 'static pending outputs' that we could use
			// here to determine the `PaymentKind`, but that's not really satisfactory, so
			// we're punting on it until we can come up with a better solution.
			let kind = crate::payment::PaymentKind::Onchain { txid, status: confirmation_status };
			let fee = locked_wallet.calculate_fee(&wtx.tx_node.tx).unwrap_or(Amount::ZERO);
			let (sent, received) = locked_wallet.sent_and_received(&wtx.tx_node.tx);
			let (direction, amount_msat) = if sent > received {
				let direction = PaymentDirection::Outbound;
				let amount_msat = Some(
					sent.to_sat().saturating_sub(fee.to_sat()).saturating_sub(received.to_sat())
						* 1000,
				);
				(direction, amount_msat)
			} else {
				let direction = PaymentDirection::Inbound;
				let amount_msat = Some(
					received.to_sat().saturating_sub(sent.to_sat().saturating_sub(fee.to_sat()))
						* 1000,
				);
				(direction, amount_msat)
			};

			let fee_paid_msat = Some(fee.to_sat() * 1000);

			let payment = PaymentDetails::new(
				id,
				kind,
				amount_msat,
				fee_paid_msat,
				direction,
				payment_status,
			);

			self.payment_store.insert_or_update(payment)?;
		}

		Ok(())
	}

	pub(crate) fn create_funding_transaction(
		&self, output_script: ScriptBuf, amount: Amount, confirmation_target: ConfirmationTarget,
		locktime: LockTime,
	) -> Result<Transaction, Error> {
		let fee_rate = self.fee_estimator.estimate_fee_rate(confirmation_target);

		let mut locked_wallet = self.inner.lock().unwrap();
		let mut tx_builder = locked_wallet.build_tx();

		tx_builder.add_recipient(output_script, amount).fee_rate(fee_rate).nlocktime(locktime);

		let mut psbt = match tx_builder.finish() {
			Ok(psbt) => {
				log_trace!(self.logger, "Created funding PSBT: {:?}", psbt);
				psbt
			},
			Err(err) => {
				log_error!(self.logger, "Failed to create funding transaction: {}", err);
				return Err(err.into());
			},
		};

		match locked_wallet.sign(&mut psbt, SignOptions::default()) {
			Ok(finalized) => {
				if !finalized {
					return Err(Error::OnchainTxCreationFailed);
				}
			},
			Err(err) => {
				log_error!(self.logger, "Failed to create funding transaction: {}", err);
				return Err(err.into());
			},
		}

		let mut locked_persister = self.persister.lock().unwrap();
		locked_wallet.persist(&mut locked_persister).map_err(|e| {
			log_error!(self.logger, "Failed to persist wallet: {}", e);
			Error::PersistenceFailed
		})?;

		let tx = psbt.extract_tx().map_err(|e| {
			log_error!(self.logger, "Failed to extract transaction: {}", e);
			e
		})?;

		Ok(tx)
	}

	/// Builds a fully-signed funding transaction paying `amount` to an arbitrary `output_script`
	/// (e.g. a P2WSH submarine-swap HTLC output) at the fee rate implied by `confirmation_target`,
	/// with the supplied `locktime`. The returned [`Transaction`] is signed and persisted but **not**
	/// broadcast.
	///
	/// This is a thin swaps-gated wrapper over [`Wallet::create_funding_transaction`]; it does not
	/// alter the existing behaviour of that method in any way.
	#[cfg(feature = "swaps")]
	pub(crate) fn create_swap_funding_tx(
		&self, output_script: ScriptBuf, amount: Amount, confirmation_target: ConfirmationTarget,
		locktime: LockTime,
	) -> Result<Transaction, Error> {
		self.create_funding_transaction(output_script, amount, confirmation_target, locktime)
	}

	/// Lists the wallet's confirmed, unspent outputs as [`Utxo`]s.
	///
	/// This is a thin swaps-gated inherent wrapper over the [`WalletSource::list_confirmed_utxos`]
	/// trait method. Unlike the trait method (whose error type is `()`), it surfaces a real
	/// [`Error`] so swap call sites get a meaningful failure value.
	#[cfg(feature = "swaps")]
	pub(crate) fn swap_list_confirmed_utxos(&self) -> Result<Vec<Utxo>, Error> {
		WalletSource::list_confirmed_utxos(self).map_err(|()| Error::WalletOperationFailed)
	}

	/// Signs a PSBT with the BDK wallet, returning the extracted [`Transaction`].
	///
	/// This is a thin swaps-gated inherent wrapper over the [`WalletSource::sign_psbt`] trait
	/// method. Unlike the trait method (whose error type is `()`), it surfaces a real [`Error`] so
	/// swap call sites get a meaningful failure value. As with the trait method, LDK-provided inputs
	/// are not finalized by BDK and the `finalized` bool is intentionally ignored.
	#[cfg(feature = "swaps")]
	pub(crate) fn swap_sign_psbt(&self, psbt: Psbt) -> Result<Transaction, Error> {
		WalletSource::sign_psbt(self, psbt).map_err(|()| Error::WalletOperationFailed)
	}

	pub(crate) fn get_new_address(&self) -> Result<bitcoin::Address, Error> {
		let mut locked_wallet = self.inner.lock().unwrap();
		let mut locked_persister = self.persister.lock().unwrap();

		let address_info = locked_wallet.reveal_next_address(KeychainKind::External);
		locked_wallet.persist(&mut locked_persister).map_err(|e| {
			log_error!(self.logger, "Failed to persist wallet: {}", e);
			Error::PersistenceFailed
		})?;
		Ok(address_info.address)
	}

	fn get_new_internal_address(&self) -> Result<bitcoin::Address, Error> {
		let mut locked_wallet = self.inner.lock().unwrap();
		let mut locked_persister = self.persister.lock().unwrap();

		let address_info = locked_wallet.next_unused_address(KeychainKind::Internal);
		locked_wallet.persist(&mut locked_persister).map_err(|e| {
			log_error!(self.logger, "Failed to persist wallet: {}", e);
			Error::PersistenceFailed
		})?;
		Ok(address_info.address)
	}

	pub(crate) fn get_balances(
		&self, total_anchor_channels_reserve_sats: u64,
	) -> Result<(u64, u64), Error> {
		let balance = self.inner.lock().unwrap().balance();

		// Make sure `list_confirmed_utxos` returns at least one `Utxo` we could use to spend/bump
		// Anchors if we have any confirmed amounts.
		#[cfg(debug_assertions)]
		if balance.confirmed != Amount::ZERO {
			debug_assert!(
				self.list_confirmed_utxos().map_or(false, |v| !v.is_empty()),
				"Confirmed amounts should always be available for Anchor spending"
			);
		}

		self.get_balances_inner(balance, total_anchor_channels_reserve_sats)
	}

	fn get_balances_inner(
		&self, balance: Balance, total_anchor_channels_reserve_sats: u64,
	) -> Result<(u64, u64), Error> {
		let (total, spendable) = (
			balance.total().to_sat(),
			balance.trusted_spendable().to_sat().saturating_sub(total_anchor_channels_reserve_sats),
		);

		Ok((total, spendable))
	}

	pub(crate) fn get_spendable_amount_sats(
		&self, total_anchor_channels_reserve_sats: u64,
	) -> Result<u64, Error> {
		self.get_balances(total_anchor_channels_reserve_sats).map(|(_, s)| s)
	}

	fn parse_and_validate_address(
		&self, network: Network, address: &Address,
	) -> Result<Address, Error> {
		Address::<NetworkUnchecked>::from_str(address.to_string().as_str())
			.map_err(|_| Error::InvalidAddress)?
			.require_network(network)
			.map_err(|_| Error::InvalidAddress)
	}

	pub(crate) fn send_to_address(
		&self, address: &bitcoin::Address, send_amount: OnchainSendAmount,
		fee_rate: Option<FeeRate>,
	) -> Result<Txid, Error> {
		self.parse_and_validate_address(self.config.network, &address)?;

		// Use the set fee_rate or default to fee estimation.
		let confirmation_target = ConfirmationTarget::OnchainPayment;
		let fee_rate =
			fee_rate.unwrap_or_else(|| self.fee_estimator.estimate_fee_rate(confirmation_target));

		let tx = {
			let mut locked_wallet = self.inner.lock().unwrap();

			// Prepare the tx_builder. We properly check the reserve requirements (again) further down.
			const DUST_LIMIT_SATS: u64 = 546;
			let tx_builder = match send_amount {
				OnchainSendAmount::ExactRetainingReserve { amount_sats, .. } => {
					let mut tx_builder = locked_wallet.build_tx();
					let amount = Amount::from_sat(amount_sats);
					tx_builder.add_recipient(address.script_pubkey(), amount).fee_rate(fee_rate);
					tx_builder
				},
				OnchainSendAmount::AllRetainingReserve { cur_anchor_reserve_sats }
					if cur_anchor_reserve_sats > DUST_LIMIT_SATS =>
				{
					let change_address_info = locked_wallet.peek_address(KeychainKind::Internal, 0);
					let balance = locked_wallet.balance();
					let spendable_amount_sats = self
						.get_balances_inner(balance, cur_anchor_reserve_sats)
						.map(|(_, s)| s)
						.unwrap_or(0);
					let tmp_tx = {
						let mut tmp_tx_builder = locked_wallet.build_tx();
						tmp_tx_builder
							.drain_wallet()
							.drain_to(address.script_pubkey())
							.add_recipient(
								change_address_info.address.script_pubkey(),
								Amount::from_sat(cur_anchor_reserve_sats),
							)
							.fee_rate(fee_rate);
						match tmp_tx_builder.finish() {
							Ok(psbt) => psbt.unsigned_tx,
							Err(err) => {
								log_error!(
									self.logger,
									"Failed to create temporary transaction: {}",
									err
								);
								return Err(err.into());
							},
						}
					};

					let estimated_tx_fee = locked_wallet.calculate_fee(&tmp_tx).map_err(|e| {
						log_error!(
							self.logger,
							"Failed to calculate fee of temporary transaction: {}",
							e
						);
						e
					})?;

					// 'cancel' the transaction to free up any used change addresses
					locked_wallet.cancel_tx(&tmp_tx);

					let estimated_spendable_amount = Amount::from_sat(
						spendable_amount_sats.saturating_sub(estimated_tx_fee.to_sat()),
					);

					if estimated_spendable_amount == Amount::ZERO {
						log_error!(self.logger,
							"Unable to send payment without infringing on Anchor reserves. Available: {}sats, estimated fee required: {}sats.",
							spendable_amount_sats,
							estimated_tx_fee,
						);
						return Err(Error::InsufficientFunds);
					}

					let mut tx_builder = locked_wallet.build_tx();
					tx_builder
						.add_recipient(address.script_pubkey(), estimated_spendable_amount)
						.fee_absolute(estimated_tx_fee);
					tx_builder
				},
				OnchainSendAmount::AllDrainingReserve
				| OnchainSendAmount::AllRetainingReserve { cur_anchor_reserve_sats: _ } => {
					let mut tx_builder = locked_wallet.build_tx();
					tx_builder.drain_wallet().drain_to(address.script_pubkey()).fee_rate(fee_rate);
					tx_builder
				},
			};

			let mut psbt = match tx_builder.finish() {
				Ok(psbt) => {
					log_trace!(self.logger, "Created PSBT: {:?}", psbt);
					psbt
				},
				Err(err) => {
					log_error!(self.logger, "Failed to create transaction: {}", err);
					return Err(err.into());
				},
			};

			// Check the reserve requirements (again) and return an error if they aren't met.
			match send_amount {
				OnchainSendAmount::ExactRetainingReserve {
					amount_sats,
					cur_anchor_reserve_sats,
				} => {
					let balance = locked_wallet.balance();
					let spendable_amount_sats = self
						.get_balances_inner(balance, cur_anchor_reserve_sats)
						.map(|(_, s)| s)
						.unwrap_or(0);
					let tx_fee_sats = locked_wallet
						.calculate_fee(&psbt.unsigned_tx)
						.map_err(|e| {
							log_error!(
								self.logger,
								"Failed to calculate fee of candidate transaction: {}",
								e
							);
							e
						})?
						.to_sat();
					if spendable_amount_sats < amount_sats.saturating_add(tx_fee_sats) {
						log_error!(self.logger,
							"Unable to send payment due to insufficient funds. Available: {}sats, Required: {}sats + {}sats fee",
							spendable_amount_sats,
							amount_sats,
							tx_fee_sats,
						);
						return Err(Error::InsufficientFunds);
					}
				},
				OnchainSendAmount::AllRetainingReserve { cur_anchor_reserve_sats } => {
					let balance = locked_wallet.balance();
					let spendable_amount_sats = self
						.get_balances_inner(balance, cur_anchor_reserve_sats)
						.map(|(_, s)| s)
						.unwrap_or(0);
					let (sent, received) = locked_wallet.sent_and_received(&psbt.unsigned_tx);
					let drain_amount = sent - received;
					if spendable_amount_sats < drain_amount.to_sat() {
						log_error!(self.logger,
							"Unable to send payment due to insufficient funds. Available: {}sats, Required: {}",
							spendable_amount_sats,
							drain_amount,
						);
						return Err(Error::InsufficientFunds);
					}
				},
				_ => {},
			}

			match locked_wallet.sign(&mut psbt, SignOptions::default()) {
				Ok(finalized) => {
					if !finalized {
						return Err(Error::OnchainTxCreationFailed);
					}
				},
				Err(err) => {
					log_error!(self.logger, "Failed to create transaction: {}", err);
					return Err(err.into());
				},
			}

			let mut locked_persister = self.persister.lock().unwrap();
			locked_wallet.persist(&mut locked_persister).map_err(|e| {
				log_error!(self.logger, "Failed to persist wallet: {}", e);
				Error::PersistenceFailed
			})?;

			psbt.extract_tx().map_err(|e| {
				log_error!(self.logger, "Failed to extract transaction: {}", e);
				e
			})?
		};

		self.broadcaster.broadcast_transactions(&[&tx]);

		let txid = tx.compute_txid();

		match send_amount {
			OnchainSendAmount::ExactRetainingReserve { amount_sats, .. } => {
				log_info!(
					self.logger,
					"Created new transaction {} sending {}sats on-chain to address {}",
					txid,
					amount_sats,
					address
				);
			},
			OnchainSendAmount::AllRetainingReserve { cur_anchor_reserve_sats } => {
				log_info!(
					self.logger,
					"Created new transaction {} sending available on-chain funds retaining a reserve of {}sats to address {}",
					txid,
					cur_anchor_reserve_sats,
					address,
				);
			},
			OnchainSendAmount::AllDrainingReserve => {
				log_info!(
					self.logger,
					"Created new transaction {} sending all available on-chain funds to address {}",
					txid,
					address
				);
			},
		}

		Ok(txid)
	}
}

impl<B: Deref, E: Deref, L: Deref> Listen for Wallet<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	fn filtered_block_connected(
		&self, header: &bitcoin::block::Header,
		txdata: &lightning::chain::transaction::TransactionData, height: u32,
	) {
		// A filter-driven engine hands over headers whose filter did not match with empty
		// `txdata`, and a matched block's relevant transactions otherwise. Either way the wallet
		// applies a block rebuilt from the header carrying exactly those transactions: BDK anchors
		// a transaction by block id and header time, not by its position, so a partial block
		// anchors the relevant transactions correctly, and an empty one still advances the
		// wallet's checkpoint so its chain stays contiguous with the other listeners.
		let block = bitcoin::Block {
			header: *header,
			txdata: txdata.iter().map(|(_, tx)| (*tx).clone()).collect(),
		};
		self.block_connected(&block, height);
	}

	fn block_connected(&self, block: &bitcoin::Block, height: u32) {
		let mut locked_wallet = self.inner.lock().unwrap();

		let pre_checkpoint = locked_wallet.latest_checkpoint();
		if pre_checkpoint.height() != height - 1
			|| pre_checkpoint.hash() != block.header.prev_blockhash
		{
			log_debug!(
				self.logger,
				"Detected reorg while applying a connected block to on-chain wallet: new block with hash {} at height {}",
				block.header.block_hash(),
				height
			);
		}

		match locked_wallet.apply_block(block, height) {
			Ok(()) => {
				if let Err(e) = self.update_payment_store(&mut *locked_wallet) {
					log_error!(self.logger, "Failed to update payment store: {}", e);
					return;
				}
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to apply connected block to on-chain wallet: {}",
					e
				);
				return;
			},
		};

		let mut locked_persister = self.persister.lock().unwrap();
		match locked_wallet.persist(&mut locked_persister) {
			Ok(_) => (),
			Err(e) => {
				log_error!(self.logger, "Failed to persist on-chain wallet: {}", e);
				return;
			},
		};
	}

	fn block_disconnected(&self, _header: &bitcoin::block::Header, _height: u32) {
		// This is a no-op as we don't have to tell BDK about disconnections. According to the BDK
		// team, it's sufficient in case of a reorg to always connect blocks starting from the last
		// point of disagreement.
	}
}

impl<B: Deref, E: Deref, L: Deref> WalletSource for Wallet<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	fn list_confirmed_utxos(&self) -> Result<Vec<Utxo>, ()> {
		let locked_wallet = self.inner.lock().unwrap();
		let mut utxos = Vec::new();
		let confirmed_txs: Vec<Txid> = locked_wallet
			.transactions()
			.filter(|t| t.chain_position.is_confirmed())
			.map(|t| t.tx_node.txid)
			.collect();
		let unspent_confirmed_utxos =
			locked_wallet.list_unspent().filter(|u| confirmed_txs.contains(&u.outpoint.txid));

		for u in unspent_confirmed_utxos {
			let script_pubkey = u.txout.script_pubkey;
			match script_pubkey.witness_version() {
				Some(version @ WitnessVersion::V0) => {
					// According to the SegWit rules of [BIP 141] a witness program is defined as:
					// > A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists of
					// > a 1-byte push opcode (one of OP_0,OP_1,OP_2,.. .,OP_16) followed by a direct
					// > data push between 2 and 40 bytes gets a new special meaning. The value of
					// > the first push is called the "version byte". The following byte vector
					// > pushed is called the "witness program"."
					//
					// We therefore skip the first byte we just read via `witness_version` and use
					// the rest (i.e., the data push) as the raw bytes to construct the
					// `WitnessProgram` below.
					//
					// [BIP 141]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program
					let witness_bytes = &script_pubkey.as_bytes()[2..];
					let witness_program =
						WitnessProgram::new(version, witness_bytes).map_err(|e| {
							log_error!(self.logger, "Failed to retrieve script payload: {}", e);
						})?;

					let wpkh = WPubkeyHash::from_slice(&witness_program.program().as_bytes())
						.map_err(|e| {
							log_error!(self.logger, "Failed to retrieve script payload: {}", e);
						})?;
					let utxo = Utxo::new_v0_p2wpkh(u.outpoint, u.txout.value, &wpkh);
					utxos.push(utxo);
				},
				Some(version @ WitnessVersion::V1) => {
					// According to the SegWit rules of [BIP 141] a witness program is defined as:
					// > A scriptPubKey (or redeemScript as defined in BIP16/P2SH) that consists of
					// > a 1-byte push opcode (one of OP_0,OP_1,OP_2,.. .,OP_16) followed by a direct
					// > data push between 2 and 40 bytes gets a new special meaning. The value of
					// > the first push is called the "version byte". The following byte vector
					// > pushed is called the "witness program"."
					//
					// We therefore skip the first byte we just read via `witness_version` and use
					// the rest (i.e., the data push) as the raw bytes to construct the
					// `WitnessProgram` below.
					//
					// [BIP 141]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program
					let witness_bytes = &script_pubkey.as_bytes()[2..];
					let witness_program =
						WitnessProgram::new(version, witness_bytes).map_err(|e| {
							log_error!(self.logger, "Failed to retrieve script payload: {}", e);
						})?;

					XOnlyPublicKey::from_slice(&witness_program.program().as_bytes()).map_err(
						|e| {
							log_error!(self.logger, "Failed to retrieve script payload: {}", e);
						},
					)?;

					let utxo = Utxo {
						outpoint: u.outpoint,
						output: TxOut {
							value: u.txout.value,
							script_pubkey: ScriptBuf::new_witness_program(&witness_program),
						},
						satisfaction_weight: 1 /* empty script_sig */ * WITNESS_SCALE_FACTOR as u64 +
							1 /* witness items */ + 1 /* schnorr sig len */ + 64, /* schnorr sig */
					};
					utxos.push(utxo);
				},
				Some(version) => {
					log_error!(self.logger, "Unexpected witness version: {}", version,);
				},
				None => {
					log_error!(
						self.logger,
						"Tried to use a non-witness script. This must never happen."
					);
					panic!("Tried to use a non-witness script. This must never happen.");
				},
			}
		}

		Ok(utxos)
	}

	fn get_change_script(&self) -> Result<ScriptBuf, ()> {
		let mut locked_wallet = self.inner.lock().unwrap();
		let mut locked_persister = self.persister.lock().unwrap();

		let address_info = locked_wallet.next_unused_address(KeychainKind::Internal);
		locked_wallet.persist(&mut locked_persister).map_err(|e| {
			log_error!(self.logger, "Failed to persist wallet: {}", e);
			()
		})?;
		Ok(address_info.address.script_pubkey())
	}

	fn sign_psbt(&self, mut psbt: Psbt) -> Result<Transaction, ()> {
		let locked_wallet = self.inner.lock().unwrap();

		// While BDK populates both `witness_utxo` and `non_witness_utxo` fields, LDK does not. As
		// BDK by default doesn't trust the witness UTXO to account for the Segwit bug, we must
		// disable it here as otherwise we fail to sign.
		let mut sign_options = SignOptions::default();
		sign_options.trust_witness_utxo = true;

		match locked_wallet.sign(&mut psbt, sign_options) {
			Ok(_finalized) => {
				// BDK will fail to finalize for all LDK-provided inputs of the PSBT. Unfortunately
				// we can't check more fine grained if it succeeded for all the other inputs here,
				// so we just ignore the returned `finalized` bool.
			},
			Err(err) => {
				log_error!(self.logger, "Failed to sign transaction: {}", err);
				return Err(());
			},
		}

		let tx = psbt.extract_tx().map_err(|e| {
			log_error!(self.logger, "Failed to extract transaction: {}", e);
			()
		})?;

		Ok(tx)
	}
}

/// Similar to [`KeysManager`], but overrides the destination and shutdown scripts so they are
/// directly spendable by the BDK wallet.
pub(crate) struct WalletKeysManager<B: Deref, E: Deref, L: Deref>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	inner: KeysManager,
	wallet: Arc<Wallet<B, E, L>>,
	logger: L,
	/// Dedicated swap-key derivation master (Peerswap native primitive B7).
	///
	/// Derived from the wallet seed at a hardened BIP-32 index reserved
	/// exclusively for swaps. It is fully isolated from the node identity
	/// secret key (which LDK derives at the low reserved children of the same
	/// master), so a swap keypair can NEVER coincide with the node identity.
	#[cfg(feature = "swaps")]
	swap_master_xprv: Xpriv,
}

impl<B: Deref, E: Deref, L: Deref> WalletKeysManager<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	/// Constructs a `WalletKeysManager` that overrides the destination and shutdown scripts.
	///
	/// See [`KeysManager::new`] for more information on `seed`, `starting_time_secs`, and
	/// `starting_time_nanos`.
	pub fn new(
		seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32,
		wallet: Arc<Wallet<B, E, L>>, logger: L,
	) -> Self {
		let inner = KeysManager::new(seed, starting_time_secs, starting_time_nanos);
		#[cfg(feature = "swaps")]
		let swap_master_xprv = Self::derive_swap_master_xprv(seed);
		Self {
			inner,
			wallet,
			logger,
			#[cfg(feature = "swaps")]
			swap_master_xprv,
		}
	}

	pub fn sign_message(&self, msg: &[u8]) -> String {
		message_signing::sign(msg, &self.inner.get_node_secret_key())
	}

	pub fn get_node_secret_key(&self) -> SecretKey {
		self.inner.get_node_secret_key()
	}

	pub fn verify_signature(&self, msg: &[u8], sig: &str, pkey: &PublicKey) -> bool {
		message_signing::verify(msg, sig, pkey)
	}

	/// Hardened BIP-32 child index of the dedicated swap-key domain (B7).
	///
	/// Value is the ASCII bytes of `"swap"` (`0x73776170`), which is `< 2^31`
	/// so it is a valid hardened index. It sits far outside the low children
	/// (`0..=6`) that LDK's `KeysManager` reserves for the node identity,
	/// channel, destination, shutdown, and inbound-payment keys — guaranteeing
	/// the swap key tree never overlaps the node identity secret key.
	#[cfg(feature = "swaps")]
	const SWAP_KEY_HARDENED_CHILD_INDEX: u32 = 0x7377_6170;

	/// Derives the dedicated swap-domain master xpriv from the wallet `seed`.
	///
	/// BIP-32 child-key derivation is network-independent for the secret
	/// material, so the fixed network used to construct the master only affects
	/// the (unused) serialization version bytes — never the derived keys.
	#[cfg(feature = "swaps")]
	fn derive_swap_master_xprv(seed: &[u8; 32]) -> Xpriv {
		let secp = Secp256k1::new();
		let master = Xpriv::new_master(Network::Bitcoin, seed)
			.expect("a 32-byte seed is always a valid BIP-32 master key");
		master
			.derive_priv(
				&secp,
				&[ChildNumber::Hardened { index: Self::SWAP_KEY_HARDENED_CHILD_INDEX }],
			)
			.expect("hardened derivation from a valid master key is infallible")
	}

	/// Derives a deterministic swap [`Keypair`] at `index` from the dedicated,
	/// swaps-only BIP-32 path (B7).
	///
	/// The key is derived from [`Self::swap_master_xprv`], i.e. a hardened path
	/// reserved exclusively for swaps; it is NEVER derived from the node
	/// identity secret key. The returned [`Keypair`] carries both the secret
	/// and the public key so callers can build and sign swap HTLC scripts.
	#[cfg(feature = "swaps")]
	pub(crate) fn derive_swap_keypair(&self, index: u32) -> Result<Keypair, Error> {
		swap_keypair_from_master(&self.swap_master_xprv, index).map_err(|e| {
			log_error!(self.logger, "Failed to derive swap keypair at index {}: {}", index, e);
			Error::InvalidSecretKey
		})
	}
}

/// Derives the swap [`Keypair`] at hardened `index` from an already-derived
/// swap-domain master xpriv (Peerswap native primitive B7).
///
/// Split out from [`WalletKeysManager::derive_swap_keypair`] as a generic-free,
/// `self`-free helper so the deterministic derivation can be exercised by unit
/// test vectors without constructing a full wallet/keys-manager. The instance
/// method adds error logging on top of this pure derivation. Secret material is
/// never logged here.
#[cfg(feature = "swaps")]
fn swap_keypair_from_master(master: &Xpriv, index: u32) -> Result<Keypair, bitcoin::bip32::Error> {
	let secp = Secp256k1::new();
	let child = master.derive_priv(&secp, &[ChildNumber::Hardened { index }])?;
	Ok(Keypair::from_secret_key(&secp, &child.private_key))
}

impl<B: Deref, E: Deref, L: Deref> NodeSigner for WalletKeysManager<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		self.inner.get_node_id(recipient)
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		self.inner.ecdh(recipient, other_key, tweak)
	}

	fn get_inbound_payment_key(&self) -> ExpandedKey {
		self.inner.get_inbound_payment_key()
	}

	fn sign_invoice(
		&self, invoice: &RawBolt11Invoice, recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		self.inner.sign_invoice(invoice, recipient)
	}

	fn sign_gossip_message(&self, msg: UnsignedGossipMessage<'_>) -> Result<Signature, ()> {
		self.inner.sign_gossip_message(msg)
	}

	fn sign_bolt12_invoice(
		&self, invoice: &lightning::offers::invoice::UnsignedBolt12Invoice,
	) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
		self.inner.sign_bolt12_invoice(invoice)
	}
}

impl<B: Deref, E: Deref, L: Deref> OutputSpender for WalletKeysManager<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	/// See [`KeysManager::spend_spendable_outputs`] for documentation on this method.
	fn spend_spendable_outputs<C: Signing>(
		&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>,
		change_destination_script: ScriptBuf, feerate_sat_per_1000_weight: u32,
		locktime: Option<LockTime>, secp_ctx: &Secp256k1<C>,
	) -> Result<Transaction, ()> {
		self.inner.spend_spendable_outputs(
			descriptors,
			outputs,
			change_destination_script,
			feerate_sat_per_1000_weight,
			locktime,
			secp_ctx,
		)
	}
}

impl<B: Deref, E: Deref, L: Deref> EntropySource for WalletKeysManager<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		self.inner.get_secure_random_bytes()
	}
}

impl<B: Deref, E: Deref, L: Deref> SignerProvider for WalletKeysManager<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	type EcdsaSigner = InMemorySigner;

	fn generate_channel_keys_id(
		&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128,
	) -> [u8; 32] {
		self.inner.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
	}

	fn derive_channel_signer(
		&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32],
	) -> Self::EcdsaSigner {
		self.inner.derive_channel_signer(channel_value_satoshis, channel_keys_id)
	}

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
		self.inner.read_chan_signer(reader)
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		let address = self.wallet.get_new_address().map_err(|e| {
			log_error!(self.logger, "Failed to retrieve new address from wallet: {}", e);
		})?;
		Ok(address.script_pubkey())
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		let address = self.wallet.get_new_address().map_err(|e| {
			log_error!(self.logger, "Failed to retrieve new address from wallet: {}", e);
		})?;

		match address.witness_program() {
			Some(program) => ShutdownScript::new_witness_program(&program).map_err(|e| {
				log_error!(self.logger, "Invalid shutdown script: {:?}", e);
			}),
			_ => {
				log_error!(
					self.logger,
					"Tried to use a non-witness address. This must never happen."
				);
				panic!("Tried to use a non-witness address. This must never happen.");
			},
		}
	}
}

impl<B: Deref, E: Deref, L: Deref> ChangeDestinationSource for WalletKeysManager<B, E, L>
where
	B::Target: BroadcasterInterface,
	E::Target: FeeEstimator,
	L::Target: LdkLogger,
{
	fn get_change_destination_script(&self) -> Result<ScriptBuf, ()> {
		let address = self.wallet.get_new_internal_address().map_err(|e| {
			log_error!(self.logger, "Failed to retrieve new address from wallet: {}", e);
		})?;
		Ok(address.script_pubkey())
	}
}

#[cfg(all(test, feature = "swaps"))]
mod swap_b7_tests {
	//! Test vectors for the B7 dedicated swap-key derivation.
	//!
	//! These exercise the exact production derivation path used by
	//! [`WalletKeysManager::derive_swap_keypair`] — namely
	//! [`WalletKeysManager::derive_swap_master_xprv`] (the swaps-only hardened
	//! BIP-32 domain) followed by [`swap_keypair_from_master`] — without having
	//! to construct a full BDK-backed wallet/keys-manager.

	use super::swap_keypair_from_master;
	use crate::types::KeysManager;
	use bitcoin::secp256k1::{PublicKey, Secp256k1};
	use lightning::sign::KeysManager as LdkKeysManager;

	/// Fixed 32-byte seed used by every vector below.
	const TEST_SEED: [u8; 32] = [
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
		0xe1, 0xf0,
	];

	/// Derives the swap public key for `index` from `TEST_SEED` over the full
	/// production path and returns it as a lowercase compressed-hex string.
	fn swap_pubkey_hex(index: u32) -> String {
		let master = KeysManager::derive_swap_master_xprv(&TEST_SEED);
		let keypair = swap_keypair_from_master(&master, index).expect("derivation must succeed");
		keypair.public_key().to_string()
	}

	#[test]
	fn swap_keypair_matches_fixed_vector() {
		// Fixed seed + index => fixed compressed public key. Regenerating this
		// value would signal an (unintended) change to the swap derivation path.
		assert_eq!(
			swap_pubkey_hex(0),
			"03d6c52bcef058703ff78e4d765f7b114ff5ad13f222596049b6a7bb66406bc6b6"
		);
		assert_eq!(
			swap_pubkey_hex(1),
			"0203784b06423d07485e4378ebce2eca4c7db3caa15426d52715c2414f4b0cebd9"
		);
	}

	#[test]
	fn swap_keypair_is_deterministic() {
		assert_eq!(swap_pubkey_hex(0), swap_pubkey_hex(0));
		// Distinct indices yield distinct keys.
		assert_ne!(swap_pubkey_hex(0), swap_pubkey_hex(1));
	}

	#[test]
	fn swap_key_differs_from_node_identity() {
		// The node identity secret key is what LDK's KeysManager derives from the
		// same seed. The swap key MUST come from a different (dedicated) path.
		let ldk = LdkKeysManager::new(&TEST_SEED, 0, 0);
		let node_secret = ldk.get_node_secret_key();
		let secp = Secp256k1::new();
		let node_pubkey = PublicKey::from_secret_key(&secp, &node_secret);

		let master = KeysManager::derive_swap_master_xprv(&TEST_SEED);
		for index in 0..8u32 {
			let swap_keypair =
				swap_keypair_from_master(&master, index).expect("derivation must succeed");
			assert_ne!(
				swap_keypair.secret_key(),
				node_secret,
				"swap secret at index {index} must never equal the node identity secret"
			);
			assert_ne!(
				swap_keypair.public_key(),
				node_pubkey,
				"swap pubkey at index {index} must never equal the node identity pubkey"
			);
		}
	}
}

#[cfg(test)]
mod broadcast_eviction_tests {
	//! The BDK behaviour the BROADCAST tail relies on when it evicts a
	//! rejected transaction, pinned down on a bare `bdk_wallet::Wallet` so it
	//! needs no chain source: an own unconfirmed spend takes the coins it
	//! spent out of `list_unspent`, and evicting it hands them back.
	use bdk_wallet::{KeychainKind, SignOptions, Wallet as BdkWallet};
	use bitcoin::hashes::Hash;
	use bitcoin::{
		absolute, transaction, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence,
		Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness,
	};

	const EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
	const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";
	const FUNDING_SATS: u64 = 100_000;

	fn new_wallet() -> BdkWallet {
		BdkWallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
			.network(Network::Regtest)
			.create_wallet_no_persist()
			.expect("valid test descriptors")
	}

	fn someone_elses_script() -> ScriptBuf {
		ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&[0x42u8; 33]))
	}

	/// An unconfirmed deposit into the wallet, spending an outpoint nobody checks.
	fn fund(wallet: &mut BdkWallet, last_seen: u64) -> OutPoint {
		let address = wallet.reveal_next_address(KeychainKind::External).address;
		let funding = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint { txid: Txid::from_byte_array([7u8; 32]), vout: 0 },
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(FUNDING_SATS),
				script_pubkey: address.script_pubkey(),
			}],
		};
		let outpoint = OutPoint { txid: funding.compute_txid(), vout: 0 };
		wallet.apply_unconfirmed_txs(vec![(funding, last_seen)]);
		outpoint
	}

	/// Builds, signs and returns a send of `sats` to a foreign script — exactly what
	/// `Wallet::send_to_address` does before it queues the result.
	fn build_send(wallet: &mut BdkWallet, sats: u64) -> Transaction {
		let mut builder = wallet.build_tx();
		builder
			.add_recipient(someone_elses_script(), Amount::from_sat(sats))
			.fee_rate(FeeRate::from_sat_per_vb_u32(1));
		let mut psbt = builder.finish().expect("the wallet can fund this send");
		assert!(wallet.sign(&mut psbt, SignOptions::default()).expect("signing works"));
		psbt.extract_tx().expect("finalized psbt extracts")
	}

	fn unspent_outpoints(wallet: &BdkWallet) -> Vec<OutPoint> {
		wallet.list_unspent().map(|u| u.outpoint).collect()
	}

	#[test]
	fn evicting_an_unconfirmed_spend_hands_its_inputs_back() {
		let mut wallet = new_wallet();
		let deposit = fund(&mut wallet, 1);
		let first = build_send(&mut wallet, 30_000);
		let first_txid = first.compute_txid();
		wallet.apply_unconfirmed_txs(vec![(first, 2)]);
		assert!(!unspent_outpoints(&wallet).contains(&deposit));

		// An eviction stamped no earlier than the last sighting wins (BDK: a transaction whose
		// `last_evicted >= last_seen` is no longer canonical).
		wallet.apply_evicted_txs(vec![(first_txid, 2)]);
		assert_eq!(unspent_outpoints(&wallet), vec![deposit], "the deposit is spendable again");

		// The eviction also hides the spend from the canonical view (`get_tx`)...
		assert!(wallet.get_tx(first_txid).is_none());
		// ...but the transaction itself is kept, and seeing it again later (a rebroadcast, or
		// the mempool) makes the spend canonical once more.
		let again = wallet.tx_graph().get_tx(first_txid).expect("evicted, not forgotten");
		wallet.apply_unconfirmed_txs(vec![((*again).clone(), 3)]);
		assert!(!unspent_outpoints(&wallet).contains(&deposit));
	}
}

#[cfg(test)]
mod chain_listen_tests {
	//! `Listen` on the on-chain wallet, driven the way a filter-driven engine drives it.
	use std::sync::Arc;

	use bdk_wallet::{KeychainKind, Wallet as BdkWallet};
	use bitcoin::block::{Header, Version};
	use bitcoin::hashes::Hash;
	use bitcoin::{
		absolute, transaction, Amount, BlockHash, CompactTarget, Network, ScriptBuf, Sequence,
		Transaction, TxIn, TxMerkleNode, TxOut, Witness,
	};
	use lightning::chain::Listen;
	use lightning::util::test_utils::TestStore;

	use super::persist::KVStoreWalletPersister;
	use crate::config::Config;
	use crate::fee_estimator::OnchainFeeEstimator;
	use crate::io::{
		PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE, PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
	};
	use crate::logger::Logger;
	use crate::tx_broadcaster::TransactionBroadcaster;
	use crate::types::{DynStore, PaymentStore, Wallet};

	const EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
	const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

	fn fresh_wallet() -> (Arc<Wallet>, Arc<DynStore>) {
		let logger = Arc::new(Logger::new_log_facade());
		let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
		let config = Arc::new(Config { network: Network::Regtest, ..Config::default() });
		let mut persister = KVStoreWalletPersister::new(Arc::clone(&kv_store), Arc::clone(&logger));
		let bdk_wallet = BdkWallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
			.network(Network::Regtest)
			.create_wallet(&mut persister)
			.expect("valid test descriptors");
		let payment_store = Arc::new(PaymentStore::new(
			Vec::new(),
			PAYMENT_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			PAYMENT_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			Arc::clone(&kv_store),
			Arc::clone(&logger),
		));
		let wallet = Wallet::new(
			bdk_wallet,
			persister,
			Arc::new(TransactionBroadcaster::new(Arc::clone(&logger))),
			Arc::new(OnchainFeeEstimator::new()),
			payment_store,
			config,
			logger,
		);
		(Arc::new(wallet), kv_store)
	}

	fn header_on(prev_blockhash: BlockHash, nonce: u32) -> Header {
		Header {
			version: Version::TWO,
			prev_blockhash,
			merkle_root: TxMerkleNode::all_zeros(),
			time: 1_700_000_000,
			bits: CompactTarget::from_consensus(0x207f_ffff),
			nonce,
		}
	}

	fn deposit_to(script_pubkey: ScriptBuf) -> Transaction {
		Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			// A real-looking input, so BDK does not treat the deposit as an immature coinbase.
			input: vec![TxIn {
				previous_output: bitcoin::OutPoint {
					txid: bitcoin::Txid::from_byte_array([7u8; 32]),
					vout: 0,
				},
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(50_000), script_pubkey }],
		}
	}

	#[test]
	fn a_filtered_block_advances_the_checkpoint_without_transactions() {
		let (wallet, _store) = fresh_wallet();
		let genesis = wallet.current_best_block();
		assert_eq!(genesis.height, 0);

		let header = header_on(genesis.block_hash, 1);
		wallet.filtered_block_connected(&header, &[], 1);

		let best = wallet.current_best_block();
		assert_eq!(best.height, 1);
		assert_eq!(best.block_hash, header.block_hash());
		assert_eq!(wallet.latest_checkpoint().height(), 1);
		assert!(wallet.get_cached_txs().is_empty(), "no transactions were handed over");
	}

	#[test]
	fn a_filtered_block_anchors_the_matched_transactions_it_carries() {
		let (wallet, _store) = fresh_wallet();
		let genesis = wallet.current_best_block();
		let address = wallet.get_new_address().expect("address");
		let deposit = deposit_to(address.script_pubkey());
		let txid = deposit.compute_txid();

		let header = header_on(genesis.block_hash, 2);
		wallet.filtered_block_connected(&header, &[(0, &deposit)], 1);

		assert_eq!(wallet.current_best_block().height, 1);
		let (total, spendable) = wallet.get_balances(0).expect("balances");
		assert_eq!(total, 50_000);
		assert_eq!(spendable, 50_000, "a deposit anchored in a block is confirmed");
		assert!(wallet.get_unconfirmed_txids().is_empty());
		assert!(wallet.get_cached_txs().iter().any(|tx| tx.compute_txid() == txid));
	}

	#[test]
	fn watched_scripts_cover_both_keychains_and_the_lookahead() {
		let (wallet, _store) = fresh_wallet();
		let before = wallet.list_watched_scripts();
		assert!(!before.is_empty(), "a fresh wallet already watches its lookahead window");

		let revealed = wallet.get_new_address().expect("address").script_pubkey();
		assert!(before.contains(&revealed), "the first external address was in the lookahead");

		let with_index = wallet.revealed_spk_index();
		assert_eq!(with_index.get(&revealed), Some(&(KeychainKind::External, 0)));
		assert!(wallet.list_watched_scripts().len() >= before.len());
	}
}
