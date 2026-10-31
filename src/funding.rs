// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Channels funded from somewhere other than the opening node's own on-chain wallet.
//!
//! In a process running several wallets, the coins may sit in one wallet while the channel
//! belongs to another: a fresh secondary has no on-chain funds of its own. A
//! [`FundingSource`] given to [`Node::open_channel_with_funding`] builds the funding
//! transaction when LDK asks for it (`FundingGenerationReady`), in place of the node's
//! wallet. The opening node's `ChannelManager` still broadcasts it once the peer has signed
//! — a source never broadcasts.
//!
//! [`Node::funding_source`] is the source every node can be: it funds from that node's BDK
//! wallet, reserving the inputs as the wallet does for its own channels, so the funding
//! wallet's coin selection cannot spend them while the open is in flight.
//!
//! The registry of in-flight external fundings lives in memory: an unfunded channel does not
//! survive a restart, so neither does the record of who funds it. A funding transaction
//! built before a crash stays reserved in the funding wallet's store until the wallet's sync
//! finds it in neither the mempool nor the chain and evicts it, as for its own fundings.
//!
//! [`Node::open_channel_with_funding`]: crate::Node::open_channel_with_funding
//! [`Node::funding_source`]: crate::Node::funding_source

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, FeeRate, ScriptBuf, Transaction, Txid};

use lightning::ln::types::ChannelId;

use crate::logger::{log_debug, log_error, LdkLogger, Logger};
use crate::types::Wallet;
use crate::Error;

/// What a [`FundingSource`] is asked to build: one transaction paying `amount_sats` to
/// `output_script`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingRequest {
	/// The channel's id until it is funded; [`FundingSource::release`] names it again.
	pub temporary_channel_id: ChannelId,
	/// The peer the channel is opened with.
	pub counterparty_node_id: PublicKey,
	/// The channel's funding output script (P2WSH of the 2-of-2).
	pub output_script: ScriptBuf,
	/// The channel value: the output must pay exactly this.
	pub amount_sats: u64,
	/// The fee rate the opening node would fund at, in sat per 1000 weight units.
	pub confirmation_target_sat_per_kw: u32,
	/// The locktime to set (the opening node's current height, against fee sniping).
	pub locktime: LockTime,
}

/// Builds funding transactions for channels another node opens; see the
/// [module documentation](self).
pub trait FundingSource: Send + Sync {
	/// Build and sign — but never broadcast — a transaction with exactly one output paying
	/// `req.amount_sats` to `req.output_script`, spending only segwit inputs. The opening
	/// node broadcasts it once the peer has signed the first commitment.
	///
	/// An error fails the open: the channel is closed without broadcasting anything and
	/// [`FundingSource::release`] follows.
	fn create_funding_transaction(&self, req: FundingRequest) -> Result<Transaction, Error>;

	/// The open of `temporary_channel_id` ended without its funding being broadcast: hand
	/// back whatever was reserved for it. Called at most once per open, also when
	/// [`FundingSource::create_funding_transaction`] was never called or failed (with an
	/// all-zero id if the channel could not even be created).
	fn release(&self, temporary_channel_id: ChannelId);

	/// The peer signed and the opening node broadcast the funding of
	/// `temporary_channel_id`: nothing will be released for it. The inputs stay spent in
	/// the funding wallet, as the broadcast transaction says. Optional.
	fn funded(&self, _temporary_channel_id: ChannelId) {}

	/// The broadcast policy the open asked for ([`crate::BroadcastPolicy`]), for the funding
	/// transaction `txid` this source just built. A source over an on-chain wallet registers it
	/// on that wallet's broadcast queue, so a funding refused for a missing input is held and
	/// rebroadcast like one the opening node built itself. Optional.
	fn register_broadcast_policy(&self, _txid: Txid, _policy: crate::BroadcastPolicy) {}
}

/// One open funded by a [`FundingSource`].
struct ExternalFunding {
	source: Arc<dyn FundingSource>,
	temporary_channel_id: Option<ChannelId>,
}

/// The node's in-flight external fundings, by user channel id — the one id LDK keeps
/// across `FundingGenerationReady`, `ChannelPending` and `ChannelClosed`.
#[derive(Default)]
pub(crate) struct ExternalFundings {
	entries: Mutex<HashMap<u128, ExternalFunding>>,
}

impl ExternalFundings {
	/// Records `source` for the channel about to be created with `user_channel_id`.
	/// Recorded before the channel exists, so no event can find it missing.
	pub(crate) fn insert(&self, user_channel_id: u128, source: Arc<dyn FundingSource>) {
		self.entries
			.lock()
			.unwrap()
			.insert(user_channel_id, ExternalFunding { source, temporary_channel_id: None });
	}

	/// The channel was created with `temporary_channel_id`.
	pub(crate) fn set_temporary_channel_id(
		&self, user_channel_id: u128, temporary_channel_id: ChannelId,
	) {
		if let Some(entry) = self.entries.lock().unwrap().get_mut(&user_channel_id) {
			entry.temporary_channel_id = Some(temporary_channel_id);
		}
	}

	/// The source funding `user_channel_id`, if an external one does.
	pub(crate) fn source(&self, user_channel_id: u128) -> Option<Arc<dyn FundingSource>> {
		self.entries.lock().unwrap().get(&user_channel_id).map(|e| Arc::clone(&e.source))
	}

	/// The open of `user_channel_id` ended unfunded: release its source and forget it.
	/// `temporary_channel_id` stands in when the channel never told us its own.
	pub(crate) fn release(&self, user_channel_id: u128, temporary_channel_id: ChannelId) {
		let entry = self.entries.lock().unwrap().remove(&user_channel_id);
		if let Some(entry) = entry {
			entry.source.release(entry.temporary_channel_id.unwrap_or(temporary_channel_id));
		}
	}

	/// The funding of `user_channel_id` was broadcast: tell its source and forget it.
	pub(crate) fn funded(&self, user_channel_id: u128, temporary_channel_id: Option<ChannelId>) {
		let entry = self.entries.lock().unwrap().remove(&user_channel_id);
		if let Some(entry) = entry {
			if let Some(id) = entry.temporary_channel_id.or(temporary_channel_id) {
				entry.source.funded(id);
			}
		}
	}

	#[cfg(test)]
	pub(crate) fn len(&self) -> usize {
		self.entries.lock().unwrap().len()
	}
}

/// A [`FundingSource`] over a node's own BDK wallet; see [`crate::Node::funding_source`].
pub(crate) struct WalletFundingSource {
	wallet: Arc<Wallet>,
	/// The funding transaction built per open, until it is broadcast or released.
	fundings: Mutex<HashMap<ChannelId, Txid>>,
	logger: Arc<Logger>,
}

impl WalletFundingSource {
	pub(crate) fn new(wallet: Arc<Wallet>, logger: Arc<Logger>) -> Self {
		Self { wallet, fundings: Mutex::new(HashMap::new()), logger }
	}
}

impl FundingSource for WalletFundingSource {
	fn create_funding_transaction(&self, req: FundingRequest) -> Result<Transaction, Error> {
		let fee_rate = FeeRate::from_sat_per_kwu(u64::from(req.confirmation_target_sat_per_kw));
		let tx = self.wallet.create_funding_transaction_at_fee_rate(
			req.output_script,
			Amount::from_sat(req.amount_sats),
			fee_rate,
			req.locktime,
		)?;
		log_debug!(
			self.logger,
			"Built funding transaction {} for channel {} of another node",
			tx.compute_txid(),
			req.temporary_channel_id
		);
		self.fundings.lock().unwrap().insert(req.temporary_channel_id, tx.compute_txid());
		Ok(tx)
	}

	fn release(&self, temporary_channel_id: ChannelId) {
		let txid = self.fundings.lock().unwrap().remove(&temporary_channel_id);
		if let Some(txid) = txid {
			if let Err(e) = self.wallet.release_funding_transaction(txid) {
				log_error!(
					self.logger,
					"Failed to release the inputs of funding transaction {}: {}",
					txid,
					e
				);
			}
		}
	}

	fn funded(&self, temporary_channel_id: ChannelId) {
		self.fundings.lock().unwrap().remove(&temporary_channel_id);
	}

	fn register_broadcast_policy(&self, txid: Txid, policy: crate::BroadcastPolicy) {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		self.wallet.broadcast_queue().register(txid, policy, now);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::time::{Duration, Instant};

	use bitcoin::hashes::Hash;
	use bitcoin::Network;
	use bitcoin::{transaction, OutPoint, Sequence, TxIn, TxOut, Witness};
	use lightning::ln::msgs::SocketAddress;
	use lightning::util::test_utils::TestStore;

	use crate::config::Config;
	use crate::{Builder, Node};

	/// Records what it is asked and answers with `answer`.
	struct FakeSource {
		requests: Mutex<Vec<FundingRequest>>,
		released: Mutex<Vec<ChannelId>>,
		answer: fn(&FundingRequest) -> Result<Transaction, Error>,
	}

	impl FakeSource {
		fn new(answer: fn(&FundingRequest) -> Result<Transaction, Error>) -> Arc<Self> {
			Arc::new(Self {
				requests: Mutex::new(Vec::new()),
				released: Mutex::new(Vec::new()),
				answer,
			})
		}
	}

	impl FundingSource for FakeSource {
		fn create_funding_transaction(&self, req: FundingRequest) -> Result<Transaction, Error> {
			let answer = (self.answer)(&req);
			self.requests.lock().unwrap().push(req);
			answer
		}

		fn release(&self, temporary_channel_id: ChannelId) {
			self.released.lock().unwrap().push(temporary_channel_id);
		}
	}

	/// A node with no chain to reach and no anchors: enough to negotiate a channel up to
	/// `FundingGenerationReady` without a coin of its own.
	fn node(seed: u8, listening: Option<u16>) -> Node {
		let mut config = Config::default();
		config.network = Network::Regtest;
		config.anchor_channels_config = None;
		config.listening_addresses =
			listening.map(|port| vec![SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port }]);
		let mut builder = Builder::from_config(config);
		builder.set_log_facade_logger();
		builder.set_entropy_seed_bytes([seed; 64]);
		builder.set_chain_source_esplora("http://127.0.0.1:1".to_string(), None);
		builder.build_with_store(Arc::new(TestStore::new(false))).unwrap()
	}

	fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
		let deadline = Instant::now() + Duration::from_secs(20);
		while !done() {
			assert!(Instant::now() < deadline, "timed out waiting for {}", what);
			std::thread::sleep(Duration::from_millis(20));
		}
	}

	/// Opens a 100 000 sat channel from a fresh node to a fresh peer, funded by `source`,
	/// and waits until the source was released.
	fn open_failing_external_funding(source: Arc<FakeSource>, seeds: (u8, u8)) {
		let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
		let peer = node(seeds.1, Some(port));
		peer.start().unwrap();
		let opener = node(seeds.0, None);
		opener.start().unwrap();

		let address = SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port };
		opener
			.open_channel_with_funding(
				peer.node_id(),
				address,
				100_000,
				None,
				None,
				false,
				Arc::clone(&source) as Arc<dyn FundingSource>,
			)
			.expect("an opener without coins may open a channel someone else funds");

		wait_until("the source to be released", || !source.released.lock().unwrap().is_empty());
		wait_until("the channel to be gone", || opener.list_channels().is_empty());

		let requests = source.requests.lock().unwrap().clone();
		assert_eq!(requests.len(), 1, "asked once, at FundingGenerationReady");
		let request = &requests[0];
		assert_eq!(request.counterparty_node_id, peer.node_id());
		assert_eq!(request.amount_sats, 100_000);
		assert!(request.output_script.is_p2wsh(), "the 2-of-2 funding output");
		assert!(request.confirmation_target_sat_per_kw >= 253);
		assert_eq!(
			*source.released.lock().unwrap(),
			vec![request.temporary_channel_id],
			"released once, for the channel it was asked about"
		);
		assert_eq!(opener.external_fundings.len(), 0, "the open is forgotten");

		opener.stop().unwrap();
		peer.stop().unwrap();
	}

	#[test]
	fn a_source_that_cannot_fund_fails_the_open_and_is_released() {
		open_failing_external_funding(FakeSource::new(|_| Err(Error::InsufficientFunds)), (71, 72));
	}

	/// A source's bad transaction (an unsigned input) is refused by LDK; that is a failed
	/// open, not the panic the node's own wallet would get.
	#[test]
	fn a_transaction_ldk_refuses_fails_the_open_without_a_panic() {
		open_failing_external_funding(
			FakeSource::new(|req| {
				Ok(Transaction {
					version: transaction::Version::TWO,
					lock_time: req.locktime,
					input: vec![TxIn {
						previous_output: OutPoint {
							txid: Txid::from_byte_array([5u8; 32]),
							vout: 0,
						},
						script_sig: ScriptBuf::new(),
						sequence: Sequence::MAX,
						witness: Witness::new(),
					}],
					output: vec![TxOut {
						value: Amount::from_sat(req.amount_sats),
						script_pubkey: req.output_script.clone(),
					}],
				})
			}),
			(73, 74),
		);
	}
}
