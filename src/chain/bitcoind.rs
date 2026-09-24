// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::fee_estimator::OnchainFeeEstimator;
use crate::logger::{log_debug, log_error, log_info, LdkLogger, Logger};
use crate::types::{Broadcaster, ChainMonitor, ChannelManager, Sweeper, Wallet};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bitcoin::block::Header;
use bitcoin::{BlockHash, FeeRate, Transaction, Txid};
use lightning::chain::transaction::{OutPoint, TransactionData};
use lightning::chain::{BestBlock, Listen};
use lightning_block_sync::gossip::UtxoSource;
use lightning_block_sync::http::{HttpEndpoint, JsonResponse};
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::rest::RestClient;
use lightning_block_sync::rpc::{RpcClient, RpcError};
use lightning_block_sync::{
	AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, Cache,
};

use serde::Serialize;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub enum BitcoindClient {
	Rpc {
		rpc_client: Arc<RpcClient>,
		latest_mempool_timestamp: AtomicU64,
		mempool_entries_cache: tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
		mempool_txs_cache: tokio::sync::Mutex<HashMap<Txid, (Transaction, u64)>>,
	},
	Rest {
		rest_client: Arc<RestClient>,
		rpc_client: Arc<RpcClient>,
		latest_mempool_timestamp: AtomicU64,
		mempool_entries_cache: tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
		mempool_txs_cache: tokio::sync::Mutex<HashMap<Txid, (Transaction, u64)>>,
	},
}

impl BitcoindClient {
	/// Creates a new RPC API client for the chain interactions with Bitcoin Core.
	pub(crate) fn new_rpc(host: String, port: u16, rpc_user: String, rpc_password: String) -> Self {
		let http_endpoint = endpoint(host, port);
		let rpc_credentials = rpc_credentials(rpc_user, rpc_password);

		let rpc_client = Arc::new(RpcClient::new(&rpc_credentials, http_endpoint));

		let latest_mempool_timestamp = AtomicU64::new(0);

		let mempool_entries_cache = tokio::sync::Mutex::new(HashMap::new());
		let mempool_txs_cache = tokio::sync::Mutex::new(HashMap::new());
		Self::Rpc { rpc_client, latest_mempool_timestamp, mempool_entries_cache, mempool_txs_cache }
	}

	/// Creates a new, primarily REST API client for the chain interactions
	/// with Bitcoin Core.
	///
	/// Aside the required REST host and port, we provide RPC configuration
	/// options for necessary calls not supported by the REST interface.
	pub(crate) fn new_rest(
		rest_host: String, rest_port: u16, rpc_host: String, rpc_port: u16, rpc_user: String,
		rpc_password: String,
	) -> Self {
		let rest_endpoint = endpoint(rest_host, rest_port).with_path("/rest".to_string());
		let rest_client = Arc::new(RestClient::new(rest_endpoint));

		let rpc_endpoint = endpoint(rpc_host, rpc_port);
		let rpc_credentials = rpc_credentials(rpc_user, rpc_password);
		let rpc_client = Arc::new(RpcClient::new(&rpc_credentials, rpc_endpoint));

		let latest_mempool_timestamp = AtomicU64::new(0);

		let mempool_entries_cache = tokio::sync::Mutex::new(HashMap::new());
		let mempool_txs_cache = tokio::sync::Mutex::new(HashMap::new());

		Self::Rest {
			rest_client,
			rpc_client,
			latest_mempool_timestamp,
			mempool_entries_cache,
			mempool_txs_cache,
		}
	}

	pub(crate) fn utxo_source(&self) -> Arc<dyn UtxoSource> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => Arc::clone(rpc_client) as Arc<dyn UtxoSource>,
			BitcoindClient::Rest { rest_client, .. } => {
				Arc::clone(rest_client) as Arc<dyn UtxoSource>
			},
		}
	}

	/// Broadcasts the provided transaction.
	pub(crate) async fn broadcast_transaction(&self, tx: &Transaction) -> std::io::Result<Txid> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::broadcast_transaction_inner(Arc::clone(rpc_client), tx).await
			},
			BitcoindClient::Rest { rpc_client, .. } => {
				// Bitcoin Core's REST interface does not support broadcasting transactions
				// so we use the RPC client.
				Self::broadcast_transaction_inner(Arc::clone(rpc_client), tx).await
			},
		}
	}

	async fn broadcast_transaction_inner(
		rpc_client: Arc<RpcClient>, tx: &Transaction,
	) -> std::io::Result<Txid> {
		let tx_serialized = bitcoin::consensus::encode::serialize_hex(tx);
		let tx_json = serde_json::json!(tx_serialized);
		rpc_client.call_method::<Txid>("sendrawtransaction", &[tx_json]).await
	}

	/// Retrieve the fee estimate needed for a transaction to begin
	/// confirmation within the provided `num_blocks`.
	pub(crate) async fn get_fee_estimate_for_target(
		&self, num_blocks: usize, estimation_mode: FeeRateEstimationMode,
	) -> std::io::Result<FeeRate> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_fee_estimate_for_target_inner(
					Arc::clone(rpc_client),
					num_blocks,
					estimation_mode,
				)
				.await
			},
			BitcoindClient::Rest { rpc_client, .. } => {
				// We rely on the internal RPC client to make this call, as this
				// operation is not supported by Bitcoin Core's REST interface.
				Self::get_fee_estimate_for_target_inner(
					Arc::clone(rpc_client),
					num_blocks,
					estimation_mode,
				)
				.await
			},
		}
	}

	/// Estimate the fee rate for the provided target number of blocks.
	async fn get_fee_estimate_for_target_inner(
		rpc_client: Arc<RpcClient>, num_blocks: usize, estimation_mode: FeeRateEstimationMode,
	) -> std::io::Result<FeeRate> {
		let num_blocks_json = serde_json::json!(num_blocks);
		let estimation_mode_json = serde_json::json!(estimation_mode);
		rpc_client
			.call_method::<FeeResponse>(
				"estimatesmartfee",
				&[num_blocks_json, estimation_mode_json],
			)
			.await
			.map(|resp| resp.0)
	}

	/// Gets the mempool minimum fee rate.
	pub(crate) async fn get_mempool_minimum_fee_rate(&self) -> std::io::Result<FeeRate> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_mempool_minimum_fee_rate_rpc(Arc::clone(rpc_client)).await
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Self::get_mempool_minimum_fee_rate_rest(Arc::clone(rest_client)).await
			},
		}
	}

	/// Get the mempool minimum fee rate via RPC interface.
	async fn get_mempool_minimum_fee_rate_rpc(
		rpc_client: Arc<RpcClient>,
	) -> std::io::Result<FeeRate> {
		rpc_client
			.call_method::<MempoolMinFeeResponse>("getmempoolinfo", &[])
			.await
			.map(|resp| resp.0)
	}

	/// Get the mempool minimum fee rate via REST interface.
	async fn get_mempool_minimum_fee_rate_rest(
		rest_client: Arc<RestClient>,
	) -> std::io::Result<FeeRate> {
		rest_client
			.request_resource::<JsonResponse, MempoolMinFeeResponse>("mempool/info.json")
			.await
			.map(|resp| resp.0)
	}

	/// Gets the raw transaction for the provided transaction ID. Returns `None` if not found.
	pub(crate) async fn get_raw_transaction(
		&self, txid: &Txid,
	) -> std::io::Result<Option<Transaction>> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_raw_transaction_rpc(Arc::clone(rpc_client), txid).await
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Self::get_raw_transaction_rest(Arc::clone(rest_client), txid).await
			},
		}
	}

	/// Retrieve raw transaction for provided transaction ID via the RPC interface.
	async fn get_raw_transaction_rpc(
		rpc_client: Arc<RpcClient>, txid: &Txid,
	) -> std::io::Result<Option<Transaction>> {
		let txid_hex = txid_to_rpc_hex(txid);
		let txid_json = serde_json::json!(txid_hex);
		match rpc_client
			.call_method::<GetRawTransactionResponse>("getrawtransaction", &[txid_json])
			.await
		{
			Ok(resp) => Ok(Some(resp.0)),
			Err(e) => match e.into_inner() {
				Some(inner) => {
					let rpc_error_res: Result<Box<RpcError>, _> = inner.downcast();

					match rpc_error_res {
						Ok(rpc_error) => {
							// Check if it's the 'not found' error code.
							if rpc_error.code == -5 {
								Ok(None)
							} else {
								Err(std::io::Error::new(std::io::ErrorKind::Other, rpc_error))
							}
						},
						Err(_) => Err(std::io::Error::new(
							std::io::ErrorKind::Other,
							"Failed to process getrawtransaction response",
						)),
					}
				},
				None => Err(std::io::Error::new(
					std::io::ErrorKind::Other,
					"Failed to process getrawtransaction response",
				)),
			},
		}
	}

	/// Retrieve raw transaction for provided transaction ID via the REST interface.
	async fn get_raw_transaction_rest(
		rest_client: Arc<RestClient>, txid: &Txid,
	) -> std::io::Result<Option<Transaction>> {
		let txid_hex = txid_to_rpc_hex(txid);
		let tx_path = format!("tx/{}.json", txid_hex);
		match rest_client
			.request_resource::<JsonResponse, GetRawTransactionResponse>(&tx_path)
			.await
		{
			Ok(resp) => Ok(Some(resp.0)),
			Err(e) => match e.kind() {
				std::io::ErrorKind::Other => {
					match e.into_inner() {
						Some(inner) => {
							let http_error_res: Result<Box<HttpError>, _> = inner.downcast();
							match http_error_res {
								Ok(http_error) => {
									// Check if it's the HTTP NOT_FOUND error code.
									if &http_error.status_code == "404" {
										Ok(None)
									} else {
										Err(std::io::Error::new(
											std::io::ErrorKind::Other,
											http_error,
										))
									}
								},
								Err(_) => {
									let error_msg =
										format!("Failed to process {} response.", tx_path);
									Err(std::io::Error::new(
										std::io::ErrorKind::Other,
										error_msg.as_str(),
									))
								},
							}
						},
						None => {
							let error_msg = format!("Failed to process {} response.", tx_path);
							Err(std::io::Error::new(std::io::ErrorKind::Other, error_msg.as_str()))
						},
					}
				},
				_ => {
					let error_msg = format!("Failed to process {} response.", tx_path);
					Err(std::io::Error::new(std::io::ErrorKind::Other, error_msg.as_str()))
				},
			},
		}
	}

	/// Confirmation depth for an ARBITRARY `txid` via verbose `getrawtransaction`
	/// (Peerswap native primitive B5).
	///
	/// To locate a tx by its id alone (the swap case — a counterparty opening tx
	/// that is not in our wallet), the backend must be able to find it, i.e. a
	/// `-txindex` node (or the tx still resident in the mempool). Returns:
	/// - `Ok(Some(n))` with `n >= 1` for a tx confirmed `n` blocks deep,
	/// - `Ok(Some(0))` for a tx seen in the mempool but unconfirmed,
	/// - `Ok(None)` when the node does not know the tx (RPC error code -5),
	/// - `Err(..)` for any transport/other failure, so the caller fails closed.
	#[cfg(feature = "swaps")]
	pub(crate) async fn swap_tx_confirmations(&self, txid: &Txid) -> std::io::Result<Option<u32>> {
		let rpc_client = match self {
			BitcoindClient::Rpc { rpc_client, .. } => Arc::clone(rpc_client),
			BitcoindClient::Rest { rpc_client, .. } => Arc::clone(rpc_client),
		};
		// Display order, as every txid handed to Core must be (see
		// [`txid_to_rpc_hex`]): the reversed hex is answered with -5, which is
		// mapped to `Ok(None)` below, so the swap watcher would mistake EVERY
		// confirmed opening tx for NotFound and never arm the confirmation/CSV
		// ladder — wedging every swap on the bitcoind backend.
		let txid_hex = txid_to_rpc_hex(txid);
		let txid_json = serde_json::json!(txid_hex);
		let verbose_json = serde_json::json!(true);
		match rpc_client
			.call_method::<SwapTxConfirmationResponse>(
				"getrawtransaction",
				&[txid_json, verbose_json],
			)
			.await
		{
			Ok(resp) => Ok(Some(resp.0)),
			Err(e) => match e.into_inner() {
				Some(inner) => {
					let rpc_error_res: Result<Box<RpcError>, _> = inner.downcast();

					match rpc_error_res {
						Ok(rpc_error) => {
							// -5 == "No such mempool or blockchain transaction".
							if rpc_error.code == -5 {
								Ok(None)
							} else {
								Err(std::io::Error::new(std::io::ErrorKind::Other, rpc_error))
							}
						},
						Err(_) => Err(std::io::Error::new(
							std::io::ErrorKind::Other,
							"Failed to process verbose getrawtransaction response",
						)),
					}
				},
				None => Err(std::io::Error::new(
					std::io::ErrorKind::Other,
					"Failed to process verbose getrawtransaction response",
				)),
			},
		}
	}

	/// Retrieves the raw mempool.
	pub(crate) async fn get_raw_mempool(&self) -> std::io::Result<Vec<Txid>> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_raw_mempool_rpc(Arc::clone(rpc_client)).await
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Self::get_raw_mempool_rest(Arc::clone(rest_client)).await
			},
		}
	}

	/// Retrieves the raw mempool via the RPC interface.
	async fn get_raw_mempool_rpc(rpc_client: Arc<RpcClient>) -> std::io::Result<Vec<Txid>> {
		let verbose_flag_json = serde_json::json!(false);
		rpc_client
			.call_method::<GetRawMempoolResponse>("getrawmempool", &[verbose_flag_json])
			.await
			.map(|resp| resp.0)
	}

	/// Retrieves the raw mempool via the REST interface.
	async fn get_raw_mempool_rest(rest_client: Arc<RestClient>) -> std::io::Result<Vec<Txid>> {
		rest_client
			.request_resource::<JsonResponse, GetRawMempoolResponse>(
				"mempool/contents.json?verbose=false",
			)
			.await
			.map(|resp| resp.0)
	}

	/// Retrieves an entry from the mempool if it exists, else return `None`.
	pub(crate) async fn get_mempool_entry(
		&self, txid: Txid,
	) -> std::io::Result<Option<MempoolEntry>> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Self::get_mempool_entry_inner(Arc::clone(rpc_client), txid).await
			},
			BitcoindClient::Rest { rpc_client, .. } => {
				Self::get_mempool_entry_inner(Arc::clone(rpc_client), txid).await
			},
		}
	}

	/// Retrieves the mempool entry of the provided transaction ID.
	async fn get_mempool_entry_inner(
		client: Arc<RpcClient>, txid: Txid,
	) -> std::io::Result<Option<MempoolEntry>> {
		let txid_hex = txid_to_rpc_hex(&txid);
		let txid_json = serde_json::json!(txid_hex);

		match client.call_method::<GetMempoolEntryResponse>("getmempoolentry", &[txid_json]).await {
			Ok(resp) => Ok(Some(MempoolEntry { txid, time: resp.time, height: resp.height })),
			Err(e) => match e.into_inner() {
				Some(inner) => {
					let rpc_error_res: Result<Box<RpcError>, _> = inner.downcast();

					match rpc_error_res {
						Ok(rpc_error) => {
							// Check if it's the 'not found' error code.
							if rpc_error.code == -5 {
								Ok(None)
							} else {
								Err(std::io::Error::new(std::io::ErrorKind::Other, rpc_error))
							}
						},
						Err(_) => Err(std::io::Error::new(
							std::io::ErrorKind::Other,
							"Failed to process getmempoolentry response",
						)),
					}
				},
				None => Err(std::io::Error::new(
					std::io::ErrorKind::Other,
					"Failed to process getmempoolentry response",
				)),
			},
		}
	}

	pub(crate) async fn update_mempool_entries_cache(&self) -> std::io::Result<()> {
		match self {
			BitcoindClient::Rpc { mempool_entries_cache, .. } => {
				self.update_mempool_entries_cache_inner(mempool_entries_cache).await
			},
			BitcoindClient::Rest { mempool_entries_cache, .. } => {
				self.update_mempool_entries_cache_inner(mempool_entries_cache).await
			},
		}
	}

	async fn update_mempool_entries_cache_inner(
		&self, mempool_entries_cache: &tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
	) -> std::io::Result<()> {
		let mempool_txids = self.get_raw_mempool().await?;

		let mut mempool_entries_cache = mempool_entries_cache.lock().await;
		mempool_entries_cache.retain(|txid, _| mempool_txids.contains(txid));

		if let Some(difference) = mempool_txids.len().checked_sub(mempool_entries_cache.capacity())
		{
			mempool_entries_cache.reserve(difference)
		}

		for txid in mempool_txids {
			if mempool_entries_cache.contains_key(&txid) {
				continue;
			}

			if let Some(entry) = self.get_mempool_entry(txid).await? {
				mempool_entries_cache.insert(txid, entry.clone());
			}
		}

		mempool_entries_cache.shrink_to_fit();

		Ok(())
	}

	/// Returns two `Vec`s:
	/// - mempool transactions, alongside their first-seen unix timestamps.
	/// - transactions that have been evicted from the mempool, alongside the last time they were seen absent.
	pub(crate) async fn get_updated_mempool_transactions(
		&self, best_processed_height: u32, unconfirmed_txids: Vec<Txid>,
	) -> std::io::Result<(Vec<(Transaction, u64)>, Vec<(Txid, u64)>)> {
		let mempool_txs =
			self.get_mempool_transactions_and_timestamp_at_height(best_processed_height).await?;
		let evicted_txids = self.get_evicted_mempool_txids_and_timestamp(unconfirmed_txids).await?;
		Ok((mempool_txs, evicted_txids))
	}

	/// Every transaction in the mempool that `relevant` accepts, with its
	/// first-seen unix timestamp, as of now — the whole mempool, not what
	/// changed since the last poll.
	///
	/// Shares the two caches with [`Self::get_updated_mempool_transactions`]
	/// but never touches that poll's emit-once watermark
	/// (`latest_mempool_timestamp`). The two are asked by different parties —
	/// the poll by this node's own wallet, this by another node through the
	/// serving path — and a snapshot that advanced the watermark would make
	/// the next poll skip, as already emitted, transactions the local wallet
	/// was never told about. The entries cache is refreshed first, so the
	/// answer is as current as a poll's; a transaction fetched here is cached
	/// for the poll, and vice versa, so the cost above a poll's is only the
	/// walk of the entries cache and the clone of the accepted transactions.
	/// `relevant` runs before the clone, because on mainnet the whole mempool
	/// is far too large to hand out.
	pub(crate) async fn get_mempool_snapshot(
		&self, relevant: impl Fn(&Transaction) -> bool + Send,
	) -> std::io::Result<Vec<(Transaction, u64)>> {
		let (mempool_entries_cache, mempool_txs_cache) = match self {
			BitcoindClient::Rpc { mempool_entries_cache, mempool_txs_cache, .. }
			| BitcoindClient::Rest { mempool_entries_cache, mempool_txs_cache, .. } => {
				(mempool_entries_cache, mempool_txs_cache)
			},
		};

		self.update_mempool_entries_cache().await?;

		// Same lock order as the poll: entries, then transactions.
		let mempool_entries_cache = mempool_entries_cache.lock().await;
		let mut mempool_txs_cache = mempool_txs_cache.lock().await;
		mempool_txs_cache.retain(|txid, _| mempool_entries_cache.contains_key(txid));

		let mut accepted = Vec::new();
		for (txid, entry) in mempool_entries_cache.iter() {
			if let Some((cached_tx, cached_time)) = mempool_txs_cache.get(txid) {
				if relevant(cached_tx) {
					accepted.push((cached_tx.clone(), *cached_time));
				}
				continue;
			}

			match self.get_raw_transaction(&entry.txid).await? {
				Some(tx) => {
					if relevant(&tx) {
						accepted.push((tx.clone(), entry.time));
					}
					mempool_txs_cache.insert(entry.txid, (tx, entry.time));
				},
				None => continue,
			}
		}
		Ok(accepted)
	}

	/// Which of `txids` the mempool no longer holds, as of the entries
	/// cache's last refresh — a refresh [`Self::get_mempool_snapshot`] and
	/// [`Self::get_mempool_transactions_and_timestamp_at_height`] have each
	/// just done when called together with this. The one definition of
	/// "evicted" ([`txids_missing_from`]), whichever scope asks.
	pub(crate) async fn txids_missing_from_mempool(&self, txids: &[Txid]) -> Vec<Txid> {
		let mempool_entries_cache = match self {
			BitcoindClient::Rpc { mempool_entries_cache, .. }
			| BitcoindClient::Rest { mempool_entries_cache, .. } => mempool_entries_cache,
		};
		let mempool_entries_cache = mempool_entries_cache.lock().await;
		txids_missing_from(&mempool_entries_cache, txids)
	}

	/// Get mempool transactions, alongside their first-seen unix timestamps.
	///
	/// This method is an adapted version of `bdk_bitcoind_rpc::Emitter::mempool`. It emits each
	/// transaction only once, unless we cannot assume the transaction's ancestors are already
	/// emitted.
	pub(crate) async fn get_mempool_transactions_and_timestamp_at_height(
		&self, best_processed_height: u32,
	) -> std::io::Result<Vec<(Transaction, u64)>> {
		match self {
			BitcoindClient::Rpc {
				latest_mempool_timestamp,
				mempool_entries_cache,
				mempool_txs_cache,
				..
			} => {
				self.get_mempool_transactions_and_timestamp_at_height_inner(
					latest_mempool_timestamp,
					mempool_entries_cache,
					mempool_txs_cache,
					best_processed_height,
				)
				.await
			},
			BitcoindClient::Rest {
				latest_mempool_timestamp,
				mempool_entries_cache,
				mempool_txs_cache,
				..
			} => {
				self.get_mempool_transactions_and_timestamp_at_height_inner(
					latest_mempool_timestamp,
					mempool_entries_cache,
					mempool_txs_cache,
					best_processed_height,
				)
				.await
			},
		}
	}

	async fn get_mempool_transactions_and_timestamp_at_height_inner(
		&self, latest_mempool_timestamp: &AtomicU64,
		mempool_entries_cache: &tokio::sync::Mutex<HashMap<Txid, MempoolEntry>>,
		mempool_txs_cache: &tokio::sync::Mutex<HashMap<Txid, (Transaction, u64)>>,
		best_processed_height: u32,
	) -> std::io::Result<Vec<(Transaction, u64)>> {
		let prev_mempool_time = latest_mempool_timestamp.load(Ordering::Relaxed);
		let mut latest_time = prev_mempool_time;

		self.update_mempool_entries_cache().await?;

		let mempool_entries_cache = mempool_entries_cache.lock().await;
		let mut mempool_txs_cache = mempool_txs_cache.lock().await;
		mempool_txs_cache.retain(|txid, _| mempool_entries_cache.contains_key(txid));

		if let Some(difference) =
			mempool_entries_cache.len().checked_sub(mempool_txs_cache.capacity())
		{
			mempool_txs_cache.reserve(difference)
		}

		let mut txs_to_emit = Vec::with_capacity(mempool_entries_cache.len());
		for (txid, entry) in mempool_entries_cache.iter() {
			if entry.time > latest_time {
				latest_time = entry.time;
			}

			// Avoid emitting transactions that are already emitted if we can guarantee
			// blocks containing ancestors are already emitted. The bitcoind rpc interface
			// provides us with the block height that the tx is introduced to the mempool.
			// If we have already emitted the block of height, we can assume that all
			// ancestor txs have been processed by the receiver.
			let ancestor_within_height = entry.height <= best_processed_height;
			let is_already_emitted = entry.time <= prev_mempool_time;
			if is_already_emitted && ancestor_within_height {
				continue;
			}

			if let Some((cached_tx, cached_time)) = mempool_txs_cache.get(txid) {
				txs_to_emit.push((cached_tx.clone(), *cached_time));
				continue;
			}

			match self.get_raw_transaction(&entry.txid).await {
				Ok(Some(tx)) => {
					mempool_txs_cache.insert(entry.txid, (tx.clone(), entry.time));
					txs_to_emit.push((tx, entry.time));
				},
				Ok(None) => {
					continue;
				},
				Err(e) => return Err(e),
			};
		}

		if !txs_to_emit.is_empty() {
			latest_mempool_timestamp.store(latest_time, Ordering::Release);
		}
		Ok(txs_to_emit)
	}

	// Retrieve a list of Txids that have been evicted from the mempool.
	//
	// The poll this follows has just refreshed the local mempool_entries_cache, so
	// every unconfirmed wallet `Txid` the cache lacks is one the mempool no longer
	// holds. Each is stamped with the poll's watermark — the latest mempool time
	// seen — as the time it was last seen absent.
	async fn get_evicted_mempool_txids_and_timestamp(
		&self, unconfirmed_txids: Vec<Txid>,
	) -> std::io::Result<Vec<(Txid, u64)>> {
		let latest_mempool_timestamp = match self {
			BitcoindClient::Rpc { latest_mempool_timestamp, .. }
			| BitcoindClient::Rest { latest_mempool_timestamp, .. } => latest_mempool_timestamp,
		}
		.load(Ordering::Relaxed);
		let evicted_txids = self
			.txids_missing_from_mempool(&unconfirmed_txids)
			.await
			.into_iter()
			.map(|txid| (txid, latest_mempool_timestamp))
			.collect();
		Ok(evicted_txids)
	}
}

/// Which of `txids` `mempool_entries` — the entries cache, as of its last
/// refresh — does not contain: the one definition of "evicted" for both the
/// wallet's incremental poll and the snapshot served to another node. A txid
/// the cache still holds is in the mempool, not evicted; the pre-seam filter
/// had this inverted, reporting exactly the transactions that were still
/// there, and never a real eviction (upstream ldk-node 3fe4f2f).
fn txids_missing_from(mempool_entries: &HashMap<Txid, MempoolEntry>, txids: &[Txid]) -> Vec<Txid> {
	txids.iter().copied().filter(|txid| !mempool_entries.contains_key(txid)).collect()
}

/// A txid as Bitcoin Core's RPC and REST interfaces speak it: display order,
/// the byte-reversed hex `Txid`'s `Display` prints — never consensus byte
/// order. `consensus::encode::serialize_hex` emits the internal bytes, i.e.
/// the reversed string, which Core answers with -5 "No such mempool or
/// blockchain transaction" (RPC) or 404 (REST).
fn txid_to_rpc_hex(txid: &Txid) -> String {
	txid.to_string()
}

/// A txid as Bitcoin Core's RPC and REST interfaces return it: the inverse
/// of [`txid_to_rpc_hex`]. `consensus::encode::deserialize_hex` would read
/// the display-order string as internal bytes and yield the byte-reversed
/// txid — one that happens to round-trip back to Core through the matching
/// encode mistake, but never equals a `Txid` computed from a transaction, so
/// a cache keyed by it never contains the wallet's own transactions.
fn txid_from_rpc_hex(hex: &str) -> Option<Txid> {
	hex.parse::<Txid>().ok()
}

impl BlockSource for BitcoindClient {
	fn get_header<'a>(
		&'a self, header_hash: &'a bitcoin::BlockHash, height_hint: Option<u32>,
	) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Box::pin(async move { rpc_client.get_header(header_hash, height_hint).await })
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Box::pin(async move { rest_client.get_header(header_hash, height_hint).await })
			},
		}
	}

	fn get_block<'a>(
		&'a self, header_hash: &'a bitcoin::BlockHash,
	) -> AsyncBlockSourceResult<'a, BlockData> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Box::pin(async move { rpc_client.get_block(header_hash).await })
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Box::pin(async move { rest_client.get_block(header_hash).await })
			},
		}
	}

	fn get_best_block(&self) -> AsyncBlockSourceResult<(bitcoin::BlockHash, Option<u32>)> {
		match self {
			BitcoindClient::Rpc { rpc_client, .. } => {
				Box::pin(async move { rpc_client.get_best_block().await })
			},
			BitcoindClient::Rest { rest_client, .. } => {
				Box::pin(async move { rest_client.get_best_block().await })
			},
		}
	}
}

pub(crate) struct FeeResponse(pub FeeRate);

impl TryInto<FeeResponse> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<FeeResponse> {
		if !self.0["errors"].is_null() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::Other,
				self.0["errors"].to_string(),
			));
		}
		let fee_rate_btc_per_kvbyte = self.0["feerate"]
			.as_f64()
			.ok_or(std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse fee rate"))?;
		// Bitcoin Core gives us a feerate in BTC/KvB.
		// Thus, we multiply by 25_000_000 (10^8 / 4) to get satoshis/kwu.
		let fee_rate = {
			let fee_rate_sat_per_kwu = (fee_rate_btc_per_kvbyte * 25_000_000.0).round() as u64;
			FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu)
		};
		Ok(FeeResponse(fee_rate))
	}
}

pub(crate) struct MempoolMinFeeResponse(pub FeeRate);

impl TryInto<MempoolMinFeeResponse> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<MempoolMinFeeResponse> {
		let fee_rate_btc_per_kvbyte = self.0["mempoolminfee"]
			.as_f64()
			.ok_or(std::io::Error::new(std::io::ErrorKind::Other, "Failed to parse fee rate"))?;
		// Bitcoin Core gives us a feerate in BTC/KvB.
		// Thus, we multiply by 25_000_000 (10^8 / 4) to get satoshis/kwu.
		let fee_rate = {
			let fee_rate_sat_per_kwu = (fee_rate_btc_per_kvbyte * 25_000_000.0).round() as u64;
			FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu)
		};
		Ok(MempoolMinFeeResponse(fee_rate))
	}
}

pub(crate) struct GetRawTransactionResponse(pub Transaction);

impl TryInto<GetRawTransactionResponse> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<GetRawTransactionResponse> {
		let tx = self
			.0
			.as_str()
			.ok_or(std::io::Error::new(
				std::io::ErrorKind::Other,
				"Failed to parse getrawtransaction response",
			))
			.and_then(|s| {
				bitcoin::consensus::encode::deserialize_hex(s).map_err(|_| {
					std::io::Error::new(
						std::io::ErrorKind::Other,
						"Failed to parse getrawtransaction response",
					)
				})
			})?;

		Ok(GetRawTransactionResponse(tx))
	}
}

/// Confirmation depth parsed from a verbose `getrawtransaction` result
/// (Peerswap native primitive B5). The `confirmations` field is absent for an
/// unconfirmed (mempool) transaction, which we map to `0`.
#[cfg(feature = "swaps")]
pub(crate) struct SwapTxConfirmationResponse(pub u32);

#[cfg(feature = "swaps")]
impl TryInto<SwapTxConfirmationResponse> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<SwapTxConfirmationResponse> {
		let confirmations = self.0["confirmations"].as_u64().unwrap_or(0);
		Ok(SwapTxConfirmationResponse(confirmations as u32))
	}
}

pub struct GetRawMempoolResponse(Vec<Txid>);

impl TryInto<GetRawMempoolResponse> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<GetRawMempoolResponse> {
		let res = self.0.as_array().ok_or(std::io::Error::new(
			std::io::ErrorKind::Other,
			"Failed to parse getrawmempool response",
		))?;

		let mut mempool_transactions = Vec::with_capacity(res.len());

		for hex in res {
			let txid = if let Some(hex_str) = hex.as_str() {
				match txid_from_rpc_hex(hex_str) {
					Some(txid) => txid,
					None => {
						return Err(std::io::Error::new(
							std::io::ErrorKind::Other,
							"Failed to parse getrawmempool response",
						));
					},
				}
			} else {
				return Err(std::io::Error::new(
					std::io::ErrorKind::Other,
					"Failed to parse getrawmempool response",
				));
			};

			mempool_transactions.push(txid);
		}

		Ok(GetRawMempoolResponse(mempool_transactions))
	}
}

pub struct GetMempoolEntryResponse {
	time: u64,
	height: u32,
}

impl TryInto<GetMempoolEntryResponse> for JsonResponse {
	type Error = std::io::Error;
	fn try_into(self) -> std::io::Result<GetMempoolEntryResponse> {
		let res = self.0.as_object().ok_or(std::io::Error::new(
			std::io::ErrorKind::Other,
			"Failed to parse getmempoolentry response",
		))?;

		let time = match res["time"].as_u64() {
			Some(time) => time,
			None => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::Other,
					"Failed to parse getmempoolentry response",
				));
			},
		};

		let height = match res["height"].as_u64().and_then(|h| h.try_into().ok()) {
			Some(height) => height,
			None => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::Other,
					"Failed to parse getmempoolentry response",
				));
			},
		};

		Ok(GetMempoolEntryResponse { time, height })
	}
}

#[derive(Debug, Clone)]
pub(crate) struct MempoolEntry {
	/// The transaction id
	txid: Txid,
	/// Local time transaction entered pool in seconds since 1 Jan 1970 GMT
	time: u64,
	/// Block height when transaction entered pool
	height: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum FeeRateEstimationMode {
	Economical,
	Conservative,
}

const MAX_HEADER_CACHE_ENTRIES: usize = 100;

pub(crate) struct BoundedHeaderCache {
	header_map: HashMap<BlockHash, ValidatedBlockHeader>,
	recently_seen: VecDeque<BlockHash>,
}

impl BoundedHeaderCache {
	pub(crate) fn new() -> Self {
		let header_map = HashMap::new();
		let recently_seen = VecDeque::new();
		Self { header_map, recently_seen }
	}
}

impl Cache for BoundedHeaderCache {
	fn look_up(&self, block_hash: &BlockHash) -> Option<&ValidatedBlockHeader> {
		self.header_map.get(block_hash)
	}

	fn block_connected(&mut self, block_hash: BlockHash, block_header: ValidatedBlockHeader) {
		self.recently_seen.push_back(block_hash);
		self.header_map.insert(block_hash, block_header);

		if self.header_map.len() >= MAX_HEADER_CACHE_ENTRIES {
			// Keep dropping old entries until we've actually removed a header entry.
			while let Some(oldest_entry) = self.recently_seen.pop_front() {
				if self.header_map.remove(&oldest_entry).is_some() {
					break;
				}
			}
		}
	}

	fn block_disconnected(&mut self, block_hash: &BlockHash) -> Option<ValidatedBlockHeader> {
		self.recently_seen.retain(|e| e != block_hash);
		self.header_map.remove(block_hash)
	}
}

/// Fans chain events out to every chain-consuming component.
///
/// Two delivery paths share this struct. The [`Listen`] impl is the ungated fan-out the bitcoind
/// engine drives through `SpvClient`: it delivers every event to every listener, and stays that
/// way. The `gated_*` methods are for a filter-driven engine that resumes from the minimum
/// listener height and therefore replays blocks to listeners already ahead; they decide per
/// listener whether a block may be handed over, and record what they could not decide.
///
/// The channel monitors are gated one by one, not as the `ChainMonitor` they live in: the
/// `ChainMonitor` has no tip of its own, and after a restart its monitors sit at different
/// heights by design (chain-sync persistence is staggered per channel). See
/// [`MonitorGate`] for the connect side and [`Self::gated_block_disconnected`] for the rewind.
pub(crate) struct ChainListener {
	pub(crate) onchain_wallet: Arc<Wallet>,
	pub(crate) channel_manager: Arc<ChannelManager>,
	pub(crate) chain_monitor: Arc<ChainMonitor>,
	pub(crate) output_sweeper: Arc<Sweeper>,
	/// What a channel monitor rewound on its own (rather than through the `ChainMonitor`) needs
	/// to re-evaluate its claims: the same broadcaster and fee estimator the `ChainMonitor`
	/// would hand it.
	pub(crate) tx_broadcaster: Arc<Broadcaster>,
	pub(crate) fee_estimator: Arc<OnchainFeeEstimator>,
	pub(crate) logger: Arc<Logger>,
	/// Records the first listener divergence seen since the last drain.
	///
	/// `Listen` returns `()`, so divergence cannot be propagated through the trait. The engine
	/// drains this after each block and must stop advancing when it is set: continuing would
	/// publish a "synced" tip while a listener sits on a stale chain.
	pub(crate) divergence: Arc<Mutex<Option<String>>>,
	/// Per-listener tally of the replay batch in flight, drained at every tip boundary.
	///
	/// Exists to tell two outcomes of [`ListenerAction::ReplayUnprovable`] apart, which are
	/// indistinguishable block by block: a listener that skips a stretch it cannot prove and then
	/// *reconnects* to the chain (benign — the resume-from-minimum design), and a listener the
	/// replay can never reach at all (stranded on a fork). See
	/// [`ChainListener::record_stranded_listeners`].
	///
	/// Keyed by listener name; channel monitors are named by funding outpoint, so each one is
	/// judged on its own.
	pub(crate) replay_batch: Arc<Mutex<BTreeMap<String, ReplayTally>>>,
	/// Every channel monitor's persisted tip as it stood when this gated fan-out was created,
	/// each held until the replay proves or refutes it. Empty on the ungated `Listen` path.
	pub(crate) monitor_gate: Mutex<MonitorGate>,
}

/// One channel monitor's tip as it was persisted, held until the replay reaches it.
///
/// The `ChainMonitor` hands every block to every monitor it holds and each monitor overwrites
/// its own tip with it, whatever the monitor's tip was. So once the first replayed block is
/// delivered, a monitor's live tip says nothing about where it had actually got to — only a
/// copy taken before the first delivery does. That copy is what the replay is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MonitorSnapshot {
	/// The name the monitor is tallied and reported under.
	pub(crate) name: String,
	/// The monitor's persisted tip at the time of the snapshot.
	pub(crate) best: BestBlock,
}

/// What one replayed block proved about one snapshotted monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MonitorDecision {
	pub(crate) snapshot: MonitorSnapshot,
	pub(crate) action: ListenerAction,
}

/// The per-monitor half of the `ChainMonitor` connect gate, over plain data so it can be
/// driven without a `ChannelMonitor`.
///
/// Holds a [`MonitorSnapshot`] per channel monitor that existed when the fan-out was created.
/// Each replayed block is classified against every live snapshot with [`listener_action`]: a
/// block at the snapshot's own height with a different hash, or at the next height with a
/// different parent, refutes the snapshot (`Diverged`); a block at its height with the same
/// hash, or at the next height with it as the parent, proves it, and the snapshot is retired —
/// from then on the monitor moves in lockstep with the `ChainMonitor` and its live tip is the
/// truth again. A block below the snapshot cannot be checked ([`ListenerAction::ReplayUnprovable`])
/// and is tallied for the tip-boundary verdict like any other listener's.
///
/// A monitor added while the engine runs (a channel opened after start) takes its tip from the
/// `ChannelManager` at creation, which this fan-out is already proving through the manager's own
/// gate, and it receives every block from then on: it needs no snapshot, and none is taken.
///
/// A rewind can also retire a snapshot, see [`Self::note_rewound`].
#[derive(Debug, Default)]
pub(crate) struct MonitorGate {
	snapshots: BTreeMap<OutPoint, MonitorSnapshot>,
}

// Driven by the gated fan-out below, which only the filter-driven engine calls.
#[cfg_attr(not(feature = "cbf"), allow(dead_code))]
impl MonitorGate {
	/// A gate over the given persisted tips, keyed by funding outpoint.
	pub(crate) fn new(tips: impl IntoIterator<Item = (OutPoint, BestBlock)>) -> Self {
		let snapshots = tips
			.into_iter()
			.map(|(funding_txo, best)| {
				let name = format!("ChannelMonitor {}", funding_txo);
				(funding_txo, MonitorSnapshot { name, best })
			})
			.collect();
		Self { snapshots }
	}

	/// Snapshots the replay has neither proven nor refuted yet.
	#[cfg(test)]
	pub(crate) fn live(&self) -> usize {
		self.snapshots.len()
	}

	/// Classifies one replayed block against every live snapshot, retiring the ones it proves.
	///
	/// Returns one decision per snapshot that was live when the block arrived, so the caller can
	/// tally and report each one; a refuted snapshot is returned as `Diverged` and kept, because
	/// the engine halts on it and the snapshot is the evidence.
	pub(crate) fn judge_block(
		&mut self, block_hash: BlockHash, prev_blockhash: BlockHash, height: u32,
	) -> Vec<MonitorDecision> {
		let mut decisions = Vec::with_capacity(self.snapshots.len());
		self.snapshots.retain(|_, snapshot| {
			let action = listener_action(&snapshot.best, block_hash, prev_blockhash, height);
			decisions.push(MonitorDecision { snapshot: snapshot.clone(), action });
			match action {
				// Proven at its own tip or as the parent of the next block: retired.
				ListenerAction::Deliver | ListenerAction::AlreadyApplied => false,
				ListenerAction::ReplayUnprovable | ListenerAction::Diverged => true,
			}
		});
		decisions
	}

	/// The monitor at `funding_txo` was just rewound below `height`: it no longer holds
	/// anything at or above it, so a snapshot claiming a tip there is moot and is retired.
	///
	/// Keeping it would guarantee a false refutation later — the chain being replayed after
	/// the reorg is a different branch from the one the snapshot was taken on, so the block at
	/// the snapshot's height can never match it again. A snapshot below the rewound height is
	/// untouched: the monitor still holds that state, and the replay still has to prove it.
	pub(crate) fn note_rewound(&mut self, funding_txo: &OutPoint, height: u32) {
		if self.snapshots.get(funding_txo).map_or(false, |s| s.best.height >= height) {
			self.snapshots.remove(funding_txo);
		}
	}
}

/// What one listener decided about the blocks of the replay batch currently in flight.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayTally {
	/// Blocks skipped because they sat below the listener's tip and could not be checked.
	pub(crate) unprovable: u32,
	/// Decisions that could actually be proven: delivered, an exact replay, or a fork.
	pub(crate) provable: u32,
	/// The listener's own tip height as of its most recent unprovable skip.
	pub(crate) tip_height: u32,
}

/// What a listener's replay batch amounts to once the replay has reached the chain's tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchVerdict {
	/// Nothing to say: the listener was never asked about a block it could not prove.
	Ordinary,
	/// Skipped a stretch it could not prove and then reconnected to the chain. Benign — this is
	/// what the resume-from-minimum design does on every restart with skewed listener durability.
	SkippedThenReconnected,
	/// The replay ended without this listener ever reaching a block it could prove, and its own
	/// tip is at or above the tip we ended at, so no later replay of this chain can reach it
	/// either. It is on a chain we can neither extend nor refute.
	Stranded,
}

impl ReplayTally {
	/// Folds one decision into the batch tally.
	fn note(&mut self, best: &BestBlock, action: ListenerAction) {
		match action {
			ListenerAction::ReplayUnprovable => {
				self.unprovable = self.unprovable.saturating_add(1);
				self.tip_height = best.height;
			},
			ListenerAction::Deliver | ListenerAction::AlreadyApplied | ListenerAction::Diverged => {
				self.provable = self.provable.saturating_add(1)
			},
		}
	}

	/// Judges the batch against the tip the replay ended at.
	///
	/// `provable == 0` on its own already implies the listener sits at or above `tip_height` — a
	/// replay passes through every height at or below a listener's tip, and the tip itself
	/// compares provably — but being unreachable is what actually makes the case terminal, so it
	/// is checked rather than assumed.
	fn verdict(&self, tip_height: u32) -> BatchVerdict {
		if self.unprovable == 0 {
			BatchVerdict::Ordinary
		} else if self.provable > 0 || self.tip_height < tip_height {
			BatchVerdict::SkippedThenReconnected
		} else {
			BatchVerdict::Stranded
		}
	}
}

/// Whether a listener should be handed a given block.
///
/// `ChannelManager` and `OutputSweeper` enforce LDK's `Listen` contract with `assert_eq!` on both
/// the previous block hash and `height == best + 1`, so handing either one a block it has already
/// applied panics the node rather than returning an error. Listener durability is not
/// synchronized — `ChannelManager` is persisted asynchronously by the background processor while
/// `OutputSweeper` is only marked dirty and flushed periodically — so after a crash they can be
/// durable at different heights. A filter-driven engine resumes from the *minimum* height across
/// all listeners, which replays blocks to any listener that got further ahead.
///
/// Classification is deliberately hash-aware. Deciding on height alone would treat a *different*
/// block at an already-seen height as an ordinary replay and skip it, silently stranding the
/// listener on a stale fork — a worse failure than the panic being avoided, because it is silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerAction {
	/// The listener expects exactly this block.
	Deliver,
	/// The listener already has this exact block on its chain; skip it.
	AlreadyApplied,
	/// The block sits BELOW the listener's tip. LDK 0.1's [`BestBlock`] carries no ancestry, so
	/// we can neither confirm nor refute that it is on the listener's chain. Skip it — but,
	/// unlike [`Self::Diverged`], do NOT halt the engine.
	///
	/// This is the *expected* case whenever listener durability skews, which is exactly the
	/// situation the resume-from-minimum design above sets up. Treating it as divergence would
	/// halt block application permanently for a listener that is merely further ahead on the
	/// same chain.
	///
	/// The decision is deferred, not dropped — but only for as long as the replay can still reach
	/// the listener. While it climbs towards `best.height` nothing can be checked; at
	/// `best.height` the same-height arm compares the block hash exactly, and at
	/// `best.height + 1` the parent hash — both PROVABLE — so a listener genuinely sitting on a
	/// fork is caught when the replay reaches its tip.
	///
	/// That argument holds only while the chain being replayed is at least as long as the
	/// listener's own chain. It does NOT cover a reorg that leaves the canonical tip *below* an
	/// ahead listener's persisted tip: the replay ends before it can prove anything, every block
	/// is unprovable, and deferring forever is the same as dropping. That geometry is caught at
	/// the tip boundary instead — see [`ChainListener::record_stranded_listeners`], which fails
	/// closed on it.
	ReplayUnprovable,
	/// The listener cannot accept this block without first being rewound.
	Diverged,
}

pub(crate) fn listener_action(
	best: &BestBlock, block_hash: BlockHash, prev_blockhash: BlockHash, height: u32,
) -> ListenerAction {
	if height == best.height + 1 {
		// The ordinary case: extends the listener's tip.
		return if best.block_hash == prev_blockhash {
			ListenerAction::Deliver
		} else {
			ListenerAction::Diverged
		};
	}

	if height == best.height {
		// Same height: an exact replay is safe to skip, a different block is a fork.
		return if best.block_hash == block_hash {
			ListenerAction::AlreadyApplied
		} else {
			ListenerAction::Diverged
		};
	}

	if height < best.height {
		// Below the tip: a `BestBlock` holds no ancestors, so this can be neither confirmed as
		// the listener's own block nor refuted as a fork. See `ListenerAction::ReplayUnprovable`.
		return ListenerAction::ReplayUnprovable;
	}

	// height > best.height + 1: a gap. Delivering would violate the one-call-per-block contract.
	ListenerAction::Diverged
}

/// How a gated disconnect treats one listener for one header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DisconnectAction {
	/// The header is the listener's current tip: rewind it.
	Rewind,
	/// The listener never connected this height; there is nothing to rewind.
	NotReached,
	/// The listener is at this height on a different block, or above a height it should have
	/// matched already: it is on a chain we cannot rewind along.
	Diverged,
}

pub(crate) fn disconnect_action(
	best: &BestBlock, header: &Header, height: u32,
) -> DisconnectAction {
	if best.height < height {
		DisconnectAction::NotReached
	} else if best.height == height && best.block_hash == header.block_hash() {
		DisconnectAction::Rewind
	} else {
		DisconnectAction::Diverged
	}
}

// The filter-driven engine's applicator (`chain::cbf::applicator`) is the caller of every gated
// method and of the divergence ledger; nothing on the bitcoind path touches them.
#[cfg_attr(not(feature = "cbf"), allow(dead_code))]
impl ChainListener {
	/// The ungated fan-out the bitcoind engine drives through `SpvClient`. Takes no monitor
	/// snapshots: the `Listen` path delivers everything to everyone and gates nothing.
	pub(crate) fn new(
		onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
		tx_broadcaster: Arc<Broadcaster>, fee_estimator: Arc<OnchainFeeEstimator>,
		logger: Arc<Logger>,
	) -> Self {
		Self {
			onchain_wallet,
			channel_manager,
			chain_monitor,
			output_sweeper,
			tx_broadcaster,
			fee_estimator,
			logger,
			divergence: Arc::new(Mutex::new(None)),
			replay_batch: Arc::new(Mutex::new(BTreeMap::new())),
			monitor_gate: Mutex::new(MonitorGate::default()),
		}
	}

	/// The gated fan-out a filter-driven engine replays into.
	///
	/// Snapshots every channel monitor's persisted tip NOW, before any block is delivered:
	/// the first delivery overwrites every monitor's live tip (see [`MonitorSnapshot`]), so this
	/// is the only moment the monitors can be read truthfully. The engine's resume height is
	/// taken from the same state right after, so the two agree.
	pub(crate) fn new_gated(
		onchain_wallet: Arc<Wallet>, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, output_sweeper: Arc<Sweeper>,
		tx_broadcaster: Arc<Broadcaster>, fee_estimator: Arc<OnchainFeeEstimator>,
		logger: Arc<Logger>,
	) -> Self {
		let listener = Self::new(
			onchain_wallet,
			channel_manager,
			chain_monitor,
			output_sweeper,
			tx_broadcaster,
			fee_estimator,
			logger,
		);
		let tips = listener
			.chain_monitor
			.list_monitors()
			.into_iter()
			.flat_map(|(funding_txo, _)| {
				listener
					.chain_monitor
					.get_monitor(funding_txo)
					.map(|monitor| (funding_txo, monitor.current_best_block()))
			})
			.collect::<Vec<_>>();
		for (funding_txo, best) in &tips {
			log_debug!(
				listener.logger,
				"ChannelMonitor {} resumes at height {} (hash {}); it is checked against the \
				 replay when the replay reaches it.",
				funding_txo,
				best.height,
				best.block_hash,
			);
		}
		*listener.monitor_gate.lock().unwrap() = MonitorGate::new(tips);
		listener
	}

	/// The furthest-behind tip across every listener: the height a replay must resume from so
	/// that no listener misses a block.
	pub(crate) fn get_best_block(&self) -> BestBlock {
		let candidates = [
			self.onchain_wallet.current_best_block(),
			self.channel_manager.current_best_block(),
			self.output_sweeper.current_best_block(),
		];
		let mut min = candidates.into_iter().min_by_key(|b| b.height).expect("non-empty");
		if let Some(worst_monitor) = self.min_monitor_best_block() {
			if worst_monitor.height < min.height {
				min = worst_monitor;
			}
		}
		min
	}

	/// The furthest-behind channel monitor, or `None` when there are no monitors.
	fn min_monitor_best_block(&self) -> Option<BestBlock> {
		self.chain_monitor
			.list_monitors()
			.iter()
			.flat_map(|(funding_txo, _)| self.chain_monitor.get_monitor(*funding_txo))
			.map(|m| m.current_best_block())
			.min_by_key(|b| b.height)
	}

	/// Drains the first divergence recorded since the last drain.
	pub(crate) fn take_divergence(&self) -> Option<String> {
		self.divergence.lock().unwrap().take()
	}

	/// Records one listener's decision about one replay block in the batch ledger, logs it, and
	/// hands it back so the caller can act on it.
	///
	/// EVERY decision must flow through here. The ledger's whole value is the contrast between a
	/// listener that skipped some blocks and one that skipped *only* blocks, so a decision that
	/// bypassed it would read as an absence of evidence.
	fn note_decision(
		&self, who: &str, best: &BestBlock, height: u32, action: ListenerAction,
	) -> ListenerAction {
		{
			let mut batch = self.replay_batch.lock().unwrap();
			match batch.get_mut(who) {
				Some(tally) => tally.note(best, action),
				// Only the first decision of a batch allocates the key.
				None => {
					let mut tally = ReplayTally::default();
					tally.note(best, action);
					batch.insert(who.to_owned(), tally);
				},
			}
		}
		match action {
			ListenerAction::ReplayUnprovable => self.log_unprovable_replay(who, best, height),
			ListenerAction::Diverged => self.log_divergence(who, best, height),
			ListenerAction::Deliver | ListenerAction::AlreadyApplied => {},
		}
		action
	}

	/// Drains the batch ledger at a tip boundary and fails closed on any listener the replay could
	/// never prove a connection to.
	///
	/// A batch that ends at `tip_height` is the last chance a listener gets: the replay is not
	/// coming back for it. So a listener that saw nothing but [`ListenerAction::ReplayUnprovable`]
	/// across the whole batch, and whose own tip is at or above the tip we just reached, is not
	/// waiting to be caught up — it is stranded on a chain we cannot extend or refute, and the
	/// deferral promised by `ReplayUnprovable` can never be honoured. Recording it as divergence
	/// halts the engine, which is the right call for exactly this (true-positive) case.
	///
	/// A listener that skipped a stretch and then reconnected — the ordinary consequence of the
	/// resume-from-minimum design, and the case `ReplayUnprovable` exists for — has `provable > 0`
	/// and is merely reported, at a level that does not depend on debug logging being on.
	///
	/// `tip_height` MUST be the true synced tip of the chain — the height the chain source
	/// itself reports as caught up to the network — and never an intermediate batch boundary or
	/// the last height a block happened to arrive at. The verdict reads "the replay is not
	/// coming back for you" into it: judged against a height the chain has not actually ended
	/// at, a listener that is merely ahead of an unfinished replay would be recorded as stranded
	/// and halt the engine for nothing.
	///
	/// Returns `true` when at least one listener was recorded as stranded.
	pub(crate) fn record_stranded_listeners(&self, tip_height: u32) -> bool {
		let batch = std::mem::take(&mut *self.replay_batch.lock().unwrap());
		let mut stranded = false;
		for (who, tally) in batch {
			match tally.verdict(tip_height) {
				BatchVerdict::Ordinary => {},
				BatchVerdict::SkippedThenReconnected => log_info!(
					self.logger,
					"{} skipped {} block(s) of the replay below its own tip, then reconnected to \
					 the chain ({} proven decision(s), listener tip {}).",
					who,
					tally.unprovable,
					tally.provable,
					tally.tip_height,
				),
				BatchVerdict::Stranded => {
					stranded = true;
					self.record_divergence(format!(
						"{} is stranded at height {} above the synced tip {} ({} block(s) \
						 replayed, none provable): the replay ended without ever reaching a block \
						 it could prove",
						who, tally.tip_height, tip_height, tally.unprovable
					));
					log_error!(
						self.logger,
						"{} sits at height {} while the chain we just synced ends at {}, and none \
						 of the {} replayed block(s) could be proven to be on its chain. It is on \
						 a chain we can neither extend nor refute, so it is stranded rather than \
						 lagging.",
						who,
						tally.tip_height,
						tip_height,
						tally.unprovable,
					);
				},
			}
		}
		stranded
	}

	/// Logs a replay this listener is too far ahead of for us to check.
	///
	/// Deliberately does NOT touch `self.divergence`: on its own this is the ordinary consequence
	/// of the resume-from-minimum design, not a fork. Whether it stayed ordinary is decided at the
	/// tip boundary by [`Self::record_stranded_listeners`], so this stays at debug level.
	fn log_unprovable_replay(&self, who: &str, best: &BestBlock, height: u32) {
		log_debug!(
			self.logger,
			"{} is at height {}, above the replayed block at height {}; skipping that block for \
			 it (its own tip is re-checked by hash when the replay reaches it).",
			who,
			best.height,
			height,
		);
	}

	/// Records the first divergence seen since the last drain. Later ones are dropped: the engine
	/// halts on the first, and the first is the one that explains the rest.
	fn record_divergence(&self, reason: String) {
		let mut recorded = self.divergence.lock().unwrap();
		if recorded.is_none() {
			*recorded = Some(reason);
		}
	}

	fn log_divergence(&self, who: &str, best: &BestBlock, height: u32) {
		self.record_divergence(format!(
			"{} diverged at height {} (listener at {}, hash {})",
			who, height, best.height, best.block_hash
		));
		log_error!(
			self.logger,
			"{} cannot accept the block at height {}: it is at height {} (hash {}). It must be \
			 rewound before it can continue; skipping to avoid a chain-order panic.",
			who,
			height,
			best.height,
			best.block_hash,
		);
	}

	/// Gated fan-out of a full block. See [`Self::gated_filtered_block_connected`].
	///
	/// The wallet takes the block as it is; only the Lightning listeners need it as `txdata`.
	/// Rebuilding a block from its own `txdata` for the wallet would clone every transaction
	/// of a matched block for nothing.
	pub(crate) fn gated_block_connected(&self, block: &bitcoin::Block, height: u32) {
		self.onchain_wallet.block_connected(block, height);
		let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
		self.gated_lightning_block_connected(&block.header, &txdata, height);
	}

	/// Gated fan-out of a (possibly filtered) block: each Lightning listener is handed the block
	/// only if [`listener_action`] says it can take it, and every decision lands in the replay
	/// ledger.
	///
	/// The on-chain wallet is deliberately not gated. Its disconnect is a no-op because BDK
	/// expects blocks to be reconnected starting from the point of disagreement, so a height gate
	/// would starve it of the new chain after a reorg. BDK also tolerates an exact duplicate,
	/// which is the only case a gate would otherwise guard against.
	pub(crate) fn gated_filtered_block_connected(
		&self, header: &Header, txdata: &TransactionData, height: u32,
	) {
		self.onchain_wallet.filtered_block_connected(header, txdata, height);
		self.gated_lightning_block_connected(header, txdata, height);
	}

	/// The Lightning half of [`Self::gated_filtered_block_connected`]: every listener but the
	/// wallet, each behind its gate.
	fn gated_lightning_block_connected(
		&self, header: &Header, txdata: &TransactionData, height: u32,
	) {
		let block_hash = header.block_hash();

		let cm_best = self.channel_manager.current_best_block();
		let cm_action = listener_action(&cm_best, block_hash, header.prev_blockhash, height);
		match self.note_decision("ChannelManager", &cm_best, height, cm_action) {
			ListenerAction::Deliver => {
				self.channel_manager.filtered_block_connected(header, txdata, height)
			},
			ListenerAction::AlreadyApplied
			| ListenerAction::ReplayUnprovable
			| ListenerAction::Diverged => {},
		}

		// `ChainMonitor` has no chain-order assertion of its own, and `ChannelMonitor` does not
		// validate anything on this path: `block_connected` overwrites the monitor's tip with the
		// incoming block unconditionally, whether the block is above, at or below the tip it had,
		// and then processes the block's transactions. So a block from a different chain would be
		// grafted in silently, and nothing a monitor holds afterwards says where it really was.
		//
		// Two gates therefore stand in front of the single `ChainMonitor` call. Every snapshot
		// taken at start (see `MonitorGate`) must NOT refute the block: a monitor proven to be on
		// another chain must not be fed this one, so on any refutation the block is withheld from
		// the whole `ChainMonitor` and the divergence halts the engine. And the furthest-behind
		// monitor's live tip — the `ChainMonitor`'s effective tip, since every delivery lands
		// on every monitor — must be able to take the block: below it nothing can be checked,
		// at it the block is an exact replay, above it by one the block extends it.
		//
		// A monitor whose snapshot is still unproven receives, through the `ChainMonitor`, the
		// blocks the replay delivers below its snapshot: an exact replay of its own blocks if it
		// is on this chain (which `transactions_confirmed` skips as already confirmed, as it does
		// on every restart of the transaction-based engines), or foreign blocks if it is not —
		// which the snapshot refutes the moment the replay reaches its height. The `ChainMonitor`
		// persists each monitor and registers its new outputs as part of that one call, which is
		// why the monitors are not fed one by one here.
		let monitor_decisions = self.monitor_gate.lock().unwrap().judge_block(
			block_hash,
			header.prev_blockhash,
			height,
		);
		let mut refuted = false;
		for decision in &monitor_decisions {
			let noted = self.note_decision(
				&decision.snapshot.name,
				&decision.snapshot.best,
				height,
				decision.action,
			);
			refuted |= noted == ListenerAction::Diverged;
		}

		if !refuted {
			match self.min_monitor_best_block() {
				Some(monitor_best) => {
					match listener_action(&monitor_best, block_hash, header.prev_blockhash, height)
					{
						ListenerAction::Deliver | ListenerAction::AlreadyApplied => {
							self.chain_monitor.filtered_block_connected(header, txdata, height)
						},
						// Below every monitor's tip, or a gap: the snapshots above already said
						// what there is to say about it.
						ListenerAction::ReplayUnprovable | ListenerAction::Diverged => {},
					}
				},
				// No monitors: nothing to strand.
				None => self.chain_monitor.filtered_block_connected(header, txdata, height),
			}
		}

		let sweeper_best = self.output_sweeper.current_best_block();
		let sweeper_action =
			listener_action(&sweeper_best, block_hash, header.prev_blockhash, height);
		match self.note_decision("OutputSweeper", &sweeper_best, height, sweeper_action) {
			ListenerAction::Deliver => {
				self.output_sweeper.filtered_block_connected(header, txdata, height)
			},
			ListenerAction::AlreadyApplied
			| ListenerAction::ReplayUnprovable
			| ListenerAction::Diverged => {},
		}
	}

	/// Gated fan-out of one disconnected header, applied tip-first down to the fork point.
	///
	/// `ChannelManager` and `OutputSweeper` assert that the disconnected header IS their current
	/// tip, so each is rewound only while that holds; a listener that never reached this height
	/// has nothing to rewind and is skipped. The on-chain wallet is not rewound, as on the
	/// ungated path: BDK reconnects from the point of disagreement.
	///
	/// Each channel monitor is rewound ON ITS OWN, by the same rule, never through the
	/// `ChainMonitor`: that would rewind every monitor it holds, and after a restart the
	/// monitors sit at different heights — chain-sync persistence is staggered per channel, so a
	/// skew is the ordinary state, not a crash artefact. Gating the `ChainMonitor` on one
	/// monitor's tip either rewinds a monitor that never reached the height (moving it onto a
	/// block whose transactions it never processed) or, gated on the furthest-behind one, leaves
	/// a monitor ahead of it untouched: its events from the abandoned branch then mature on the
	/// new one. `ChainMonitor::block_disconnected` is a plain loop over its monitors with no
	/// persistence of its own, so rewinding a monitor directly is the same operation, one
	/// monitor at a time. A rewind retires the monitor's start-of-replay snapshot when it
	/// reaches below it, see [`MonitorGate::note_rewound`].
	///
	/// A listener at this height on a different block, or still above a height every listener
	/// should have matched by now, is recorded as diverged: it is on a chain this sequence of
	/// disconnects cannot rewind along. Disconnects arrive descending from the tip, so a
	/// listener that was at that tip has been rewound to `height` by the time the header at
	/// `height` is processed; one still above it was never at the tip of this branch, and a
	/// `BestBlock` carries no ancestry that could tell which branch it IS on. That includes a
	/// monitor persisted ahead of the resume height that the replay had not reached when the
	/// reorg arrived: its claim above the fork cannot be checked against either branch, so the
	/// engine halts rather than guess — silently purging the claim by height would accept state
	/// nothing can verify. The halt is transient: a restart resumes from the persisted heights,
	/// and the monitor is proven or refuted at its own height by the replay.
	pub(crate) fn gated_block_disconnected(&self, header: &Header, height: u32) {
		self.onchain_wallet.block_disconnected(header, height);

		let cm_best = self.channel_manager.current_best_block();
		match disconnect_action(&cm_best, header, height) {
			DisconnectAction::Rewind => self.channel_manager.block_disconnected(header, height),
			DisconnectAction::NotReached => {},
			DisconnectAction::Diverged => {
				self.log_disconnect_divergence("ChannelManager", &cm_best, header, height)
			},
		}

		for (funding_txo, _) in self.chain_monitor.list_monitors() {
			let Ok(monitor) = self.chain_monitor.get_monitor(funding_txo) else {
				// Removed between the listing and the lookup: nothing left to rewind.
				continue;
			};
			let monitor_best = monitor.current_best_block();
			match disconnect_action(&monitor_best, header, height) {
				DisconnectAction::Rewind => {
					monitor.block_disconnected(
						header,
						height,
						&*self.tx_broadcaster,
						&*self.fee_estimator,
						&self.logger,
					);
					self.monitor_gate.lock().unwrap().note_rewound(&funding_txo, height);
				},
				DisconnectAction::NotReached => {},
				DisconnectAction::Diverged => self.log_disconnect_divergence(
					&format!("ChannelMonitor {}", funding_txo),
					&monitor_best,
					header,
					height,
				),
			}
		}

		let sweeper_best = self.output_sweeper.current_best_block();
		match disconnect_action(&sweeper_best, header, height) {
			DisconnectAction::Rewind => self.output_sweeper.block_disconnected(header, height),
			DisconnectAction::NotReached => {},
			DisconnectAction::Diverged => {
				self.log_disconnect_divergence("OutputSweeper", &sweeper_best, header, height)
			},
		}

		// Every rewound listener just left the chain the batch was tallied against. The replay
		// that follows the disconnects is the one that gets judged.
		self.replay_batch.lock().unwrap().clear();
	}

	fn log_disconnect_divergence(&self, who: &str, best: &BestBlock, header: &Header, height: u32) {
		self.record_divergence(format!(
			"{} cannot be rewound past height {} (listener at {}, hash {}, disconnecting {})",
			who,
			height,
			best.height,
			best.block_hash,
			header.block_hash()
		));
		log_error!(
			self.logger,
			"{} is at height {} (hash {}) while the block at height {} (hash {}) is being \
			 disconnected, which is not its tip. It is on a chain this reorg cannot rewind it \
			 along; leaving it untouched to avoid a chain-order panic.",
			who,
			best.height,
			best.block_hash,
			height,
			header.block_hash(),
		);
	}
}

impl Listen for ChainListener {
	fn filtered_block_connected(
		&self, header: &bitcoin::block::Header,
		txdata: &lightning::chain::transaction::TransactionData, height: u32,
	) {
		self.onchain_wallet.filtered_block_connected(header, txdata, height);
		self.channel_manager.filtered_block_connected(header, txdata, height);
		self.chain_monitor.filtered_block_connected(header, txdata, height);
		self.output_sweeper.filtered_block_connected(header, txdata, height);
	}
	fn block_connected(&self, block: &bitcoin::Block, height: u32) {
		self.onchain_wallet.block_connected(block, height);
		self.channel_manager.block_connected(block, height);
		self.chain_monitor.block_connected(block, height);
		self.output_sweeper.block_connected(block, height);
	}

	fn block_disconnected(&self, header: &bitcoin::block::Header, height: u32) {
		self.onchain_wallet.block_disconnected(header, height);
		self.channel_manager.block_disconnected(header, height);
		self.chain_monitor.block_disconnected(header, height);
		self.output_sweeper.block_disconnected(header, height);
	}
}

pub(crate) fn rpc_credentials(rpc_user: String, rpc_password: String) -> String {
	BASE64_STANDARD.encode(format!("{}:{}", rpc_user, rpc_password))
}

pub(crate) fn endpoint(host: String, port: u16) -> HttpEndpoint {
	HttpEndpoint::for_host(host).with_port(port)
}

#[derive(Debug)]
pub struct HttpError {
	pub(crate) status_code: String,
	pub(crate) contents: Vec<u8>,
}

impl std::error::Error for HttpError {}

impl std::fmt::Display for HttpError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let contents = String::from_utf8_lossy(&self.contents);
		write!(f, "status_code: {}, contents: {}", self.status_code, contents)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::hashes::Hash;

	fn hash(byte: u8) -> BlockHash {
		BlockHash::from_byte_array([byte; 32])
	}

	/// A listener tip at `height` with a byte-tagged hash. LDK 0.1's `BestBlock` carries no
	/// ancestry, so this is all a listener can tell us about itself.
	fn best(height: u32, hash_byte: u8) -> BestBlock {
		BestBlock::new(hash(hash_byte), height)
	}

	#[test]
	fn listener_action_delivers_the_next_block_in_order() {
		// Extends the tip: parent matches, height is best + 1.
		assert_eq!(
			listener_action(&best(100, 50), hash(51), hash(50), 101),
			ListenerAction::Deliver
		);
	}

	#[test]
	fn listener_action_rejects_a_next_height_block_with_the_wrong_parent() {
		assert_eq!(
			listener_action(&best(100, 50), hash(99), hash(200), 101),
			ListenerAction::Diverged
		);
	}

	#[test]
	fn listener_action_skips_an_exact_replay_at_the_tip() {
		// The crash case the gating exists for: the resume floor is the minimum height across all
		// listeners, so a listener that persisted further ahead is replayed its own blocks.
		// `ChannelManager` and `OutputSweeper` assert on chain order, so delivering would panic.
		assert_eq!(
			listener_action(&best(100, 50), hash(50), hash(49), 100),
			ListenerAction::AlreadyApplied
		);
	}

	#[test]
	fn listener_action_reports_a_different_block_at_the_same_height() {
		// The bug this classifier exists to prevent. Height alone would call this an ordinary
		// replay and skip it, silently stranding the listener on the stale fork — worse than the
		// panic being avoided, because nothing reports it.
		assert_eq!(
			listener_action(&best(100, 50), hash(0xbb), hash(0xaa), 100),
			ListenerAction::Diverged
		);
	}

	#[test]
	fn below_tip_is_always_unprovable_without_ancestry() {
		// A `BestBlock` holds no ancestors, so nothing below the tip can be checked: not the
		// block that IS on the listener's chain (an exact replay two blocks back), not a block
		// that is NOT (a different block at a seen height), and not one far below. All three are
		// withheld from the listener — none is `AlreadyApplied`, so a genuine replay is not
		// assumed safe — and none halts the engine, because none is evidence of a fork either.
		// The proof arrives at the tip: see `an_unprovable_replay_still_meets_a_provable_check_at_the_listeners_own_tip`.
		let ahead = best(100, 50);
		assert_eq!(
			listener_action(&ahead, hash(48), hash(47), 98),
			ListenerAction::ReplayUnprovable,
			"the listener's own block, two back"
		);
		assert_eq!(
			listener_action(&ahead, hash(0xbb), hash(0xaa), 98),
			ListenerAction::ReplayUnprovable,
			"a foreign block at a seen height"
		);
		assert_eq!(
			listener_action(&ahead, hash(1), hash(0), 50),
			ListenerAction::ReplayUnprovable,
			"far below the tip"
		);
	}

	#[test]
	fn an_unprovable_replay_still_meets_a_provable_check_at_the_listeners_own_tip() {
		// The safety property that makes `ReplayUnprovable` safe to not halt on: the replay keeps
		// climbing, and at the listener's own height the classifier compares block hashes
		// exactly. A listener genuinely on a fork is caught there instead of below it.
		//
		// This holds only while the replay can actually GET to that height. When it cannot — a
		// chain shorter than the listener's own — the tip-boundary check decides instead, see
		// `a_replay_that_ends_below_an_ahead_listener_strands_it`.
		let ahead = best(100, 50);
		assert_eq!(listener_action(&ahead, hash(1), hash(0), 50), ListenerAction::ReplayUnprovable);
		// At the tip on the same chain: a plain replay.
		assert_eq!(
			listener_action(&ahead, hash(50), hash(49), 100),
			ListenerAction::AlreadyApplied
		);
		// At the tip on a DIFFERENT chain: still caught, still halts.
		assert_eq!(listener_action(&ahead, hash(0xbb), hash(0xaa), 100), ListenerAction::Diverged);
	}

	/// Replays the blocks of one batch over a single listener tip and returns what the batch
	/// ledger would hold, using the same fold the live path uses.
	///
	/// The tip is held fixed, so this models the listener for as long as the replay has not
	/// advanced it — which is the entire batch for a listener the replay never reaches, and up to
	/// its own tip for one it does.
	fn replay_over(
		best: &BestBlock, from: u32, through: u32, chain: impl Fn(u32) -> BlockHash,
	) -> ReplayTally {
		let mut tally = ReplayTally::default();
		for height in from..=through {
			tally.note(best, listener_action(best, chain(height), chain(height - 1), height));
		}
		tally
	}

	#[test]
	fn a_replay_that_ends_below_an_ahead_listener_strands_it() {
		// The geometry the per-block classifier cannot decide: a reorg that leaves the canonical
		// tip BELOW an ahead listener's persisted tip. The replay walks the canonical chain and
		// stops at 85, so it never climbs to the listener's own height where a hash comparison
		// could rule — every block is `ReplayUnprovable`, and "we'll decide when we get there"
		// never comes due. Without ancestry this trap needs no deep reorg: any canonical tip
		// below the listener's own is unreachable.
		let ahead = best(100, 100);
		let canonical = |h: u32| hash(h as u8 + 128);

		let tally = replay_over(&ahead, 76, 85, canonical);

		assert_eq!(tally.unprovable, 10, "every block of the batch was undecidable");
		assert_eq!(tally.provable, 0, "nothing in the batch could be proven either way");
		assert_eq!(
			tally.verdict(85),
			BatchVerdict::Stranded,
			"a listener at 100 that the canonical chain ends 15 blocks below is stranded, not \
			 lagging: no later replay of THIS chain reaches it either"
		);
	}

	#[test]
	fn a_behind_listener_the_replay_catches_up_to_still_heals() {
		// The case `ReplayUnprovable` exists for, and the one a stranded-detector must not eat:
		// listener durability skews on every restart, the resume floor is the minimum across
		// listeners, and a listener cannot prove ANY of the replay below its tip. It is still
		// perfectly healthy — the proof arrives when the replay reaches its own height.
		//
		// Stopping the replay at the listener's tip is the pessimistic cut: every block above it
		// is `Deliver`, which only adds proof.
		let restored = best(100, 100);
		let canonical = |h: u32| hash(h as u8);

		let tally = replay_over(&restored, 81, 100, canonical);

		assert_eq!(tally.unprovable, 19, "81..=99 could not be proven");
		assert_eq!(tally.provable, 1, "its own tip at 100 compares by hash, and matches");
		assert_eq!(
			tally.verdict(120),
			BatchVerdict::SkippedThenReconnected,
			"skipping a stretch and then reconnecting must never halt the engine"
		);
	}

	#[test]
	fn a_batch_that_proved_a_fork_is_not_also_reported_as_stranded() {
		// Divergence is a proven decision. It halts through its own path, and reporting the same
		// listener twice for the same batch would misdescribe why.
		let ahead = best(100, 100);
		let forked = |h: u32| hash(h as u8 + 128);

		// 80..=99 are below the tip and undecidable; 100 is the tip and disagrees.
		let tally = replay_over(&ahead, 80, 100, forked);

		assert_eq!(tally.provable, 1, "the tip ruled");
		assert_eq!(tally.verdict(100), BatchVerdict::SkippedThenReconnected);
	}

	#[test]
	fn the_stranded_verdict_needs_both_no_proof_and_an_unreachable_tip() {
		let nothing_skipped = ReplayTally { unprovable: 0, provable: 5, tip_height: 0 };
		assert_eq!(nothing_skipped.verdict(90), BatchVerdict::Ordinary);

		let skipped_then_proved = ReplayTally { unprovable: 3, provable: 1, tip_height: 100 };
		assert_eq!(skipped_then_proved.verdict(90), BatchVerdict::SkippedThenReconnected);

		// Defensive: a listener below the tip the replay reached is reachable by construction, so
		// however it got here it is not the terminal case.
		let below_the_tip = ReplayTally { unprovable: 3, provable: 0, tip_height: 89 };
		assert_eq!(below_the_tip.verdict(90), BatchVerdict::SkippedThenReconnected);

		let unreachable = ReplayTally { unprovable: 3, provable: 0, tip_height: 100 };
		assert_eq!(unreachable.verdict(90), BatchVerdict::Stranded);
		assert_eq!(
			unreachable.verdict(100),
			BatchVerdict::Stranded,
			"at the tip it is still ahead"
		);
	}

	#[test]
	fn listener_action_reports_a_gap() {
		// More than one block ahead: delivering violates LDK's one-call-per-block contract.
		assert_eq!(
			listener_action(&best(90, 50), hash(60), hash(59), 101),
			ListenerAction::Diverged
		);
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

	#[test]
	fn a_disconnect_only_rewinds_a_listener_whose_tip_it_is() {
		// `ChannelManager` and `OutputSweeper` assert the disconnected header is their tip, so the
		// gate must reproduce that check exactly, and only skip (never rewind) a listener that
		// never got this far.
		let tip = header_with(hash(99), 1);
		let at_tip = BestBlock::new(tip.block_hash(), 100);
		assert_eq!(disconnect_action(&at_tip, &tip, 100), DisconnectAction::Rewind);

		let behind = best(98, 98);
		assert_eq!(disconnect_action(&behind, &tip, 100), DisconnectAction::NotReached);

		let same_height_other_block = best(100, 0xbb);
		assert_eq!(
			disconnect_action(&same_height_other_block, &tip, 100),
			DisconnectAction::Diverged
		);

		// Disconnects run tip-first, so a listener still above a height being disconnected must
		// have failed to match at its own height already: it is not on this chain.
		let still_ahead = best(103, 103);
		assert_eq!(disconnect_action(&still_ahead, &tip, 100), DisconnectAction::Diverged);
	}

	fn funding(seed: u8) -> OutPoint {
		OutPoint { txid: Txid::from_byte_array([seed; 32]), index: 0 }
	}

	fn monitor_name(seed: u8) -> String {
		format!("ChannelMonitor {}", funding(seed))
	}

	#[test]
	fn skewed_monitors_are_rewound_each_on_its_own_tip() {
		// The disconnect gate, applied per monitor. Chain-sync persistence is staggered per
		// channel, so after a restart monitors sit at different heights as a matter of course.
		// Gated on the furthest-behind monitor, this reorg would have been `NotReached` for the
		// whole `ChainMonitor`, and the monitor at 105 would have kept the abandoned block.
		let block_105 = header_with(hash(104), 105);
		let behind = best(104, 104);
		let at_tip = BestBlock::new(block_105.block_hash(), 105);
		assert_eq!(disconnect_action(&behind, &block_105, 105), DisconnectAction::NotReached);
		assert_eq!(disconnect_action(&at_tip, &block_105, 105), DisconnectAction::Rewind);

		// The same height on a different block, or above the height being disconnected —
		// including a monitor persisted ahead of the replay that a reorg reaches before the
		// replay does — cannot be rewound along this branch and fails closed.
		let other_105 = best(105, 0xbb);
		assert_eq!(disconnect_action(&other_105, &block_105, 105), DisconnectAction::Diverged);
		let ahead_unfed = best(110, 110);
		assert_eq!(disconnect_action(&ahead_unfed, &block_105, 105), DisconnectAction::Diverged);
	}

	#[test]
	fn a_snapshot_is_unprovable_below_its_height_and_kept() {
		let mut gate = MonitorGate::new([(funding(1), best(110, 110))]);
		let decisions = gate.judge_block(hash(105), hash(104), 105);
		assert_eq!(decisions.len(), 1);
		assert_eq!(decisions[0].action, ListenerAction::ReplayUnprovable);
		assert_eq!(decisions[0].snapshot.best, best(110, 110));
		assert_eq!(decisions[0].snapshot.name, monitor_name(1));
		assert_eq!(gate.live(), 1, "still waiting for the replay to reach 110");
	}

	#[test]
	fn a_snapshot_is_proven_at_its_own_height_and_retired() {
		// An ahead monitor on the same chain: its own block replays as an exact match. Proven,
		// and never decided again — the next block is delivered to it in lockstep, not judged.
		let mut gate = MonitorGate::new([(funding(1), best(110, 110))]);
		let decisions = gate.judge_block(hash(110), hash(109), 110);
		assert_eq!(decisions[0].action, ListenerAction::AlreadyApplied);
		assert_eq!(gate.live(), 0);
		assert!(gate.judge_block(hash(111), hash(110), 111).is_empty());
	}

	#[test]
	fn a_snapshot_is_proven_as_the_parent_of_the_next_block_and_retired() {
		// The resume floor is the furthest-behind monitor, so ITS snapshot is proven by the very
		// first replayed block, which extends it.
		let mut gate = MonitorGate::new([(funding(1), best(104, 104))]);
		let decisions = gate.judge_block(hash(105), hash(104), 105);
		assert_eq!(decisions[0].action, ListenerAction::Deliver);
		assert_eq!(gate.live(), 0);
	}

	#[test]
	fn a_snapshot_on_another_chain_is_refuted_at_its_own_height_and_kept_as_evidence() {
		let mut gate = MonitorGate::new([(funding(1), best(110, 0xbb))]);
		let decisions = gate.judge_block(hash(110), hash(109), 110);
		assert_eq!(decisions[0].action, ListenerAction::Diverged);
		assert_eq!(decisions[0].snapshot.name, monitor_name(1));
		assert_eq!(gate.live(), 1);
	}

	#[test]
	fn a_snapshot_with_the_wrong_parent_or_a_gap_is_refuted() {
		let mut gate =
			MonitorGate::new([(funding(1), best(110, 110)), (funding(2), best(110, 110))]);
		// Next height, but the parent is not the snapshot: another chain.
		let decisions = gate.judge_block(hash(111), hash(0xaa), 111);
		assert_eq!(decisions.len(), 2);
		assert!(decisions.iter().all(|d| d.action == ListenerAction::Diverged));
		// A gap: the replay skipped a block, which a lockstep listener cannot absorb.
		let decisions = gate.judge_block(hash(113), hash(112), 113);
		assert!(decisions.iter().all(|d| d.action == ListenerAction::Diverged));
		assert_eq!(gate.live(), 2);
	}

	#[test]
	fn snapshots_are_judged_independently() {
		// Three monitors at three heights, the ordinary post-restart skew: one block proves the
		// monitor it extends, replays the one at its height, and cannot yet say anything about
		// the third.
		let mut gate = MonitorGate::new([
			(funding(1), best(104, 104)),
			(funding(2), best(105, 105)),
			(funding(3), best(107, 107)),
		]);
		let decisions = gate.judge_block(hash(105), hash(104), 105);
		let action_of = |seed: u8| {
			decisions.iter().find(|d| d.snapshot.name == monitor_name(seed)).unwrap().action
		};
		assert_eq!(action_of(1), ListenerAction::Deliver);
		assert_eq!(action_of(2), ListenerAction::AlreadyApplied);
		assert_eq!(action_of(3), ListenerAction::ReplayUnprovable);
		assert_eq!(gate.live(), 1, "only the monitor at 107 is still unproven");

		// ... and it is proven two blocks later.
		gate.judge_block(hash(106), hash(105), 106);
		let decisions = gate.judge_block(hash(107), hash(106), 107);
		assert_eq!(decisions.len(), 1);
		assert_eq!(decisions[0].snapshot.name, monitor_name(3));
		assert_eq!(decisions[0].action, ListenerAction::AlreadyApplied);
		assert_eq!(gate.live(), 0);
	}

	#[test]
	fn a_rewind_retires_the_snapshots_it_reaches_below() {
		let mut gate =
			MonitorGate::new([(funding(1), best(110, 110)), (funding(2), best(103, 103))]);
		// Rewound below its snapshot: the claim at 110 is moot — the chain replayed after the
		// reorg is another branch, so a block at 110 could never match it again.
		gate.note_rewound(&funding(1), 105);
		assert_eq!(gate.live(), 1);
		// Rewound above its snapshot: the monitor still holds the state the snapshot describes.
		gate.note_rewound(&funding(2), 105);
		assert_eq!(gate.live(), 1);
		// At exactly the snapshot height: nothing at or above it is left.
		gate.note_rewound(&funding(2), 103);
		assert_eq!(gate.live(), 0);
		// A monitor the gate never knew about is ignored.
		gate.note_rewound(&funding(9), 1);
		assert_eq!(gate.live(), 0);
	}

	#[test]
	fn an_empty_gate_decides_nothing() {
		let mut gate = MonitorGate::default();
		assert!(gate.judge_block(hash(1), hash(0), 1).is_empty());
		assert_eq!(gate.live(), 0);
	}

	fn txid(seed: u8) -> Txid {
		Txid::from_byte_array([seed; 32])
	}

	fn entry(txid: Txid) -> MempoolEntry {
		MempoolEntry { txid, time: 1_700_000_000, height: 100 }
	}

	/// Core speaks txids in display order. The consensus codec is the
	/// byte-reversed string: encoding with it asks Core about a txid that
	/// does not exist, and decoding with it yields a txid that is not the
	/// transaction's — the two mistakes cancel over the wire and leave every
	/// cache keyed by a txid nothing else in the node will ever look up.
	#[test]
	fn rpc_txid_hex_is_display_order_and_round_trips() {
		let mut bytes = [0u8; 32];
		for (i, b) in bytes.iter_mut().enumerate() {
			*b = i as u8;
		}
		let id = Txid::from_byte_array(bytes);

		let hex = txid_to_rpc_hex(&id);
		assert_eq!(hex, id.to_string());
		assert_eq!(txid_from_rpc_hex(&hex), Some(id), "round-trips through Core's own format");

		let consensus_hex = bitcoin::consensus::encode::serialize_hex(&id);
		assert_ne!(hex, consensus_hex, "the consensus codec is the reversed string");
		let misread: Txid = bitcoin::consensus::encode::deserialize_hex(&hex).unwrap();
		assert_ne!(misread, id, "decoding Core's string as consensus bytes is not the txid");
		assert_eq!(
			bitcoin::consensus::encode::serialize_hex(&misread),
			hex,
			"which is why the two mistakes used to cancel on the way back to Core"
		);

		assert_eq!(txid_from_rpc_hex("not hex"), None);
		assert_eq!(txid_from_rpc_hex(&hex[..10]), None, "a short string is not a txid");
	}

	/// Evicted is what the entries cache lacks — not what it holds.
	#[test]
	fn evicted_is_what_the_entries_cache_lacks() {
		let (still_there, gone, also_gone) = (txid(1), txid(2), txid(3));
		let mut cache = HashMap::new();
		cache.insert(still_there, entry(still_there));

		assert_eq!(
			txids_missing_from(&cache, &[still_there, gone, also_gone]),
			vec![gone, also_gone]
		);
		assert_eq!(txids_missing_from(&cache, &[still_there]), Vec::<Txid>::new());
		assert_eq!(txids_missing_from(&cache, &[]), Vec::<Txid>::new());
		assert_eq!(
			txids_missing_from(&HashMap::new(), &[still_there, gone]),
			vec![still_there, gone],
			"an empty mempool has evicted everything the wallet still holds"
		);
	}
}
