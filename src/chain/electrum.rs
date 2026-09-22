// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::config::{
	Config, BDK_CLIENT_STOP_GAP, BDK_WALLET_SYNC_TIMEOUT_SECS, FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS,
	LDK_WALLET_SYNC_TIMEOUT_SECS, TX_BROADCAST_TIMEOUT_SECS,
};
use crate::error::Error;
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
	ConfirmationTarget,
};
use crate::logger::{log_bytes, log_error, log_info, log_trace, LdkLogger, Logger};

use lightning::chain::{Confirm, Filter, WatchedOutput};
use lightning::util::ser::Writeable;
use lightning_transaction_sync::ElectrumSyncClient;

use bdk_chain::bdk_core::spk_client::FullScanRequest as BdkFullScanRequest;
use bdk_chain::bdk_core::spk_client::FullScanResponse as BdkFullScanResponse;
use bdk_chain::bdk_core::spk_client::SyncRequest as BdkSyncRequest;
use bdk_chain::bdk_core::spk_client::SyncResponse as BdkSyncResponse;
use bdk_wallet::KeychainKind as BdkKeyChainKind;

use bdk_electrum::BdkElectrumClient;

use electrum_client::Client as ElectrumClient;
use electrum_client::ConfigBuilder as ElectrumConfigBuilder;
use electrum_client::{Batch, ElectrumApi};

use bitcoin::{BlockHash, FeeRate, Network, OutPoint, Script, ScriptBuf, Transaction, Txid};

use crate::chain::provider::{
	WireBlockId, WireConfirmedTx, WireLightningSyncRequest, WireLightningSyncResponse,
	WireSyncRequest, WireUpdate, CHAIN_WIRE_VERSION,
};
use crate::chain::wire_convert::{
	block_hash_from_wire, header_to_wire, outpoint_from_wire, script_from_wire,
	sync_response_to_wire, tx_to_wire, txid_from_wire, wire_to_sync_request,
};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const BDK_ELECTRUM_CLIENT_BATCH_SIZE: usize = 5;
const ELECTRUM_CLIENT_NUM_RETRIES: u8 = 3;
const ELECTRUM_CLIENT_TIMEOUT_SECS: u8 = 20;

pub(crate) struct ElectrumRuntimeClient {
	electrum_client: Arc<ElectrumClient>,
	bdk_electrum_client: Arc<BdkElectrumClient<ElectrumClient>>,
	tx_sync: Arc<ElectrumSyncClient<Arc<Logger>>>,
	runtime: Arc<tokio::runtime::Runtime>,
	config: Arc<Config>,
	logger: Arc<Logger>,
}

impl ElectrumRuntimeClient {
	pub(crate) fn new(
		server_url: String, runtime: Arc<tokio::runtime::Runtime>, config: Arc<Config>,
		logger: Arc<Logger>,
	) -> Result<Self, Error> {
		let electrum_config = ElectrumConfigBuilder::new()
			.retry(ELECTRUM_CLIENT_NUM_RETRIES)
			.timeout(Some(ELECTRUM_CLIENT_TIMEOUT_SECS))
			.build();

		let electrum_client = Arc::new(
			ElectrumClient::from_config(&server_url, electrum_config.clone()).map_err(|e| {
				log_error!(logger, "Failed to connect to electrum server: {}", e);
				Error::ConnectionFailed
			})?,
		);
		let electrum_client_2 =
			ElectrumClient::from_config(&server_url, electrum_config).map_err(|e| {
				log_error!(logger, "Failed to connect to electrum server: {}", e);
				Error::ConnectionFailed
			})?;
		let bdk_electrum_client = Arc::new(BdkElectrumClient::new(electrum_client_2));
		let tx_sync = Arc::new(
			ElectrumSyncClient::new(server_url.clone(), Arc::clone(&logger)).map_err(|e| {
				log_error!(logger, "Failed to connect to electrum server: {}", e);
				Error::ConnectionFailed
			})?,
		);
		Ok(Self { electrum_client, bdk_electrum_client, tx_sync, runtime, config, logger })
	}

	pub(crate) async fn sync_confirmables(
		&self, confirmables: Vec<Arc<dyn Confirm + Sync + Send>>,
	) -> Result<(), Error> {
		let now = Instant::now();

		let tx_sync = Arc::clone(&self.tx_sync);
		let spawn_fut = self.runtime.spawn_blocking(move || tx_sync.sync(confirmables));
		let timeout_fut =
			tokio::time::timeout(Duration::from_secs(LDK_WALLET_SYNC_TIMEOUT_SECS), spawn_fut);

		let res = timeout_fut
			.await
			.map_err(|e| {
				log_error!(self.logger, "Sync of Lightning wallet timed out: {}", e);
				Error::TxSyncTimeout
			})?
			.map_err(|e| {
				log_error!(self.logger, "Sync of Lightning wallet failed: {}", e);
				Error::TxSyncFailed
			})?
			.map_err(|e| {
				log_error!(self.logger, "Sync of Lightning wallet failed: {}", e);
				Error::TxSyncFailed
			})?;

		log_info!(
			self.logger,
			"Sync of Lightning wallet finished in {}ms.",
			now.elapsed().as_millis()
		);

		Ok(res)
	}

	pub(crate) async fn get_full_scan_wallet_update(
		&self, request: BdkFullScanRequest<BdkKeyChainKind>,
		cached_txs: impl IntoIterator<Item = impl Into<Arc<Transaction>>>,
	) -> Result<BdkFullScanResponse<BdkKeyChainKind>, Error> {
		let bdk_electrum_client = Arc::clone(&self.bdk_electrum_client);
		bdk_electrum_client.populate_tx_cache(cached_txs);

		let spawn_fut = self.runtime.spawn_blocking(move || {
			bdk_electrum_client.full_scan(
				request,
				BDK_CLIENT_STOP_GAP,
				BDK_ELECTRUM_CLIENT_BATCH_SIZE,
				true,
			)
		});
		let wallet_sync_timeout_fut =
			tokio::time::timeout(Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS), spawn_fut);

		wallet_sync_timeout_fut
			.await
			.map_err(|e| {
				log_error!(self.logger, "Sync of on-chain wallet timed out: {}", e);
				Error::WalletOperationTimeout
			})?
			.map_err(|e| {
				log_error!(self.logger, "Sync of on-chain wallet failed: {}", e);
				Error::WalletOperationFailed
			})?
			.map_err(|e| {
				log_error!(self.logger, "Sync of on-chain wallet failed: {}", e);
				Error::WalletOperationFailed
			})
	}

	pub(crate) async fn get_incremental_sync_wallet_update(
		&self, request: BdkSyncRequest<(BdkKeyChainKind, u32)>,
		cached_txs: impl IntoIterator<Item = impl Into<Arc<Transaction>>>,
	) -> Result<BdkSyncResponse, Error> {
		let bdk_electrum_client = Arc::clone(&self.bdk_electrum_client);
		bdk_electrum_client.populate_tx_cache(cached_txs);

		let spawn_fut = self.runtime.spawn_blocking(move || {
			bdk_electrum_client.sync(request, BDK_ELECTRUM_CLIENT_BATCH_SIZE, true)
		});
		let wallet_sync_timeout_fut =
			tokio::time::timeout(Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS), spawn_fut);

		wallet_sync_timeout_fut
			.await
			.map_err(|e| {
				log_error!(self.logger, "Incremental sync of on-chain wallet timed out: {}", e);
				Error::WalletOperationTimeout
			})?
			.map_err(|e| {
				log_error!(self.logger, "Incremental sync of on-chain wallet failed: {}", e);
				Error::WalletOperationFailed
			})?
			.map_err(|e| {
				log_error!(self.logger, "Incremental sync of on-chain wallet failed: {}", e);
				Error::WalletOperationFailed
			})
	}

	pub(crate) async fn broadcast(&self, tx: Transaction) {
		let electrum_client = Arc::clone(&self.electrum_client);

		let txid = tx.compute_txid();
		let tx_bytes = tx.encode();

		let spawn_fut =
			self.runtime.spawn_blocking(move || electrum_client.transaction_broadcast(&tx));

		let timeout_fut =
			tokio::time::timeout(Duration::from_secs(TX_BROADCAST_TIMEOUT_SECS), spawn_fut);

		match timeout_fut.await {
			Ok(res) => match res {
				Ok(_) => {
					log_trace!(self.logger, "Successfully broadcast transaction {}", txid);
				},
				Err(e) => {
					log_error!(self.logger, "Failed to broadcast transaction {}: {}", txid, e);
					log_trace!(
						self.logger,
						"Failed broadcast transaction bytes: {}",
						log_bytes!(tx_bytes)
					);
				},
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to broadcast transaction due to timeout {}: {}",
					txid,
					e
				);
				log_trace!(
					self.logger,
					"Failed broadcast transaction bytes: {}",
					log_bytes!(tx_bytes)
				);
			},
		}
	}

	/// Reorg-aware confirmation query for an ARBITRARY `txid` via its watched
	/// scriptPubKey's history (Peerswap native primitive B5).
	///
	/// Electrum locates a transaction through its scriptHash history (not by
	/// txid), so the watched output script is required. Any client/transport/
	/// task failure yields [`RawTxObservation::Unreachable`] so the caller fails
	/// closed (never a falsely-confirmed result, E6).
	#[cfg(feature = "swaps")]
	pub(crate) async fn swap_query_tx(
		&self, txid: Txid, script_pubkey: bitcoin::ScriptBuf,
	) -> crate::chain::RawTxObservation {
		use crate::chain::RawTxObservation;

		let electrum_client = Arc::clone(&self.electrum_client);

		let spawn_fut = self.runtime.spawn_blocking(move || {
			let history = electrum_client.script_get_history(script_pubkey.as_script())?;
			let tip = electrum_client.block_headers_subscribe()?;
			Ok::<_, electrum_client::Error>((history, tip.height))
		});

		let (history, tip_height) = match spawn_fut.await {
			Ok(Ok(result)) => result,
			Ok(Err(e)) => {
				log_error!(
					self.logger,
					"swap_query_tx: Electrum query failed for {}: {}",
					txid,
					e
				);
				return RawTxObservation::Unreachable;
			},
			Err(e) => {
				log_error!(
					self.logger,
					"swap_query_tx: Electrum task join failed for {}: {}",
					txid,
					e
				);
				return RawTxObservation::Unreachable;
			},
		};

		match history.into_iter().find(|entry| entry.tx_hash == txid) {
			Some(entry) => {
				// Electrum reports height 0 (unconfirmed) or -1 (unconfirmed with
				// unconfirmed parents); both mean "in the mempool".
				if entry.height <= 0 {
					RawTxObservation::InMempool
				} else {
					let height = entry.height as u32;
					let confirmations =
						(tip_height as u32).saturating_sub(height).saturating_add(1);
					RawTxObservation::Confirmed { height: Some(height), confirmations }
				}
			},
			None => RawTxObservation::NotFound,
		}
	}

	pub(crate) async fn get_fee_rate_cache_update(
		&self,
	) -> Result<HashMap<ConfirmationTarget, FeeRate>, Error> {
		let electrum_client = Arc::clone(&self.electrum_client);

		let mut batch = Batch::default();
		let confirmation_targets = get_all_conf_targets();
		for target in confirmation_targets {
			let num_blocks = get_num_block_defaults_for_target(target);
			batch.estimate_fee(num_blocks);
		}

		let spawn_fut = self.runtime.spawn_blocking(move || electrum_client.batch_call(&batch));

		let timeout_fut = tokio::time::timeout(
			Duration::from_secs(FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS),
			spawn_fut,
		);

		let raw_estimates_btc_kvb = timeout_fut
			.await
			.map_err(|e| {
				log_error!(self.logger, "Updating fee rate estimates timed out: {}", e);
				Error::FeerateEstimationUpdateTimeout
			})?
			.map_err(|e| {
				log_error!(self.logger, "Failed to retrieve fee rate estimates: {}", e);
				Error::FeerateEstimationUpdateFailed
			})?
			.map_err(|e| {
				log_error!(self.logger, "Failed to retrieve fee rate estimates: {}", e);
				Error::FeerateEstimationUpdateFailed
			})?;

		if raw_estimates_btc_kvb.len() != confirmation_targets.len()
			&& self.config.network == Network::Bitcoin
		{
			// Ensure we fail if we didn't receive all estimates.
			debug_assert!(false,
				"Electrum server didn't return all expected results. This is disallowed on Mainnet."
			);
			log_error!(self.logger,
				"Failed to retrieve fee rate estimates: Electrum server didn't return all expected results. This is disallowed on Mainnet."
			);
			return Err(Error::FeerateEstimationUpdateFailed);
		}

		let mut new_fee_rate_cache = HashMap::with_capacity(10);
		for (target, raw_fee_rate_btc_per_kvb) in
			confirmation_targets.into_iter().zip(raw_estimates_btc_kvb.into_iter())
		{
			// Parse the retrieved serde_json::Value and fall back to 1 sat/vb (10^3 / 10^8 = 10^-5
			// = 0.00001 btc/kvb) if we fail or it yields less than that. This is mostly necessary
			// to continue on `signet`/`regtest` where we might not get estimates (or bogus
			// values).
			let fee_rate_btc_per_kvb = raw_fee_rate_btc_per_kvb
				.as_f64()
				.map_or(0.00001, |converted| converted.max(0.00001));

			// Electrum, just like Bitcoin Core, gives us a feerate in BTC/KvB.
			// Thus, we multiply by 25_000_000 (10^8 / 4) to get satoshis/kwu.
			let fee_rate = {
				let fee_rate_sat_per_kwu = (fee_rate_btc_per_kvb * 25_000_000.0).round() as u64;
				FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu)
			};

			// LDK 0.0.118 introduced changes to the `ConfirmationTarget` semantics that
			// require some post-estimation adjustments to the fee rates, which we do here.
			let adjusted_fee_rate = apply_post_estimation_adjustments(target, fee_rate);

			new_fee_rate_cache.insert(target, adjusted_fee_rate);

			log_trace!(
				self.logger,
				"Fee rate estimation updated for {:?}: {} sats/kwu",
				target,
				adjusted_fee_rate.to_sat_per_kwu(),
			);
		}

		Ok(new_fee_rate_cache)
	}

	// ── serving a Dependent node ─────────────────────────────────────────────

	/// Run a Dependent node's on-chain scan against this node's Electrum
	/// server.
	///
	/// Uses the same `BdkElectrumClient` this node syncs itself with, so a
	/// served answer and a local one come from one code path — and, more to
	/// the point, from the same batching. Electrum folds many script lookups
	/// into one round trip, which is what makes serving someone else's wallet
	/// affordable where a request-per-script HTTP API is not.
	pub(crate) async fn serve_wallet_sync(
		&self, req: &WireSyncRequest,
	) -> Result<WireUpdate, Error> {
		let sync_request = wire_to_sync_request(req).map_err(|e| {
			log_error!(self.logger, "Refusing a malformed wallet sync request: {}", e);
			Error::ChainServeFailed
		})?;

		let bdk_electrum_client = Arc::clone(&self.bdk_electrum_client);
		let spawn_fut = self.runtime.spawn_blocking(move || {
			bdk_electrum_client.sync(sync_request, BDK_ELECTRUM_CLIENT_BATCH_SIZE, true)
		});

		let response =
			tokio::time::timeout(Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS), spawn_fut)
				.await
				.map_err(|e| {
					log_error!(self.logger, "Serving a wallet sync request timed out: {}", e);
					Error::ChainServeFailed
				})?
				.map_err(|e| {
					log_error!(self.logger, "Serving a wallet sync request could not run: {}", e);
					Error::ChainServeFailed
				})?
				.map_err(|e| {
					log_error!(self.logger, "Serving a wallet sync request failed: {}", e);
					Error::ChainServeFailed
				})?;

		Ok(sync_response_to_wire(response))
	}

	/// Answer a Dependent node's Lightning sync request.
	///
	/// Electrum indexes by script, not by txid, so a watched transaction is
	/// resolved the way LDK's own Electrum sync resolves it: fetch the
	/// transaction, take one of its own outputs, and look *that* script up.
	/// The caller therefore needs to send no more than it already does.
	pub(crate) async fn serve_lightning_sync(
		&self, req: &WireLightningSyncRequest,
	) -> Result<WireLightningSyncResponse, Error> {
		let malformed = |e: crate::chain::provider::ChainProviderError| {
			log_error!(self.logger, "Refusing a malformed lightning sync request: {}", e);
			Error::ChainServeFailed
		};

		// Decode before the runtime hop, so a bad request costs the server
		// nothing.
		let mut watched_txs = Vec::with_capacity(req.txids.len());
		for w in &req.txids {
			let txid = txid_from_wire(&w.txid).map_err(malformed)?;
			let known = w
				.known_block_hash
				.as_deref()
				.map(block_hash_from_wire)
				.transpose()
				.map_err(malformed)?;
			watched_txs.push((txid, known));
		}

		let mut watched_outputs = Vec::with_capacity(req.outputs.len());
		for o in &req.outputs {
			let outpoint = outpoint_from_wire(&o.outpoint).map_err(malformed)?;
			let script = script_from_wire(&o.script_hex).map_err(malformed)?;
			watched_outputs.push((outpoint, script));
		}

		let electrum_client = Arc::clone(&self.electrum_client);
		let logger = Arc::clone(&self.logger);
		let spawn_fut = self.runtime.spawn_blocking(move || {
			serve_lightning_sync_blocking(&electrum_client, &logger, watched_txs, watched_outputs)
		});

		tokio::time::timeout(Duration::from_secs(LDK_WALLET_SYNC_TIMEOUT_SECS), spawn_fut)
			.await
			.map_err(|e| {
				log_error!(self.logger, "Serving a lightning sync request timed out: {}", e);
				Error::ChainServeFailed
			})?
			.map_err(|e| {
				log_error!(self.logger, "Serving a lightning sync request could not run: {}", e);
				Error::ChainServeFailed
			})?
	}
}

/// The blocking half of [`ElectrumRuntimeClient::serve_lightning_sync`].
///
/// Every Electrum call blocks, so the whole answer is assembled on one
/// `spawn_blocking` thread rather than hopping per call.
///
/// On a server inconsistency this fails the whole request rather than
/// returning a partial answer. A silently dropped confirmation would leave the
/// asking node believing its funds are still unconfirmed with nothing to
/// retry; failing makes the next tick ask again. This is the same trade LDK's
/// own Electrum sync makes for itself.
fn serve_lightning_sync_blocking(
	electrum_client: &ElectrumClient, logger: &Logger, watched_txs: Vec<(Txid, Option<BlockHash>)>,
	watched_outputs: Vec<(OutPoint, ScriptBuf)>,
) -> Result<WireLightningSyncResponse, Error> {
	let chain_failed = |what: &str, e: electrum_client::Error| {
		log_error!(logger, "Serving a lightning sync request failed ({}): {}", what, e);
		Error::ChainServeFailed
	};

	// The tip first: everything else is reported relative to it, and a tip
	// read afterwards could be ahead of the answers already given.
	let tip = electrum_client
		.block_headers_subscribe()
		.map_err(|e| chain_failed("reading the tip", e))?;
	let tip_height = tip.height as u32;
	let tip_header = tip.header;
	let tip_hash = tip_header.block_hash();

	let mut confirmed = Vec::new();
	let mut unconfirmed = Vec::new();

	// Resolve each watched transaction to one of its own scripts, which is
	// the only handle Electrum offers on its history.
	let mut probe_scripts: Vec<ScriptBuf> = Vec::with_capacity(watched_txs.len());
	let mut probes: Vec<(Txid, Option<BlockHash>, Transaction)> =
		Vec::with_capacity(watched_txs.len());

	for (txid, known) in watched_txs {
		match electrum_client.transaction_get(&txid) {
			Ok(tx) => {
				// Bitcoin's Merkle tree cannot distinguish an inner node from
				// a 64-byte leaf, so a 64-byte transaction is refused rather
				// than trusted. Same guard LDK applies.
				if tx.total_size() == 64 {
					log_error!(logger, "Skipping transaction {}: suspicious 64-byte length", txid);
					continue;
				}
				let Some(first_out) = tx.output.first() else {
					log_error!(logger, "Skipping transaction {}: it has no outputs", txid);
					continue;
				};
				probe_scripts.push(first_out.script_pubkey.clone());
				probes.push((txid, known, tx));
			},
			Err(electrum_client::Error::Protocol(_)) => {
				// The server does not have it. Only worth saying so if the
				// caller believed otherwise.
				if known.is_some() {
					unconfirmed.push(txid.to_string());
				}
			},
			Err(e) => return Err(chain_failed("looking up a watched transaction", e)),
		}
	}

	let num_tx_probes = probe_scripts.len();
	for (_outpoint, script) in &watched_outputs {
		probe_scripts.push(script.clone());
	}

	// One round trip for every script, transactions and outputs together.
	// This batching is the whole reason Electrum can serve a Dependent node
	// without exhausting a request budget.
	let histories = electrum_client
		.batch_script_get_history(probe_scripts.iter().map(|s| s.as_script()))
		.map_err(|e| chain_failed("reading script histories", e))?;
	let (tx_histories, output_histories) = histories.split_at(num_tx_probes);

	for ((txid, known, tx), history) in probes.iter().zip(tx_histories) {
		let Some(entry) = history.iter().find(|h| h.tx_hash == *txid) else {
			// Not in the best chain at all.
			if known.is_some() {
				unconfirmed.push(txid.to_string());
			}
			continue;
		};
		// Electrum reports 0 for unconfirmed and -1 for unconfirmed with
		// unconfirmed parents; both mean "in the mempool".
		if entry.height <= 0 {
			if known.is_some() {
				unconfirmed.push(txid.to_string());
			}
			continue;
		}
		let height = entry.height as u32;
		if let Some(wire_tx) = confirmed_tx_entry(electrum_client, logger, tx, height, *known)? {
			confirmed.push(wire_tx);
		}
	}

	for ((outpoint, _script), history) in watched_outputs.iter().zip(output_histories) {
		for candidate in history {
			if candidate.height <= 0 {
				continue;
			}
			let spend = match electrum_client.transaction_get(&candidate.tx_hash) {
				Ok(tx) => tx,
				Err(electrum_client::Error::Protocol(_)) => continue,
				Err(e) => return Err(chain_failed("looking up a possible spend", e)),
			};
			if !spend.input.iter().any(|txin| txin.previous_output == *outpoint) {
				continue;
			}
			let height = candidate.height as u32;
			if let Some(wire_tx) =
				confirmed_tx_entry(electrum_client, logger, &spend, height, None)?
			{
				confirmed.push(wire_tx);
			}
		}
	}

	Ok(WireLightningSyncResponse {
		version: CHAIN_WIRE_VERSION,
		tip: WireBlockId { height: tip_height, hash: tip_hash.to_string() },
		tip_header_hex: header_to_wire(&tip_header),
		confirmed,
		unconfirmed,
	})
}

/// Build one confirmed-transaction answer, or `None` when the caller already
/// knows what we would tell it.
///
/// `pos_in_block` comes from the Merkle proof because LDK's `Confirm` requires
/// it; the proof is not re-validated here, since a Dependent node takes this
/// node's word for the chain by definition.
fn confirmed_tx_entry(
	electrum_client: &ElectrumClient, logger: &Logger, tx: &Transaction, height: u32,
	known: Option<BlockHash>,
) -> Result<Option<WireConfirmedTx>, Error> {
	let header = electrum_client.block_header(height as usize).map_err(|e| {
		log_error!(logger, "Failed to read the header at height {}: {}", height, e);
		Error::ChainServeFailed
	})?;
	let block_hash = header.block_hash();

	// Still in the same block the caller already recorded: nothing to say.
	if known == Some(block_hash) {
		return Ok(None);
	}

	let txid = tx.compute_txid();
	let proof = electrum_client.transaction_get_merkle(&txid, height as usize).map_err(|e| {
		log_error!(logger, "Failed to read the Merkle proof for {} at {}: {}", txid, height, e);
		Error::ChainServeFailed
	})?;

	Ok(Some(WireConfirmedTx {
		tx_hex: tx_to_wire(tx),
		block: WireBlockId { height, hash: block_hash.to_string() },
		pos_in_block: proof.pos as u32,
		header_hex: header_to_wire(&header),
	}))
}

impl Filter for ElectrumRuntimeClient {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.tx_sync.register_tx(txid, script_pubkey)
	}
	fn register_output(&self, output: WatchedOutput) {
		self.tx_sync.register_output(output)
	}
}
