// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Chain ability adapters for a node with no chain source of its own.
//!
//! Every slot is filled from a single [`ChainDataProvider`]: the node asks
//! another node and believes the answer. There is no verification step here
//! and that is the design — a Dependent node that could check the answer
//! would not need to ask.
//!
//! What it does not offer is a UTXO source. It could ask its provider to check
//! the UTXO set, but an announcement "verified" by asking the same node that
//! supplied it is not verified; not implementing [`UtxoCapability`] makes the
//! node log, at startup, that its routing graph carries unchecked capacities —
//! which is the honest position.
//!
//! [`UtxoCapability`]: crate::chain::seam::UtxoCapability
//!
//! What it does *not* do is pretend. Every path below distinguishes "the
//! provider said no" from "I could not ask", because the second is not
//! evidence of anything.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::{FeeRate, Transaction};

use crate::chain::provider::{
	ChainDataProvider, WireBroadcastRequest, WireSyncRequest, CHAIN_WIRE_VERSION,
};
use crate::chain::seam::{
	ActionResult, Anchored, BroadcastAction, BroadcastRejection, ChainActionError, FeeAction,
	FeeUpdate, MempoolAction, MempoolAnswer, MempoolQuery, PackageOutcomes, ScriptHistoryAction,
	TxBroadcastOutcome, ADAPTER_BUDGET_MARGIN, MAX_BROADCAST_PACKAGE_TXS,
};
use crate::chain::wire_convert::{
	check_version, mempool_query_to_wire, tx_to_wire, wire_to_mempool_answer, wire_update_to_bdk,
};
use crate::fee_estimator::{apply_post_estimation_adjustments, conf_target_from_wire_name};
use crate::logger::{log_error, log_trace, LdkLogger, Logger};

#[cfg(feature = "swaps")]
use crate::chain::provider::WireTxStatusRequest;
#[cfg(feature = "swaps")]
use crate::chain::seam::TxStatusAction;
#[cfg(feature = "swaps")]
use crate::chain::wire_convert::{block_hash_from_wire, script_to_wire, txid_to_wire};
#[cfg(feature = "swaps")]
use crate::chain::RawTxObservation;
#[cfg(feature = "swaps")]
use bitcoin::{ScriptBuf, Txid};

use async_trait::async_trait;

/// The ceiling the embedding app puts on one [`ChainDataProvider`] call:
/// `CHAIN_CALL_TIMEOUT_SECS` in node-app-ldk-node's `src/chain_provider.rs`
/// (1.6.0), "deliberately shorter than ldk-node's own wallet-sync timeout, so
/// a slow provider surfaces as a provider problem there rather than as a
/// sync timeout two layers up". Mirrored here because it is the app's
/// constant: every provider call this adapter makes has either answered or
/// failed within it, whatever the serving node's own backend takes, so the
/// seam's budgets are that ceiling plus the margin — never shorter, or the
/// seam would fire first and the app's own timeout, and its attribution of
/// where the time went, would never be seen.
const PROVIDER_CALL_TIMEOUT_SECS: u64 = 20;

/// One provider call plus the margin.
const DEPENDENT_CALL_BUDGET: Duration =
	Duration::from_secs(PROVIDER_CALL_TIMEOUT_SECS + ADAPTER_BUDGET_MARGIN.as_secs());

/// FEE budget: one provider call.
const DEPENDENT_FEE_BUDGET: Duration = DEPENDENT_CALL_BUDGET;

/// BROADCAST budget: the wire carries one transaction per request, so a
/// package is as many provider calls as it has transactions. Sized for the
/// largest package, like the backends' own budgets.
const DEPENDENT_BROADCAST_BUDGET: Duration =
	Duration::from_secs(MAX_BROADCAST_PACKAGE_TXS * DEPENDENT_CALL_BUDGET.as_secs());

/// TX_STATUS budget: one provider call. The serving node runs its own
/// TX_STATUS chain behind it, through whichever adapter it has, but the app
/// bounds the call regardless of how long that chain may take.
#[cfg(feature = "swaps")]
const DEPENDENT_TX_STATUS_BUDGET: Duration = DEPENDENT_CALL_BUDGET;

/// MEMPOOL budget: one provider call, which answers completely and
/// filtered, so its size is the asker's own transactions, not the mempool.
const DEPENDENT_MEMPOOL_BUDGET: Duration = DEPENDENT_CALL_BUDGET;

/// SCRIPT_HISTORY budget: one provider call. The serving node runs a real
/// scan behind it, which is the heaviest thing a provider does, but the app
/// bounds the call at its ceiling regardless — as it does for the Dependent
/// engine's own wallet sync, which is the same route.
const DEPENDENT_SCRIPT_HISTORY_BUDGET: Duration = DEPENDENT_CALL_BUDGET;

/// Fills the FEE, TX_STATUS and BROADCAST slots from a remote node, and the
/// MEMPOOL and SCRIPT_HISTORY slots of a hybrid node that follows the chain
/// itself but has no mempool and no script index to scan.
pub(crate) struct DependentChainAdapter {
	provider: Arc<dyn ChainDataProvider>,
	logger: Arc<Logger>,
}

impl DependentChainAdapter {
	pub(crate) fn new(provider: Arc<dyn ChainDataProvider>, logger: Arc<Logger>) -> Self {
		Self { provider, logger }
	}

	/// The pre-chain fee fetch, unchanged: the provider's answer, checked and
	/// re-floored locally. Provider errors map straight onto the seam's error
	/// — `Unreachable` is the timeout, as it was pre-chain — with no `Error`
	/// in between.
	async fn fetch_fee_rate_update(&self) -> ActionResult<FeeUpdate> {
		let estimates = self.provider.fee_estimates().await.map_err(|e| {
			log_error!(self.logger, "Failed to retrieve fee rate estimates from provider: {}", e);
			ChainActionError::from(e)
		})?;

		check_version(estimates.version).map_err(|e| {
			log_error!(self.logger, "Rejecting fee rate estimates from provider: {}", e);
			ChainActionError::unavailable(e.to_string())
		})?;

		let mut new_fee_rate_cache = HashMap::with_capacity(estimates.targets.len());
		for entry in &estimates.targets {
			let Some(target) = conf_target_from_wire_name(&entry.target) else {
				// A target this build does not know. Skipping it is right —
				// guessing which local target it meant would silently apply
				// the wrong rate — but it must be visible.
				log_trace!(
					self.logger,
					"Ignoring unknown confirmation target '{}' from chain provider",
					entry.target
				);
				continue;
			};

			// The serving node has already applied its own per-target policy;
			// the post-estimation adjustments are this node's own floors and
			// caps, so they still belong here.
			let fee_rate = FeeRate::from_sat_per_kwu(entry.sat_per_kwu);
			new_fee_rate_cache.insert(target, apply_post_estimation_adjustments(target, fee_rate));
		}

		// An empty cache would leave every target at its hardcoded fallback
		// while looking like a successful update, so refuse it outright.
		if new_fee_rate_cache.is_empty() {
			log_error!(
				self.logger,
				"Chain provider returned no usable fee rate estimates; keeping the previous cache"
			);
			return Err(ChainActionError::unavailable("no usable fee rate estimates"));
		}

		Ok(FeeUpdate::Apply { cache: new_fee_rate_cache, log_unchanged: false })
	}
}

#[async_trait]
impl FeeAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_FEE_BUDGET)
	}

	async fn fee_rate_update(&self) -> ActionResult<FeeUpdate> {
		self.fetch_fee_rate_update().await
	}
}

#[async_trait]
impl BroadcastAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_BROADCAST_BUDGET)
	}

	/// One request per transaction, since the wire carries one.
	///
	/// This adapter never answers `Rejected`. The wire (frozen at
	/// `CHAIN_WIRE_VERSION` 1) cannot express a rejection: the serving node
	/// fails the call whether its own chain could not broadcast or the network
	/// refused the transaction, and both reach this node as the same
	/// [`ChainProviderError::Refused`]. `Refused` means only that the provider
	/// would not serve, so it is `Unavailable` like every other provider
	/// error, and the chain advances.
	async fn broadcast_package(
		&self, txs: &[Transaction],
	) -> ActionResult<PackageOutcomes, BroadcastRejection> {
		let mut outcomes = Vec::with_capacity(txs.len());
		for tx in txs {
			outcomes.push((tx.compute_txid(), self.broadcast_tx(tx).await));
		}
		Ok(outcomes)
	}
}

impl DependentChainAdapter {
	/// The pre-seam per-transaction send and its log levels. A provider error
	/// maps straight onto the seam's error — `Unreachable` is the timeout, as
	/// it was pre-chain — and from there onto the per-transaction outcome.
	async fn broadcast_tx(&self, tx: &Transaction) -> TxBroadcastOutcome {
		let txid = tx.compute_txid();
		let req = WireBroadcastRequest { version: CHAIN_WIRE_VERSION, tx_hex: tx_to_wire(tx) };

		match self.provider.broadcast(req).await {
			Ok(()) => {
				log_trace!(
					self.logger,
					"Chain provider accepted transaction {} for broadcast",
					txid
				);
				TxBroadcastOutcome::Accepted
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Chain provider failed to broadcast transaction {}: {}",
					txid,
					e
				);
				ChainActionError::from(e).into()
			},
		}
	}
}

/// Anchored at `(tip_height, tip_hash)` when the answer carries both — a
/// serving node that read the tip it answered at says which block it was —
/// so a hybrid node checks the answer against its own chain. An answer with
/// either missing is unanchored, as every answer was before the hash was on
/// the wire; one whose hash does not parse is unusable and fails closed.
#[cfg(feature = "swaps")]
#[async_trait]
impl TxStatusAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_TX_STATUS_BUDGET)
	}

	async fn tx_status(
		&self, txid: Txid, script_pubkey: Option<&ScriptBuf>,
	) -> ActionResult<Anchored<RawTxObservation>> {
		let req = WireTxStatusRequest {
			version: CHAIN_WIRE_VERSION,
			txid: txid_to_wire(&txid),
			script_hex: script_pubkey.map(script_to_wire),
		};

		let resp = match self.provider.tx_status(req).await {
			Ok(resp) => resp,
			Err(e) => {
				// FAIL CLOSED (E6). No answer is not the same as "not
				// confirmed", and callers arm CSV deadlines off this.
				log_error!(
					self.logger,
					"swap_query_tx: chain provider could not answer for {}: {}",
					txid,
					e
				);
				return Err(e.into());
			},
		};

		if check_version(resp.version).is_err() {
			log_error!(
				self.logger,
				"swap_query_tx: chain provider answered for {} with wire version {} (expected {}); failing closed",
				txid,
				resp.version,
				CHAIN_WIRE_VERSION
			);
			return Err(ChainActionError::unavailable(format!(
				"wire version {} (expected {})",
				resp.version, CHAIN_WIRE_VERSION
			)));
		}

		let tip = match wire_tip(&resp) {
			Ok(tip) => tip,
			Err(e) => {
				log_error!(
					self.logger,
					"swap_query_tx: chain provider answered for {} with an unusable tip hash; failing closed: {}",
					txid,
					e
				);
				return Err(ChainActionError::unavailable(format!("unusable tip hash: {}", e)));
			},
		};
		let anchored = |value| Ok(Anchored { value, tip });

		if !resp.confirmed {
			return anchored(if resp.in_mempool {
				RawTxObservation::InMempool
			} else {
				RawTxObservation::NotFound
			});
		}

		// Confirmed, so the answer must carry a height and a tip to derive
		// depth from. A confirmation without them is incoherent; treat it as
		// no answer rather than inventing a depth.
		let (Some(height), Some(tip_height)) = (resp.confirmation_height, resp.tip_height) else {
			log_error!(
				self.logger,
				"swap_query_tx: chain provider reported {} confirmed without a height/tip pair; failing closed",
				txid
			);
			return Err(ChainActionError::unavailable("confirmed without a height/tip pair"));
		};

		if tip_height < height {
			// The same inconsistency the Esplora adapter guards against (B5
			// LOW-2): a tip below the confirming block cannot happen on one
			// consistent chain.
			log_error!(
				self.logger,
				"swap_query_tx: chain provider tip {} below confirming-block height {} for {} (reorg/race); failing closed",
				tip_height,
				height,
				txid
			);
			return Err(ChainActionError::unavailable(format!(
				"tip {} below confirming-block height {}",
				tip_height, height
			)));
		}

		let confirmations = tip_height.saturating_sub(height).saturating_add(1);
		anchored(RawTxObservation::Confirmed { height: Some(height), confirmations })
	}
}

/// The block a TX_STATUS answer was taken at, when the answer names both its
/// height and its hash; `None` when either is missing.
#[cfg(feature = "swaps")]
fn wire_tip(
	resp: &crate::chain::provider::WireTxStatusResponse,
) -> Result<Option<bdk_chain::BlockId>, crate::chain::provider::ChainProviderError> {
	match (resp.tip_height, resp.tip_hash.as_deref()) {
		(Some(height), Some(hash)) => {
			Ok(Some(bdk_chain::BlockId { height, hash: block_hash_from_wire(hash)? }))
		},
		_ => Ok(None),
	}
}

/// The provider answers completely every time, whatever scope the query
/// asks — it remembers nothing about this node — and the answer is anchored
/// to the tip it reports, which a hybrid node checks against its own chain.
#[async_trait]
impl MempoolAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_MEMPOOL_BUDGET)
	}

	async fn mempool(&self, query: &MempoolQuery) -> ActionResult<Anchored<MempoolAnswer>> {
		let req = mempool_query_to_wire(query);
		let resp = self.provider.mempool(req).await.map_err(|e| {
			log_error!(self.logger, "Chain provider could not answer a mempool question: {}", e);
			ChainActionError::from(e)
		})?;

		let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
		let (answer, tip) = wire_to_mempool_answer(&resp, now).map_err(|e| {
			log_error!(self.logger, "Chain provider returned an unusable mempool answer: {}", e);
			ChainActionError::unavailable(e.to_string())
		})?;
		Ok(Anchored { value: answer, tip: Some(tip) })
	}
}

/// The wide scan, run on the provider: the same route the Dependent engine's
/// own wallet sync takes, phrased on the wire request the engine already
/// builds with [`sync_request_to_wire`] and
/// [`full_scan_request_batch_to_wire`].
///
/// The request carries scripts only, so the update's `last_active_indices`
/// is empty: which keys the scripts came from is the asking wallet's own
/// knowledge, and the caller that owns the wallet derives the indices from
/// the returned transactions and its `revealed_spk_index`, as the engine
/// does. The answer is anchored to the update's checkpoint tip, if the scan
/// produced one.
///
/// [`sync_request_to_wire`]: crate::chain::wire_convert::sync_request_to_wire
/// [`full_scan_request_batch_to_wire`]: crate::chain::wire_convert::full_scan_request_batch_to_wire
#[async_trait]
impl ScriptHistoryAction for DependentChainAdapter {
	fn name(&self) -> &'static str {
		"dependent"
	}

	fn budget(&self) -> Option<Duration> {
		Some(DEPENDENT_SCRIPT_HISTORY_BUDGET)
	}

	async fn script_history(
		&self, req: WireSyncRequest,
	) -> ActionResult<Anchored<bdk_wallet::Update>> {
		let spk_count = req.spks.len();
		let wire_update = self.provider.wallet_sync(req).await.map_err(|e| {
			log_error!(
				self.logger,
				"Chain provider could not scan {} scripts' history: {}",
				spk_count,
				e
			);
			ChainActionError::from(e)
		})?;

		let update = wire_update_to_bdk(&wire_update, &HashMap::new()).map_err(|e| {
			log_error!(self.logger, "Chain provider returned an unusable update: {}", e);
			ChainActionError::unavailable(e.to_string())
		})?;
		let tip = update.chain.as_ref().map(|checkpoint| checkpoint.block_id());
		Ok(Anchored { value: update, tip })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::chain::provider::{
		ChainProviderError, WireFeeEstimates, WireLightningSyncRequest, WireLightningSyncResponse,
		WireTxStatusRequest, WireTxStatusResponse, WireUpdate,
	};
	use crate::chain::seam::MempoolScope;
	use crate::logger::Logger;

	/// A provider built against the port as it shipped: it implements the
	/// five original calls and inherits `mempool`'s refusing default.
	struct OlderProvider;

	#[async_trait]
	impl ChainDataProvider for OlderProvider {
		fn name(&self) -> String {
			"older".into()
		}

		async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn broadcast(&self, _req: WireBroadcastRequest) -> Result<(), ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn tx_status(
			&self, _req: WireTxStatusRequest,
		) -> Result<WireTxStatusResponse, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn wallet_sync(
			&self, _req: WireSyncRequest,
		) -> Result<WireUpdate, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn lightning_sync(
			&self, _req: WireLightningSyncRequest,
		) -> Result<WireLightningSyncResponse, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}
	}

	/// N4: a provider that does not carry the mempool route refuses, and the
	/// adapter reports that as `Unavailable` — not timed out, and never an
	/// empty mempool — so the chain advances past it.
	#[tokio::test]
	async fn dependent_mempool_maps_refused_to_unavailable() {
		let adapter =
			DependentChainAdapter::new(Arc::new(OlderProvider), Arc::new(Logger::new_log_facade()));
		let query = MempoolQuery {
			scripts: Vec::new(),
			known_unconfirmed: Vec::new(),
			scope: MempoolScope::Complete,
		};

		let err = adapter.mempool(&query).await.unwrap_err();

		assert_eq!(
			err,
			ChainActionError::Unavailable {
				reason: ChainProviderError::Refused("unsupported".into()).to_string(),
				timed_out: false,
			}
		);
	}

	/// A provider whose TX_STATUS answer is fixed.
	#[cfg(feature = "swaps")]
	struct AnsweringProvider(WireTxStatusResponse);

	#[cfg(feature = "swaps")]
	#[async_trait]
	impl ChainDataProvider for AnsweringProvider {
		fn name(&self) -> String {
			"answering".into()
		}

		async fn fee_estimates(&self) -> Result<WireFeeEstimates, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn broadcast(&self, _req: WireBroadcastRequest) -> Result<(), ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn tx_status(
			&self, _req: WireTxStatusRequest,
		) -> Result<WireTxStatusResponse, ChainProviderError> {
			Ok(self.0.clone())
		}

		async fn wallet_sync(
			&self, _req: WireSyncRequest,
		) -> Result<WireUpdate, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}

		async fn lightning_sync(
			&self, _req: WireLightningSyncRequest,
		) -> Result<WireLightningSyncResponse, ChainProviderError> {
			Err(ChainProviderError::Unreachable("not under test".into()))
		}
	}

	/// The answer is anchored at the serving node's tip when the wire names
	/// both its height and its hash — so a hybrid node's tip check has
	/// something to check — unanchored when either is missing, and refused
	/// when the hash is garbage.
	#[cfg(feature = "swaps")]
	#[tokio::test]
	async fn dependent_tx_status_is_anchored_when_the_wire_names_the_tip() {
		use bitcoin::hashes::Hash;

		let tip_hash = bitcoin::BlockHash::from_byte_array([0x42; 32]);
		let confirmed = WireTxStatusResponse {
			version: CHAIN_WIRE_VERSION,
			confirmed: true,
			in_mempool: false,
			confirmation_height: Some(100),
			tip_height: Some(102),
			tip_hash: Some(tip_hash.to_string()),
		};
		let ask = |resp: WireTxStatusResponse| async move {
			let adapter = DependentChainAdapter::new(
				Arc::new(AnsweringProvider(resp)),
				Arc::new(Logger::new_log_facade()),
			);
			adapter.tx_status(Txid::from_byte_array([1u8; 32]), None).await
		};

		let answer = ask(confirmed.clone()).await.unwrap();
		assert_eq!(
			answer.value,
			RawTxObservation::Confirmed { height: Some(100), confirmations: 3 }
		);
		assert_eq!(answer.tip, Some(bdk_chain::BlockId { height: 102, hash: tip_hash }));

		let in_mempool = WireTxStatusResponse {
			confirmed: false,
			in_mempool: true,
			confirmation_height: None,
			..confirmed.clone()
		};
		let answer = ask(in_mempool).await.unwrap();
		assert_eq!(answer.value, RawTxObservation::InMempool);
		assert_eq!(answer.tip, Some(bdk_chain::BlockId { height: 102, hash: tip_hash }));

		let no_hash = WireTxStatusResponse { tip_hash: None, ..confirmed.clone() };
		let answer = ask(no_hash).await.unwrap();
		assert_eq!(answer.tip, None, "an answer from an older provider is unanchored");
		assert_eq!(
			answer.value,
			RawTxObservation::Confirmed { height: Some(100), confirmations: 3 }
		);

		let garbage = WireTxStatusResponse { tip_hash: Some("not a hash".into()), ..confirmed };
		assert!(matches!(
			ask(garbage).await,
			Err(ChainActionError::Unavailable { timed_out: false, .. })
		));
	}

	/// The budgets are the app's per-call ceiling plus the margin, so the
	/// app's own timeout always fires first.
	#[test]
	fn budgets_outlast_the_apps_provider_call_timeout() {
		let app_ceiling = Duration::from_secs(PROVIDER_CALL_TIMEOUT_SECS);
		assert!(DEPENDENT_FEE_BUDGET > app_ceiling);
		assert_eq!(DEPENDENT_FEE_BUDGET, Duration::from_secs(21));
		assert_eq!(DEPENDENT_BROADCAST_BUDGET, Duration::from_secs(21 * MAX_BROADCAST_PACKAGE_TXS));
		assert_eq!(DEPENDENT_BROADCAST_BUDGET, Duration::from_secs(525));
		assert_eq!(DEPENDENT_MEMPOOL_BUDGET, Duration::from_secs(21));
		assert_eq!(DEPENDENT_SCRIPT_HISTORY_BUDGET, Duration::from_secs(21));
		#[cfg(feature = "swaps")]
		{
			assert!(DEPENDENT_TX_STATUS_BUDGET > app_ceiling);
			assert_eq!(DEPENDENT_TX_STATUS_BUDGET, Duration::from_secs(21));
		}
	}
}
