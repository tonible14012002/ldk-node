// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Concrete chain ability adapters.
//!
//! One module per backend. Each fills whichever slots that backend can serve;
//! nothing here knows about node kinds, tiers or presets.
//!
//! What they share is the one `sendrawtransaction` verdict table below: every
//! backend that ends up at a bitcoind — directly over RPC, or through an
//! electrs relaying the RPC error in its HTTP or Electrum reply — folds the
//! same error code and message into the same [`TxBroadcastOutcome`].

pub(crate) mod bitcoind;
pub(crate) mod dependent;
pub(crate) mod electrum;
pub(crate) mod esplora;

use crate::chain::seam::TxBroadcastOutcome;

use serde::Deserialize;

/// `sendrawtransaction` error codes from Bitcoin Core's `RPCErrorCode`.
///
/// `RPC_TRANSACTION_ERROR` (-25) is `TransactionError::MISSING_INPUTS` and,
/// since Core 0.21, everything else `sendrawtransaction` reports that is not
/// a mempool verdict — "Fee exceeds maximum configured by user" among them.
/// Only the missing-inputs reason is a verdict on the transaction.
const RPC_TRANSACTION_ERROR: i64 = -25;
/// `RPC_TRANSACTION_REJECTED` (-26): a mempool policy or consensus verdict
/// (`insufficient fee, rejecting replacement`, `txn-mempool-conflict`,
/// `min relay fee not met`, ...). The network refusing this transaction as it
/// stands; resending it elsewhere would only buy the same verdict.
const RPC_TRANSACTION_REJECTED: i64 = -26;
/// `RPC_TRANSACTION_ALREADY_IN_CHAIN` (-27): the transaction is confirmed, so
/// the network has it. As good as accepted.
const RPC_TRANSACTION_ALREADY_IN_CHAIN: i64 = -27;

/// The one -26 reason that is not a refusal: bitcoind already has this
/// transaction in its mempool. A stable Core reject string.
const REJECT_TXN_ALREADY_KNOWN: &str = "txn-already-known";

/// The -25 reasons that are a verdict on the transaction: its inputs are not
/// in the UTXO set, spent or never existed. `Missing inputs` is what
/// `sendrawtransaction` says; `bad-txns-inputs-missingorspent` is the
/// consensus reject string behind it; `missing-inputs` is `testmempoolaccept`'s
/// and `submitpackage`'s spelling of the same thing.
const REJECT_MISSING_INPUTS: [&str; 3] =
	["Missing inputs", "bad-txns-inputs-missingorspent", "missing-inputs"];

/// What electrs writes in front of the `{"code":..,"message":..}` it relays
/// from bitcoind — in the HTTP 400 body of a `POST /tx`, and in the Electrum
/// protocol error of a `blockchain.transaction.broadcast`.
const SENDRAWTRANSACTION_RPC_ERROR_MARKER: &str = "sendrawtransaction RPC error:";

/// Classify a `sendrawtransaction` RPC error by its code and message.
///
/// The verdicts, and only these, are a statement about the transaction:
///
/// * -27, and -26 `txn-already-known`: the network has it → `AlreadyKnown`.
/// * any other -26: a policy or consensus refusal → `Rejected`.
/// * -25 with a missing-inputs reason → `Rejected`.
///
/// Every other error — any other -25 (a fee cap on the sending node, a
/// mempool that would not take it for a local reason), any other code — says
/// something about the node that was asked, not about the transaction, and is
/// `Unavailable` so the chain moves on to a node that may take it.
pub(crate) fn classify_sendrawtransaction(code: i64, message: &str) -> TxBroadcastOutcome {
	let with_code = || format!("{} ({})", message, code);
	match code {
		RPC_TRANSACTION_ALREADY_IN_CHAIN => TxBroadcastOutcome::AlreadyKnown,
		RPC_TRANSACTION_REJECTED if message.contains(REJECT_TXN_ALREADY_KNOWN) => {
			TxBroadcastOutcome::AlreadyKnown
		},
		RPC_TRANSACTION_REJECTED => TxBroadcastOutcome::Rejected(with_code()),
		RPC_TRANSACTION_ERROR
			if REJECT_MISSING_INPUTS.iter().any(|reason| message.contains(reason)) =>
		{
			TxBroadcastOutcome::Rejected(with_code())
		},
		_ => TxBroadcastOutcome::Unavailable { reason: with_code(), timed_out: false },
	}
}

/// The JSON electrs relays after the marker.
#[derive(Deserialize)]
struct RelayedRpcError {
	code: i64,
	message: String,
}

/// Classify a `sendrawtransaction` RPC error relayed inside free text, as
/// electrs does: `sendrawtransaction RPC error: {"code":-26,"message":"..."}`.
///
/// `None` when the text carries no such relay, or the JSON after the marker
/// does not parse: then nothing is known about the transaction, and the
/// caller must answer `Unavailable`, never a verdict.
pub(crate) fn classify_relayed_sendrawtransaction(text: &str) -> Option<TxBroadcastOutcome> {
	let after_marker = text
		.find(SENDRAWTRANSACTION_RPC_ERROR_MARKER)
		.map(|at| &text[at + SENDRAWTRANSACTION_RPC_ERROR_MARKER.len()..])?;
	let json = &after_marker[after_marker.find('{')?..];
	// The first JSON value after the marker; whatever electrs appends after it
	// is not consulted.
	let relayed: RelayedRpcError =
		serde_json::Deserializer::from_str(json).into_iter().next()?.ok()?;
	Some(classify_sendrawtransaction(relayed.code, &relayed.message))
}

/// Best-effort classification of an Electrum protocol error from a
/// `blockchain.transaction.broadcast`.
///
/// The Electrum protocol carries a server error as an opaque JSON value:
/// electrs sends the relay text as a bare string, other servers as an object
/// whose `message` holds it. Whichever it is, the text is handed to
/// [`classify_relayed_sendrawtransaction`]; `None` when it holds no relay, or
/// the value has neither shape.
pub(crate) fn classify_electrum_protocol_error(
	value: &serde_json::Value,
) -> Option<TxBroadcastOutcome> {
	let text = value.as_str().or_else(|| value.get("message").and_then(|m| m.as_str()))?;
	classify_relayed_sendrawtransaction(text)
}

#[cfg(test)]
mod tests {
	use super::*;

	use serde_json::json;

	fn rejected(outcome: &TxBroadcastOutcome) -> bool {
		matches!(outcome, TxBroadcastOutcome::Rejected(_))
	}

	fn unavailable(outcome: &TxBroadcastOutcome) -> bool {
		matches!(outcome, TxBroadcastOutcome::Unavailable { timed_out: false, .. })
	}

	#[test]
	fn sendrawtransaction_verdict_table() {
		// -27: confirmed, the network has it.
		assert_eq!(
			classify_sendrawtransaction(-27, "Transaction already in block chain"),
			TxBroadcastOutcome::AlreadyKnown
		);
		// -26 txn-already-known: in the mempool, the network has it.
		assert_eq!(
			classify_sendrawtransaction(-26, "txn-already-known"),
			TxBroadcastOutcome::AlreadyKnown
		);
		// Every other -26 is a policy or consensus refusal.
		for message in [
			"insufficient fee, rejecting replacement abc; new feerate 0.00001 <= old feerate 0.00002",
			"txn-mempool-conflict",
			"min relay fee not met, 0 < 110",
			"bad-txns-in-belowout, value in (0.001) < value out (0.002)",
		] {
			let outcome = classify_sendrawtransaction(-26, message);
			assert!(rejected(&outcome), "{}: {:?}", message, outcome);
			assert_eq!(outcome, TxBroadcastOutcome::Rejected(format!("{} (-26)", message)));
		}
		// -25 is a verdict only for missing inputs, in each spelling.
		for message in ["Missing inputs", "bad-txns-inputs-missingorspent", "missing-inputs"] {
			let outcome = classify_sendrawtransaction(-25, message);
			assert!(rejected(&outcome), "{}: {:?}", message, outcome);
		}
		// Any other -25 says something about the asked node, not the tx.
		for message in [
			"Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
			"mempool full",
			"TX decode failed",
		] {
			let outcome = classify_sendrawtransaction(-25, message);
			assert!(unavailable(&outcome), "{}: {:?}", message, outcome);
		}
		// Codes outside the table are never a verdict.
		for code in [-1, -5, -8, -22, -28, 0, 1] {
			let outcome = classify_sendrawtransaction(code, "txn-already-known");
			assert!(unavailable(&outcome), "{}: {:?}", code, outcome);
		}
	}

	#[test]
	fn relayed_electrs_body_is_classified_by_the_same_table() {
		// electrs answers every sendrawtransaction failure with HTTP 400 and
		// this body shape; the same text sits in its Electrum protocol error.
		let policy = r#"sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met, 0 < 110"}"#;
		assert_eq!(
			classify_relayed_sendrawtransaction(policy),
			Some(TxBroadcastOutcome::Rejected("min relay fee not met, 0 < 110 (-26)".into()))
		);

		let in_chain = r#"sendrawtransaction RPC error: {"code":-27,"message":"Transaction already in block chain"}"#;
		assert_eq!(
			classify_relayed_sendrawtransaction(in_chain),
			Some(TxBroadcastOutcome::AlreadyKnown)
		);

		let missing = r#"sendrawtransaction RPC error: {"code":-25,"message":"Missing inputs"}"#;
		assert_eq!(
			classify_relayed_sendrawtransaction(missing),
			Some(TxBroadcastOutcome::Rejected("Missing inputs (-25)".into()))
		);

		// A -25 that is not missing inputs stays a node problem through the relay.
		let fee_cap = r#"sendrawtransaction RPC error: {"code":-25,"message":"Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)"}"#;
		assert!(matches!(
			classify_relayed_sendrawtransaction(fee_cap),
			Some(TxBroadcastOutcome::Unavailable { timed_out: false, .. })
		));

		// Text electrs may put around the relay does not disturb the parse.
		let wrapped = r#"error: sendrawtransaction RPC error: {"code":-26,"message":"txn-already-known"} (while broadcasting)"#;
		assert_eq!(
			classify_relayed_sendrawtransaction(wrapped),
			Some(TxBroadcastOutcome::AlreadyKnown)
		);
	}

	#[test]
	fn unrecognised_400_body_is_no_verdict() {
		for body in [
			"",
			"Bad Request",
			"sendrawtransaction RPC error:",
			"sendrawtransaction RPC error: not json",
			r#"sendrawtransaction RPC error: {"code":"-26"}"#,
			r#"sendrawtransaction RPC error: {"message":"no code"}"#,
			r#"{"code":-26,"message":"no marker"}"#,
			"Transaction already in block chain",
		] {
			assert_eq!(classify_relayed_sendrawtransaction(body), None, "{:?}", body);
		}
	}

	#[test]
	fn electrum_protocol_error_is_best_effort() {
		let relay =
			r#"sendrawtransaction RPC error: {"code":-26,"message":"txn-mempool-conflict"}"#;
		// electrs: the relay as a bare string.
		assert_eq!(
			classify_electrum_protocol_error(&json!(relay)),
			Some(TxBroadcastOutcome::Rejected("txn-mempool-conflict (-26)".into()))
		);
		// A server that wraps it in a JSON-RPC error object.
		assert_eq!(
			classify_electrum_protocol_error(&json!({ "code": 1, "message": relay })),
			Some(TxBroadcastOutcome::Rejected("txn-mempool-conflict (-26)".into()))
		);
		// No relay in the text, or no text at all: nothing is known.
		assert_eq!(classify_electrum_protocol_error(&json!("the wallet is locked")), None);
		assert_eq!(
			classify_electrum_protocol_error(&json!({ "code": 1, "message": "rejected" })),
			None
		);
		assert_eq!(classify_electrum_protocol_error(&json!({ "code": 1 })), None);
		assert_eq!(classify_electrum_protocol_error(&json!(null)), None);
		assert_eq!(classify_electrum_protocol_error(&json!(["a", "list"])), None);
	}
}
