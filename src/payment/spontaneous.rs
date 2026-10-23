// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Holds a payment handler allowing to send spontaneous ("keysend") payments.

use crate::config::{Config, LDK_PAYMENT_RETRY_TIMEOUT};
use crate::error::Error;
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::payment::store::{PaymentDetails, PaymentDirection, PaymentKind, PaymentStatus};
use crate::payment::SendingParameters;
use crate::types::{ChannelManager, CustomTlvRecord, KeysManager, PaymentStore};

use lightning::ln::channelmanager::{PaymentId, RecipientOnionFields, Retry, RetryableSendFailure};
use lightning::routing::router::{PaymentParameters, RouteHint, RouteParameters};
use lightning::sign::EntropySource;

use lightning_types::payment::{PaymentHash, PaymentPreimage};

use bitcoin::secp256k1::PublicKey;

use std::sync::{Arc, RwLock};

// The default `final_cltv_expiry_delta` we apply when not set.
const LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA: u32 = 144;

/// A payment handler allowing to send spontaneous ("keysend") payments.
///
/// Should be retrieved by calling [`Node::spontaneous_payment`].
///
/// [`Node::spontaneous_payment`]: crate::Node::spontaneous_payment
pub struct SpontaneousPayment {
	runtime: Arc<RwLock<Option<Arc<tokio::runtime::Runtime>>>>,
	channel_manager: Arc<ChannelManager>,
	keys_manager: Arc<KeysManager>,
	payment_store: Arc<PaymentStore>,
	config: Arc<Config>,
	logger: Arc<Logger>,
}

impl SpontaneousPayment {
	pub(crate) fn new(
		runtime: Arc<RwLock<Option<Arc<tokio::runtime::Runtime>>>>,
		channel_manager: Arc<ChannelManager>, keys_manager: Arc<KeysManager>,
		payment_store: Arc<PaymentStore>, config: Arc<Config>, logger: Arc<Logger>,
	) -> Self {
		Self { runtime, channel_manager, keys_manager, payment_store, config, logger }
	}

	/// Send a spontaneous aka. "keysend", payment.
	///
	/// If `sending_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::sending_parameters`] on a per-field basis.
	pub fn send(
		&self, amount_msat: u64, node_id: PublicKey, sending_parameters: Option<SendingParameters>,
	) -> Result<PaymentId, Error> {
		self.send_inner(amount_msat, node_id, sending_parameters, None, Vec::new())
	}

	/// Send a spontaneous payment including a list of custom TLVs.
	pub fn send_with_custom_tlvs(
		&self, amount_msat: u64, node_id: PublicKey, sending_parameters: Option<SendingParameters>,
		custom_tlvs: Vec<CustomTlvRecord>,
	) -> Result<PaymentId, Error> {
		self.send_inner(amount_msat, node_id, sending_parameters, Some(custom_tlvs), Vec::new())
	}

	/// Send a spontaneous payment, giving the router private last-hop route hints.
	///
	/// Each [`RouteHint`] describes a path ending at `node_id` over channels the router cannot
	/// see in the public graph (e.g., an unannounced or 0-conf channel identified by its SCID
	/// alias). An empty `route_hints` behaves exactly like [`Self::send`].
	pub fn send_with_route_hints(
		&self, amount_msat: u64, node_id: PublicKey, sending_parameters: Option<SendingParameters>,
		route_hints: Vec<RouteHint>,
	) -> Result<PaymentId, Error> {
		self.send_inner(amount_msat, node_id, sending_parameters, None, route_hints)
	}

	/// Send a spontaneous payment including a list of custom TLVs, giving the router private
	/// last-hop route hints.
	///
	/// See [`Self::send_with_route_hints`] for the hint semantics. An empty `route_hints`
	/// behaves exactly like [`Self::send_with_custom_tlvs`].
	pub fn send_with_custom_tlvs_and_route_hints(
		&self, amount_msat: u64, node_id: PublicKey, sending_parameters: Option<SendingParameters>,
		custom_tlvs: Vec<CustomTlvRecord>, route_hints: Vec<RouteHint>,
	) -> Result<PaymentId, Error> {
		self.send_inner(amount_msat, node_id, sending_parameters, Some(custom_tlvs), route_hints)
	}

	fn send_inner(
		&self, amount_msat: u64, node_id: PublicKey, sending_parameters: Option<SendingParameters>,
		custom_tlvs: Option<Vec<CustomTlvRecord>>, route_hints: Vec<RouteHint>,
	) -> Result<PaymentId, Error> {
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		let payment_preimage = PaymentPreimage(self.keys_manager.get_secure_random_bytes());
		let payment_hash = PaymentHash::from(payment_preimage);
		let payment_id = PaymentId(payment_hash.0);

		if let Some(payment) = self.payment_store.get(&payment_id) {
			if payment.status == PaymentStatus::Pending
				|| payment.status == PaymentStatus::Succeeded
			{
				log_error!(self.logger, "Payment error: must not send duplicate payments.");
				return Err(Error::DuplicatePayment);
			}
		}

		let payment_params = keysend_payment_params(node_id, route_hints).map_err(|e| {
			log_error!(self.logger, "Payment error: invalid route hints for {}.", node_id);
			e
		})?;
		let mut route_params =
			RouteParameters::from_payment_params_and_value(payment_params, amount_msat);

		let override_params =
			sending_parameters.as_ref().or(self.config.sending_parameters.as_ref());
		if let Some(override_params) = override_params {
			override_params
				.max_total_routing_fee_msat
				.map(|f| route_params.max_total_routing_fee_msat = f.into());
			override_params
				.max_total_cltv_expiry_delta
				.map(|d| route_params.payment_params.max_total_cltv_expiry_delta = d);
			override_params.max_path_count.map(|p| route_params.payment_params.max_path_count = p);
			override_params
				.max_channel_saturation_power_of_half
				.map(|s| route_params.payment_params.max_channel_saturation_power_of_half = s);
		};

		let recipient_fields = match custom_tlvs {
			Some(tlvs) => RecipientOnionFields::spontaneous_empty()
				.with_custom_tlvs(tlvs.into_iter().map(|tlv| (tlv.type_num, tlv.value)).collect())
				.map_err(|e| {
					log_error!(self.logger, "Failed to send payment with custom TLVs: {:?}", e);
					Error::InvalidCustomTlvs
				})?,
			None => RecipientOnionFields::spontaneous_empty(),
		};

		match self.channel_manager.send_spontaneous_payment(
			Some(payment_preimage),
			recipient_fields,
			PaymentId(payment_hash.0),
			route_params,
			Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT),
		) {
			Ok(_hash) => {
				log_info!(self.logger, "Initiated sending {}msat to {}.", amount_msat, node_id);

				let kind = PaymentKind::Spontaneous {
					hash: payment_hash,
					preimage: Some(payment_preimage),
				};
				let payment = PaymentDetails::new(
					payment_id,
					kind,
					Some(amount_msat),
					None,
					PaymentDirection::Outbound,
					PaymentStatus::Pending,
				);
				self.payment_store.insert(payment)?;

				Ok(payment_id)
			},
			Err(e) => {
				log_error!(self.logger, "Failed to send payment: {:?}", e);

				match e {
					RetryableSendFailure::DuplicatePayment => Err(Error::DuplicatePayment),
					_ => {
						let kind = PaymentKind::Spontaneous {
							hash: payment_hash,
							preimage: Some(payment_preimage),
						};
						let payment = PaymentDetails::new(
							payment_id,
							kind,
							Some(amount_msat),
							None,
							PaymentDirection::Outbound,
							PaymentStatus::Failed,
						);

						self.payment_store.insert(payment)?;
						Err(Error::PaymentSendingFailed)
					},
				}
			},
		}
	}

	/// Sends payment probes over all paths of a route that would be used to pay the given
	/// amount to the given `node_id`.
	///
	/// See [`Bolt11Payment::send_probes`] for more information.
	///
	/// [`Bolt11Payment::send_probes`]: crate::payment::Bolt11Payment
	pub fn send_probes(&self, amount_msat: u64, node_id: PublicKey) -> Result<(), Error> {
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		let liquidity_limit_multiplier = Some(self.config.probing_liquidity_limit_multiplier);

		self.channel_manager
			.send_spontaneous_preflight_probes(
				node_id,
				amount_msat,
				LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA,
				liquidity_limit_multiplier,
			)
			.map_err(|e| {
				log_error!(self.logger, "Failed to send payment probes: {:?}", e);
				Error::ProbeSendingFailed
			})?;

		Ok(())
	}
}

/// Builds the keysend [`PaymentParameters`] for `node_id`, attaching `route_hints` when given.
///
/// With no hints this is exactly `PaymentParameters::from_node_id`, so callers without hints keep
/// the previous behaviour.
fn keysend_payment_params(
	node_id: PublicKey, route_hints: Vec<RouteHint>,
) -> Result<PaymentParameters, Error> {
	let params = PaymentParameters::from_node_id(node_id, LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA);
	if route_hints.is_empty() {
		return Ok(params);
	}
	// `with_route_hints` only fails for a blinded payee, which `from_node_id` never builds.
	params.with_route_hints(route_hints).map_err(|()| Error::PaymentSendingFailed)
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use lightning::routing::gossip::RoutingFees;
	use lightning::routing::router::{Payee, RouteHintHop};

	fn pubkey(byte: u8) -> PublicKey {
		let secp = Secp256k1::new();
		PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
	}

	fn hint(src: PublicKey, scid: u64) -> RouteHint {
		RouteHint(vec![RouteHintHop {
			src_node_id: src,
			short_channel_id: scid,
			fees: RoutingFees { base_msat: 1_000, proportional_millionths: 100 },
			cltv_expiry_delta: 72,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}])
	}

	#[test]
	fn no_hints_matches_from_node_id() {
		let payee = pubkey(2);
		let params = keysend_payment_params(payee, Vec::new()).unwrap();
		assert_eq!(
			params,
			PaymentParameters::from_node_id(payee, LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA)
		);
	}

	#[test]
	fn hints_are_attached_to_clear_payee() {
		let payee = pubkey(2);
		let hints = vec![hint(pubkey(3), 42), hint(pubkey(4), 43)];
		let params = keysend_payment_params(payee, hints.clone()).unwrap();
		match params.payee {
			Payee::Clear { node_id, route_hints, final_cltv_expiry_delta, .. } => {
				assert_eq!(node_id, payee);
				assert_eq!(route_hints, hints);
				assert_eq!(final_cltv_expiry_delta, LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA);
			},
			_ => panic!("expected a clear payee"),
		}
	}
}
