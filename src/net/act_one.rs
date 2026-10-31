// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Which static key a BOLT 8 act one was written for.
//!
//! The initiator of a Lightning connection opens with act one: a version byte, its
//! ephemeral public key `e`, and a 16-byte ChaCha20-Poly1305 tag over the empty string,
//! keyed by `HKDF(ck, ECDH(e, rs))` where `rs` is the static key of the node it means to
//! reach. Only the holder of that node's secret can reproduce the key, so checking the tag
//! against each local node's key says which node the dialer wants — without completing (or
//! disturbing) the handshake, which the chosen node's `PeerManager` then runs from the
//! untouched socket.
//!
//! rust-lightning's `PeerChannelEncryptor` does exactly this check, but it is
//! `pub(crate)` there, so the few lines of BOLT 8 it needs are spelled out here with the
//! same primitives: SHA-256 and HKDF from `bitcoin::hashes`, ECDH through the node's
//! [`NodeSigner`] (the static secret never leaves the signer), and ChaCha20-Poly1305 from
//! rust-bitcoin's `chacha20-poly1305` crate.
//!
//! [`NodeSigner`]: lightning::sign::NodeSigner

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::PublicKey;

use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Length of act one on the wire: version byte, compressed ephemeral key, 16-byte tag.
pub(crate) const ACT_ONE_LEN: usize = 50;

const PROTOCOL_NAME: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"lightning";

fn sha256_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
	let mut engine = Sha256::engine();
	engine.input(a);
	engine.input(b);
	Sha256::from_engine(engine).to_byte_array()
}

/// BOLT 8's `HKDF(salt, ikm)`: the two 32-byte outputs of HKDF-SHA256 with an empty info.
fn hkdf_two(salt: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
	let mut extract = HmacEngine::<Sha256>::new(salt);
	extract.input(ikm);
	let prk = Hmac::<Sha256>::from_engine(extract).to_byte_array();

	let mut expand = HmacEngine::<Sha256>::new(&prk);
	expand.input(&[1u8]);
	let t1 = Hmac::<Sha256>::from_engine(expand).to_byte_array();

	let mut expand = HmacEngine::<Sha256>::new(&prk);
	expand.input(&t1);
	expand.input(&[2u8]);
	let t2 = Hmac::<Sha256>::from_engine(expand).to_byte_array();
	(t1, t2)
}

/// The handshake hash `h` after the responder's static key is mixed in: the state both
/// sides hold before act one.
fn initial_h(responder_static: &PublicKey) -> [u8; 32] {
	let h = Sha256::hash(PROTOCOL_NAME).to_byte_array();
	let h = sha256_concat(&h, PROLOGUE);
	sha256_concat(&h, &responder_static.serialize())
}

/// Whether `act_one` was written for the node with static key `our_node_id`.
///
/// `ecdh` computes `ECDH(their_ephemeral, our_static_secret)` — for a node, its
/// `NodeSigner::ecdh(Recipient::Node, ..)`. Any malformed act (wrong version, a point not
/// on the curve, a failing ECDH) is simply not a match.
pub(crate) fn act_one_matches<F>(
	act_one: &[u8; ACT_ONE_LEN], our_node_id: &PublicKey, ecdh: F,
) -> bool
where
	F: FnOnce(&PublicKey) -> Result<SharedSecret, ()>,
{
	if act_one[0] != 0 {
		return false;
	}
	let their_ephemeral = match PublicKey::from_slice(&act_one[1..34]) {
		Ok(key) => key,
		Err(_) => return false,
	};
	let es = match ecdh(&their_ephemeral) {
		Ok(es) => es,
		Err(()) => return false,
	};

	let h = sha256_concat(&initial_h(our_node_id), &their_ephemeral.serialize());
	let ck = Sha256::hash(PROTOCOL_NAME).to_byte_array();
	let (_ck, temp_k1) = hkdf_two(&ck, &es.secret_bytes());

	let mut tag = [0u8; 16];
	tag.copy_from_slice(&act_one[34..ACT_ONE_LEN]);
	ChaCha20Poly1305::new(Key::new(temp_k1), Nonce::new([0u8; 12]))
		.decrypt(&mut [], tag, Some(&h))
		.is_ok()
}

/// The initiator's side: act one from `ephemeral` to `responder_static`. Only the tests
/// write acts; the node's own outbound handshakes go through LDK.
#[cfg(test)]
pub(crate) fn build_act_one(
	responder_static: &PublicKey, ephemeral: &bitcoin::secp256k1::SecretKey,
) -> [u8; ACT_ONE_LEN] {
	let secp = bitcoin::secp256k1::Secp256k1::signing_only();
	let e_pub = PublicKey::from_secret_key(&secp, ephemeral);
	let h = sha256_concat(&initial_h(responder_static), &e_pub.serialize());
	let es = SharedSecret::new(responder_static, ephemeral);
	let ck = Sha256::hash(PROTOCOL_NAME).to_byte_array();
	let (_ck, temp_k1) = hkdf_two(&ck, &es.secret_bytes());
	let tag =
		ChaCha20Poly1305::new(Key::new(temp_k1), Nonce::new([0u8; 12])).encrypt(&mut [], Some(&h));

	let mut act = [0u8; ACT_ONE_LEN];
	act[1..34].copy_from_slice(&e_pub.serialize());
	act[34..].copy_from_slice(&tag);
	act
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	fn key(byte: u8) -> SecretKey {
		SecretKey::from_slice(&[byte; 32]).unwrap()
	}

	fn node(secret: SecretKey) -> (PublicKey, impl Fn(&PublicKey) -> Result<SharedSecret, ()>) {
		let public = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
		(public, move |their: &PublicKey| Ok(SharedSecret::new(their, &secret)))
	}

	fn matches(act: &[u8; ACT_ONE_LEN], secret: SecretKey) -> bool {
		let (public, ecdh) = node(secret);
		act_one_matches(act, &public, ecdh)
	}

	/// BOLT 8's transport test vector: initiator ephemeral 0x12.., responder static 0x21...
	fn bolt8_act_one() -> [u8; ACT_ONE_LEN] {
		let bytes = Vec::<u8>::from_hex(
			"00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a",
		)
		.unwrap();
		bytes.try_into().unwrap()
	}

	#[test]
	fn the_bolt8_vector_matches_its_responder_only() {
		let act = bolt8_act_one();
		assert!(matches(&act, key(0x21)), "the vector's responder static key 0x21..");
		assert!(!matches(&act, key(0x11)), "another node's key");
	}

	#[test]
	fn our_initiator_reproduces_the_bolt8_vector() {
		let responder = PublicKey::from_secret_key(&Secp256k1::new(), &key(0x21));
		assert_eq!(build_act_one(&responder, &key(0x12)), bolt8_act_one());
	}

	#[test]
	fn two_wallets_each_claim_only_acts_written_for_them() {
		let (alice, bob) = (key(0xa1), key(0xb2));
		let alice_pub = PublicKey::from_secret_key(&Secp256k1::new(), &alice);
		let bob_pub = PublicKey::from_secret_key(&Secp256k1::new(), &bob);

		let to_alice = build_act_one(&alice_pub, &key(0x31));
		let to_bob = build_act_one(&bob_pub, &key(0x32));
		assert!(matches(&to_alice, alice) && !matches(&to_alice, bob));
		assert!(matches(&to_bob, bob) && !matches(&to_bob, alice));
	}

	#[test]
	fn garbage_matches_nobody() {
		let alice = key(0xa1);
		assert!(!matches(&[0u8; ACT_ONE_LEN], alice), "all zeroes: not a point");
		assert!(!matches(&[0x5au8; ACT_ONE_LEN], alice), "bad version byte");

		let alice_pub = PublicKey::from_secret_key(&Secp256k1::new(), &alice);
		let mut act = build_act_one(&alice_pub, &key(0x31));
		act[0] = 1;
		assert!(!matches(&act, alice), "an unknown handshake version");

		let mut act = build_act_one(&alice_pub, &key(0x31));
		act[ACT_ONE_LEN - 1] ^= 1;
		assert!(!matches(&act, alice), "a flipped tag bit");
	}

	#[test]
	fn a_failing_signer_is_no_match() {
		let alice = key(0xa1);
		let alice_pub = PublicKey::from_secret_key(&Secp256k1::new(), &alice);
		let act = build_act_one(&alice_pub, &key(0x31));
		assert!(!act_one_matches(&act, &alice_pub, |_| Err(())));
	}
}
