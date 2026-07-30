//! Integration test: generate a payer proof via the LDK builder API, then
//! round-trip it through `bolt12_payer_proof::verify` / `verify_bytes`.

use std::time::Duration;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};

use lightning::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
use lightning::blinded_path::BlindedHop;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::offers::merkle::TaggedHash;
use lightning::offers::payer_proof::{PaidBolt12Invoice, PayerProof, UnsignedPayerProof};
use lightning::offers::refund::RefundBuilder;
use lightning::types::features::BlindedHopFeatures;
use lightning_types::payment::{PaymentHash, PaymentPreimage};

use bolt12_payer_proof::{verify, verify_bytes, VerifyError};

fn pubkey(secp: &Secp256k1<bitcoin::secp256k1::All>, seed: u8) -> PublicKey {
	let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
	PublicKey::from_secret_key(secp, &secret)
}

fn keypair(secp: &Secp256k1<bitcoin::secp256k1::All>, seed: u8) -> Keypair {
	let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
	Keypair::from_secret_key(secp, &secret)
}

/// Build a valid, signed payer proof with known payer key, amount, and description.
fn build_test_proof() -> PayerProof {
	let secp = Secp256k1::new();

	let payer_pubkey = pubkey(&secp, 42);
	let recipient_pubkey = pubkey(&secp, 43);

	let preimage = PaymentPreimage([100u8; 32]);
	let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

	let payment_paths = vec![BlindedPaymentPath::from_blinded_path_and_payinfo(
		pubkey(&secp, 40),
		pubkey(&secp, 41),
		vec![BlindedHop {
			blinded_node_id: pubkey(&secp, 44),
			encrypted_payload: vec![0; 43],
		}],
		BlindedPayInfo {
			fee_base_msat: 1,
			fee_proportional_millionths: 1_000,
			cltv_expiry_delta: 42,
			htlc_minimum_msat: 100,
			htlc_maximum_msat: 1_000_000_000_000,
			features: BlindedHopFeatures::empty(),
		},
	)];

	let refund = RefundBuilder::new(vec![42u8; 32], payer_pubkey, 100_000)
		.unwrap()
		.description("Test payment".into())
		.build()
		.unwrap();

	let unsigned_invoice = refund
		.respond_with_no_std(
			payment_paths,
			payment_hash,
			recipient_pubkey,
			Duration::from_secs(1_700_000_000),
		)
		.unwrap()
		.build()
		.unwrap();

	let invoice = unsigned_invoice
		.sign(|msg: &UnsignedBolt12Invoice| {
			let keys = keypair(&secp, 43);
			Ok(secp.sign_schnorr_no_aux_rand(msg.as_ref().as_digest(), &keys))
		})
		.unwrap();

	let unsigned_proof = PaidBolt12Invoice::Bolt12Invoice(invoice)
		.prove_payer(preimage)
		.unwrap()
		.include_offer_description()
		.include_invoice_amount();

	unsigned_proof
		.build()
		.unwrap()
		.sign(|p: &UnsignedPayerProof| {
			let keys = keypair(&secp, 42);
			Ok(secp.sign_schnorr_no_aux_rand(p.as_ref().as_digest(), &keys))
		})
		.unwrap()
}

#[test]
fn round_trip_bech32() {
	let proof = build_test_proof();
	let bech32 = proof.to_string();
	let expected_pubkey = {
		let secp = Secp256k1::new();
		pubkey(&secp, 42)
	};

	let verified = verify(&bech32).expect("valid proof should verify");

	assert_eq!(verified.payer_pubkey(), expected_pubkey);
	assert_eq!(verified.amount_msats(), Some(100_000));
	assert_eq!(verified.description(), Some("Test payment"));
	// Round-trip the bech32 encoding
	assert_eq!(verified.to_bech32(), bech32);
}

#[test]
fn round_trip_bytes() {
	let proof = build_test_proof();
	let bytes = proof.bytes().to_vec();
	let expected_pubkey = {
		let secp = Secp256k1::new();
		pubkey(&secp, 42)
	};

	let verified = verify_bytes(&bytes).expect("valid proof should verify");

	assert_eq!(verified.payer_pubkey(), expected_pubkey);
	assert_eq!(verified.as_bytes(), &bytes[..]);
}

#[test]
fn tampered_proof_fails() {
	let proof = build_test_proof();
	let mut bytes = proof.bytes().to_vec();

	// Flip the last byte — should break a signature
	let last = bytes.last_mut().unwrap();
	*last ^= 0x01;

	assert!(matches!(
		verify_bytes(&bytes),
		Err(VerifyError::VerificationFailed) | Err(VerifyError::MalformedProof)
	));
}

#[test]
fn invalid_bech32_prefix_rejected() {
	assert_eq!(verify("lni1qqqs").unwrap_err(), VerifyError::InvalidBech32);
	assert_eq!(verify("").unwrap_err(), VerifyError::InvalidBech32);
}
