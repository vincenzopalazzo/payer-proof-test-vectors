//! Test vector generation and serialization for payer proofs.
//!
//! This module provides deterministic test vector generation using the
//! rust-lightning crate's payer proof implementation.

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use lightning::blinded_path::message::BlindedMessagePath;
use lightning::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
use lightning::blinded_path::BlindedHop;
use lightning::offers::invoice::{Bolt12Invoice, UnsignedBolt12Invoice};
use lightning::offers::merkle::TaggedHash;
use lightning::offers::payer_proof::{PayerProof, PayerProofBuilder};
use lightning::offers::refund::RefundBuilder;
use lightning::types::features::BlindedHopFeatures;
use lightning::util::ser::Writeable;
use lightning_types::payment::{PaymentHash, PaymentPreimage};

use crate::payer_proof::TestVectorError;

/// A single test vector for payer proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVector {
    /// Human-readable description of this test vector.
    pub description: String,
    /// The test case name/identifier.
    pub name: String,
    /// Input data for the test.
    pub input: TestVectorInput,
    /// Expected output/results.
    pub expected: TestVectorExpected,
    /// Optional comments or notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

/// Input data for a test vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorInput {
    /// The BOLT 12 invoice bytes in hex.
    pub invoice_hex: String,
    /// The payment preimage in hex (32 bytes).
    pub preimage_hex: String,
    /// The payer's secret key in hex (32 bytes).
    pub payer_secret_key_hex: String,
    /// TLV types to include in the proof (for selective disclosure).
    pub included_tlv_types: Vec<u64>,
    /// Optional note to include in the proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Expected outputs for a test vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorExpected {
    /// Whether the proof should be valid.
    pub valid: bool,
    /// The expected merkle root in hex.
    pub merkle_root_hex: String,
    /// The expected payer proof bytes in hex.
    pub proof_hex: String,
    /// The expected bech32-encoded proof.
    pub proof_bech32: String,
    /// Expected payer signature in hex.
    pub payer_signature_hex: String,
    /// Optional error message if invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A collection of test vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorFile {
    /// File format version.
    pub version: String,
    /// Description of this test vector file.
    pub description: String,
    /// Reference to the BOLT specification.
    pub bolt_reference: String,
    /// Reference to the implementation.
    pub implementation_reference: String,
    /// The test vectors.
    pub vectors: Vec<TestVector>,
}

impl TestVectorFile {
    pub fn new() -> Self {
        Self {
            version: "1.0.0".to_string(),
            description: "BOLT 12 Payer Proof Test Vectors".to_string(),
            bolt_reference: "https://github.com/lightning/bolts/pull/1295".to_string(),
            implementation_reference: "https://github.com/lightningdevkit/rust-lightning/pull/4297"
                .to_string(),
            vectors: Vec::new(),
        }
    }

    pub fn add_vector(&mut self, vector: TestVector) {
        self.vectors.push(vector);
    }
}

impl Default for TestVectorFile {
    fn default() -> Self {
        Self::new()
    }
}

/// Generator for creating deterministic test vectors.
pub struct TestVectorGenerator {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    #[allow(dead_code)]
    rng: ChaCha20Rng,
}

impl TestVectorGenerator {
    /// Creates a new generator with a fixed seed for reproducibility.
    pub fn new(seed: u64) -> Self {
        Self {
            secp: Secp256k1::new(),
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    /// Creates a deterministic secret key from a byte pattern.
    fn secret_key(&self, seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).expect("valid secret key")
    }

    /// Creates a keypair from a byte pattern.
    fn keypair(&self, seed: u8) -> Keypair {
        Keypair::from_secret_key(&self.secp, &self.secret_key(seed))
    }

    /// Creates a public key from a byte pattern.
    fn pubkey(&self, seed: u8) -> PublicKey {
        PublicKey::from_secret_key(&self.secp, &self.secret_key(seed))
    }

    /// Creates deterministic payment paths for testing.
    fn payment_paths(&self) -> Vec<BlindedPaymentPath> {
        vec![BlindedPaymentPath::from_blinded_path_and_payinfo(
            self.pubkey(40),
            self.pubkey(41),
            vec![
                BlindedHop {
                    blinded_node_id: self.pubkey(43),
                    encrypted_payload: vec![0; 43],
                },
                BlindedHop {
                    blinded_node_id: self.pubkey(44),
                    encrypted_payload: vec![0; 44],
                },
            ],
            BlindedPayInfo {
                fee_base_msat: 1,
                fee_proportional_millionths: 1_000,
                cltv_expiry_delta: 42,
                htlc_minimum_msat: 100,
                htlc_maximum_msat: 1_000_000_000_000,
                features: BlindedHopFeatures::empty(),
            },
        )]
    }

    /// Creates a deterministic blinded message path.
    #[allow(dead_code)]
    fn blinded_path(&self) -> BlindedMessagePath {
        BlindedMessagePath::from_blinded_path(
            self.pubkey(40),
            self.pubkey(41),
            vec![
                BlindedHop {
                    blinded_node_id: self.pubkey(42),
                    encrypted_payload: vec![0; 43],
                },
                BlindedHop {
                    blinded_node_id: self.pubkey(43),
                    encrypted_payload: vec![0; 44],
                },
            ],
        )
    }

    /// Sign function for invoice signing (takes something that implements AsRef<TaggedHash>).
    fn invoice_sign<T: AsRef<TaggedHash>>(
        &self,
        seed: u8,
    ) -> impl Fn(&T) -> Result<Signature, ()> + '_ {
        move |message: &T| {
            let keys = self.keypair(seed);
            Ok(self
                .secp
                .sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
        }
    }

    /// Sign function for the payer proof (takes a Message).
    fn payer_proof_sign(&self, seed: u8) -> impl FnOnce(&Message) -> Result<Signature, ()> + '_ {
        move |message: &Message| {
            let keys = self.keypair(seed);
            Ok(self.secp.sign_schnorr_no_aux_rand(message, &keys))
        }
    }

    /// Creates an invoice from a refund (uses explicit payer signing pubkey).
    ///
    /// This flow gives us full control over the payer's signing key, unlike
    /// the offer -> invoice_request flow which derives the payer key internally.
    fn create_invoice_from_refund(
        &self,
        payer_seed: u8,
        recipient_seed: u8,
        payment_hash: PaymentHash,
    ) -> Result<Bolt12Invoice, TestVectorError> {
        let payer_pubkey = self.pubkey(payer_seed);
        let payment_paths = self.payment_paths();
        let created_at = Duration::from_secs(1700000000);

        // Create a refund with explicit payer signing pubkey
        let refund = RefundBuilder::new(vec![payer_seed; 32], payer_pubkey, 100_000)
            .map_err(|e| TestVectorError::OfferBuild(format!("{:?}", e)))?
            .description("Test refund".into())
            .build()
            .map_err(|e| TestVectorError::OfferBuild(format!("{:?}", e)))?;

        // Respond to the refund with an invoice
        let recipient_pubkey = self.pubkey(recipient_seed);
        let unsigned: UnsignedBolt12Invoice = refund
            .respond_with_no_std(payment_paths, payment_hash, recipient_pubkey, created_at)
            .map_err(|e| TestVectorError::InvoiceBuild(format!("{:?}", e)))?
            .build()
            .map_err(|e| TestVectorError::InvoiceBuild(format!("{:?}", e)))?;

        unsigned
            .sign(self.invoice_sign::<UnsignedBolt12Invoice>(recipient_seed))
            .map_err(|e| TestVectorError::InvoiceBuild(format!("{:?}", e)))
    }

    /// Get invoice bytes using Writeable trait.
    fn invoice_bytes(invoice: &Bolt12Invoice) -> Vec<u8> {
        let mut bytes = Vec::new();
        invoice
            .write(&mut bytes)
            .expect("Vec write should not fail");
        bytes
    }

    /// Generates a basic test vector.
    pub fn generate_basic_vector(
        &self,
        name: &str,
        description: &str,
        preimage_seed: u8,
        payer_seed: u8,
        recipient_seed: u8,
    ) -> Result<TestVector, TestVectorError> {
        // Create deterministic preimage and payment hash
        let preimage = PaymentPreimage([preimage_seed; 32]);
        let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

        // Create invoice using refund flow (explicit payer signing pubkey)
        let invoice = self.create_invoice_from_refund(payer_seed, recipient_seed, payment_hash)?;

        // Get invoice bytes
        let invoice_bytes = Self::invoice_bytes(&invoice);

        // Build the payer proof
        let builder = PayerProofBuilder::new(&invoice, preimage)
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;

        // Build and sign with payer's known key
        let proof = builder
            .build_and_sign(self.payer_proof_sign(payer_seed), None)
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;
        let merkle_root = proof.merkle_root();

        // Verify the proof
        proof
            .verify()
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;

        Ok(TestVector {
            description: description.to_string(),
            name: name.to_string(),
            input: TestVectorInput {
                invoice_hex: hex::encode(&invoice_bytes),
                preimage_hex: hex::encode(preimage.0),
                payer_secret_key_hex: hex::encode([payer_seed; 32]),
                included_tlv_types: vec![], // Default includes required fields
                note: None,
            },
            expected: TestVectorExpected {
                valid: true,
                merkle_root_hex: hex::encode(merkle_root.as_byte_array()),
                proof_hex: hex::encode(proof.as_ref()),
                proof_bech32: proof.to_string(),
                payer_signature_hex: String::new(), // Would need to extract from proof
                error: None,
            },
            comments: None,
        })
    }

    /// Generates a test vector with a note.
    pub fn generate_vector_with_note(
        &self,
        name: &str,
        note: &str,
        preimage_seed: u8,
        payer_seed: u8,
        recipient_seed: u8,
    ) -> Result<TestVector, TestVectorError> {
        let preimage = PaymentPreimage([preimage_seed; 32]);
        let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

        // Create invoice using refund flow (explicit payer signing pubkey)
        let invoice = self.create_invoice_from_refund(payer_seed, recipient_seed, payment_hash)?;

        let invoice_bytes = Self::invoice_bytes(&invoice);

        let builder = PayerProofBuilder::new(&invoice, preimage)
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;

        // Build and sign with payer's known key
        let proof = builder
            .build_and_sign(self.payer_proof_sign(payer_seed), Some(note))
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;
        let merkle_root = proof.merkle_root();

        proof
            .verify()
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;

        Ok(TestVector {
            description: format!("Payer proof with note: {}", note),
            name: name.to_string(),
            input: TestVectorInput {
                invoice_hex: hex::encode(&invoice_bytes),
                preimage_hex: hex::encode(preimage.0),
                payer_secret_key_hex: hex::encode([payer_seed; 32]),
                included_tlv_types: vec![],
                note: Some(note.to_string()),
            },
            expected: TestVectorExpected {
                valid: true,
                merkle_root_hex: hex::encode(merkle_root.as_byte_array()),
                proof_hex: hex::encode(proof.as_ref()),
                proof_bech32: proof.to_string(),
                payer_signature_hex: String::new(),
                error: None,
            },
            comments: Some("Proof includes a payer note field".to_string()),
        })
    }

    /// Generates an invalid test vector (wrong preimage).
    pub fn generate_invalid_preimage_vector(
        &self,
        name: &str,
        real_preimage_seed: u8,
        wrong_preimage_seed: u8,
        payer_seed: u8,
        recipient_seed: u8,
    ) -> Result<TestVector, TestVectorError> {
        // Use real preimage for payment hash but wrong preimage in proof
        let real_preimage = PaymentPreimage([real_preimage_seed; 32]);
        let wrong_preimage = PaymentPreimage([wrong_preimage_seed; 32]);
        let payment_hash = PaymentHash(Sha256::hash(&real_preimage.0).to_byte_array());

        // Create invoice using refund flow (explicit payer signing pubkey)
        let invoice = self.create_invoice_from_refund(payer_seed, recipient_seed, payment_hash)?;

        let invoice_bytes = Self::invoice_bytes(&invoice);

        // Build proof with WRONG preimage - this should fail at build time
        let builder_result = PayerProofBuilder::new(&invoice, wrong_preimage);

        match builder_result {
            Err(e) => {
                // The builder correctly rejects wrong preimage
                Ok(TestVector {
                    description: "Invalid proof - preimage does not match payment hash".to_string(),
                    name: name.to_string(),
                    input: TestVectorInput {
                        invoice_hex: hex::encode(&invoice_bytes),
                        preimage_hex: hex::encode(wrong_preimage.0),
                        payer_secret_key_hex: hex::encode([payer_seed; 32]),
                        included_tlv_types: vec![],
                        note: None,
                    },
                    expected: TestVectorExpected {
                        valid: false,
                        merkle_root_hex: String::new(),
                        proof_hex: String::new(),
                        proof_bech32: String::new(),
                        payer_signature_hex: String::new(),
                        error: Some(format!("{:?}", e)),
                    },
                    comments: Some(
                        "This vector tests that implementations correctly reject invalid preimages"
                            .to_string(),
                    ),
                })
            }
            Ok(_) => {
                // This shouldn't happen - wrong preimage should be rejected
                Err(TestVectorError::Verification(
                    "Expected preimage mismatch error but builder succeeded".to_string(),
                ))
            }
        }
    }
}

impl Default for TestVectorGenerator {
    fn default() -> Self {
        Self::new(12345) // Default deterministic seed
    }
}

/// Verifies a test vector by parsing and validating the proof.
pub fn verify_test_vector(vector: &TestVector) -> Result<bool, TestVectorError> {
    // For invalid vectors with empty proof, return success (expected failure)
    if !vector.expected.valid && vector.expected.proof_hex.is_empty() {
        return Ok(true);
    }

    // Parse the proof from hex
    let proof_bytes = hex::decode(&vector.expected.proof_hex)
        .map_err(|e| TestVectorError::Parse(format!("Invalid proof hex: {}", e)))?;

    // Try to parse as PayerProof
    let proof = PayerProof::try_from(proof_bytes)
        .map_err(|e| TestVectorError::Parse(format!("Failed to parse proof: {:?}", e)))?;

    // Verify the proof
    let verify_result = proof.verify();

    match (vector.expected.valid, verify_result) {
        (true, Ok(())) => Ok(true),
        (false, Err(_)) => Ok(true), // Expected failure
        (true, Err(e)) => Err(TestVectorError::Verification(format!("{:?}", e))),
        (false, Ok(())) => Err(TestVectorError::Verification(
            "Expected invalid proof but verification passed".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_determinism() {
        let gen1 = TestVectorGenerator::new(42);
        let gen2 = TestVectorGenerator::new(42);

        // Same seed should produce same keys
        assert_eq!(gen1.pubkey(1), gen2.pubkey(1));
        assert_eq!(gen1.secret_key(1), gen2.secret_key(1));
    }
}
