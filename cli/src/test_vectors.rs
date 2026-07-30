//! Test vector generation and serialization for payer proofs.
//!
//! This module provides deterministic test vector generation using the
//! rust-lightning crate's payer proof implementation.

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use lightning::blinded_path::message::BlindedMessagePath;
use lightning::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
use lightning::blinded_path::BlindedHop;
use lightning::offers::invoice::{Bolt12Invoice, UnsignedBolt12Invoice};
use lightning::offers::merkle::TaggedHash;
use lightning::offers::payer_proof::{PaidBolt12Invoice, PayerProof, UnsignedPayerProof};
use lightning::offers::refund::RefundBuilder;
use lightning::types::features::BlindedHopFeatures;
use lightning::util::ser::{BigSize, Readable, Writeable};
use lightning_types::payment::{PaymentHash, PaymentPreimage};

use crate::payer_proof::TestVectorError;

const EXPERIMENTAL_INVOICE_TLV_TYPE: u64 = 3_000_000_001;
const EXPERIMENTAL_INVOICE_TLV_VALUE: &[u8] = b"experimental-payer-proof-field";

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
    ///
    /// TODO: The public rust-lightning API does not expose the raw payer
    /// signature separately from the proof bytes, so this field is currently
    /// always empty.  Remove it once downstream consumers confirm they do not
    /// rely on it, or populate it if a future API exposes the signature.
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

    /// Sign function for the payer proof (takes an UnsignedPayerProof).
    fn payer_proof_sign(&self, seed: u8) -> impl Fn(&UnsignedPayerProof) -> Result<Signature, ()> + '_ {
        move |proof: &UnsignedPayerProof| {
            let keys = self.keypair(seed);
            Ok(self
                .secp
                .sign_schnorr_no_aux_rand(proof.as_ref().as_digest(), &keys))
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

    /// Get unsigned invoice bytes using Writeable trait.
    fn unsigned_invoice_bytes(invoice: &UnsignedBolt12Invoice) -> Vec<u8> {
        let mut bytes = Vec::new();
        invoice
            .write(&mut bytes)
            .expect("Vec write should not fail");
        bytes
    }

    fn last_tlv_type(bytes: &[u8]) -> Option<u64> {
        let mut cursor = std::io::Cursor::new(bytes);
        let mut last_type = None;

        while (cursor.position() as usize) < bytes.len() {
            let tlv_type: BigSize =
                Readable::read(&mut cursor).expect("invoice bytes should contain valid TLVs");
            let tlv_len: BigSize =
                Readable::read(&mut cursor).expect("invoice bytes should contain valid TLVs");
            cursor.set_position(cursor.position() + tlv_len.0);
            last_type = Some(tlv_type.0);
        }

        last_type
    }

    /// Append a raw TLV record to an already canonical TLV stream.
    ///
    /// The caller must preserve strict ascending TLV ordering when appending.
    fn append_raw_tlv_record(bytes: &mut Vec<u8>, tlv_type: u64, value: &[u8]) {
        debug_assert!(
            Self::last_tlv_type(bytes)
                .map(|last_type| tlv_type > last_type)
                .unwrap_or(true),
            "appended TLV types must preserve strict ascending order"
        );
        BigSize(tlv_type)
            .write(bytes)
            .expect("Vec write should not fail");
        BigSize(value.len() as u64)
            .write(bytes)
            .expect("Vec write should not fail");
        bytes.extend_from_slice(value);
    }

    /// Re-parse a generated proof through rust-lightning's full payer-proof validation path.
    ///
    /// On the pinned rust-lightning revision, `PayerProof::try_from` verifies the preimage hash
    /// plus both the issuer and payer signatures before returning `Ok`.
    fn reparse_verified_proof(bytes: &[u8]) -> Result<PayerProof, TestVectorError> {
        PayerProof::try_from(bytes.to_vec())
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))
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
        let builder = PaidBolt12Invoice::Bolt12Invoice(invoice)
            .prove_payer(preimage)
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;

        // Build and sign with payer's known key
        let unsigned = builder
            .build()
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;
        let proof = unsigned
            .sign(self.payer_proof_sign(payer_seed))
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;
        let merkle_root = proof.merkle_root();
        Self::reparse_verified_proof(proof.as_ref())?;

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

        let builder = PaidBolt12Invoice::Bolt12Invoice(invoice)
            .prove_payer(preimage)
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;

        // Build and sign with payer's known key
        let unsigned = builder
            .with_proof_note(note.to_string())
            .build()
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;
        let proof = unsigned
            .sign(self.payer_proof_sign(payer_seed))
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;
        let merkle_root = proof.merkle_root();
        Self::reparse_verified_proof(proof.as_ref())?;

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

    /// Generates a payer proof vector that includes an odd experimental invoice TLV.
    pub fn generate_vector_with_included_experimental_invoice_tlv(
        &self,
        name: &str,
        preimage_seed: u8,
        payer_seed: u8,
        recipient_seed: u8,
    ) -> Result<TestVector, TestVectorError> {
        let preimage = PaymentPreimage([preimage_seed; 32]);
        let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

        let payer_pubkey = self.pubkey(payer_seed);
        let payment_paths = self.payment_paths();
        let created_at = Duration::from_secs(1700000000);

        let refund = RefundBuilder::new(vec![payer_seed; 32], payer_pubkey, 100_000)
            .map_err(|e| TestVectorError::OfferBuild(format!("{:?}", e)))?
            .description("Test refund".into())
            .build()
            .map_err(|e| TestVectorError::OfferBuild(format!("{:?}", e)))?;

        let recipient_pubkey = self.pubkey(recipient_seed);
        let unsigned_invoice = refund
            .respond_with_no_std(payment_paths, payment_hash, recipient_pubkey, created_at)
            .map_err(|e| TestVectorError::InvoiceBuild(format!("{:?}", e)))?
            .build()
            .map_err(|e| TestVectorError::InvoiceBuild(format!("{:?}", e)))?;

        let mut unsigned_invoice_bytes = Self::unsigned_invoice_bytes(&unsigned_invoice);
        Self::append_raw_tlv_record(
            &mut unsigned_invoice_bytes,
            EXPERIMENTAL_INVOICE_TLV_TYPE,
            EXPERIMENTAL_INVOICE_TLV_VALUE,
        );

        let unsigned_invoice = UnsignedBolt12Invoice::try_from(unsigned_invoice_bytes)
            .map_err(|e| TestVectorError::InvoiceBuild(format!("{:?}", e)))?;
        let invoice = unsigned_invoice
            .sign(self.invoice_sign::<UnsignedBolt12Invoice>(recipient_seed))
            .map_err(|e| TestVectorError::InvoiceBuild(format!("{:?}", e)))?;

        let invoice_bytes = Self::invoice_bytes(&invoice);

        let builder = PaidBolt12Invoice::Bolt12Invoice(invoice)
            .prove_payer(preimage)
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?
            .include_type(EXPERIMENTAL_INVOICE_TLV_TYPE)
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;

        let unsigned = builder
            .build()
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;
        let proof = unsigned
            .sign(self.payer_proof_sign(payer_seed))
            .map_err(|e| TestVectorError::Verification(format!("{:?}", e)))?;
        let merkle_root = proof.merkle_root();

        Self::reparse_verified_proof(proof.as_ref())?;

        Ok(TestVector {
            description: "Payer proof selectively disclosing an odd experimental invoice TLV above the reserved signature range".to_string(),
            name: name.to_string(),
            input: TestVectorInput {
                invoice_hex: hex::encode(&invoice_bytes),
                preimage_hex: hex::encode(preimage.0),
                payer_secret_key_hex: hex::encode([payer_seed; 32]),
                included_tlv_types: vec![EXPERIMENTAL_INVOICE_TLV_TYPE],
                note: None,
            },
            expected: TestVectorExpected {
                valid: true,
                merkle_root_hex: hex::encode(merkle_root.as_byte_array()),
                proof_hex: hex::encode(proof.as_ref()),
                proof_bech32: proof.to_string(),
                payer_signature_hex: String::new(),
                error: None,
            },
            comments: Some(
                "BOLT PR #1295 reserves only TLV types 240..=1000 for signature and payer-proof fields; experimental invoice TLVs above that range remain selectively disclosable.".to_string(),
            ),
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
        let builder_result = PaidBolt12Invoice::Bolt12Invoice(invoice)
            .prove_payer(wrong_preimage);

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

    // On the pinned rust-lightning revision, parsing a payer proof also verifies the
    // preimage hash and both signatures, so this is cryptographic validation rather
    // than a structural check only.
    let proof = match PayerProof::try_from(proof_bytes) {
        Ok(proof) => proof,
        Err(e) => {
            if !vector.expected.valid {
                return Ok(true); // Expected parse failure
            }
            return Err(TestVectorError::Parse(format!(
                "Failed to parse proof: {:?}",
                e
            )));
        }
    };
    let actual_merkle_root = hex::encode(proof.merkle_root().as_byte_array());
    if vector.expected.merkle_root_hex != actual_merkle_root {
        return Err(TestVectorError::Verification(format!(
            "Merkle root mismatch: expected {}, got {}",
            vector.expected.merkle_root_hex, actual_merkle_root
        )));
    }

    let actual_bech32 = proof.to_string();
    if vector.expected.proof_bech32 != actual_bech32 {
        return Err(TestVectorError::Verification(format!(
            "Bech32 mismatch: expected {}, got {}",
            vector.expected.proof_bech32, actual_bech32
        )));
    }

    if !vector.expected.valid {
        return Err(TestVectorError::Verification(
            "Expected invalid proof but verification passed".to_string(),
        ));
    }

    Ok(true)
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

    #[test]
    fn test_generates_vector_with_included_experimental_invoice_tlv() {
        let generator = TestVectorGenerator::default();

        let vector = generator
            .generate_vector_with_included_experimental_invoice_tlv(
                "included_experimental_invoice_tlv",
                210,
                70,
                71,
            )
            .expect("experimental invoice TLV vector should generate");

        assert_eq!(
            vector.input.included_tlv_types,
            vec![EXPERIMENTAL_INVOICE_TLV_TYPE]
        );
        assert!(verify_test_vector(&vector).expect("vector should verify"));
    }

    /// Regression test: the experimental TLV vector's proof bytes must
    /// round-trip through `PayerProof::try_from` on the pinned rust-lightning
    /// revision (4e0068a3).
    ///
    /// On the previous PR head (3378fa3c7655e3312529d0e424231fd9bb4dde55)
    /// the same bytes are rejected with `Decode(InvalidValue)` because that
    /// revision incorrectly treats disclosed experimental invoice TLVs above
    /// the reserved 240..=1000 payer-proof/signature range as invalid.
    ///
    /// Run `tests/regression_old_ldk.sh` to reproduce the failure against the
    /// old revision.
    #[test]
    fn test_experimental_tlv_proof_parses_on_fixed_revision() {
        let generator = TestVectorGenerator::default();

        let vector = generator
            .generate_vector_with_included_experimental_invoice_tlv(
                "experimental_regression",
                210,
                70,
                71,
            )
            .expect("experimental invoice TLV vector should generate");

        // The generator already calls `reparse_verified_proof` internally, but
        // exercise the full `try_from` path explicitly so the test name makes
        // the intent clear: these proof bytes must parse on the fixed revision.
        let proof_bytes =
            hex::decode(&vector.expected.proof_hex).expect("generated proof hex must be valid");
        let proof = PayerProof::try_from(proof_bytes)
            .expect("experimental TLV proof must parse on the fixed rust-lightning revision");

        // Sanity-check the merkle root so a silent mis-parse is caught.
        assert_eq!(
            hex::encode(proof.merkle_root().as_byte_array()),
            vector.expected.merkle_root_hex,
        );

        // Sanity-check bech32 round-trip.
        assert_eq!(proof.to_string(), vector.expected.proof_bech32);
    }

    #[test]
    fn test_verify_rejects_tampered_proof_bytes() {
        let generator = TestVectorGenerator::default();

        let mut vector = generator
            .generate_basic_vector("basic_tampered", "Tampered payer proof", 100, 42, 43)
            .expect("basic vector should generate");

        let mut proof_bytes = hex::decode(&vector.expected.proof_hex).expect("proof hex is valid");
        let last_byte = proof_bytes
            .last_mut()
            .expect("generated payer proof should not be empty");
        *last_byte ^= 0x01;
        vector.expected.proof_hex = hex::encode(proof_bytes);

        assert!(verify_test_vector(&vector).is_err());
    }
}
