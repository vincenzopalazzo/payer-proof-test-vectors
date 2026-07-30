//! # bolt12-payer-proof
//!
//! A focused, ergonomic library for **verifying** BOLT 12 payer proofs.
//!
//! A payer proof (encoded as an `lnp1...` bech32 string or raw TLV bytes)
//! cryptographically proves that a Lightning payment was made — by whom, for
//! how much, and what it was for — without revealing the full invoice.
//!
//! ## Quick start
//!
//! ```no_run
//! use bolt12_payer_proof::verify;
//!
//! let proof_str = "lnp1...";
//! match verify(proof_str) {
//!     Ok(proof) => {
//!         println!("Paid by:  {}", proof.payer_pubkey());
//!         println!("Amount:   {} msats", proof.amount_msats().unwrap_or(0));
//!         println!("For:      {}", proof.description().unwrap_or("(undisclosed)"));
//!     }
//!     Err(e) => eprintln!("Invalid proof: {e}"),
//! }
//! ```
//!
//! Both [`verify`] (bech32 string) and [`verify_bytes`] (raw bytes) perform
//! full cryptographic validation before returning: the preimage hash, the
//! invoice signature, and the payer signature are all checked.
//!
//! ## What is a payer proof?
//!
//! Per [BOLT 12](https://github.com/lightning/bolts/pull/1295), a payer proof
//! is a selective disclosure of invoice fields plus the payment preimage and
//! two signatures (the invoice issuer's and the payer's). It lets a third party
//! verify a payment occurred without seeing the full invoice.

use std::fmt;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;

use lightning::offers::parse::Bolt12ParseError;
use lightning::offers::payer_proof::PayerProof;

// Re-export payment types so consumers don't need to depend on LDK directly
// just for these simple wrappers.
pub use lightning_types::payment::{PaymentHash, PaymentPreimage};

/// Verify a payer proof from its bech32 encoding (`lnp1...`).
///
/// Performs full cryptographic validation:
/// - The preimage hashes to the declared payment hash.
/// - The invoice (issuer) signature is valid.
/// - The payer signature is valid.
///
/// # Example
///
/// ```no_run
/// # use bolt12_payer_proof::verify;
/// let result = verify("lnp1...");
/// ```
pub fn verify(proof: &str) -> Result<VerifiedPayerProof, VerifyError> {
	// Quick structural pre-check so we can give a distinct error for
	// obviously-wrong input before invoking the full decoder.
	if !proof.starts_with("lnp1") {
		return Err(VerifyError::InvalidBech32);
	}
	let inner = proof.parse::<PayerProof>().map_err(map_parse_error)?;
	Ok(VerifiedPayerProof { inner })
}

/// Verify a payer proof from its raw TLV bytes.
///
/// Equivalent to [`verify`] but accepts the raw byte encoding instead of the
/// bech32 string form.
pub fn verify_bytes(bytes: &[u8]) -> Result<VerifiedPayerProof, VerifyError> {
	let inner = PayerProof::try_from(bytes.to_vec()).map_err(map_parse_error)?;
	Ok(VerifiedPayerProof { inner })
}

/// A cryptographically verified BOLT 12 payer proof.
///
/// This type can **only** be constructed through [`verify`] or
/// [`verify_bytes`], both of which check the preimage hash, the invoice
/// signature, and the payer signature. Once you hold a
/// `VerifiedPayerProof`, the proof is trustworthy.
///
/// Accessor methods return the selectively-disclosed invoice fields. Fields
/// the payer chose not to include return `None`.
#[derive(Clone, Debug)]
pub struct VerifiedPayerProof {
	inner: PayerProof,
}

impl VerifiedPayerProof {
	/// The payer's public key — identifies who authorized the payment.
	pub fn payer_pubkey(&self) -> PublicKey {
		self.inner.payer_signing_pubkey()
	}

	/// The invoice issuer's signing public key — the node that created the invoice.
	pub fn issuer_pubkey(&self) -> PublicKey {
		self.inner.issuer_signing_pubkey()
	}

	/// The payment hash that the preimage resolves.
	pub fn payment_hash(&self) -> PaymentHash {
		self.inner.payment_hash()
	}

	/// The disclosed invoice amount in millisatoshis, if the payer included it.
	pub fn amount_msats(&self) -> Option<u64> {
		self.inner.invoice_amount_msats()
	}

	/// The invoice creation time as a Unix timestamp (seconds), if disclosed.
	pub fn created_at(&self) -> Option<u64> {
		self.inner.invoice_created_at().map(|d| d.as_secs())
	}

	/// The offer description — a human-readable payment purpose, if disclosed.
	pub fn description(&self) -> Option<&str> {
		self.inner.offer_description().map(|s| s.0)
	}

	/// The offer issuer name, if disclosed.
	pub fn issuer(&self) -> Option<&str> {
		self.inner.offer_issuer().map(|s| s.0)
	}

	/// A free-text note the payer attached to this proof, if any.
	///
	/// This is distinct from any invoice-request note sent to the payee; it is
	/// scoped to the proof and committed to by the payer signature.
	pub fn note(&self) -> Option<&str> {
		self.inner.proof_note().map(|s| s.0)
	}

	/// The merkle root of the original invoice.
	pub fn merkle_root(&self) -> sha256::Hash {
		self.inner.merkle_root()
	}

	/// Re-encode the proof as a bech32 `lnp1...` string.
	pub fn to_bech32(&self) -> String {
		self.inner.to_string()
	}

	/// The raw proof bytes.
	pub fn as_bytes(&self) -> &[u8] {
		self.inner.bytes()
	}
}

/// Why a payer proof failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
	/// The input string is not a valid bech32 payer proof (wrong prefix, bad
	/// checksum, or unparseable encoding).
	InvalidBech32,
	/// The proof is structurally malformed — required TLVs are missing, the
	/// merkle proof is inconsistent, or the TLV stream is invalid.
	MalformedProof,
	/// Cryptographic verification failed — the preimage does not match the
	/// payment hash, or the invoice or payer signature is invalid.
	VerificationFailed,
}

impl fmt::Display for VerifyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidBech32 => {
				write!(f, "not a valid bech32 payer proof string (expected 'lnp1...' prefix)")
			},
			Self::MalformedProof => {
				write!(f, "the proof is structurally malformed (missing or inconsistent TLV fields)")
			},
			Self::VerificationFailed => write!(
				f,
				"cryptographic verification failed (preimage hash or signature mismatch)"
			),
		}
	}
}

impl std::error::Error for VerifyError {}

/// Map an LDK `Bolt12ParseError` to our clean error type.
///
/// LDK lumps both structural and crypto failures into `Decode(InvalidValue)`,
/// so we treat all `Decode` errors as potential verification failures. Semantic
/// errors (missing required fields) are clearly structural.
fn map_parse_error(e: Bolt12ParseError) -> VerifyError {
	match e {
		Bolt12ParseError::InvalidSemantics(_) => VerifyError::MalformedProof,
		// Decode errors cover both structural corruption and cryptographic
		// failures — we surface them as verification failures since the caller
		// cannot trust the proof either way.
		_ => VerifyError::VerificationFailed,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn empty_string_is_invalid_bech32() {
		assert_eq!(verify("").unwrap_err(), VerifyError::InvalidBech32);
	}

	#[test]
	fn wrong_prefix_is_invalid_bech32() {
		assert_eq!(verify("lno1...").unwrap_err(), VerifyError::InvalidBech32);
		assert_eq!(verify("hello").unwrap_err(), VerifyError::InvalidBech32);
	}

	#[test]
	fn empty_bytes_fail() {
		assert!(verify_bytes(&[]).is_err());
	}

	#[test]
	fn garbage_bytes_fail() {
		assert!(verify_bytes(&[0xff; 64]).is_err());
	}
}
