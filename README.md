# BOLT 12 Payer Proof Test Vectors

A CLI tool for generating and verifying test vectors for BOLT 12 payer proofs as specified in [BOLT PR #1295](https://github.com/lightning/bolts/pull/1295).

## Overview

Payer proofs allow a payer to cryptographically prove they made a specific payment without revealing unnecessary information. This tool generates deterministic test vectors that can be used by other implementations to verify their payer proof logic.

## Library: `bolt12-payer-proof`

This workspace includes a focused verification library — `bolt12-payer-proof` —
that wraps LDK's payer-proof primitives behind a clean, ergonomic API.

### Quick start

```rust
use bolt12_payer_proof::verify;

match verify("lnp1...") {
    Ok(proof) => {
        println!("Paid by:  {}", proof.payer_pubkey());
        println!("Amount:   {} msats", proof.amount_msats().unwrap_or(0));
        println!("For:      {}", proof.description().unwrap_or("(undisclosed)"));
    }
    Err(e) => eprintln!("Invalid proof: {e}"),
}
```

Both `verify` (bech32 string) and `verify_bytes` (raw TLV bytes)
perform full cryptographic validation: preimage hash, invoice signature, and
payer signature are all checked before returning a `VerifiedPayerProof`.

### Errors

`VerifyError` distinguishes three failure categories:

| Variant | Meaning |
|---------|---------|
| `InvalidBech32` | Wrong prefix, bad checksum, or unparseable encoding |
| `MalformedProof` | Missing required TLVs or inconsistent merkle proof |
| `VerificationFailed` | Preimage mismatch or invalid signature |

## References

- **BOLT Specification**: https://github.com/lightning/bolts/pull/1295
- **Reference Implementation**: https://github.com/lightningdevkit/rust-lightning/pull/4297

## Installation

### From Source

```bash
git clone https://github.com/vincenzopalazzo/payer-proof-test-vectors
cd payer-proof-test-vectors
cargo build --release
```

The binary will be available at `./target/release/payer-proof-test-vectors`.

## Usage

### Generate Test Vectors

Generate test vectors and write them to a JSON file:

```bash
# Default output (test_vectors.json)
payer-proof-test-vectors generate

# Specify output file
payer-proof-test-vectors generate -o my_vectors.json

# Custom options
payer-proof-test-vectors generate --basic-count 5 --seed 54321

# Skip optional test vectors
payer-proof-test-vectors generate --no-notes --no-invalid
```

**Options:**
- `-o, --output <FILE>`: Output file path (default: `test_vectors.json`)
- `--seed <NUM>`: Random seed for deterministic generation (default: `12345`)
- `--basic-count <NUM>`: Number of basic test vectors to generate (default: `3`)
- `--no-notes`: Skip test vectors that include payer notes
- `--no-invalid`: Skip invalid/negative test vectors

The experimental TLV spec regression vector is always generated so every regenerated
corpus keeps covering the BOLT PR #1295 behavior.

### Verify Test Vectors

Verify test vectors from a JSON file:

```bash
# Default input (test_vectors.json)
payer-proof-test-vectors verify

# Specify input file
payer-proof-test-vectors verify -i my_vectors.json

# Verbose output
payer-proof-test-vectors verify -v

# Continue on failures
payer-proof-test-vectors verify --continue-on-failure
```

**Options:**
- `-i, --input <FILE>`: Input file path (default: `test_vectors.json`)
- `-v, --verbose`: Show detailed results for each test
- `--continue-on-failure`: Don't stop on first failure

## Test Vector Format

The generated JSON file contains an array of test vectors with the following structure:

```json
{
  "version": "1.0.0",
  "description": "BOLT 12 Payer Proof Test Vectors",
  "bolt_reference": "https://github.com/lightning/bolts/pull/1295",
  "implementation_reference": "https://github.com/lightningdevkit/rust-lightning/pull/4297",
  "vectors": [
    {
      "name": "basic_1",
      "description": "Basic payer proof with required fields only",
      "input": {
        "invoice_hex": "...",
        "preimage_hex": "...",
        "payer_secret_key_hex": "...",
        "included_tlv_types": [],
        "note": null
      },
      "expected": {
        "valid": true,
        "merkle_root_hex": "...",
        "proof_hex": "...",
        "proof_bech32": "lnppay1...",
        "payer_signature_hex": "",
        "error": null
      },
      "comments": null
    }
  ]
}
```

### Field Descriptions

**Input Fields:**
- `invoice_hex`: The BOLT 12 invoice bytes in hexadecimal
- `preimage_hex`: The 32-byte payment preimage in hexadecimal
- `payer_secret_key_hex`: The payer's 32-byte secret key in hexadecimal
- `included_tlv_types`: TLV types to include in selective disclosure (empty for default)
- `note`: Optional payer note to include in the proof

**Expected Fields:**
- `valid`: Whether the proof should pass verification
- `merkle_root_hex`: The expected merkle root of the proof
- `proof_hex`: The serialized payer proof in hexadecimal
- `proof_bech32`: The bech32-encoded payer proof (human-readable format)
- `payer_signature_hex`: The payer's Schnorr signature (if extracted)
- `error`: Expected error message for invalid test vectors

## Test Vector Types

The tool generates four types of test vectors:

### 1. Basic Test Vectors
Basic payer proofs with only required fields. These test the fundamental proof generation and verification logic.

### 2. Test Vectors with Notes
Payer proofs that include an optional note field. The note is included in the merkle tree and signed.

### 3. Invalid Test Vectors
Negative test cases that should fail verification:
- `invalid_preimage`: Proof created with a preimage that doesn't match the invoice's payment hash

### 4. Spec Regression Test Vectors
Positive test cases covering specification edge cases from [BOLT PR #1295](https://github.com/lightning/bolts/pull/1295):
- `included_experimental_invoice_tlv`: Proof selectively discloses an odd experimental invoice TLV above the reserved `240..=1000` payer-proof/signature range, and is always generated so every regenerated corpus keeps covering the normative regression

## Implementation Details

This tool uses the [rust-lightning](https://github.com/lightningdevkit/rust-lightning) implementation from the payer proof PR. Key implementation choices:

- **Refund Flow**: Uses the BOLT 12 refund flow instead of offer/invoice_request flow. This allows explicit control over the payer's signing key, which is necessary for deterministic test vector generation.

- **Deterministic Keys**: All keys are derived from simple byte patterns using a seeded RNG, ensuring reproducible test vectors across runs.

- **Schnorr Signatures**: Payer proofs use BIP-340 Schnorr signatures for authentication.

## Building from Source

### Prerequisites

- Rust 1.70 or later
- Cargo

### Dependencies

The project uses these main dependencies:
- `lightning` / `lightning-types`: rust-lightning with payer proof support
- `bitcoin`: Bitcoin primitives and secp256k1
- `clap`: Command-line argument parsing
- `serde` / `serde_json`: JSON serialization

### Build Commands

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Check without building
cargo check
```

## License

This project is licensed under the same terms as the rust-lightning project.

## Contributing

Contributions are welcome! Please ensure any changes:
1. Maintain deterministic test vector generation
2. Are compatible with the BOLT 12 payer proof specification
3. Include appropriate test coverage
