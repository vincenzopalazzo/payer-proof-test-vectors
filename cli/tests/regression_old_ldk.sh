#!/usr/bin/env bash
# regression_old_ldk.sh — Prove that the experimental TLV payer-proof vector
# fails verification on the OLD rust-lightning PR head and passes on the FIXED
# revision.
#
# Usage:
#   ./tests/regression_old_ldk.sh
#
# What it does:
#   1. Verifies the vector passes on the current (fixed) pinned revision.
#   2. Temporarily re-pins Cargo.toml to the OLD revision that rejects
#      disclosed experimental invoice TLVs above the 240..=1000 range.
#   3. Runs `cargo run -- verify` and expects the experimental vector to fail.
#   4. Restores the original Cargo.toml.
#
# BOLT PR #1295 spec reference:
#   TLV types 240..=1000 are reserved for payer-proof and signature fields.
#   Experimental invoice TLVs above that range remain selectively disclosable.
#   The old revision (3378fa3c) incorrectly rejected these with
#   Decode(InvalidValue).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

OLD_REV="3378fa3c7655e3312529d0e424231fd9bb4dde55"
FIXED_REV="4e0068a33c3313a2b36e6e967f2e31e1232a8a19"

cleanup() {
    echo "Restoring Cargo.toml to the fixed revision..."
    git checkout -- Cargo.toml Cargo.lock 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Step 1: Verify vector passes on the FIXED revision ($FIXED_REV) ==="
cargo run --quiet -- verify -i test_vectors.json --verbose
echo ""
echo "PASS: All vectors verified on the fixed revision."
echo ""

echo "=== Step 2: Re-pin to the OLD revision ($OLD_REV) ==="
sed -i.bak "s|rev = \"$FIXED_REV\"|rev = \"$OLD_REV\"|g" Cargo.toml
rm -f Cargo.toml.bak
cargo update -p lightning -p lightning-types 2>/dev/null || true

echo ""
echo "=== Step 3: Verify that the experimental TLV vector FAILS on old revision ==="
OUTPUT=$(cargo run --quiet -- verify -i test_vectors.json --continue-on-failure --verbose 2>&1 || true)
echo "$OUTPUT"
TARGET_RESULT=$(
    printf '%s\n' "$OUTPUT" | awk '
        $0 ~ /^Test [0-9]+: included_experimental_invoice_tlv$/ { in_target = 1; next }
        in_target && $0 ~ /^Test [0-9]+:/ { exit }
        in_target && $0 ~ /^  Result: / {
            sub(/^  Result: /, "");
            print;
            exit;
        }
    '
)
if [[ "$TARGET_RESULT" == "FAILED - Parse error: Failed to parse proof: Decode(InvalidValue)" ]]; then
    echo ""
    echo "PASS: The experimental TLV vector correctly fails on the old revision."
    echo "This confirms the regression that BOLT PR #1295 fixes."
else
    echo ""
    echo "UNEXPECTED: The experimental TLV vector did not fail as expected."
    if [[ -n "$TARGET_RESULT" ]]; then
        echo "Observed target result: $TARGET_RESULT"
    else
        echo "Could not locate the included_experimental_invoice_tlv result block."
    fi
    echo "Check the output above for details."
    exit 1
fi
