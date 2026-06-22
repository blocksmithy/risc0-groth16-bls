#!/usr/bin/env bash
# Full Groth16Bls pipeline e2e: the REAL identity_bls seal -> groth16bls (dev) setup + prove ->
# Cardano-v2 artifacts -> INDEPENDENT native Rust verifier accepts -> tampered proof is rejected.
#
# This is the cross-language release gate: it ties the frozen circuit (stark.ReceiptTemplate(50)),
# the Go prover, the Cardano-v2 serialization, and the native Rust verifier (the on-chain analogue)
# into one chain on a real RISC0 receipt. Unlike cmd/provee2e (which stops at gnark's own Go verify),
# the proof here is checked by a SEPARATE verifier - the meaningful test.
#
# The front half (real guest -> lift -> join -> identity_bls -> seal.bin) is validated separately by
# the Rust e2e test test_recursion_lift_join_identity_bls_e2e; seal.bin is its captured output.
#
# INSECURE: uses `setup --dev` (toxic waste in-memory). Production keys come from the Phase-2
# ceremony. Heavy: the nq=50 circuit is ~4.5M constraints (minutes + GBs of RAM).
#
# Usage:  tools/pipeline_e2e.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GODIR="$REPO/go"
RUSTDIR="$REPO/rust/groth16-bls-verify"
SEAL="$REPO/testdata/identity_bls/seal.bin"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

step() { printf '\n\033[1m>> %s\033[0m\n' "$1"; }

[ -f "$SEAL" ] || { echo "missing seal: $SEAL"; exit 1; }

step "build groth16bls (CPU) + native Rust verifier"
( cd "$GODIR" && go build -o "$TMP/groth16bls" ./cmd/groth16bls )
( cd "$RUSTDIR" && cargo build --release --bin verify_cardano >/dev/null 2>&1 )
VERIFY="$RUSTDIR/target/release/verify_cardano"

step "groth16bls setup --dev  (compile ReceiptTemplate(50) + INSECURE dev keys)"
"$TMP/groth16bls" setup --dev --keys "$TMP"

step "groth16bls prove --dev  (prove the real identity_bls seal -> Cardano-v2 artifacts)"
"$TMP/groth16bls" prove --dev --keys "$TMP" --seal "$SEAL" --out "$TMP"
ls -l "$TMP"/{vk,proof,public}.cardano.bin

step "native Rust verify  (independent verifier must ACCEPT the fresh proof)"
"$VERIFY" "$TMP/vk.cardano.bin" "$TMP/proof.cardano.bin" "$TMP/public.cardano.bin"

step "negative: tamper one proof byte  (independent verifier must REJECT)"
cp "$TMP/proof.cardano.bin" "$TMP/proof.tampered.bin"
python3 - "$TMP/proof.tampered.bin" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[40] ^= 1            # flip a bit inside the A point
open(p, "wb").write(b)
PY
if "$VERIFY" "$TMP/vk.cardano.bin" "$TMP/proof.tampered.bin" "$TMP/public.cardano.bin"; then
    echo "FAIL: tampered proof was accepted"
    exit 1
fi
echo "ok: tampered proof rejected"

printf '\n\033[32m=== PIPELINE E2E PASS: real seal -> groth16bls(dev) -> native Rust verify (accept + tamper-reject) ===\033[0m\n'
