#!/usr/bin/env bash
# verify_constants.sh - mechanical re-extraction check.
# Re-generates the poseidon_bls constants from the vendored hadeshash reference and diffs
# them against the committed Go/Rust definitions, and sanity-checks the BabyBear modulus.
# A constant that does not survive this check does not ship.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "VERIFY-CONSTANTS FAILED: $1" >&2; exit 1; }
ok=0

# 1. poseidon_bls Go constants == freshly generated from the vendored reference.
tmp_go="$(mktemp)"
python3 prototype/poseidon_bls/gen_consts_go.py "$tmp_go" >/dev/null
# Compare gofmt-canonical forms so a formatting-only difference (e.g. comment spacing)
# never masks a real constant drift.
{ gofmt <"$tmp_go" >"$tmp_go.fmt" && mv "$tmp_go.fmt" "$tmp_go"; } 2>/dev/null || rm -f "$tmp_go.fmt"
if ! diff -q "$tmp_go" go/hash/poseidon_bls/consts.go >/dev/null; then
  rm -f "$tmp_go"; fail "go/hash/poseidon_bls/consts.go differs from gen_consts_go.py output"
fi
rm -f "$tmp_go"; echo "ok: poseidon_bls Go constants match vendored reference"; ok=$((ok+1))

# 2. poseidon_bls Rust constants (in the risc0 clone) == freshly generated.
# local checkout of the risc0 fork: git clone -b v3.0.5-bls.1 https://github.com/blocksmithy/risc0 ../risc0-poseidon-bls
RISC0_CLONE="${RISC0_CLONE:-../risc0-poseidon-bls}"
rs_target="$RISC0_CLONE/risc0/zkp/src/core/hash/poseidon_bls/consts.rs"
if [ -f "$rs_target" ]; then
  tmp_rs="$(mktemp)"
  python3 prototype/poseidon_bls/gen_consts_rs.py "$tmp_rs" >/dev/null
  if ! diff -q "$tmp_rs" "$rs_target" >/dev/null; then
    rm -f "$tmp_rs"; fail "poseidon_bls consts.rs differs from gen_consts_rs.py output"
  fi
  rm -f "$tmp_rs"; echo "ok: poseidon_bls Rust constants match vendored reference"; ok=$((ok+1))
else
  echo "skip: risc0 clone consts.rs not found at $rs_target (set RISC0_CLONE)"
fi

# 3. BabyBear modulus identity p = 15*2^27 + 1 = 2013265921, and present in the Go source.
python3 - <<'PY' || fail "BabyBear modulus identity check failed"
assert 15*(1<<27)+1 == 2013265921
PY
grep -q "2013265921" go/hash/poseidon_bls/sponge.go || fail "babyBearModulus 2013265921 not found in sponge.go"
if grep -qE 'pub const P: u32 = 15 \* \(1 << 27\) \+ 1;' \
     "$RISC0_CLONE/risc0/core/src/field/baby_bear.rs" 2>/dev/null; then
  echo "ok: BabyBear modulus P = 15*2^27+1 matches risc0 baby_bear.rs"
else
  echo "skip: could not confirm BabyBear modulus against risc0 source (clone missing)"
fi
ok=$((ok+1))

# 4. Derived control id constant present and consistent across docs/source.
BLS_ID="5b53e73e4d7c7a440567053460d07f582c62b6b9dafd1cb6e116092068409368"
grep -q "$BLS_ID" PUBLIC_INPUTS.md || fail "BLS_IDENTITY_CONTROL_ID missing from docs"
echo "ok: BLS_IDENTITY_CONTROL_ID present in docs"; ok=$((ok+1))

# 4b. Claim/control binding constants in go/stark/claim.go derive from the pinned risc0 digests.
ALLOWED_CR="a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56"
python3 - "$ALLOWED_CR" "$BLS_ID" <<'PY' || fail "claim.go control constants do not match risc0 digests"
import re, struct, sys
allowed_cr, bls_id = sys.argv[1], sys.argv[2]
src = open("go/stark/claim.go").read()
# controlRootWords must equal the 8 little-endian u32 words of ALLOWED_CONTROL_ROOT.
words = list(struct.unpack("<8I", bytes.fromhex(allowed_cr)))
slice_src = re.search(r"controlRootWords\s*=\s*\[\]\*big\.Int\{([^}]*)\}", src).group(1)
got = [int(x) for x in re.findall(r"big\.NewInt\((\d+)\)", slice_src)]
assert got == words, ("controlRootWords", got, words)
# blsIdentityControlIDFr must equal BLS_IDENTITY_CONTROL_ID as little-endian Fr.
fr = int.from_bytes(bytes.fromhex(bls_id), "little")
m = re.search(r'blsIdentityControlIDFr.*?SetString\(\s*"(\d+)"', src, re.S)
assert m and int(m.group(1)) == fr, ("blsIdentityControlIDFr", m and m.group(1), fr)
PY
grep -q "$ALLOWED_CR" PUBLIC_INPUTS.md || fail "ALLOWED_CONTROL_ROOT missing from PUBLIC_INPUTS.md"
echo "ok: claim.go control-root/control-id constants match pinned risc0 digests"; ok=$((ok+1))

# 5b. DEEP-ALI static tables (taps.json + poly_ext DEF) == freshly dumped from the risc0 circuit.
# These drive the in-circuit poly_ext interpreter; they must not drift from the pinned circuit
# (generated-artifact rule). Gated on the clone like the consts.rs check.
if [ -d "$RISC0_CLONE/risc0/circuit/recursion" ]; then
  tmp_tables="$(mktemp -d)"
  ( cd "$RISC0_CLONE" && POLYEXT_DUMP_DIR="$tmp_tables" \
      cargo test -p risc0-circuit-recursion dump_polyext_and_taps >/dev/null 2>&1 ) \
    || { rm -rf "$tmp_tables"; fail "dump_polyext_and_taps failed (cannot verify DEEP tables)"; }
  for f in taps.json polyext_def.json; do
    if ! diff -q "$tmp_tables/$f" "go/stark/testdata/$f" >/dev/null; then
      rm -rf "$tmp_tables"; fail "go/stark/testdata/$f differs from the risc0 circuit dump (table drift)"
    fi
  done
  rm -rf "$tmp_tables"; echo "ok: DEEP-ALI taps/poly_ext tables match the pinned risc0 circuit"; ok=$((ok+1))
else
  echo "skip: DEEP-ALI table dump-diff (risc0 clone missing)"
fi

# 5. ProtocolInfo context strings (transcript constants) == risc0 source, byte-for-byte.
grep -q 'ProofSystemInfo = \[\]byte("RISC0_STARK:v1__")' go/stark/transcript.go \
  || fail "ProofSystemInfo string changed in transcript.go"
grep -q 'CircuitInfo     = \[\]byte("RECURSION:rev1v1")' go/stark/transcript.go \
  || fail "CircuitInfo string changed in transcript.go"
if [ -f "$RISC0_CLONE/risc0/zkp/src/adapter.rs" ]; then
  grep -q 'PROOF_SYSTEM_INFO: ProtocolInfo = ProtocolInfo(\*b"RISC0_STARK:v1__")' \
    "$RISC0_CLONE/risc0/zkp/src/adapter.rs" || fail "PROOF_SYSTEM_INFO mismatch vs risc0 adapter.rs"
  grep -q 'CIRCUIT_INFO: ProtocolInfo = ProtocolInfo(\*b"RECURSION:rev1v1")' \
    "$RISC0_CLONE/risc0/circuit/recursion/src/info.rs" || fail "CIRCUIT_INFO mismatch vs risc0 info.rs"
  echo "ok: ProtocolInfo strings match risc0 adapter.rs/info.rs byte-for-byte"; ok=$((ok+1))
else
  echo "skip: ProtocolInfo cross-check (risc0 clone missing)"
fi

# 6. BabyBear NBETA + the ROU_FWD/ROU_REV-derived FRI constants in the Go sources == pinned risc0
# core/src/field/baby_bear.rs (these were provenance-commented but not mechanically
# checked). Gated on the clone.
if [ -f "$RISC0_CLONE/risc0/core/src/field/baby_bear.rs" ]; then
  python3 - "$RISC0_CLONE/risc0/core/src/field/baby_bear.rs" <<'PY' || fail "FRI/NBETA constants do not match risc0 baby_bear.rs"
import re, sys
src = open(sys.argv[1]).read()
P = 2013265921
def arr(name):
    m = re.search(name + r".*?rou_array!\s*\[(.*?)\]", src, re.S)
    return [int(x) for x in re.findall(r"\d+", m.group(1))]
fwd, rev = arr("ROU_FWD"), arr("ROU_REV")
go = {f: open("go/"+f).read() for f in
      ["stark/fri.go","stark/deep_evalu.go","stark/deep_frieval.go","stark/deep_polyext.go","field/babybear/babybear.go"]}
def has(f, val): assert str(val) in go[f], (f, val)
# fri.go ROU_REV[4]/[20]/[16]/[12], ROU_FWD[8]
has("stark/fri.go", rev[4]); has("stark/fri.go", rev[20]); has("stark/fri.go", rev[16]); has("stark/fri.go", rev[12]); has("stark/fri.go", fwd[8])
has("stark/deep_evalu.go", rev[18])     # friBackOne = ROU_REV[18]
has("stark/deep_frieval.go", fwd[20])   # rouFwd20 = ROU_FWD[20]
# NBETA = P - 11
nbeta = re.search(r"const NBETA[^=]*=\s*Elem::new\(P\s*-\s*(\d+)\)", src)
beta = int(nbeta.group(1)) if nbeta else 11
has("stark/deep_polyext.go", P - beta)  # polyExtNBeta literal
assert re.search(r"Beta\s*=\s*%d\b" % beta, go["field/babybear/babybear.go"]), "babybear Beta"  # nbeta = modulus - Beta (derived)
print("FRI/NBETA constants OK")
PY
  echo "ok: NBETA + ROU_FWD/ROU_REV FRI constants match risc0 baby_bear.rs"; ok=$((ok+1))
else
  echo "skip: FRI/NBETA constant check (risc0 clone missing)"
fi

echo "verify-constants: $ok checks passed"
