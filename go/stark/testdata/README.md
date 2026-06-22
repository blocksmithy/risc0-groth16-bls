# go/stark/testdata - real-seal KAT fixtures

These fixtures pin the in-circuit verifier against **RISC0's actual output** for a real
`identity_bls` succinct receipt (expected values come from the RISC0 Rust side,
never from the code under test).

## Provenance and pairing

The seal is **randomized per proving run** (the STARK is zero-knowledge), so every `*_real.json`
fixture is only valid for the *specific* `../../../testdata/identity_bls/seal.bin` it was produced
from. They MUST be regenerated together, from one armed run. Splitting them produces fixtures that
are each internally self-consistent yet attest to different seals - a silent-pass failure mode.

| File | Produced by | Source of expected values | Bound to seal.bin by |
|---|---|---|---|
| `transcript_real.json` | `prototype/transcript/convert_transcript.py` | RISC0 `read_iop.rs` TR_* trace | `TestSealDriveReal` (recomputes all 76 challenges from seal.bin) |
| `merkle_real.json` | `prototype/merkle/convert_real_dump.py` | RISC0 `verify/merkle.rs` DUMP_* trace | `TestFixtureConsistency` (idx == query-0 pos) |
| `fri_round_real.json` | `go/cmd/genfri` | RISC0 `verify/fri.rs` FRI_GOAL trace (goals/mixes/group); leaves from seal parser | `TestFixtureConsistency` |
| `fri_query_real.json` | `go/cmd/genfri` | RISC0 FRI_GOAL0 trace (pos0/goal0/mixes); leaves+final from seal parser | `TestFixtureConsistency` (pos0 == transcript bits[0]) |
| `deep_real.json` | `prototype/deep/convert_deep.py` | RISC0 `verify/mod.rs` VV_* trace (eval_u/result/check/z/poly_mix) | `convert_deep.py` asserts poly_mix==ext[0], z==ext[1] |
| `merkle_ref.json` | `prototype/merkle/gen_merkle_ref.py` | self-contained synthetic tree (NOT seal-bound) | - (structural test only) |

**Static circuit tables (NOT seal-bound, change only with the recursion circuit version):**

| File | Produced by | Contents |
|---|---|---|
| `taps.json` | `dump_polyext_and_taps` (recursion crate) | tap registers + combos (DEEP-ALI) |
| `polyext_def.json` | `dump_polyext_and_taps` | the 12,359-step `poly_ext` validity program |

These are embedded into the verifier via `go:embed` (see `deep_tables.go`); regenerate with
`make deep-tables` only when bumping the risc0 circuit.

`genfri` uses the validated `go/stark` seal parser only to read **leaf/final witness bytes** out
of the same seal; all **expected** goals/positions/mixes come from the RISC0 trace, so the tests
remain non-circular.

## Regeneration (atomic)

    make kat-regen        # one armed RISC0 dump -> all converters -> consistency check

This (1) runs the armed `dump_identity_bls_fixture` test (writes a fresh `seal.bin` + emits the
TR_/DUMP_/FRI_/VV_ traces), (2) runs all four converters (transcript, merkle, genfri, deep) against
that single trace log, and (3) runs the `*Real*` + `TestFixtureConsistency` tests. Never regenerate
one fixture in isolation.

`TestFixtureConsistency` and `TestSealDriveReal` will fail loudly if the committed fixtures ever
drift out of sync with `seal.bin`.
