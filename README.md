# risc0-groth16-bls

A gnark (Go) circuit that verifies a RISC Zero succinct STARK receipt inside a Groth16 proof over
**BLS12-381**, so a RISC Zero proof can be settled on-chain on Cardano (native BLS12-381 builtins) with
a single small pairing check, without touching BN254.

> **Not audited.** This is a faithful in-circuit reimplementation of RISC Zero's STARK verifier
> (`risc0_zkp::verify`), pinned to and differentially checked against the upstream source - but it has
> **not** had a formal security audit. Review and use accordingly.

## Why BLS12-381

RISC Zero's stock `stark2snark` path wraps proofs into a BN254 Groth16 proof. Cardano's on-chain
pairing builtins are BLS12-381, not BN254, and BN254 offers only about 100-bit security against the
TNFS family. This project replaces the final wrap so the on-chain verifier is a standard BLS12-381
Groth16 check.

The approach mirrors RISC Zero's own design: re-prove the recursion STARK with a hash native to the
wrapping curve's scalar field, then Groth16-verify that STARK. RISC Zero does this for BN254 with
`identity_p254` (Poseidon over the BN254 scalar field); this project adds the BLS analogue,
`identity_bls` (Poseidon over the BLS12-381 scalar field), and a gnark circuit that verifies its seal.
The `poseidon_bls` hash suite and `identity_bls` entrypoint are an additive contribution to a RISC Zero
fork (the prover side); this repository is the in-circuit verifier and the native verifier.

## Architecture

```
RISC Zero host:  prove -> lift -> join -> succinct receipt (poseidon2 / BabyBear)
                                            |
                                            v   identity_bls    (re-prove with poseidon_bls)
                                     identity_bls receipt       (seal hashed with Poseidon over BLS12-381 Fr)
                                            |
                                            v   shrink_wrap_bls
                            groth16bls (Go)  --  proves the in-circuit STARK verifier (gnark, BLS12-381)
                                            |
                                            v
                     proof / public input / verifying key (Cardano wire format)
                                            |
                                            v
                     Cardano (Plutus builtins) or the native Rust verifier
```

Hashing inside the circuit is native BLS-Fr Poseidon. The trace field BabyBear and its degree-4
extension are used for the FRI/DEEP arithmetic only.

## Layout

| Path | Contents |
|---|---|
| `go/stark/` | The in-circuit RISC Zero STARK verifier (gnark, BLS12-381): validity spine, FRI, claim binding, driven by in-circuit Fiat-Shamir. |
| `go/hash/poseidon_bls/` | In-circuit Poseidon over BLS12-381 Fr (`poseidonperm_x5_255_3`), matching the RISC Zero `poseidon_bls` suite. |
| `go/field/babybear/` | Emulated BabyBear and its degree-4 extension, used for FRI/DEEP arithmetic. |
| `go/cmd/groth16bls/` | The gnark prover backend (`setup`, `prove`, `verify`, `emit-ccs`, `circuit-id`). |
| `go/keys/` | Committed verifying keys + the key manifest; proving keys are fetched from the release. |
| `go/serialize/` | Cardano wire-format serialization of proof / public input / verifying key. |
| `rust/groth16-bls-verify/` | Standalone `no_std` native BLS12-381 Groth16 verifier for the Cardano-format proof. |
| `prototype/poseidon_bls/` | Provenance for the Poseidon constants: generator scripts and reference vectors. |
| `testdata/` | The real `identity_bls` seal and claim used as the cross-language known-answer corpus. |

## Two verifiers, one seal

- **In-circuit (gnark):** `go/stark` is a full RISC Zero succinct-receipt verifier expressed as a
  BLS12-381 constraint system; `groth16bls` proves it. This is what makes a STARK cheap to check
  on-chain.
- **Native (Rust):** `rust/groth16-bls-verify` verifies the resulting Groth16 proof in the Cardano wire
  format - the same check a Plutus script performs, runnable off-chain.

## Keys

The verifying key is committed (`go/keys/<key-set>/vk.bin`, 976 bytes), so **verification needs nothing
extra** - the on-chain (Plutus/Aiken) script and the native Rust verifier already have everything.

For **proving**, `groth16bls` ships with a key manifest and fetches the large proving key on first use:

```sh
groth16bls prove --seal seal.bin --out .
```

No flags, no env var, no dev key: it resolves the active key-set from `go/keys/manifest.json`, uses the
embedded vk, and downloads the proving key + constraint system from the ceremony release (each
SHA-256-verified against the manifest, then cached in `~/.risc0/groth16-bls/`). `--key NAME` selects a
different key-set; `--keys DIR` uses a custom keys directory.

The active key is **`small-ceremony-2026-06`** - a 10-participant Phase-2 MPC ceremony sealed with a
Cardano mainnet block-hash beacon. The proving key, all 10 contribution blobs, the transcript, and a
one-command re-verify procedure are published as a
[release](https://github.com/blocksmithy/risc0-groth16-bls/releases/tag/keys-small-ceremony-2026-06),
so anyone can reproduce the verifying key independently. (A larger ceremony is planned; switching keys
is a one-line manifest change.)

## Build and test

```sh
make build            # Go circuit + Rust verifier
make test             # all tests
make test-negative    # the single-mutation rejection suite
make kat              # cross-language known-answer tests
make verify-constants # re-extract every pinned constant from its upstream source
```

## Security model

The repository follows a soundness-first engineering discipline: no cryptographic constants from
memory, every hint output constrained, mandatory single-mutation negative tests, and byte-exact
fidelity to the pinned RISC Zero verifier. The receipt is fully adversarial input; the circuit is the
security boundary.

The Groth16 keys come from a Phase-2 MPC ceremony (see Keys); `prove` fails closed unless the loaded
key matches the pinned ceremony fingerprint, so it cannot silently fall back to an insecure dev key.
The current key is from a small (10-participant) ceremony; a larger one is planned.

## Documents

| Document | Purpose |
|---|---|
| [go/STARK_VERIFY_SPEC.md](go/STARK_VERIFY_SPEC.md) | The RISC0 STARK verifier specification the circuit implements. |
| [PUBLIC_INPUTS.md](PUBLIC_INPUTS.md) | Public-input layout. |

Status: research-grade. Code-reviewed, not externally audited.
