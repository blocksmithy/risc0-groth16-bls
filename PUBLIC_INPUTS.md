# PUBLIC_INPUTS.md - public input layout (authoritative)

This file defines the circuit's public input layout once. Any change is
breaking: version bump, new VK hash recorded, changelog entry.

> Status: **IMPLEMENTED.** Wired by `go/stark/claim.go::BindClaim`, composed into
> `stark/driver.go::VerifyReceipt`. Validated: `TestBindClaimMatchesMeta` (claim reconstruction ==
> RISC0 meta claim_digest, non-circular), `TestVerifyReceiptRejectsWrongPublic` (all 5 inputs bound),
> `TestReceiptPublicsMatchPlatform`. Constants checked by `make verify-constants`.

## We match RISC0's Groth16 receipt schema exactly - just over BLS12-381 instead of BN254

**Source of truth: RISC0.** `risc0-groth16` `src/verifier.rs::Verifier::new` builds
the public-input vector `[a0, a1, c0, c1, id_bn254_fr]` via `split_digest`; we reproduce it byte-for-
byte over the BLS12-381 scalar field. Keeping control_root / control_id / claim_digest as **public
inputs** (not baked circuit constants) is what makes a single VK **agnostic of the RISC0 version, the
allowed control set, and the guest program** - those values are carried by the inputs and checked by
the on-chain verifier, so a version/program change needs no new circuit or ceremony.

## Layout

| Index | Name | Origin | Varies per proof |
|---|---|---|---|
| 0 | `control_root_low`  | inner poseidon2 recursion control root (split, low) | No (platform constant) |
| 1 | `control_root_high` | inner poseidon2 recursion control root (split, high) | No (platform constant) |
| 2 | `claim_digest_low`  | the `ReceiptClaim` digest (image_id + journal), split low | Yes |
| 3 | `claim_digest_high` | the `ReceiptClaim` digest, split high | Yes |
| 4 | `control_id`        | the recursion program's control_id (= CODE-group root) | No (per program/version) |

Total: **5 public scalars** (BLS12-381 Fr). gnark's emulated-field range checks inject exactly one
bsb22 (Pedersen) commitment, so the proof carries `n_commitments = 1` and the verifying key's `K`
array has **7 entries** (1 one-wire + 5 public + 1 commitment). The on-chain (Aiken) verifier MUST
include the commitment and its proof-of-knowledge terms in the pairing check.

## Digest split (`control_root`, `claim_digest`) - RISC0 `split_digest`

A RISC0 `Digest` is `[u32; 8]`; `as_bytes()` is its little-endian byte image. `split_digest` reverses
the 32-byte image to big-endian and returns `(low = be[16:32], high = be[0:16])`, each a 128-bit Fr.
For the 8-word digest this is equivalent (and implemented in-circuit) as:

- `low  = words[0] + words[1]·2³² + words[2]·2⁶⁴ + words[3]·2⁹⁶`
- `high = words[4] + words[5]·2³² + words[6]·2⁶⁴ + words[7]·2⁹⁶`

Each half `< 2^128 ≪ r`, so no Fr wraparound. The `control_root` words are the even-indexed entries of
`globals[0:16]`; the `claim_digest` words come from `globals[16:32]` (16 SHA half-words via
`read_sha_halfs`, each range-checked `< 2^16` in-circuit, mirroring RISC0).

## `control_id` (index 4)

Not split. `control_id = from_be_bytes(reverse(digest.as_bytes())) = from_le_bytes(as_bytes)` =
`digest_to_fr` - the CODE-group Merkle root carried as a single Fr. Must be `< r` (it is). The
in-circuit binding is `code_root == control_id` (the circuit does not hardcode the value).

## Expected platform constants (checked by the on-chain verifier, NOT baked in the circuit)

- inputs 0,1 == `split(ALLOWED_CONTROL_ROOT)` where `ALLOWED_CONTROL_ROOT =
  a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56` (the standard poseidon2 root).
- input 4 == `BLS_IDENTITY_CONTROL_ID =
  5b53e73e4d7c7a440567053460d07f582c62b6b9dafd1cb6e116092068409368` (as `digest_to_fr`).
- inputs 2,3 == `split(claim_digest)` where the relying party recomputes `claim_digest` from
  `(image_id, journal, exit_code)` via RISC0's `ReceiptClaim` tagged-struct digest (the journal is
  committed inside `output = digest(journal, assumptions)`).

`make verify-constants` checks the circuit's `controlRootWords` and `blsIdentityControlIDFr` against
the pinned risc0 `control_id.rs` digests.

## In-circuit bindings

1. `split(seal inner control_root) == (control_root_low, control_root_high)`
2. `split(seal claim_digest) == (claim_digest_low, claim_digest_high)`, each SHA half `< 2^16`
3. `seal code_root == control_id`

The seal-emitted values are NOT freely-witnessed: they are read from the seal `globals` after the
seal has been ingested (canonical), Merkle-committed, and FRI-verified by `VerifyReceipt`.
