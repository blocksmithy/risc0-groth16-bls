# End to end: a RISC Zero program to a verified BLS12-381 Groth16 proof

This walks a real RISC Zero guest - the stock `hello-world` example - from execution all the way to a
BLS12-381 Groth16 proof that verifies, in a single prover call. The proof is in the Cardano wire
format, so the same bytes verify on-chain (Plutus/Aiken BLS12-381 builtins) and off-chain (this repo's
native Rust verifier).

```
guest execution            (RISC Zero)
  -> succinct receipt      lift + join                 (RISC Zero)
  -> identity_bls receipt  re-prove with poseidon_bls  (fork: blocksmithy/risc0)
  -> BLS Groth16 receipt   groth16bls (this repo)      proves the in-circuit STARK verifier
  -> verify                fork verifier / native Rust / on-chain
```

`ProverOpts::groth16_bls()` drives the whole chain in one call: the fork re-proves the succinct receipt
with `identity_bls`, then spawns the `groth16bls` prover, and returns a `Groth16Bls` receipt.

## Prerequisites

**1. Build the `groth16bls` prover (this repo).** The fork's `shrink_wrap_bls` finds it on `$PATH`, or
you can point at it with `RISC0_GROTH16_BLS_BIN`.

```sh
make groth16bls            # builds go/groth16bls
# or: make install-groth16bls   # installs it onto $PATH
```

No key handling is needed: on the first non-dev prove, `groth16bls` resolves the active key-set from
its manifest, downloads the proving key from the ceremony release (SHA-256-verified), and caches it
under `~/.risc0/groth16-bls/`. The verifying key is already embedded.

**2. Clone the RISC Zero fork** (adds `poseidon_bls`, `identity_bls`, `ReceiptKind::Groth16Bls`, and the
`small_ceremony_2026_06` verifying key):

```sh
git clone --depth 1 -b v3.0.5-bls.1 https://github.com/blocksmithy/risc0
```

The fork is a large repository and uses Git LFS; `--depth 1` keeps the checkout to roughly 150 MB.

## Prove and verify the hello-world example

The fork ships `examples/hello-world`: a guest that proves it knows the factors of 391 without
revealing them. Two small edits turn its receipt into a BLS12-381 Groth16 receipt.

### 1. Prove to a BLS Groth16 receipt

In `examples/hello-world/src/lib.rs`, replace the `prove` call so it proves with `groth16_bls` (drop the now-unused `let prover`):

```rust
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};

// ...inside multiply():
let receipt = default_prover()
    .prove_with_opts(env, MULTIPLY_ELF, &ProverOpts::groth16_bls())
    .unwrap()
    .receipt;

if let InnerReceipt::Groth16Bls(ref g) = receipt.inner {
    println!("produced a BLS12-381 Groth16 receipt ({}-byte seal)", g.seal.len());
}
```

### 2. Verify against the ceremony key

In `examples/hello-world/src/main.rs`, replace the `receipt.verify(...)` call to install the production
verifying key and verify. The BLS verifier has no default key (it is ceremony-specific), so the relying
party installs it explicitly - here, the key baked into the fork:

```rust
use risc0_zkvm::{Groth16BlsReceiptVerifierParameters, VerifierContext};

// ...after obtaining `receipt`:
let ctx = VerifierContext::default().with_groth16_bls_verifier_parameters(
    Groth16BlsReceiptVerifierParameters::small_ceremony_2026_06(),
);
receipt
    .verify_with_context(&ctx, MULTIPLY_ID)
    .expect("BLS Groth16 receipt failed to verify");
println!("verified the BLS12-381 Groth16 receipt against the small-ceremony key");
```

### 3. Run it

```sh
cd examples/hello-world
RISC0_GROTH16_BLS_BIN=/path/to/go/groth16bls \
  cargo run --release --features prove
```

On the first run the prover pauses for several minutes with no progress output while it downloads about
2.3 GB (the proving key and constraint system) into `~/.risc0/groth16-bls/`. This is the key fetch, not
a hang. Expected output:

```
produced a BLS12-381 Groth16 receipt (388-byte seal)
I know the factors of 391, and I can prove it!
verified the BLS12-381 Groth16 receipt against the small-ceremony key
```

That is the full pipeline: a guest program proven to a BLS12-381 Groth16 receipt and verified, with no
manual steps between `prove` and a checkable proof.

## Verifying the proof elsewhere

The receipt's seal is the Cardano-v2 proof; the same bytes verify two other ways:

- **On-chain (Cardano).** A Plutus/Aiken script checks the proof with the BLS12-381 pairing builtins.
  The proof, public inputs, and verifying key are the `proof.cardano.bin` / `public.cardano.bin` /
  `vk.cardano.bin` byte layout described in [PUBLIC_INPUTS.md](PUBLIC_INPUTS.md).
- **Native Rust, standalone.** Run the `groth16bls` prover directly on an `identity_bls` seal to emit
  those three files, then check them with this repo's verifier:

  ```sh
  groth16bls prove --seal seal.bin --out .
  cargo run -p groth16-bls-verify --bin verify_cardano --release -- \
    vk.cardano.bin proof.cardano.bin public.cardano.bin
  ```

## Notes

- The default key is **`small-ceremony-2026-06`** (a 10-participant Phase-2 MPC ceremony). `--dev`
  selects the insecure dev key for local work only. The code is not yet externally audited.
- For GPU proving, build `groth16bls-gpu` (`make groth16bls-gpu`, ICICLE/CUDA) and the fork picks it up
  when compiled with `cuda`.
