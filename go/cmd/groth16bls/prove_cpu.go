//go:build !icicle

package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

const proverBackend = "cpu"

// newProvingKey allocates the proving-key value to deserialize pk.bin into. The GPU build
// (prove_gpu.go) returns the ICICLE proving-key type instead, which iciclegroth16.Prove requires.
func newProvingKey() groth16.ProvingKey {
	return groth16.NewProvingKey(ecc.BLS12_381)
}

// proveBackend is the default CPU Groth16 prover. The GPU variant lives in prove_gpu.go behind the
// `icicle` build tag; RISC0 selects the GPU binary via its own CUDA feature (see shrink_wrap_bls).
func proveBackend(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	return groth16.Prove(ccs, pk, w)
}
