//go:build icicle

package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	iciclegroth16 "github.com/consensys/gnark/backend/accelerated/icicle/groth16"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

const proverBackend = "gpu(icicle)"

// newProvingKey returns the ICICLE proving-key VALUE (not the bare gnark one): iciclegroth16.Prove
// type-asserts the pk to the ICICLE type, so the CPU pk would panic it. The ICICLE pk deserializes
// the SAME pk.bin bytes (it embeds the standard pk + lazily-built device info), so the keys dir is
// shared with the CPU build. The device transfer happens inside Prove.
func newProvingKey() groth16.ProvingKey {
	return iciclegroth16.NewProvingKey(ecc.BLS12_381)
}

// proveBackend uses gnark's ICICLE GPU backend (MSM + NTT on the GPU). Requires CGO + the ICICLE
// CUDA libraries + an NVIDIA GPU at build and run time.
func proveBackend(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	return iciclegroth16.Prove(ccs, pk, w)
}
