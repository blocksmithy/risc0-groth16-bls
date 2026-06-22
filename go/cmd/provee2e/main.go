// Command provee2e runs the full release-gate pipeline on the real identity_bls seal: compile the
// VerifyReceipt circuit -> Groth16 Setup -> Prove -> Verify, then a negative (verify the proof against
// a tampered public claim must fail). This is the proof that the whole in-circuit verifier produces
// a valid BLS12-381 Groth16 proof for a real RISC0 receipt (release is never cut on
// solver-only evidence).
//
// NOTE: groth16.Setup here is the INSECURE development setup (toxic waste generated in-memory).
// Production keys come from the Phase-2 MPC ceremony (gnark mpcsetup) over a Phase-1 SRS (Filecoin
// Powers-of-Tau) - see the ceremony section of STARK_to_SNARK_BLS12_381_plan.md. The proving/
// verifying logic exercised here is identical; only the keys differ (toxic waste vs ceremony).
//
// Usage:  go run ./cmd/provee2e            (NQ=50, full; heavy - minutes + GBs)
//
//	NQ=4 go run ./cmd/provee2e       (fast smoke over the first 4 queries)
package main

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"

	"github.com/pitcon/stark-to-snark-bls/go/stark"
)

func main() {
	logger.Set(zerolog.Nop())
	nq := 50
	if v := os.Getenv("NQ"); v != "" {
		nq, _ = strconv.Atoi(v)
	}

	wd, _ := os.Getwd()
	sealPath := filepath.Join(wd, "..", "testdata", "identity_bls", "seal.bin")
	seal := readSeal(sealPath)

	step := func(name string, fn func() error) {
		t := time.Now()
		if err := fn(); err != nil {
			fmt.Printf("FAIL %s: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("ok   %-26s %s\n", name, time.Since(t).Round(time.Millisecond))
	}

	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var fullWit, pubWit witness.Witness
	var proof groth16.Proof

	fmt.Printf("=== Groth16 e2e: VerifyReceipt, nq=%d ===\n", nq)
	step("compile", func() (err error) {
		ccs, err = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, stark.ReceiptTemplate(nq))
		if err == nil {
			fmt.Printf("     %d constraints\n", ccs.GetNbConstraints())
		}
		return
	})
	step("setup (INSECURE dev)", func() (err error) { pk, vk, err = groth16.Setup(ccs); return })
	step("assign witness", func() error {
		c, err := stark.AssignReceipt(seal, nq)
		if err != nil {
			return err
		}
		fullWit, err = frontend.NewWitness(c, ecc.BLS12_381.ScalarField())
		if err != nil {
			return err
		}
		pubWit, err = fullWit.Public()
		return err
	})
	step("prove", func() (err error) { proof, err = groth16.Prove(ccs, pk, fullWit); return })
	step("verify (valid)", func() error { return groth16.Verify(proof, vk, pubWit) })
	step("verify (tampered claim must fail)", func() error {
		bad, err := stark.AssignReceipt(seal, nq)
		if err != nil {
			return err
		}
		bad.ClaimDigestLow = new(big.Int).Add(bad.ClaimDigestLow.(*big.Int), big.NewInt(1))
		bw, err := frontend.NewWitness(bad, ecc.BLS12_381.ScalarField())
		if err != nil {
			return err
		}
		bpw, err := bw.Public()
		if err != nil {
			return err
		}
		if groth16.Verify(proof, vk, bpw) == nil {
			return fmt.Errorf("tampered claim public input verified (should have failed)")
		}
		return nil
	})
	fmt.Println("=== PASS: valid Groth16 proof produced and verified; wrong claim rejected ===")
}

func readSeal(path string) []uint32 {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("read seal:", err)
		os.Exit(1)
	}
	w := make([]uint32, len(b)/4)
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	return w
}
