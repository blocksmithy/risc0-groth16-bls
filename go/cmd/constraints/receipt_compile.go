package main

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
	"github.com/pitcon/stark-to-snark-bls/go/stark"
)

// receiptCompileC compiles the FULL top-level verifier (validity + FRI, all 50 queries) to real
// R1CS. Gated behind COMPILE_RECEIPT=1 because it takes ~20s; the headline count is recorded in
// constraints.txt. Confirms the whole composition compiles (no hidden emulated-field overflow at
// full scale - the lesson from the PolyExt const-overflow bug).
type receiptCompileC struct {
	Globals  [33]frontend.Variable
	CodeTop  [32]frontend.Variable
	DataTop  [32]frontend.Variable
	AccumTop [32]frontend.Variable
	CheckTop [32]frontend.Variable
	UCoeffs  [2636]frontend.Variable
	Fri0Top  [32]frontend.Variable
	Fri1Top  [32]frontend.Variable
	Fri2Top  [32]frontend.Variable
	Final    [256]frontend.Variable
	Q        []stark.QueryVars

	ControlRootLow  frontend.Variable `gnark:",public"`
	ControlRootHigh frontend.Variable `gnark:",public"`
	ClaimDigestLow  frontend.Variable `gnark:",public"`
	ClaimDigestHigh frontend.Variable `gnark:",public"`
	ControlID       frontend.Variable `gnark:",public"`
}

func (c *receiptCompileC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	p := &stark.SealPrefixVars{Globals: c.Globals[:], CodeTop: c.CodeTop[:], DataTop: c.DataTop[:],
		AccumTop: c.AccumTop[:], CheckTop: c.CheckTop[:], UCoeffs: c.UCoeffs[:],
		FriTops: [3][]frontend.Variable{c.Fri0Top[:], c.Fri1Top[:], c.Fri2Top[:]}, Final: c.Final[:]}
	stark.VerifyReceipt(api, f, p, c.Q,
		c.ControlRootLow, c.ControlRootHigh, c.ClaimDigestLow, c.ClaimDigestHigh, c.ControlID)
	return nil
}

func countFullReceipt() {
	mk := func(n int) []frontend.Variable { return make([]frontend.Variable, n) }
	q := make([]stark.QueryVars, 50)
	for i := range q {
		q[i] = stark.QueryVars{
			MainLeaf: [4][]frontend.Variable{mk(12), mk(23), mk(128), mk(16)},
			MainPath: [4][]frontend.Variable{mk(15), mk(15), mk(15), mk(15)},
			FriLeaf:  [3][]frontend.Variable{mk(64), mk(64), mk(64)},
			FriPath:  [3][]frontend.Variable{mk(11), mk(7), mk(3)},
		}
	}
	t := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &receiptCompileC{Q: q})
	if err != nil {
		fmt.Println("compile VerifyReceipt:", err)
		return
	}
	fmt.Printf("%-40s %8d   (compiled in %s)\n", "stark.VerifyReceipt (FULL, 50 queries)", ccs.GetNbConstraints(), time.Since(t).Round(time.Second))
}
