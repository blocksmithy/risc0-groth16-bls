package stark

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

type evalUCircuit struct {
	CoeffU [2636]emulated.Element[bb.Base] // 659 Fp4, flat base elements from the seal
	Z      [4]emulated.Element[bb.Base]
	EvalU  [643][4]emulated.Element[bb.Base] // expected RISC0 eval_u
}

func (c *evalUCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	flat := make([]*bb.Elem, len(c.CoeffU))
	for i := range c.CoeffU {
		flat[i] = &c.CoeffU[i]
	}
	coeffU := CoeffUFromUCoeffs(f, flat)
	z := bb.E4{C: [4]*bb.Elem{&c.Z[0], &c.Z[1], &c.Z[2], &c.Z[3]}}
	got := EvalU(f, coeffU, z)
	if len(got) != 643 {
		panic("eval_u length")
	}
	for i := 0; i < 643; i++ {
		exp := bb.E4{C: [4]*bb.Elem{&c.EvalU[i][0], &c.EvalU[i][1], &c.EvalU[i][2], &c.EvalU[i][3]}}
		f.E4AssertEq(got[i], exp)
	}
	return nil
}

// TestEvalURealSeal validates the DEEP-ALI eval_u computation (tap interpolations at
// z·back_one^back) against RISC0's actual VV_EVALU trace for the real seal. coeff_u is parsed from
// the committed seal (the same U-coeffs whose hash TestSealDriveReal binds to the transcript); z is
// the real DEEP query point (= transcript ext[1], cross-checked by convert_deep.py). Non-circular:
// expected eval_u are RISC0's, coeff_u are seal witness bytes.
func TestEvalURealSeal(t *testing.T) {
	seal := readSeal(t)
	if len(seal) != 55667 {
		t.Skipf("seal.bin is %d words, expected 55667", len(seal))
	}
	p, err := ParsePrefix(seal)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("testdata/deep_real.json")
	if err != nil {
		t.Skipf("deep fixture missing: %v", err)
	}
	var ref struct {
		Z      []string   `json:"z"`
		EvalU  [][]string `json:"eval_u"`
		Result []string   `json:"result"`
		Check  []string   `json:"check"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}

	var c evalUCircuit
	for i := 0; i < 2636; i++ {
		c.CoeffU[i] = emulated.ValueOf[bb.Base](p.UCoeffs[i])
	}
	for j := 0; j < 4; j++ {
		c.Z[j] = emulated.ValueOf[bb.Base](ref.Z[j])
	}
	for i := 0; i < 643; i++ {
		for j := 0; j < 4; j++ {
			c.EvalU[i][j] = emulated.ValueOf[bb.Base](ref.EvalU[i][j])
		}
	}

	if err := test.IsSolved(&evalUCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("eval_u diverged from RISC0: %v", err)
	}

	// Single-mutation negative: a wrong z must change essentially all eval_u (so the asserts fail).
	bad := c
	bad.Z[0] = emulated.ValueOf[bb.Base](0)
	if err := test.IsSolved(&evalUCircuit{}, &bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong z to be rejected")
	}
}
