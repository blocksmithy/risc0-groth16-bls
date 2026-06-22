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

type checkCircuit struct {
	CoeffU [2636]emulated.Element[bb.Base]
	Z      [4]emulated.Element[bb.Base]
	Check  [4]emulated.Element[bb.Base] // expected RISC0 check value
}

func (c *checkCircuit) Define(api frontend.API) error {
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
	got := ComputeCheck(f, coeffU, z, 18) // po2 = 18 for the recursion circuit
	f.E4AssertEq(got, bb.E4{C: [4]*bb.Elem{&c.Check[0], &c.Check[1], &c.Check[2], &c.Check[3]}})
	return nil
}

// TestComputeCheckRealSeal validates the DEEP-ALI check-polynomial reconstruction against RISC0's
// actual VV_CHECK for the real seal. Because the receipt verified, RISC0's check == result; this
// test plus TestPolyExtRealSeal (result) together establish the check == result equality the driver
// enforces. coeff_u from the seal; z + expected check are RISC0's ground truth.
func TestComputeCheckRealSeal(t *testing.T) {
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
	var deep struct {
		Z      []string `json:"z"`
		Check  []string `json:"check"`
		Result []string `json:"result"`
	}
	if err := json.Unmarshal(data, &deep); err != nil {
		t.Fatal(err)
	}
	// Sanity: the fixture itself must record check == result (the receipt verified).
	for j := 0; j < 4; j++ {
		if deep.Check[j] != deep.Result[j] {
			t.Fatalf("fixture check != result at %d: %s vs %s", j, deep.Check[j], deep.Result[j])
		}
	}

	var c checkCircuit
	for i := 0; i < 2636; i++ {
		c.CoeffU[i] = emulated.ValueOf[bb.Base](p.UCoeffs[i])
	}
	for j := 0; j < 4; j++ {
		c.Z[j] = emulated.ValueOf[bb.Base](deep.Z[j])
		c.Check[j] = emulated.ValueOf[bb.Base](deep.Check[j])
	}

	if err := test.IsSolved(&checkCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("check polynomial diverged from RISC0: %v", err)
	}

	// Single-mutation negative: a wrong z must change check.
	bad := c
	bad.Z[0] = emulated.ValueOf[bb.Base](0)
	if err := test.IsSolved(&checkCircuit{}, &bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong z to be rejected")
	}
}
