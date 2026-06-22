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

type polyExtCircuit struct {
	EvalU      [643][4]emulated.Element[bb.Base]
	PolyMix    [4]emulated.Element[bb.Base]
	GlobalsOut [32]emulated.Element[bb.Base]
	AccumMix   [20]emulated.Element[bb.Base]
	Result     [4]emulated.Element[bb.Base] // expected RISC0 poly_ext result
}

func (c *polyExtCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	evalU := make([]bb.E4, 643)
	for i := 0; i < 643; i++ {
		evalU[i] = bb.E4{C: [4]*bb.Elem{&c.EvalU[i][0], &c.EvalU[i][1], &c.EvalU[i][2], &c.EvalU[i][3]}}
	}
	globalsOut := make([]*bb.Elem, 32)
	for i := range globalsOut {
		globalsOut[i] = &c.GlobalsOut[i]
	}
	accumMix := make([]*bb.Elem, 20)
	for i := range accumMix {
		accumMix[i] = &c.AccumMix[i]
	}
	polyMix := bb.E4{C: [4]*bb.Elem{&c.PolyMix[0], &c.PolyMix[1], &c.PolyMix[2], &c.PolyMix[3]}}
	got := PolyExt(f, polyMix, evalU, globalsOut, accumMix)
	f.E4AssertEq(got, bb.E4{C: [4]*bb.Elem{&c.Result[0], &c.Result[1], &c.Result[2], &c.Result[3]}})
	return nil
}

// TestPolyExtRealSeal validates the DEEP-ALI poly_ext step program (~12.4k steps) against RISC0's
// actual `result` for the real seal. Inputs are independent ground truth: eval_u + poly_mix + the
// expected result from RISC0's VV_ trace, the globals (out) from the seal, and the accum mix from
// the transcript challenges. Non-circular: the entire step program is exercised and its output is
// compared to RISC0's, not to a recomputation by this code.
func TestPolyExtRealSeal(t *testing.T) {
	seal := readSeal(t)
	if len(seal) != 55667 {
		t.Skipf("seal.bin is %d words, expected 55667", len(seal))
	}
	p, err := ParsePrefix(seal)
	if err != nil {
		t.Fatal(err)
	}

	deepData, err := os.ReadFile("testdata/deep_real.json")
	if err != nil {
		t.Skipf("deep fixture missing: %v", err)
	}
	var deep struct {
		PolyMix []string   `json:"poly_mix"`
		EvalU   [][]string `json:"eval_u"`
		Result  []string   `json:"result"`
	}
	if err := json.Unmarshal(deepData, &deep); err != nil {
		t.Fatal(err)
	}

	trData, err := os.ReadFile("testdata/transcript_real.json")
	if err != nil {
		t.Skipf("transcript fixture missing: %v", err)
	}
	var tr struct {
		Elems []string `json:"elems"`
	}
	if err := json.Unmarshal(trData, &tr); err != nil {
		t.Fatal(err)
	}

	var c polyExtCircuit
	for i := 0; i < 643; i++ {
		for j := 0; j < 4; j++ {
			c.EvalU[i][j] = emulated.ValueOf[bb.Base](deep.EvalU[i][j])
		}
	}
	for j := 0; j < 4; j++ {
		c.PolyMix[j] = emulated.ValueOf[bb.Base](deep.PolyMix[j])
		c.Result[j] = emulated.ValueOf[bb.Base](deep.Result[j])
	}
	for i := 0; i < 32; i++ {
		c.GlobalsOut[i] = emulated.ValueOf[bb.Base](p.Globals[i])
	}
	for i := 0; i < 20; i++ {
		c.AccumMix[i] = emulated.ValueOf[bb.Base](tr.Elems[i])
	}

	if err := test.IsSolved(&polyExtCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("poly_ext diverged from RISC0: %v", err)
	}

	// Single-mutation negative: a wrong poly_mix must change result.
	bad := c
	bad.PolyMix[0] = emulated.ValueOf[bb.Base](0)
	if err := test.IsSolved(&polyExtCircuit{}, &bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong poly_mix to be rejected")
	}
}
