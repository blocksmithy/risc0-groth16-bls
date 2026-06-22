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

type friEvalCircuit struct {
	CoeffU    [2636]emulated.Element[bb.Base]
	FriMix    [4]emulated.Element[bb.Base]
	Z         [4]emulated.Element[bb.Base]
	Pos0      frontend.Variable
	AccumLeaf [12]emulated.Element[bb.Base]
	CodeLeaf  [23]emulated.Element[bb.Base]
	DataLeaf  [128]emulated.Element[bb.Base]
	CheckLeaf [16]emulated.Element[bb.Base]
	Goal0     [4]emulated.Element[bb.Base] // expected DEEP value entering FRI round 0
}

func (c *friEvalCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	flat := make([]*bb.Elem, len(c.CoeffU))
	for i := range c.CoeffU {
		flat[i] = &c.CoeffU[i]
	}
	coeffU := CoeffUFromUCoeffs(f, flat)
	friMix := bb.E4{C: [4]*bb.Elem{&c.FriMix[0], &c.FriMix[1], &c.FriMix[2], &c.FriMix[3]}}
	z := bb.E4{C: [4]*bb.Elem{&c.Z[0], &c.Z[1], &c.Z[2], &c.Z[3]}}

	comboU, tapMixPows, checkMixPows := ComboU(f, coeffU, friMix)

	toPtrs := func(s []emulated.Element[bb.Base]) []*bb.Elem {
		out := make([]*bb.Elem, len(s))
		for i := range s {
			out[i] = &s[i]
		}
		return out
	}
	rows := [3][]*bb.Elem{toPtrs(c.AccumLeaf[:]), toPtrs(c.CodeLeaf[:]), toPtrs(c.DataLeaf[:])}
	checkRow := toPtrs(c.CheckLeaf[:])

	xBase := powConst(f, rouFwd20, api.ToBinary(c.Pos0, 20))
	got := FriEvalTaps(f, comboU, checkRow, xBase, z, rows, tapMixPows, checkMixPows)
	f.E4AssertEq(got, bb.E4{C: [4]*bb.Elem{&c.Goal0[0], &c.Goal0[1], &c.Goal0[2], &c.Goal0[3]}})
	return nil
}

// TestFriEvalTapsRealSeal validates the DEEP-ALI -> FRI bridge: combo_u (from coeff_u + fri_mix) and
// fri_eval_taps, evaluated at query 0's position over its real Merkle-opened tap rows, must
// reproduce exactly the goal0 that FRI's round 0 consumes (fri_query_real.json goal0, dumped as
// FRI_GOAL0). This closes the loop - the DEEP value FRI takes as input is now produced in-circuit.
func TestFriEvalTapsRealSeal(t *testing.T) {
	seal := readSeal(t)
	if len(seal) != 55667 {
		t.Skipf("seal.bin is %d words, expected 55667", len(seal))
	}
	p, err := ParsePrefix(seal)
	if err != nil {
		t.Fatal(err)
	}
	queries, err := ParseQueries(seal)
	if err != nil {
		t.Fatal(err)
	}
	q0 := queries[0]

	trData, err := os.ReadFile("testdata/transcript_real.json")
	if err != nil {
		t.Skipf("transcript fixture missing: %v", err)
	}
	var tr struct {
		Ext [][]string `json:"ext"`
	}
	if err := json.Unmarshal(trData, &tr); err != nil {
		t.Fatal(err)
	}

	fqData, err := os.ReadFile("testdata/fri_query_real.json")
	if err != nil {
		t.Skipf("fri query fixture missing: %v", err)
	}
	var fq struct {
		Pos0  int      `json:"pos0"`
		Goal0 []string `json:"goal0"`
	}
	if err := json.Unmarshal(fqData, &fq); err != nil {
		t.Fatal(err)
	}

	var c friEvalCircuit
	for i := 0; i < 2636; i++ {
		c.CoeffU[i] = emulated.ValueOf[bb.Base](p.UCoeffs[i])
	}
	for j := 0; j < 4; j++ {
		c.FriMix[j] = emulated.ValueOf[bb.Base](tr.Ext[2][j]) // fri_mix = ext[2]
		c.Z[j] = emulated.ValueOf[bb.Base](tr.Ext[1][j])      // z = ext[1]
		c.Goal0[j] = emulated.ValueOf[bb.Base](fq.Goal0[j])
	}
	c.Pos0 = fq.Pos0
	setLeaf := func(dst []emulated.Element[bb.Base], src []frontend.Variable) {
		for i := range dst {
			dst[i] = emulated.ValueOf[bb.Base](src[i])
		}
	}
	setLeaf(c.AccumLeaf[:], q0.MainLeaf[0])
	setLeaf(c.CodeLeaf[:], q0.MainLeaf[1])
	setLeaf(c.DataLeaf[:], q0.MainLeaf[2])
	setLeaf(c.CheckLeaf[:], q0.MainLeaf[3])

	if err := test.IsSolved(&friEvalCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("fri_eval_taps goal0 diverged from RISC0: %v", err)
	}

	// Single-mutation negative: a wrong fri_mix must change goal0.
	bad := c
	bad.FriMix[0] = emulated.ValueOf[bb.Base](0)
	if err := test.IsSolved(&friEvalCircuit{}, &bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong fri_mix to be rejected")
	}
}
