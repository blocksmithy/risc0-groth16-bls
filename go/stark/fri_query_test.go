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

type friQueryCircuit struct {
	Pos0   frontend.Variable
	Goal0  [4]emulated.Element[bb.Base]
	Leaves [3][64]emulated.Element[bb.Base]
	Mixes  [3][4]emulated.Element[bb.Base]
	Final  [256]emulated.Element[bb.Base]
}

func (c *friQueryCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	goal0 := bb.E4{C: [4]*bb.Elem{&c.Goal0[0], &c.Goal0[1], &c.Goal0[2], &c.Goal0[3]}}
	var leaves [3][]*bb.Elem
	for r := 0; r < 3; r++ {
		leaves[r] = make([]*bb.Elem, 64)
		for i := 0; i < 64; i++ {
			leaves[r][i] = &c.Leaves[r][i]
		}
	}
	var mixes [3]bb.E4
	for r := 0; r < 3; r++ {
		mixes[r] = bb.E4{C: [4]*bb.Elem{&c.Mixes[r][0], &c.Mixes[r][1], &c.Mixes[r][2], &c.Mixes[r][3]}}
	}
	final := make([]*bb.Elem, 256)
	for i := 0; i < 256; i++ {
		final[i] = &c.Final[i]
	}
	VerifyFRIQuery(api, f, c.Pos0, goal0, leaves, mixes, final)
	return nil
}

// TestVerifyFRIQueryReal validates the COMPLETE FRI per-query verification (all 3 round
// quot-checks + folds + the final-layer check) against RISC0's real seal for query 0: it must
// be satisfiable exactly when RISC0 accepts. goal0 is the DEEP value entering round 0 (the
// DEEP-ALI layer will produce it in-circuit; here it is taken from RISC0's trace).
func TestVerifyFRIQueryReal(t *testing.T) {
	data, err := os.ReadFile("testdata/fri_query_real.json")
	if err != nil {
		t.Skipf("fri query fixture missing: %v", err)
	}
	var ref struct {
		Pos0   int        `json:"pos0"`
		Goal0  []string   `json:"goal0"`
		Leaves [][]string `json:"leaves"`
		Mixes  [][]string `json:"mixes"`
		Final  []string   `json:"final"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}

	var c friQueryCircuit
	c.Pos0 = ref.Pos0
	for i := 0; i < 4; i++ {
		c.Goal0[i] = emulated.ValueOf[bb.Base](ref.Goal0[i])
	}
	for r := 0; r < 3; r++ {
		for i := 0; i < 64; i++ {
			c.Leaves[r][i] = emulated.ValueOf[bb.Base](ref.Leaves[r][i])
		}
		for i := 0; i < 4; i++ {
			c.Mixes[r][i] = emulated.ValueOf[bb.Base](ref.Mixes[r][i])
		}
	}
	for i := 0; i < 256; i++ {
		c.Final[i] = emulated.ValueOf[bb.Base](ref.Final[i])
	}

	if err := test.IsSolved(&friQueryCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("full FRI query verify diverged from RISC0: %v", err)
	}

	// Single-mutation negative: a wrong DEEP goal0 must fail the round-0 quot-check.
	bad := c
	bad.Goal0[0] = emulated.ValueOf[bb.Base](0)
	if err := test.IsSolved(&friQueryCircuit{}, &bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong goal0 to be rejected")
	}
}
