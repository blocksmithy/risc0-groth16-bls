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

type friFoldCircuit struct {
	Leaf      [64]emulated.Element[bb.Base]
	Mix       [4]emulated.Element[bb.Base]
	Group     frontend.Variable
	Goal      [4]emulated.Element[bb.Base]
	groupBits int
	rpo2      int
}

func (c *friFoldCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	leaf := make([]*bb.Elem, 64)
	for i := 0; i < 64; i++ {
		leaf[i] = &c.Leaf[i]
	}
	mix := bb.E4{C: [4]*bb.Elem{&c.Mix[0], &c.Mix[1], &c.Mix[2], &c.Mix[3]}}
	got := FoldRound(api, f, leaf, c.Group, c.groupBits, mix, c.rpo2)
	f.E4AssertEq(got, bb.E4{C: [4]*bb.Elem{&c.Goal[0], &c.Goal[1], &c.Goal[2], &c.Goal[3]}})
	return nil
}

// TestFriFoldReal validates the in-circuit FRI fold against RISC0's actual per-round folded
// goal for the real seal (query 0, all 3 rounds): reshape -> inverse-NTT (constant transform) ->
// poly_eval at mix·inv_wk. Non-circular: leaf from the real seal, goal/mix/group from RISC0's
// verify_query trace.
func TestFriFoldReal(t *testing.T) {
	data, err := os.ReadFile("testdata/fri_round_real.json")
	if err != nil {
		t.Skipf("fri round fixture missing: %v", err)
	}
	var rounds map[string]struct {
		Goal  []string `json:"goal"`
		Mix   []string `json:"mix"`
		Leaf  []string `json:"leaf"`
		Group int      `json:"group"`
		Quot  int      `json:"quot"`
		Rpo2  int      `json:"rpo2"`
	}
	if err := json.Unmarshal(data, &rounds); err != nil {
		t.Fatal(err)
	}

	e4 := func(dst *[4]emulated.Element[bb.Base], src []string) {
		for i := 0; i < 4; i++ {
			dst[i] = emulated.ValueOf[bb.Base](src[i])
		}
	}
	for r := 0; r < 3; r++ {
		rd := rounds[map[int]string{0: "0", 1: "1", 2: "2"}[r]]
		var c friFoldCircuit
		c.groupBits = rd.Rpo2 - 4 // log2(round.domain)
		c.rpo2 = rd.Rpo2
		c.Group = rd.Group
		for i := 0; i < 64; i++ {
			c.Leaf[i] = emulated.ValueOf[bb.Base](rd.Leaf[i])
		}
		e4(&c.Mix, rd.Mix)
		e4(&c.Goal, rd.Goal)
		if err := test.IsSolved(&friFoldCircuit{groupBits: c.groupBits, rpo2: c.rpo2}, &c, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("FRI fold round %d diverged from RISC0: %v", r, err)
		}

		// Single-mutation negative test (round 0): a wrong folded goal must be rejected.
		if r == 0 {
			bad := c
			bad.Goal[0] = emulated.ValueOf[bb.Base](0)
			if err := test.IsSolved(&friFoldCircuit{groupBits: c.groupBits, rpo2: c.rpo2}, &bad, ecc.BLS12_381.ScalarField()); err == nil {
				t.Fatal("expected wrong FRI fold goal to be rejected")
			}
		}
	}
}
