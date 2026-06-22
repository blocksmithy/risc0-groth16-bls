package stark

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type merkleCircuit struct {
	Pos      frontend.Variable
	Leaf     []frontend.Variable
	Siblings []frontend.Variable
	Top      []frontend.Variable
	nbits    int
}

func (c *merkleCircuit) Define(api frontend.API) error {
	MerkleVerify(api, c.Pos, c.nbits, c.Leaf, c.Siblings, c.Top)
	return nil
}

func toVars(ss []string) []frontend.Variable {
	out := make([]frontend.Variable, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// TestMerkleVerify checks the in-circuit Merkle opening against a reference tree built with
// the validated poseidon_bls hash (prototype/merkle/gen_merkle_ref.py), matching risc0
// verify/merkle.rs conventions (leaf hash, bottom-up fold, top-row compare).
func TestMerkleVerify(t *testing.T) {
	data, err := os.ReadFile("testdata/merkle_ref.json")
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Nbits    int      `json:"nbits"`
		ColSize  int      `json:"col_size"`
		TopSize  int      `json:"top_size"`
		Pos      int      `json:"pos"`
		Leaf     []string `json:"leaf"`
		Siblings []string `json:"siblings"`
		Top      []string `json:"top"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}

	assignment := &merkleCircuit{
		nbits:    ref.Nbits,
		Pos:      ref.Pos,
		Leaf:     toVars(ref.Leaf),
		Siblings: toVars(ref.Siblings),
		Top:      toVars(ref.Top),
	}
	empty := &merkleCircuit{
		nbits:    ref.Nbits,
		Leaf:     make([]frontend.Variable, len(ref.Leaf)),
		Siblings: make([]frontend.Variable, len(ref.Siblings)),
		Top:      make([]frontend.Variable, len(ref.Top)),
	}
	if err := test.IsSolved(empty, assignment, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatal(err)
	}

	// Soundness: tampering a sibling must make the opening unsatisfiable.
	bad := &merkleCircuit{
		nbits:    ref.Nbits,
		Pos:      ref.Pos,
		Leaf:     toVars(ref.Leaf),
		Siblings: toVars(ref.Siblings),
		Top:      toVars(ref.Top),
	}
	bad.Siblings[0] = "123456789"
	if err := test.IsSolved(empty, bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected tampered Merkle opening to be rejected")
	}
}
