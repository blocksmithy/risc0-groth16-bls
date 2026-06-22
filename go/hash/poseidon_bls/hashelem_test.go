package poseidon_bls

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type hashElemCircuit struct {
	In  [10]frontend.Variable
	Exp frontend.Variable
}

func (c *hashElemCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(HashElemSlice(api, c.In[:]), c.Exp)
	return nil
}

// TestHashElemSlice validates unpadded base-p packing + sponge for hash_elem_slice([0,1,...,9]).
// The expected digest cross-checks with the Rust `poseidon_bls_hash_and_rng_kat` (mutually anchored
// with this port); the genuine non-circular anchor is stark.TestSealDriveReal, which recomputes
// HashElemSlice over the real seal's globals/U-coeffs and matches RISC0's actual transcript commits.
func TestHashElemSlice(t *testing.T) {
	assignment := &hashElemCircuit{
		In:  [10]frontend.Variable{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		Exp: "884671265139700862754989059462429453333922945423157299124474582327185633395",
	}
	if err := test.IsSolved(&hashElemCircuit{}, assignment, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

// TestHashElemSliceRejectsWrong is the single-mutation negative test: a wrong
// expected digest must be unsatisfiable, proving the HashElemSlice output is actually constrained.
func TestHashElemSliceRejectsWrong(t *testing.T) {
	bad := &hashElemCircuit{
		In:  [10]frontend.Variable{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		Exp: "884671265139700862754989059462429453333922945423157299124474582327185633396", // +1
	}
	if err := test.IsSolved(&hashElemCircuit{}, bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong HashElemSlice digest to be rejected")
	}
}
