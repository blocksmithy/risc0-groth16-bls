package stark

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type merkleRealCircuit struct {
	Pos      frontend.Variable
	LeafHash frontend.Variable
	Siblings []frontend.Variable
	Top      []frontend.Variable
	nbits    int
}

func (c *merkleRealCircuit) Define(api frontend.API) error {
	MerkleVerifyFromLeafHash(api, c.Pos, c.nbits, c.LeafHash, c.Siblings, c.Top)
	return nil
}

// TestMerkleVerifyRealOpening de-circularizes the Merkle test: it validates the in-circuit
// fold + top-row selection against a REAL Merkle opening (leaf hash, sibling path, top row)
// dumped from RISC0's verify/merkle.rs during verification of the actual identity_bls seal.
// If our convention (hash_pair order, index mapping, top-row layout) diverged from RISC0's,
// this would fail even though the self-consistent Python test passes.
func TestMerkleVerifyRealOpening(t *testing.T) {
	data, err := os.ReadFile("testdata/merkle_real.json")
	if err != nil {
		t.Skipf("real opening not generated yet: %v", err)
	}
	var ref struct {
		Nbits    int      `json:"nbits"`
		TopSize  int      `json:"top_size"`
		Idx      int      `json:"idx"`
		LeafHash string   `json:"leaf_hash"`
		Siblings []string `json:"siblings"`
		Top      []string `json:"top"`
		Present  string   `json:"present"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}

	assignment := &merkleRealCircuit{
		nbits:    ref.Nbits,
		Pos:      ref.Idx,
		LeafHash: ref.LeafHash,
		Siblings: toVars(ref.Siblings),
		Top:      toVars(ref.Top),
	}
	empty := &merkleRealCircuit{
		nbits:    ref.Nbits,
		Siblings: make([]frontend.Variable, len(ref.Siblings)),
		Top:      make([]frontend.Variable, len(ref.Top)),
	}
	if err := test.IsSolved(empty, assignment, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("real RISC0 Merkle opening failed in-circuit (convention mismatch): %v", err)
	}
}

type merkleRootCircuit struct {
	Top  []frontend.Variable
	Root frontend.Variable
}

func (c *merkleRootCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(MerkleRoot(api, c.Top), c.Root)
	return nil
}

// TestMerkleRootRealOpening validates MerkleRoot (the top-row -> root fold that the STARK
// driver commits to the transcript) against the root RISC0 actually computed in
// MerkleTreeVerifier::new for the real poseidon_bls opening. Non-circular: the root is RISC0's.
func TestMerkleRootRealOpening(t *testing.T) {
	data, err := os.ReadFile("testdata/merkle_real.json")
	if err != nil {
		t.Skipf("real opening not generated yet: %v", err)
	}
	var ref struct {
		Top  []string `json:"top"`
		Root string   `json:"root"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	if ref.Root == "" {
		t.Skip("root not present in fixture (regenerate with DUMP_ROOT capture)")
	}
	empty := &merkleRootCircuit{Top: make([]frontend.Variable, len(ref.Top))}
	good := &merkleRootCircuit{Top: toVars(ref.Top), Root: ref.Root}
	if err := test.IsSolved(empty, good, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("MerkleRoot mismatch vs real RISC0 root: %v", err)
	}

	// Single-mutation negative test: tampering one top digest must change the root.
	bad := &merkleRootCircuit{Top: toVars(ref.Top), Root: ref.Root}
	bad.Top[0] = "123456789"
	if err := test.IsSolved(empty, bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected tampered top row to change the root")
	}
}
