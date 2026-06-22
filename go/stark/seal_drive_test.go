package stark

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	pbls "github.com/pitcon/stark-to-snark-bls/go/hash/poseidon_bls"
)

// sealDriveCircuit drives the Fiat-Shamir transcript from the parsed real seal prefix: it
// recomputes each committed digest in-circuit (globals hash, group/FRI Merkle roots, U-coeffs
// hash, final-coeffs hash) and asserts the resulting challenges match the seal's prover-side
// challenges. This is the D1 (seal parse) + D2 (transcript) integration end-to-end.
type sealDriveCircuit struct {
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

	Elems [20]frontend.Variable
	Ext   [6][4]frontend.Variable
	Bits  [50]frontend.Variable
}

func (c *sealDriveCircuit) Define(api frontend.API) error {
	tr := NewTranscript()
	assertExt := func(got, want [4]frontend.Variable) {
		for i := 0; i < 4; i++ {
			api.AssertIsEqual(got[i], want[i])
		}
	}
	tr.CommitInfo(api, ProofSystemInfo)
	tr.CommitInfo(api, CircuitInfo)
	tr.Commit(api, pbls.HashElemSlice(api, c.Globals[:]))
	tr.Commit(api, MerkleRoot(api, c.CodeTop[:]))
	tr.Commit(api, MerkleRoot(api, c.DataTop[:]))
	for i := 0; i < 20; i++ {
		api.AssertIsEqual(tr.RandomElem(api), c.Elems[i])
	}
	tr.Commit(api, MerkleRoot(api, c.AccumTop[:]))
	assertExt(tr.RandomExtElem(api), c.Ext[0]) // poly_mix
	tr.Commit(api, MerkleRoot(api, c.CheckTop[:]))
	assertExt(tr.RandomExtElem(api), c.Ext[1]) // z
	tr.Commit(api, pbls.HashElemSlice(api, c.UCoeffs[:]))
	assertExt(tr.RandomExtElem(api), c.Ext[2]) // fri_mix
	tr.Commit(api, MerkleRoot(api, c.Fri0Top[:]))
	assertExt(tr.RandomExtElem(api), c.Ext[3])
	tr.Commit(api, MerkleRoot(api, c.Fri1Top[:]))
	assertExt(tr.RandomExtElem(api), c.Ext[4])
	tr.Commit(api, MerkleRoot(api, c.Fri2Top[:]))
	assertExt(tr.RandomExtElem(api), c.Ext[5])
	tr.Commit(api, pbls.HashElemSlice(api, c.Final[:]))
	for i := 0; i < 50; i++ {
		api.AssertIsEqual(tr.RandomBits(api, 20), c.Bits[i])
	}
	return nil
}

func readSeal(t *testing.T) []uint32 {
	data, err := os.ReadFile("../../testdata/identity_bls/seal.bin")
	if err != nil {
		t.Skipf("seal.bin fixture missing: %v", err)
	}
	w := make([]uint32, len(data)/4)
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(data[4*i:])
	}
	return w
}

// TestSealDriveReal parses the real identity_bls seal prefix and drives the transcript from it,
// asserting all 76 challenges match RISC0's actual trace for the SAME seal. Validates the seal
// parser (Montgomery decode, digest bytes, layout) + in-circuit commit recomputation end-to-end.
func TestSealDriveReal(t *testing.T) {
	seal := readSeal(t)
	if len(seal) != 55667 {
		t.Skipf("seal.bin is %d words, expected 55667 (po2=18 fixture)", len(seal))
	}
	p, err := ParsePrefix(seal)
	if err != nil {
		t.Fatal(err)
	}

	var c sealDriveCircuit
	copy(c.Globals[:], p.Globals)
	copy(c.CodeTop[:], p.CodeTop)
	copy(c.DataTop[:], p.DataTop)
	copy(c.AccumTop[:], p.AccumTop)
	copy(c.CheckTop[:], p.CheckTop)
	copy(c.UCoeffs[:], p.UCoeffs)
	copy(c.Fri0Top[:], p.FriTops[0])
	copy(c.Fri1Top[:], p.FriTops[1])
	copy(c.Fri2Top[:], p.FriTops[2])
	copy(c.Final[:], p.Final)

	data, err := os.ReadFile("testdata/transcript_real.json")
	if err != nil {
		t.Skipf("transcript trace missing: %v", err)
	}
	var ref struct {
		Elems []string   `json:"elems"`
		Ext   [][]string `json:"ext"`
		Bits  []string   `json:"bits"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		c.Elems[i] = ref.Elems[i]
	}
	for i := 0; i < 6; i++ {
		for j := 0; j < 4; j++ {
			c.Ext[i][j] = ref.Ext[i][j]
		}
	}
	for i := 0; i < 50; i++ {
		c.Bits[i] = ref.Bits[i]
	}

	if err := test.IsSolved(&sealDriveCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("seal-driven transcript diverged from RISC0: %v", err)
	}
}
