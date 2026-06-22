package stark

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// queryMainCircuit verifies one query's four main-group openings (accum/code/data/check) parsed
// from the seal: each leaf+path must Merkle-reconstruct to the parsed group root at the query
// position. Exercises ParseQueries + MerkleVerify on real data.
type queryMainCircuit struct {
	Pos       frontend.Variable
	AccumLeaf [12]frontend.Variable
	AccumPath [15]frontend.Variable
	CodeLeaf  [23]frontend.Variable
	CodePath  [15]frontend.Variable
	DataLeaf  [128]frontend.Variable
	DataPath  [15]frontend.Variable
	CheckLeaf [16]frontend.Variable
	CheckPath [15]frontend.Variable
	AccumTop  [32]frontend.Variable
	CodeTop   [32]frontend.Variable
	DataTop   [32]frontend.Variable
	CheckTop  [32]frontend.Variable
}

func (c *queryMainCircuit) Define(api frontend.API) error {
	MerkleVerify(api, c.Pos, 20, c.AccumLeaf[:], c.AccumPath[:], c.AccumTop[:])
	MerkleVerify(api, c.Pos, 20, c.CodeLeaf[:], c.CodePath[:], c.CodeTop[:])
	MerkleVerify(api, c.Pos, 20, c.DataLeaf[:], c.DataPath[:], c.DataTop[:])
	MerkleVerify(api, c.Pos, 20, c.CheckLeaf[:], c.CheckPath[:], c.CheckTop[:])
	return nil
}

// TestQueryOpeningReal parses query 0 of the real seal and verifies its four main openings
// in-circuit against the parsed group roots at the real query position. (All 50 queries × 7
// openings are validated against the real roots in prototype/ Python; this exercises the Go
// ParseQueries + MerkleVerify path on real data.)
func TestQueryOpeningReal(t *testing.T) {
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
	q := queries[0]

	data, err := os.ReadFile("testdata/transcript_real.json")
	if err != nil {
		t.Skipf("transcript trace missing: %v", err)
	}
	var ref struct {
		Bits []string `json:"bits"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}

	var c queryMainCircuit
	c.Pos = ref.Bits[0]
	copy(c.AccumLeaf[:], q.MainLeaf[0])
	copy(c.AccumPath[:], q.MainPath[0])
	copy(c.CodeLeaf[:], q.MainLeaf[1])
	copy(c.CodePath[:], q.MainPath[1])
	copy(c.DataLeaf[:], q.MainLeaf[2])
	copy(c.DataPath[:], q.MainPath[2])
	copy(c.CheckLeaf[:], q.MainLeaf[3])
	copy(c.CheckPath[:], q.MainPath[3])
	copy(c.AccumTop[:], p.AccumTop)
	copy(c.CodeTop[:], p.CodeTop)
	copy(c.DataTop[:], p.DataTop)
	copy(c.CheckTop[:], p.CheckTop)

	if err := test.IsSolved(&queryMainCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("query 0 main openings failed to verify: %v", err)
	}
}
