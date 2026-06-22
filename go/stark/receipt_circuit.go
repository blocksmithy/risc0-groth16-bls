package stark

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

// QueryWit is one query's openings as fixed-size circuit witness arrays (the slice-typed QueryVars
// are built from these in Define). Sizes are the recursion po2=18 layout.
type QueryWit struct {
	AccumLeaf [12]frontend.Variable
	CodeLeaf  [23]frontend.Variable
	DataLeaf  [128]frontend.Variable
	CheckLeaf [16]frontend.Variable
	AccumPath [15]frontend.Variable
	CodePath  [15]frontend.Variable
	DataPath  [15]frontend.Variable
	CheckPath [15]frontend.Variable
	Fri0Leaf  [64]frontend.Variable
	Fri1Leaf  [64]frontend.Variable
	Fri2Leaf  [64]frontend.Variable
	Fri0Path  [11]frontend.Variable
	Fri1Path  [7]frontend.Variable
	Fri2Path  [3]frontend.Variable
}

// ReceiptCircuit is the full top-level verifier circuit. The two public inputs are the claim digest
// halves; everything else is private witness (the parsed seal). Queries is allocated to the number
// of query openings to verify (50 for a complete verification).
type ReceiptCircuit struct {
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
	Queries  []QueryWit

	// The five public inputs in risc0's Groth16 schema order (over BLS12-381). See claim.go/BindClaim.
	ControlRootLow  frontend.Variable `gnark:",public"`
	ControlRootHigh frontend.Variable `gnark:",public"`
	ClaimDigestLow  frontend.Variable `gnark:",public"`
	ClaimDigestHigh frontend.Variable `gnark:",public"`
	ControlID       frontend.Variable `gnark:",public"`
}

func (c *ReceiptCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	prefix := &SealPrefixVars{
		Globals:  c.Globals[:],
		CodeTop:  c.CodeTop[:],
		DataTop:  c.DataTop[:],
		AccumTop: c.AccumTop[:],
		CheckTop: c.CheckTop[:],
		UCoeffs:  c.UCoeffs[:],
		FriTops:  [3][]frontend.Variable{c.Fri0Top[:], c.Fri1Top[:], c.Fri2Top[:]},
		Final:    c.Final[:],
	}
	queries := make([]QueryVars, len(c.Queries))
	for i := range c.Queries {
		q := &c.Queries[i]
		queries[i] = QueryVars{
			MainLeaf: [4][]frontend.Variable{q.AccumLeaf[:], q.CodeLeaf[:], q.DataLeaf[:], q.CheckLeaf[:]},
			MainPath: [4][]frontend.Variable{q.AccumPath[:], q.CodePath[:], q.DataPath[:], q.CheckPath[:]},
			FriLeaf:  [3][]frontend.Variable{q.Fri0Leaf[:], q.Fri1Leaf[:], q.Fri2Leaf[:]},
			FriPath:  [3][]frontend.Variable{q.Fri0Path[:], q.Fri1Path[:], q.Fri2Path[:]},
		}
	}
	VerifyReceipt(api, f, prefix, queries,
		c.ControlRootLow, c.ControlRootHigh, c.ClaimDigestLow, c.ClaimDigestHigh, c.ControlID)
	return nil
}

// ReceiptTemplate returns an empty circuit shaped for nq queries - used as the Compile template.
func ReceiptTemplate(nq int) *ReceiptCircuit {
	return &ReceiptCircuit{Queries: make([]QueryWit, nq)}
}

// AssignReceipt builds a full witness assignment for the circuit from a parsed identity_bls seal,
// verifying the first nq queries. The public claim digest (lo/hi) is reconstructed from the seal
// globals. Returns an error on a malformed seal.
func AssignReceipt(seal []uint32, nq int) (*ReceiptCircuit, error) {
	p, err := ParsePrefix(seal)
	if err != nil {
		return nil, err
	}
	qs, err := ParseQueries(seal)
	if err != nil {
		return nil, err
	}
	if nq < 1 || nq > len(qs) {
		return nil, fmt.Errorf("nq=%d out of range [1,%d]", nq, len(qs))
	}
	c := ReceiptTemplate(nq)
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
	// Public inputs (risc0 schema): control_root split + claim_digest split + control_id.
	crLow, crHigh := ControlRootSplit()
	cdLow, cdHigh := claimDigestFromGlobals(p.Globals)
	c.ControlRootLow = crLow
	c.ControlRootHigh = crHigh
	c.ClaimDigestLow = cdLow
	c.ClaimDigestHigh = cdHigh
	c.ControlID = ControlIDFr()
	for i := 0; i < nq; i++ {
		q := &c.Queries[i]
		copy(q.AccumLeaf[:], qs[i].MainLeaf[0])
		copy(q.CodeLeaf[:], qs[i].MainLeaf[1])
		copy(q.DataLeaf[:], qs[i].MainLeaf[2])
		copy(q.CheckLeaf[:], qs[i].MainLeaf[3])
		copy(q.AccumPath[:], qs[i].MainPath[0])
		copy(q.CodePath[:], qs[i].MainPath[1])
		copy(q.DataPath[:], qs[i].MainPath[2])
		copy(q.CheckPath[:], qs[i].MainPath[3])
		copy(q.Fri0Leaf[:], qs[i].FriLeaf[0])
		copy(q.Fri1Leaf[:], qs[i].FriLeaf[1])
		copy(q.Fri2Leaf[:], qs[i].FriLeaf[2])
		copy(q.Fri0Path[:], qs[i].FriPath[0])
		copy(q.Fri1Path[:], qs[i].FriPath[1])
		copy(q.Fri2Path[:], qs[i].FriPath[2])
	}
	return c, nil
}
