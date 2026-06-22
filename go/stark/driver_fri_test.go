package stark

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// loadReceipt builds a full receipt witness from the committed seal, verifying the first nq queries.
func loadReceipt(t *testing.T, nq int) *ReceiptCircuit {
	t.Helper()
	seal := readSeal(t)
	if len(seal) != 55667 {
		t.Skipf("seal.bin is %d words, expected 55667", len(seal))
	}
	c, err := AssignReceipt(seal, nq)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestVerifyReceiptReal is the full top-level verifier integration: validity spine (V1) + FRI phase
// + claim binding, driven entirely by in-circuit Fiat-Shamir challenges and positions, with every
// seal element ingested (F1/F2) and every tap-row/FRI-column leaf Merkle-verified against the
// committed roots. It must be satisfiable for the real seal (which RISC0 accepted). Verifies all 50
// queries (the transcript draws one position per query).
func TestVerifyReceiptReal(t *testing.T) {
	const nq = 50
	c := loadReceipt(t, nq)
	if err := test.IsSolved(ReceiptTemplate(nq), c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("full receipt verifier diverged from RISC0: %v", err)
	}
}

// TestVerifyReceiptRejectsTamper is the single-mutation negative suite for the FRI phase + claim
// binding: one mutation per soundness-critical class must make the circuit
// unsatisfiable. Each mutation keeps the value canonical (so the rejection comes from the binding
// being exercised, not the F1 canonicality check). nq=1 for speed.
func TestVerifyReceiptRejectsTamper(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ReceiptCircuit)
	}{
		{"FRI column leaf", func(c *ReceiptCircuit) { c.Queries[0].Fri0Leaf[0] = bumpCanonical(c.Queries[0].Fri0Leaf[0]) }},
		{"main tap leaf (accum)", func(c *ReceiptCircuit) { c.Queries[0].AccumLeaf[0] = bumpCanonical(c.Queries[0].AccumLeaf[0]) }},
		// The check row flows through a distinct path (checkRow / check_mix_pows / the check-term
		// denominator in FriEvalTaps), so it gets its own mutation.
		{"check tap leaf", func(c *ReceiptCircuit) { c.Queries[0].CheckLeaf[0] = bumpCanonical(c.Queries[0].CheckLeaf[0]) }},
		{"main Merkle path sibling", func(c *ReceiptCircuit) { c.Queries[0].AccumPath[0] = bumpCanonical(c.Queries[0].AccumPath[0]) }},
		{"FRI Merkle path sibling", func(c *ReceiptCircuit) { c.Queries[0].Fri0Path[0] = bumpCanonical(c.Queries[0].Fri0Path[0]) }},
		{"group top digest", func(c *ReceiptCircuit) { c.CodeTop[0] = bumpCanonical(c.CodeTop[0]) }},
		{"FRI round top digest", func(c *ReceiptCircuit) { c.Fri0Top[0] = bumpCanonical(c.Fri0Top[0]) }},
		{"final-layer coeff", func(c *ReceiptCircuit) { c.Final[0] = bumpCanonical(c.Final[0]) }},
		{"control-root global", func(c *ReceiptCircuit) { c.Globals[0] = bumpCanonical(c.Globals[0]) }},
		// The claim_digest occupies globals[16:32]; tampering it (to forge a different claim) must be
		// rejected because ALL globals are committed to the Fiat-Shamir transcript, so a mutated claim
		// changes every downstream challenge and breaks the (unmutated) FRI/Merkle openings.
		{"claim_digest global", func(c *ReceiptCircuit) { c.Globals[16] = bumpCanonical(c.Globals[16]) }},
		// Every other seal-prefix group: the data/accum/check Merkle caps, the DEEP-ALI U coefficients,
		// and the FRI round-1/2 caps must each be bound (transcript commit + Merkle/eval use). Tamper
		// one element of each and confirm the circuit becomes unsatisfiable - no under-constrained class.
		{"data group top", func(c *ReceiptCircuit) { c.DataTop[0] = bumpCanonical(c.DataTop[0]) }},
		{"accum group top", func(c *ReceiptCircuit) { c.AccumTop[0] = bumpCanonical(c.AccumTop[0]) }},
		{"check group top", func(c *ReceiptCircuit) { c.CheckTop[0] = bumpCanonical(c.CheckTop[0]) }},
		{"DEEP U coeff", func(c *ReceiptCircuit) { c.UCoeffs[0] = bumpCanonical(c.UCoeffs[0]) }},
		{"DEEP U coeff (mid)", func(c *ReceiptCircuit) { c.UCoeffs[1318] = bumpCanonical(c.UCoeffs[1318]) }},
		{"FRI round-1 top", func(c *ReceiptCircuit) { c.Fri1Top[0] = bumpCanonical(c.Fri1Top[0]) }},
		{"FRI round-2 top", func(c *ReceiptCircuit) { c.Fri2Top[0] = bumpCanonical(c.Fri2Top[0]) }},
		// Not covered (and not coverable) here: the query positions and the FRI round mixes. Both are
		// Fiat-Shamir transcript draws, not witness - there is no value a prover can mutate, so they
		// are structurally unforgeable and no single-mutation negative is possible.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const nq = 1
			c := loadReceipt(t, nq)
			tc.mutate(c)
			if err := test.IsSolved(ReceiptTemplate(nq), c, ecc.BLS12_381.ScalarField()); err == nil {
				t.Fatalf("expected tampered %s to be rejected", tc.name)
			}
		})
	}
}
