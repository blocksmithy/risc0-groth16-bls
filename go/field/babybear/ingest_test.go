package babybear

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type ingestCircuit struct {
	V        frontend.Variable
	WantEmul emulated.Element[Base]
}

func (c *ingestCircuit) Define(api frontend.API) error {
	f, err := NewField(api)
	if err != nil {
		return err
	}
	native, el := f.IngestElem(c.V)
	api.AssertIsEqual(native, c.V)      // native value passes through unchanged
	f.AssertElemEq(el, &c.WantEmul)     // emulated element is bound to v
	return nil
}

// TestIngestElem validates the seal-ingest boundary: a canonical native value v yields an emulated
// element encoding the same integer (F2 — the native and emulated representations are derived from
// one wire and cannot diverge).
func TestIngestElem(t *testing.T) {
	for _, v := range []uint64{0, 1, 12345, 746097124, 2013265920 /* p-1 */} {
		c := &ingestCircuit{V: v, WantEmul: emulated.ValueOf[Base](v)}
		if err := test.IsSolved(&ingestCircuit{}, c, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("v=%d: %v", v, err)
		}
	}
}

// TestIngestRejectsNonCanonical is the F1 negative: a non-canonical native value (>= p) must be
// rejected by the in-circuit canonicality check, mirroring RISC0's read_field_elem_slice.
func TestIngestRejectsNonCanonical(t *testing.T) {
	// p and a gap-region value [p, 2^31) and a value >= 2^31; WantEmul is irrelevant (must reject
	// before the binding). Use ValueOf(0) — the canonical check fails first.
	for _, v := range []uint64{2013265921 /* p */, 2013265921 + 10, 1 << 31, (1 << 31) + 7} {
		c := &ingestCircuit{V: v, WantEmul: emulated.ValueOf[Base](0)}
		if err := test.IsSolved(&ingestCircuit{}, c, ecc.BLS12_381.ScalarField()); err == nil {
			t.Fatalf("expected non-canonical v=%d to be rejected", v)
		}
	}
}

// TestIngestBindsEmulated is the F2 negative: the emulated element is pinned to the native wire, so
// claiming a different emulated value (here v+1) is unsatisfiable — a prover cannot feed one value
// to the native (hash) side and a different one to the emulated (Fp4/FRI/DEEP) side.
func TestIngestBindsEmulated(t *testing.T) {
	c := &ingestCircuit{V: 12345, WantEmul: emulated.ValueOf[Base](12346)}
	if err := test.IsSolved(&ingestCircuit{}, c, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected mismatched emulated value to be rejected (native↔emulated binding)")
	}
}
