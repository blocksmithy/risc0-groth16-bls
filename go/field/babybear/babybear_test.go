package babybear

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type fp4OpsCircuit struct {
	A, B     [4]emulated.Element[Base]
	Mul      [4]emulated.Element[Base]
	Add      [4]emulated.Element[Base]
	Sub      [4]emulated.Element[Base]
}

func (c *fp4OpsCircuit) Define(api frontend.API) error {
	f, err := NewField(api)
	if err != nil {
		return err
	}
	conv := func(v *[4]emulated.Element[Base]) E4 {
		return E4{C: [4]*Elem{&v[0], &v[1], &v[2], &v[3]}}
	}
	f.E4AssertEq(f.E4Mul(conv(&c.A), conv(&c.B)), conv(&c.Mul))
	f.E4AssertEq(f.E4Add(conv(&c.A), conv(&c.B)), conv(&c.Add))
	f.E4AssertEq(f.E4Sub(conv(&c.A), conv(&c.B)), conv(&c.Sub))
	return nil
}

func e4(v [4]uint64) [4]emulated.Element[Base] {
	return [4]emulated.Element[Base]{
		emulated.ValueOf[Base](v[0]), emulated.ValueOf[Base](v[1]),
		emulated.ValueOf[Base](v[2]), emulated.ValueOf[Base](v[3]),
	}
}

// TestFp4OpsAgainstRisc0 validates Fp4 mul/add/sub against expected outputs over the public
// extension field F_p[X]/(X^4+11) (beta=11 from risc0 core/src/field/baby_bear.rs). The
// expected values were computed independently over that documented field and are corroborated
// by TestFp4InvAgainstRisc0 (a*inv==1) and the real-seal FRI tests; they are not produced by
// the code under test.
func TestFp4OpsAgainstRisc0(t *testing.T) {
	cases := []fp4OpsCircuit{
		{ // a=[100,200,300,400], b=[5,6,7,8]
			A: e4([4]uint64{100, 200, 300, 400}), B: e4([4]uint64{5, 6, 7, 8}),
			Mul: e4([4]uint64{2013199321, 2013210321, 2013234121, 6000}),
			Add: e4([4]uint64{105, 206, 307, 408}),
			Sub: e4([4]uint64{95, 194, 293, 392}),
		},
		{ // c=[p-1,1,0,7], d=[11,22,33,44] (wrap-around)
			A: e4([4]uint64{2013265920, 1, 0, 7}), B: e4([4]uint64{11, 22, 33, 44}),
			Mul: e4([4]uint64{2013263732, 2013263369, 2013262522, 66}),
			Add: e4([4]uint64{10, 23, 33, 51}),
			Sub: e4([4]uint64{2013265909, 2013265900, 2013265888, 2013265884}),
		},
	}
	for i := range cases {
		c := cases[i]
		if err := test.IsSolved(&fp4OpsCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}

type fp4InvCircuit struct {
	A      [4]emulated.Element[Base]
	ExpInv [4]emulated.Element[Base]
}

func (c *fp4InvCircuit) Define(api frontend.API) error {
	f, err := NewField(api)
	if err != nil {
		return err
	}
	conv := func(v *[4]emulated.Element[Base]) E4 {
		return E4{C: [4]*Elem{&v[0], &v[1], &v[2], &v[3]}}
	}
	inv := f.E4Inv(conv(&c.A)) // internally constrains A*inv == 1
	f.E4AssertEq(inv, conv(&c.ExpInv))
	return nil
}

// TestFp4InvAgainstRisc0 validates the hint-based Fp4 inverse against RISC0's authoritative
// ExtElem::inv outputs, and (via E4Inv's internal a*inv==1) that the constraint holds.
func TestFp4InvAgainstRisc0(t *testing.T) {
	cases := []fp4InvCircuit{
		{A: e4([4]uint64{100, 200, 300, 400}),
			ExpInv: e4([4]uint64{109795346, 1294946348, 1132142100, 1464759056})},
		{A: e4([4]uint64{2013265920, 1, 0, 7}),
			ExpInv: e4([4]uint64{1514532920, 200221461, 1951895969, 474030883})},
	}
	for i := range cases {
		c := cases[i]
		if err := test.IsSolved(&fp4InvCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}

// TestFp4RejectsWrong is the single-mutation negative test for Fp4 ops: a
// wrong product/inverse must be unsatisfiable, proving E4Mul/E4Inv outputs are constrained
// (and, for E4Inv, that the a·inv==1 binding actually rejects a non-inverse).
func TestFp4RejectsWrong(t *testing.T) {
	wrongMul := fp4OpsCircuit{
		A: e4([4]uint64{100, 200, 300, 400}), B: e4([4]uint64{5, 6, 7, 8}),
		Mul: e4([4]uint64{2013199322, 2013210321, 2013234121, 6000}), // mutated c0 by +1
		Add: e4([4]uint64{105, 206, 307, 408}),
		Sub: e4([4]uint64{95, 194, 293, 392}),
	}
	if err := test.IsSolved(&fp4OpsCircuit{}, &wrongMul, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong Fp4 product to be rejected")
	}

	wrongInv := fp4InvCircuit{
		A:      e4([4]uint64{100, 200, 300, 400}),
		ExpInv: e4([4]uint64{109795347, 1294946348, 1132142100, 1464759056}), // mutated c0 by +1
	}
	if err := test.IsSolved(&fp4InvCircuit{}, &wrongInv, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong Fp4 inverse to be rejected")
	}
}

type canonCircuit struct {
	V frontend.Variable
}

func (c *canonCircuit) Define(api frontend.API) error {
	f, err := NewField(api)
	if err != nil {
		return err
	}
	f.AssertCanonical(c.V)
	return nil
}

// TestAssertCanonical checks the canonical BabyBear range check against the plan's golden
// edge cases: values in [0,p) pass; p, the gap region [p,2^31), and >= 2^31 are rejected.
func TestAssertCanonical(t *testing.T) {
	pass := []string{"0", "1", "2013265919", "2013265920"} // ..., 0x77FFFFFF, p-1=0x78000000
	for _, v := range pass {
		if err := test.IsSolved(&canonCircuit{}, &canonCircuit{V: v}, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("expected %s to be canonical: %v", v, err)
		}
	}
	reject := []string{
		"2013265921", // p           (=0x78000001)
		"2147483648", // 0x80000000  (gap region, = 2^31)
		"4160749567", // 0xF7FFFFFF
		"4160749569", // 0xF8000001  (validBabyBear-alone would pass; ReduceStrict must reject)
	}
	for _, v := range reject {
		if err := test.IsSolved(&canonCircuit{}, &canonCircuit{V: v}, ecc.BLS12_381.ScalarField()); err == nil {
			t.Fatalf("expected %s to be rejected as non-canonical", v)
		}
	}
}
