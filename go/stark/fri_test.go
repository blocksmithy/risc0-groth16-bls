package stark

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

type polyEvalCircuit struct {
	Coeffs [3][4]emulated.Element[bb.Base]
	X      [4]emulated.Element[bb.Base]
	Exp    [4]emulated.Element[bb.Base]
}

func e4of(v *[4]emulated.Element[bb.Base]) bb.E4 {
	return bb.E4{C: [4]*bb.Elem{&v[0], &v[1], &v[2], &v[3]}}
}

func (c *polyEvalCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	coeffs := []bb.E4{e4of(&c.Coeffs[0]), e4of(&c.Coeffs[1]), e4of(&c.Coeffs[2])}
	f.E4AssertEq(PolyEval(f, coeffs, e4of(&c.X)), e4of(&c.Exp))
	return nil
}

func e4val(v [4]uint64) [4]emulated.Element[bb.Base] {
	return [4]emulated.Element[bb.Base]{
		emulated.ValueOf[bb.Base](v[0]), emulated.ValueOf[bb.Base](v[1]),
		emulated.ValueOf[bb.Base](v[2]), emulated.ValueOf[bb.Base](v[3]),
	}
}

// TestPolyEval validates Fp4 polynomial evaluation against an independent Python reference:
// poly_eval([[1,2,3,4],[5,6,7,8],[9,10,11,12]], x=[2,0,1,0]).
func TestPolyEval(t *testing.T) {
	good := &polyEvalCircuit{
		Coeffs: [3][4]emulated.Element[bb.Base]{
			e4val([4]uint64{1, 2, 3, 4}), e4val([4]uint64{5, 6, 7, 8}), e4val([4]uint64{9, 10, 11, 12}),
		},
		X:   e4val([4]uint64{2, 0, 1, 0}),
		Exp: e4val([4]uint64{2013265308, 2013265249, 2013265902, 2013265903}),
	}
	if err := test.IsSolved(&polyEvalCircuit{}, good, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatal(err)
	}
	// Single-mutation negative test.
	bad := *good
	bad.Exp[0] = emulated.ValueOf[bb.Base](0)
	if err := test.IsSolved(&polyEvalCircuit{}, &bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong poly_eval result to be rejected")
	}
}
