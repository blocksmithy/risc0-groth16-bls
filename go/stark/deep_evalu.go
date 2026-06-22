package stark

import (
	"math/big"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

// friBackOne is ROU_REV[po2] for the recursion po2=18 (= back_one in verify/mod.rs:326). Validated
// against the armed VV_BACKONE dump for the real seal. risc0 core/src/field/baby_bear.rs ROU_REV[18].
var friBackOne = big.NewInt(1525739923)

// CoeffUFromUCoeffs groups the flat U-coefficient base elements (parsed from the seal prefix,
// canonical BabyBear) into 659 Fp4 coeff_u elements: coeff_u[k] = (u[4k], u[4k+1], u[4k+2], u[4k+3]).
// RISC0 reads coeff_u via read_field_elem_slice::<ExtElem>, i.e. 4 consecutive base words per ext.
func CoeffUFromUCoeffs(f *bb.Field, uCoeffs []*bb.Elem) []bb.E4 {
	n := len(uCoeffs) / 4
	out := make([]bb.E4, n)
	for k := 0; k < n; k++ {
		out[k] = f.E4From(uCoeffs[4*k], uCoeffs[4*k+1], uCoeffs[4*k+2], uCoeffs[4*k+3])
	}
	return out
}

// EvalU converts the U coefficients (coeff_u, the first tap_size=643 of the 659 read from the seal)
// into evaluation form: for each tap register and each of its `back` offsets, eval_u[flat] =
// poly_eval over that register's coefficient slice at x = z·back_one^back. Mirrors the eval_u loop
// in verify/mod.rs:337-346. The back_one^back factors are circuit constants (z is the only
// variable), so each is a single scalar-constant multiply.
func EvalU(f *bb.Field, coeffU []bb.E4, z bb.E4) []bb.E4 {
	// Precompute the distinct back_one^back scalar constants (backs ∈ {0,1,2,3,4,7,15,16,68}).
	powCache := map[int]*big.Int{}
	powOf := func(b int) *big.Int {
		if p, ok := powCache[b]; ok {
			return p
		}
		p := new(big.Int).Exp(friBackOne, big.NewInt(int64(b)), friP)
		powCache[b] = p
		return p
	}

	evalU := make([]bb.E4, 0, tapsTable.TapSize)
	curPos := 0
	for _, r := range tapsTable.Regs {
		coeffs := coeffU[curPos : curPos+r.Size]
		for i := 0; i < r.Size; i++ {
			x := f.E4ScalarMulConst(z, powOf(r.Backs[i]))
			evalU = append(evalU, PolyEval(f, coeffs, x))
		}
		curPos += r.Size
	}
	return evalU
}
