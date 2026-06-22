package stark

import (
	"math/big"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

// ComputeCheck reconstructs the DEEP-ALI "check" polynomial value at the query point z from the
// check-group coefficients (the last CHECK_SIZE=16 of the 659 coeff_u), mirroring verify/mod.rs
// (the `check` accumulation + the (3z)^tot_cycles − 1 factor). The verifier asserts check ==
// result (= PolyExt(...)); equality is the constraint-satisfaction guarantee.
//
//	check = Σ_{i=0}^{3} z^i · Σ_{j=0}^{3} coeff_u[tap_size + remap[i] + 4j] · X^j
//	check *= (3z)^{2^po2} − 1            (remap = [0,2,1,3]; X^j are the Fp4 basis elements)
func ComputeCheck(f *bb.Field, coeffU []bb.E4, z bb.E4, totCyclesPo2 int) bb.E4 {
	remap := [4]int{0, 2, 1, 3}
	numTaps := tapsTable.TapSize // 643
	zero, one := f.Const(0), f.Const(1)
	basis := [4]bb.E4{
		f.E4From(one, zero, zero, zero),
		f.E4From(zero, one, zero, zero),
		f.E4From(zero, zero, one, zero),
		f.E4From(zero, zero, zero, one),
	}

	check := f.E4Zero()
	zpow := f.E4One()
	for i := 0; i < 4; i++ {
		inner := f.E4Zero()
		for j := 0; j < 4; j++ {
			inner = f.E4Add(inner, f.E4Mul(coeffU[numTaps+remap[i]+4*j], basis[j]))
		}
		check = f.E4Add(check, f.E4Mul(zpow, inner))
		zpow = f.E4Mul(zpow, z)
	}

	// factor = (3z)^(2^po2) − 1, computed by po2 repeated squarings of 3z.
	factor := f.E4ScalarMulConst(z, big.NewInt(3))
	for k := 0; k < totCyclesPo2; k++ {
		factor = f.E4Mul(factor, factor)
	}
	factor = f.E4Sub(factor, f.E4One())

	return f.E4Mul(check, factor)
}
