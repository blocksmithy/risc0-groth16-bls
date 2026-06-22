package stark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

// rouFwd20 = ROU_FWD[20], the generator of the DEEP evaluation domain (size INV_RATE·tot_cycles =
// 2^20 for the recursion circuit). risc0 core/src/field/baby_bear.rs ROU_FWD[20].
var rouFwd20 = big.NewInt(1461624142)

// DeepQueryX computes the DEEP evaluation-domain point x = ROU_FWD[20]^pos for a query, from the
// LSB-first bits of the 20-bit query position (gen = ROU_FWD[log2(domain=2^20)]).
func DeepQueryX(f *bb.Field, posBits []frontend.Variable) *bb.Elem {
	return powConst(f, rouFwd20, posBits)
}

// ComboU builds the mixed-U polynomials combo_u (tot_combo_backs+1 = 21 Fp4) and the per-register
// fri_mix powers (tap_mix_pows, len reg_count=163) + check_mix_pows (len CHECK_SIZE=16), from
// coeff_u and the FRI mix challenge. Mirrors verify/mod.rs:400-426. Columns sharing a tap-set are
// grouped into a single combo (same DEEP-ALI denominator).
func ComboU(f *bb.Field, coeffU []bb.E4, friMix bb.E4) (comboU, tapMixPows, checkMixPows []bb.E4) {
	comboU = make([]bb.E4, tapsTable.TotComboBacks+1)
	for i := range comboU {
		comboU[i] = f.E4Zero()
	}
	curMix := f.E4One()
	curPos := 0
	for _, r := range tapsTable.Regs {
		base := tapsTable.ComboBegin[r.Combo]
		for i := 0; i < r.Size; i++ {
			comboU[base+i] = f.E4Add(comboU[base+i], f.E4Mul(curMix, coeffU[curPos+i]))
		}
		tapMixPows = append(tapMixPows, curMix)
		curMix = f.E4Mul(curMix, friMix)
		curPos += r.Size
	}
	for i := 0; i < tapsTable.CheckSize; i++ {
		idx := tapsTable.TotComboBacks
		comboU[idx] = f.E4Add(comboU[idx], f.E4Mul(curMix, coeffU[curPos]))
		curPos++
		checkMixPows = append(checkMixPows, curMix)
		curMix = f.E4Mul(curMix, friMix)
	}
	return
}

// FriEvalTaps computes the DEEP query value (goal0 - the value FRI's round 0 consumes) at one query
// point x = gen^idx, mirroring verify/mod.rs::fri_eval_taps. It mixes the Merkle-opened tap rows by
// the fri_mix powers into per-combo totals, subtracts the combo_u polynomial evaluated at x, and
// divides by the DEEP-ALI denominator Π(x − z·back_one^back) per combo (plus the check term over
// x − z^INV_RATE). rows[g] is the group-g column opening (0=accum,1=code,2=data); checkRow the
// check-group opening; z the DEEP point; back_one = ROU_REV[po2].
func FriEvalTaps(f *bb.Field, comboU []bb.E4, checkRow []*bb.Elem, xBase *bb.Elem, z bb.E4,
	rows [3][]*bb.Elem, tapMixPows, checkMixPows []bb.E4) bb.E4 {

	comboCount := tapsTable.CombosCount
	x := f.E4From(xBase, f.Const(0), f.Const(0), f.Const(0))

	tot := make([]bb.E4, comboCount+1)
	for i := range tot {
		tot[i] = f.E4Zero()
	}
	for ri, r := range tapsTable.Regs {
		// cur · rows[group][offset]  (tap_mix_pow is Fp4, the row element is base)
		term := f.E4ScalarMul(tapMixPows[ri], rows[r.Group][r.Offset])
		tot[r.Combo] = f.E4Add(tot[r.Combo], term)
	}
	for i := 0; i < tapsTable.CheckSize; i++ {
		tot[comboCount] = f.E4Add(tot[comboCount], f.E4ScalarMul(checkMixPows[i], checkRow[i]))
	}

	powOf := func(b int) *big.Int { return new(big.Int).Exp(friBackOne, big.NewInt(int64(b)), friP) }

	ret := f.E4Zero()
	for i := 0; i < comboCount; i++ {
		coeffs := comboU[tapsTable.ComboBegin[i]:tapsTable.ComboBegin[i+1]]
		num := f.E4Sub(tot[i], PolyEval(f, coeffs, x))
		divisor := f.E4One()
		for _, b := range tapsTable.ComboTaps[tapsTable.ComboBegin[i]:tapsTable.ComboBegin[i+1]] {
			zb := f.E4ScalarMulConst(z, powOf(b)) // z · back_one^b
			divisor = f.E4Mul(divisor, f.E4Sub(x, zb))
		}
		ret = f.E4Add(ret, f.E4Mul(num, f.E4Inv(divisor)))
	}
	// Check group shares the denominator x − z^INV_RATE (INV_RATE = 4).
	checkNum := f.E4Sub(tot[comboCount], comboU[tapsTable.TotComboBacks])
	z2 := f.E4Mul(z, z)
	z4 := f.E4Mul(z2, z2)
	ret = f.E4Add(ret, f.E4Mul(checkNum, f.E4Inv(f.E4Sub(x, z4))))
	return ret
}
