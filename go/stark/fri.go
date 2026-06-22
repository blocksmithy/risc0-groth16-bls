package stark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

// FRI roots of unity (canonical BabyBear), from risc0 core/src/field/baby_bear.rs ROU_REV.
// w = ROU_REV[4] is the 16th reverse root used by the fold's inverse NTT; rouRev[k] = ROU_REV[k]
// is used to compute inv_wk = ROU_REV[log2(16*round.domain)]^group (rpo2 = 20/16/12 for the
// three rounds at po2=18). Checked by make verify-constants against the pinned source.
var (
	friP   = big.NewInt(2013265921)
	friW   = big.NewInt(196396260) // ROU_REV[4]
	rouRev = map[int]*big.Int{
		20: big.NewInt(1463599021), // ROU_REV[20]
		16: big.NewInt(1893145354), // ROU_REV[16]
		12: big.NewInt(1827366325), // ROU_REV[12]
	}
	friTwiddle [16][16]*big.Int // (1/16) * w^((k*i) mod 16) mod p
)

func init() {
	inv16 := new(big.Int).ModInverse(big.NewInt(16), friP)
	for k := 0; k < 16; k++ {
		for i := 0; i < 16; i++ {
			t := new(big.Int).Exp(friW, big.NewInt(int64((k*i)%16)), friP)
			t.Mul(t, inv16)
			friTwiddle[k][i] = t.Mod(t, friP)
		}
	}
}

// reshapeLeaf turns a 64-element FRI column leaf into 16 Fp4 points (data_ext[i] = Fp4 of the
// 4 base elements spaced FRI_FOLD=16 apart), per verify_query.
func reshapeLeaf(f *bb.Field, leaf []*bb.Elem) []bb.E4 {
	d := make([]bb.E4, 16)
	for i := 0; i < 16; i++ {
		d[i] = f.E4From(leaf[i], leaf[16+i], leaf[32+i], leaf[48+i])
	}
	return d
}

// powConst computes base^exp in-circuit by square-and-multiply over the bits of exp (LSB-first
// in `bits`), with base^(2^j) precomputed as field constants. Returns a base-field element.
func powConst(f *bb.Field, base *big.Int, bits []frontend.Variable) *bb.Elem {
	one := f.Const(1)
	acc := one
	pow := new(big.Int).Set(base)
	for j := 0; j < len(bits); j++ {
		acc = f.Mul(acc, f.Select(bits[j], f.ConstBig(new(big.Int).Set(pow)), one))
		pow.Mul(pow, pow).Mod(pow, friP)
	}
	return acc
}

// foldDataExt applies the FRI inverse-NTT fold to already-reshaped points: result[i] = (1/16)·
// Σ_k data_ext[k]·ROU_REV[4]^(k·i) (the validated constant transform), then evaluates at
// mix·inv_wk with inv_wk = ROU_REV[rpo2]^group. groupLSBs are the low groupBits of the position.
func foldDataExt(f *bb.Field, dataExt []bb.E4, groupLSBs []frontend.Variable, mix bb.E4, rpo2 int) bb.E4 {
	result := make([]bb.E4, 16)
	for i := 0; i < 16; i++ {
		acc := f.E4ScalarMulConst(dataExt[0], friTwiddle[0][i])
		for k := 1; k < 16; k++ {
			acc = f.E4Add(acc, f.E4ScalarMulConst(dataExt[k], friTwiddle[k][i]))
		}
		result[i] = acc
	}
	invwk := powConst(f, rouRev[rpo2], groupLSBs)
	return PolyEval(f, result, f.E4ScalarMul(mix, invwk))
}

// FoldRound computes the FRI fold goal for one round from a column leaf. Kept for the
// standalone fold KAT; VerifyFRIQuery uses the shared helpers directly.
func FoldRound(api frontend.API, f *bb.Field, leaf []*bb.Elem, group frontend.Variable,
	groupBits int, mix bb.E4, rpo2 int) bb.E4 {
	return foldDataExt(f, reshapeLeaf(f, leaf), api.ToBinary(group, groupBits), mix, rpo2)
}

// muxE4 selects vals[index] (16 Fp4 points) where index = sum(bits[i]*2^i), via a per-limb
// binary select tree. len(vals) must equal 2^len(bits).
func muxE4(f *bb.Field, bits []frontend.Variable, vals []bb.E4) bb.E4 {
	cur := vals
	for _, b := range bits {
		next := make([]bb.E4, len(cur)/2)
		for i := range next {
			var e bb.E4
			for limb := 0; limb < 4; limb++ {
				e.C[limb] = f.Select(b, cur[2*i+1].C[limb], cur[2*i].C[limb])
			}
			next[i] = e
		}
		cur = next
	}
	return cur[0]
}

// FRI round parameters for the recursion circuit at po2=18 (orig_domain=2^20, 3 rounds):
// per round, the number of low position bits that form `group` and rpo2 = log2(16*round.domain).
var friRoundParams = [3]struct{ groupBits, rpo2 int }{{16, 20}, {12, 16}, {8, 12}}

var rouFwd8 = big.NewInt(1453957774) // ROU_FWD[8] (gen for the final-layer eval domain, size 256)

// VerifyFRIQuery verifies one FRI query end-to-end (risc0 verify/fri.rs fri_verify body): for
// each round it checks the goal against data_ext[quot] and folds to the next goal; then it
// checks the final-layer polynomial evaluated at gen^pos equals the final goal. All round
// quotients/groups and the final position derive from the 20-bit query position by bit-slicing
// (group=bits[0:groupBits], quot=bits[groupBits:groupBits+4], pos_final=bits[0:8]). goal0 is the
// DEEP value entering round 0 (produced by the DEEP-ALI layer / inner callback).
func VerifyFRIQuery(api frontend.API, f *bb.Field, pos0 frontend.Variable, goal0 bb.E4,
	leaves [3][]*bb.Elem, mixes [3]bb.E4, finalCoeffs []*bb.Elem) {

	bits := api.ToBinary(pos0, 20)
	goal := goal0
	for r := 0; r < 3; r++ {
		gb := friRoundParams[r].groupBits
		dataExt := reshapeLeaf(f, leaves[r])
		// Goal consistency: data_ext[quot] == goal (quot = bits[gb:gb+4], 4 bits => 16-way mux).
		f.E4AssertEq(muxE4(f, bits[gb:gb+4], dataExt), goal)
		// Fold to the next goal.
		goal = foldDataExt(f, dataExt, bits[:gb], mixes[r], friRoundParams[r].rpo2)
	}
	// Final-layer check: x = ROU_FWD[8]^pos_final (pos_final = group of last round = bits[0:8]);
	// reshape final_coeffs (256) into 64 Fp4; assert poly_eval(poly, lift(x)) == goal.
	xBase := powConst(f, rouFwd8, bits[:8])
	polyBuf := make([]bb.E4, 64)
	for i := 0; i < 64; i++ {
		polyBuf[i] = f.E4From(finalCoeffs[i], finalCoeffs[64+i], finalCoeffs[128+i], finalCoeffs[192+i])
	}
	xExt := f.E4From(xBase, f.Const(0), f.Const(0), f.Const(0))
	f.E4AssertEq(PolyEval(f, polyBuf, xExt), goal)
}

// PolyEval evaluates the Fp4 polynomial with the given coefficients at x:
//
//	tot = sum_i coeffs[i] * x^i
//
// matching risc0 verify/mod.rs `poly_eval` (used by FRI: the per-round fold evaluates the
// inverse-NTT'd column at round.mix·inv_wk, and the final layer evaluates the final-coeffs
// polynomial at gen^pos). Operates over the emulated BabyBear Fp4.
func PolyEval(f *bb.Field, coeffs []bb.E4, x bb.E4) bb.E4 {
	mulX := f.E4One()
	tot := f.E4Zero()
	for _, c := range coeffs {
		tot = f.E4Add(tot, f.E4Mul(c, mulX))
		mulX = f.E4Mul(mulX, x)
	}
	return tot
}
