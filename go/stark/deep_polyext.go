package stark

import (
	"fmt"
	"math/big"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

// polyExtNBeta = NBETA = -11 mod p (the Fp4 reduction constant, X^4 = NBETA). Matches
// babybear.nbeta used by E4Mul; also appears as Const(2013265910) in the DEF.
var polyExtNBeta = big.NewInt(2013265910)

// fpVal is a poly_ext fp-register value with constant folding: a large part of the DEF is pure
// constant arithmetic (the circuit's structural constants), which we fold in Go rather than emit
// as Fp4 constraints. This both (a) avoids gnark's emulated-field "reduce a constant with overflow
// flag" failure that arises when constant×constant chains are built symbolically, and (b) cuts the
// constraint count dramatically. A value is either a reduced constant `k` or a circuit value `v`.
type fpVal struct {
	isConst bool
	k       [4]*big.Int
	v       bb.E4
}

// mixVal mirrors adapter::MixState { tot, mul }, each constant-folded.
type mixVal struct{ tot, mul fpVal }

func konst(c [4]*big.Int) fpVal { return fpVal{isConst: true, k: c} }

func kmod(x *big.Int) *big.Int { return new(big.Int).Mod(x, friP) }

func kAdd(a, b [4]*big.Int) [4]*big.Int {
	var c [4]*big.Int
	for i := 0; i < 4; i++ {
		c[i] = kmod(new(big.Int).Add(a[i], b[i]))
	}
	return c
}

func kSub(a, b [4]*big.Int) [4]*big.Int {
	var c [4]*big.Int
	for i := 0; i < 4; i++ {
		c[i] = kmod(new(big.Int).Sub(a[i], b[i]))
	}
	return c
}

// kMul is the Fp4 product over F_p[X]/(X^4+11), identical to babybear.E4Mul (NBETA = -11):
//
//	c0 = a0b0 + N(a1b3+a2b2+a3b1)   c1 = a0b1+a1b0 + N(a2b3+a3b2)
//	c2 = a0b2+a1b1+a2b0 + N(a3b3)   c3 = a0b3+a1b2+a2b1+a3b0
func kMul(a, b [4]*big.Int) [4]*big.Int {
	m := func(x, y *big.Int) *big.Int { return new(big.Int).Mul(x, y) }
	add := func(xs ...*big.Int) *big.Int {
		acc := new(big.Int)
		for _, x := range xs {
			acc.Add(acc, x)
		}
		return acc
	}
	N := func(x *big.Int) *big.Int { return new(big.Int).Mul(x, polyExtNBeta) }
	c0 := add(m(a[0], b[0]), N(add(m(a[1], b[3]), m(a[2], b[2]), m(a[3], b[1]))))
	c1 := add(m(a[0], b[1]), m(a[1], b[0]), N(add(m(a[2], b[3]), m(a[3], b[2]))))
	c2 := add(m(a[0], b[2]), m(a[1], b[1]), m(a[2], b[0]), N(m(a[3], b[3])))
	c3 := add(m(a[0], b[3]), m(a[1], b[2]), m(a[2], b[1]), m(a[3], b[0]))
	return [4]*big.Int{kmod(c0), kmod(c1), kmod(c2), kmod(c3)}
}

// PolyExt evaluates the DEEP-ALI validity step program (risc0 adapter::PolyExtStepDef::step) over
// the emulated Fp4, with Go-side constant folding. It maintains two register banks (fp values and
// mix states) growing in block order, and returns mix[ret].tot = the mixed constraint polynomial
// `result`. mix = poly_mix; evalU = eval_u (len tap_size); args = [globalsOut(32), accumMix(20)]
// for GetGlobal(base, off).
func PolyExt(f *bb.Field, polyMix bb.E4, evalU []bb.E4, globalsOut, accumMix []*bb.Elem) bb.E4 {
	zero, one := big.NewInt(0), big.NewInt(1)
	lift := func(x fpVal) bb.E4 {
		if !x.isConst {
			return x.v
		}
		return f.E4From(f.ConstBig(x.k[0]), f.ConstBig(x.k[1]), f.ConstBig(x.k[2]), f.ConstBig(x.k[3]))
	}
	fpAdd := func(a, b fpVal) fpVal {
		if a.isConst && b.isConst {
			return konst(kAdd(a.k, b.k))
		}
		return fpVal{v: f.E4Add(lift(a), lift(b))}
	}
	fpSub := func(a, b fpVal) fpVal {
		if a.isConst && b.isConst {
			return konst(kSub(a.k, b.k))
		}
		return fpVal{v: f.E4Sub(lift(a), lift(b))}
	}
	fpMul := func(a, b fpVal) fpVal {
		if a.isConst && b.isConst {
			return konst(kMul(a.k, b.k))
		}
		return fpVal{v: f.E4Mul(lift(a), lift(b))}
	}

	polyMixVal := fpVal{v: polyMix}
	bigOf := func(x int) *big.Int { return big.NewInt(int64(x)) }
	args := [2][]*bb.Elem{globalsOut, accumMix}
	baseVar := func(e *bb.Elem) fpVal { return fpVal{v: f.E4From(e, f.Const(0), f.Const(0), f.Const(0))} }

	fp := make([]fpVal, 0, len(polyExtDef.Block))
	mix := make([]mixVal, 0, polyExtDef.Ret+1)

	for _, st := range polyExtDef.Block {
		switch st[0] {
		case 0: // Const(x)
			fp = append(fp, konst([4]*big.Int{bigOf(st[1]), zero, zero, zero}))
		case 1: // ConstExt(a,b,c,d)
			fp = append(fp, konst([4]*big.Int{bigOf(st[1]), bigOf(st[2]), bigOf(st[3]), bigOf(st[4])}))
		case 2: // Get(tap) - eval_u variable
			fp = append(fp, fpVal{v: evalU[st[1]]})
		case 3: // GetGlobal(base, off) - globals/mix variable
			fp = append(fp, baseVar(args[st[1]][st[2]]))
		case 4: // Add
			fp = append(fp, fpAdd(fp[st[1]], fp[st[2]]))
		case 5: // Sub
			fp = append(fp, fpSub(fp[st[1]], fp[st[2]]))
		case 6: // Mul
			fp = append(fp, fpMul(fp[st[1]], fp[st[2]]))
		case 7: // True
			mix = append(mix, mixVal{
				tot: konst([4]*big.Int{zero, zero, zero, zero}),
				mul: konst([4]*big.Int{one, zero, zero, zero}),
			})
		case 8: // AndEqz(chain, inner): tot += mul·inner; mul *= poly_mix
			ch := mix[st[1]]
			mix = append(mix, mixVal{
				tot: fpAdd(ch.tot, fpMul(ch.mul, fp[st[2]])),
				mul: fpMul(ch.mul, polyMixVal),
			})
		case 9: // AndCond(chain, cond, inner): tot += cond·inner.tot·mul; mul *= inner.mul
			ch := mix[st[1]]
			inner := mix[st[3]]
			mix = append(mix, mixVal{
				tot: fpAdd(ch.tot, fpMul(fpMul(fp[st[2]], inner.tot), ch.mul)),
				mul: fpMul(ch.mul, inner.mul),
			})
		default:
			panic("deep: unknown poly_ext opcode")
		}
	}
	// Mirror the Rust executor's bank-size invariants (adapter.rs:203-212): a mis-extracted table
	// would fail here with a clear message rather than silently mis-evaluating.
	if len(fp) != len(polyExtDef.Block)-(polyExtDef.Ret+1) || len(mix) != polyExtDef.Ret+1 {
		panic(fmt.Sprintf("deep: poly_ext bank sizes wrong (fp=%d mix=%d ret=%d block=%d)",
			len(fp), len(mix), polyExtDef.Ret, len(polyExtDef.Block)))
	}
	return lift(mix[polyExtDef.Ret].tot)
}
