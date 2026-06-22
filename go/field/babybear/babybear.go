// Package babybear implements, in-circuit over BLS12-381 Fr, the RISC0 trace field
// BabyBear (p = 0x78000001) and its degree-4 extension Fp4 = F_p[X]/(X^4 + 11), used by
// the STARK verifier's FRI and DEEP-ALI layers. BabyBear elements use gnark's emulated
// field with the small-field optimization (modBits=31 < nativeBits-2), which auto-activates
// for emparams.BabyBear inside BLS12-381 Fr (~3 R1CS per mul).
//
// The Fp4 multiply mirrors risc0 core/src/field/baby_bear.rs:762-766 exactly.
package babybear

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// Base is the BabyBear base field (emparams.BabyBear has Modulus 0x78000001).
type Base = emparams.BabyBear

// Elem is a single emulated BabyBear element.
type Elem = emulated.Element[Base]

// Beta is the Fp4 irreducible-polynomial constant: Fp4 = F_p[X]/(X^4 + Beta), Beta = 11.
const Beta = 11

// nbeta = p - Beta = -Beta mod p (the value of X^4 in the reduction).
var nbeta = new(big.Int).Sub(modulus(), big.NewInt(Beta))

func modulus() *big.Int { return Base{}.Modulus() }

// E4 is an Fp4 element a0 + a1*X + a2*X^2 + a3*X^3.
type E4 struct {
	C [4]*Elem
}

// Field bundles the emulated base field and provides BabyBear + Fp4 operations.
type Field struct {
	api frontend.API
	f   *emulated.Field[Base]
}

// NewField constructs the BabyBear/Fp4 chip over the given gnark API.
func NewField(api frontend.API) (*Field, error) {
	f, err := emulated.NewField[Base](api)
	if err != nil {
		return nil, err
	}
	return &Field{api: api, f: f}, nil
}

// --- base field ---

func (e *Field) Add(a, b *Elem) *Elem   { return e.f.Add(a, b) }
func (e *Field) Sub(a, b *Elem) *Elem   { return e.f.Sub(a, b) }
func (e *Field) Mul(a, b *Elem) *Elem   { return e.f.Mul(a, b) }
func (e *Field) Const(v uint64) *Elem   { x := emulated.ValueOf[Base](v); return &x }
func (e *Field) AssertEq(a, b *Elem)    { e.f.AssertIsEqual(a, b) }
func (e *Field) MulConst(a *Elem, c *big.Int) *Elem {
	return e.f.MulConst(a, c)
}

// --- Fp4 ---

// E4From builds an Fp4 element from four base elements.
func (e *Field) E4From(a0, a1, a2, a3 *Elem) E4 {
	return E4{C: [4]*Elem{a0, a1, a2, a3}}
}

func (e *Field) E4Add(a, b E4) E4 {
	return E4{C: [4]*Elem{
		e.f.Add(a.C[0], b.C[0]),
		e.f.Add(a.C[1], b.C[1]),
		e.f.Add(a.C[2], b.C[2]),
		e.f.Add(a.C[3], b.C[3]),
	}}
}

func (e *Field) E4Sub(a, b E4) E4 {
	return E4{C: [4]*Elem{
		e.f.Sub(a.C[0], b.C[0]),
		e.f.Sub(a.C[1], b.C[1]),
		e.f.Sub(a.C[2], b.C[2]),
		e.f.Sub(a.C[3], b.C[3]),
	}}
}

// nb multiplies by NBETA = -11 mod p.
func (e *Field) nb(x *Elem) *Elem { return e.f.MulConst(x, nbeta) }

// E4Mul mirrors risc0 baby_bear.rs:762-766:
//
//	c0 = a0*b0 + NBETA*(a1*b3 + a2*b2 + a3*b1)
//	c1 = a0*b1 + a1*b0 + NBETA*(a2*b3 + a3*b2)
//	c2 = a0*b2 + a1*b1 + a2*b0 + NBETA*(a3*b3)
//	c3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
func (e *Field) E4Mul(a, b E4) E4 {
	f := e.f
	m := func(x, y *Elem) *Elem { return f.Mul(x, y) }
	add := func(xs ...*Elem) *Elem {
		acc := xs[0]
		for _, x := range xs[1:] {
			acc = f.Add(acc, x)
		}
		return acc
	}
	a0, a1, a2, a3 := a.C[0], a.C[1], a.C[2], a.C[3]
	b0, b1, b2, b3 := b.C[0], b.C[1], b.C[2], b.C[3]

	c0 := add(m(a0, b0), e.nb(add(m(a1, b3), m(a2, b2), m(a3, b1))))
	c1 := add(m(a0, b1), m(a1, b0), e.nb(add(m(a2, b3), m(a3, b2))))
	c2 := add(m(a0, b2), m(a1, b1), m(a2, b0), e.nb(m(a3, b3)))
	c3 := add(m(a0, b3), m(a1, b2), m(a2, b1), m(a3, b0))
	return E4{C: [4]*Elem{c0, c1, c2, c3}}
}

func (e *Field) E4AssertEq(a, b E4) {
	for i := 0; i < 4; i++ {
		e.f.AssertIsEqual(a.C[i], b.C[i])
	}
}

// ConstBig returns an emulated BabyBear constant.
func (e *Field) ConstBig(c *big.Int) *Elem {
	x := emulated.ValueOf[Base](c)
	return &x
}

// Select returns x if b==1 else y (base field).
func (e *Field) Select(b frontend.Variable, x, y *Elem) *Elem {
	return e.f.Select(b, x, y)
}

// E4ScalarMulConst scales every Fp4 limb by a base-field constant.
func (e *Field) E4ScalarMulConst(a E4, c *big.Int) E4 {
	return E4{C: [4]*Elem{
		e.f.MulConst(a.C[0], c), e.f.MulConst(a.C[1], c),
		e.f.MulConst(a.C[2], c), e.f.MulConst(a.C[3], c),
	}}
}

// E4ScalarMul scales every Fp4 limb by a base-field element.
func (e *Field) E4ScalarMul(a E4, s *Elem) E4 {
	return E4{C: [4]*Elem{
		e.f.Mul(a.C[0], s), e.f.Mul(a.C[1], s),
		e.f.Mul(a.C[2], s), e.f.Mul(a.C[3], s),
	}}
}

func (e *Field) E4One() E4 {
	return e.E4From(e.Const(1), e.Const(0), e.Const(0), e.Const(0))
}

func (e *Field) E4Zero() E4 {
	return e.E4From(e.Const(0), e.Const(0), e.Const(0), e.Const(0))
}

// fp4InvHint computes the Fp4 inverse off-circuit (ported from risc0 baby_bear.rs:460-492).
// Correctness is enforced in-circuit by the a*inv==1 constraint in E4Inv, so the hint need
// only produce a candidate; an incorrect candidate makes the circuit unsatisfiable.
func fp4InvHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(p *big.Int, in []*big.Int, out []*big.Int) error {
			beta := big.NewInt(Beta)
			a0, a1, a2, a3 := in[0], in[1], in[2], in[3]
			mul := func(x, y *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(x, y), p) }
			add := func(x, y *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(x, y), p) }
			sub := func(x, y *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(x, y), p) }
			dbl := func(x *big.Int) *big.Int { return add(x, x) }

			// b0 = a0^2 + BETA*(a1*(a3+a3) - a2^2)
			b0 := add(mul(a0, a0), mul(beta, sub(mul(a1, dbl(a3)), mul(a2, a2))))
			// b2 = a0*(a2+a2) - a1^2 + BETA*a3^2
			b2 := add(sub(mul(a0, dbl(a2)), mul(a1, a1)), mul(beta, mul(a3, a3)))
			// c = b0^2 + BETA*b2^2
			c := add(mul(b0, b0), mul(beta, mul(b2, b2)))
			ic := new(big.Int).ModInverse(c, p)
			if ic == nil {
				// c == 0 only if a == 0; produce 0 (circuit's a*inv==1 will then reject).
				ic = big.NewInt(0)
			}
			b0 = mul(b0, ic)
			b2 = mul(b2, ic)
			// out = a' * b' * inv(c), with NBETA = -BETA mod p.
			out[0].Set(add(mul(a0, b0), mul(beta, mul(a2, b2))))
			out[1].Set(add(mul(sub(big.NewInt(0), a1), b0), mul(sub(p, beta), mul(a3, b2))))
			out[2].Set(add(mul(sub(big.NewInt(0), a0), b2), mul(a2, b0)))
			out[3].Set(sub(mul(a1, b2), mul(a3, b0)))
			return nil
		})
}

func init() { solver.RegisterHint(fp4InvHint) }

// E4Inv returns a^{-1} in Fp4, computed by hint and enforced by a*inv == 1. Requires a != 0
// (a == 0 yields an unsatisfiable constraint). Matches risc0 ExtElem::inv on nonzero inputs.
func (e *Field) E4Inv(a E4) E4 {
	outs, err := e.f.NewHint(fp4InvHint, 4, a.C[0], a.C[1], a.C[2], a.C[3])
	if err != nil {
		panic(err)
	}
	inv := E4{C: [4]*Elem{outs[0], outs[1], outs[2], outs[3]}}
	e.E4AssertEq(e.E4Mul(a, inv), e.E4One())
	return inv
}

// AssertCanonical enforces that a native Variable holds a canonical BabyBear element in
// [0, p), matching the validity check the RISC0 verifier applies to every field element it
// reads from the seal (read_field_elem_slice). It range-checks v < 2^31 and v <= p-1 via two
// explicit 31-bit decompositions (the second of p-1-v proves non-negativity, i.e. v <= p-1).
// Rejects the gap region [p, 2^31) and everything >= 2^31. (plan ReduceStrict / validBabyBear.)
func (e *Field) AssertCanonical(v frontend.Variable) {
	e.api.ToBinary(v, 31) // 0 <= v < 2^31
	pm1 := new(big.Int).Sub(modulus(), big.NewInt(1))
	e.api.ToBinary(e.api.Sub(pm1, v), 31) // 0 <= p-1-v < 2^31  =>  v <= p-1
}

// IngestElem brings an off-circuit-parsed seal field element into the circuit as a TRUSTED
// canonical BabyBear value available in BOTH representations from a single source wire. `v` is the
// native BLS-Fr variable the seal parser produced (used by poseidon/Merkle/transcript). IngestElem:
//
//   - range-checks v in [0, p) — the canonicality the RISC0 verifier applies to every element it
//     reads (read_field_elem_slice); this is the F1 obligation, and
//   - derives the emulated Element from the SAME 31-bit decomposition of v, so the emulated value
//     (used by Fp4/FRI/DEEP) and the native v provably encode the identical integer — the F2
//     native↔emulated binding, enforced structurally (there is no second witness that could
//     diverge), not by a separate equality assertion.
//
// It returns the unchanged native v and the bound emulated element. The driver calls this once per
// seal field element and feeds v to the native side and the element to the emulated side.
func (e *Field) IngestElem(v frontend.Variable) (frontend.Variable, *Elem) {
	bits := e.api.ToBinary(v, 31) // 0 <= v < 2^31, each bit boolean
	pm1 := new(big.Int).Sub(modulus(), big.NewInt(1))
	e.api.ToBinary(e.api.Sub(pm1, v), 31) // 0 <= p-1-v < 2^31  =>  v <= p-1 (canonical, F1)
	return v, e.f.FromBits(bits...)        // emulated value == v, from the same wire (F2)
}

// AssertElemEq asserts two emulated BabyBear elements are equal (thin wrapper used by ingest tests
// and the driver to bind a derived element to an expected value).
func (e *Field) AssertElemEq(a, b *Elem) { e.f.AssertIsEqual(a, b) }

// FromCanonicalNative converts a native value that is ALREADY proven canonical (`v < p`) into the
// emulated representation, via a single 31-bit decomposition (the F2 native↔emulated binding) and
// WITHOUT re-checking canonicality. Use this only for values whose `v < p` is already constrained
// elsewhere — e.g. sponge `RandomElem` outputs, which the divmod binding pins to `r ≤ p-1`. For
// untrusted seal-read elements use IngestElem (which also performs the F1 canonicality check).
func (e *Field) FromCanonicalNative(v frontend.Variable) *Elem {
	return e.f.FromBits(e.api.ToBinary(v, 31)...)
}
