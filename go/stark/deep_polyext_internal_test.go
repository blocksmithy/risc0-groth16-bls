package stark

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

// b4 builds an [4]*big.Int from uint64s.
func b4(xs ...uint64) [4]*big.Int {
	var out [4]*big.Int
	for i := 0; i < 4; i++ {
		out[i] = new(big.Int).SetUint64(xs[i])
	}
	return out
}

func eqB4(t *testing.T, name string, got, want [4]*big.Int) {
	t.Helper()
	for i := 0; i < 4; i++ {
		if got[i].Cmp(want[i]) != 0 {
			t.Fatalf("%s limb %d: got %s want %s", name, i, got[i], want[i])
		}
	}
}

// TestKMulAgainstRisc0 checks the constant-folding Fp4 arithmetic (kMul/kAdd/kSub used by PolyExt)
// against fixed vectors computed over the public field F_p[X]/(X^4+11) (the same vectors as
// babybear.TestFp4OpsAgainstRisc0; F_p[X]/(X^4+11) is the documented risc0 ExtElem). These are not
// produced by the code under test; their true RISC0-execution anchor is the real-seal FRI/poly_ext
// tests. The independent ground truth for the folding path is TestKMulMatchesE4Mul (24-point
// differential vs the validated circuit E4Mul) - a folding bug (wrong NBETA sign, missing
// reduction) would diverge there even on products the single seal does not exercise.
func TestKMulAgainstRisc0(t *testing.T) {
	// [100,200,300,400] · [5,6,7,8]
	eqB4(t, "mul0", kMul(b4(100, 200, 300, 400), b4(5, 6, 7, 8)),
		b4(2013199321, 2013210321, 2013234121, 6000))
	// [p-1,1,0,7] · [11,22,33,44]  (wrap-around case)
	eqB4(t, "mul1", kMul(b4(2013265920, 1, 0, 7), b4(11, 22, 33, 44)),
		b4(2013263732, 2013263369, 2013262522, 66))
	// add / sub against the same authoritative vectors
	eqB4(t, "add0", kAdd(b4(100, 200, 300, 400), b4(5, 6, 7, 8)), b4(105, 206, 307, 408))
	eqB4(t, "sub1", kSub(b4(2013265920, 1, 0, 7), b4(11, 22, 33, 44)),
		b4(2013265909, 2013265900, 2013265888, 2013265884))
}

type kmulDiffCircuit struct {
	A, B, Expected [4]emulated.Element[bb.Base]
}

func (c *kmulDiffCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	e := func(v *[4]emulated.Element[bb.Base]) bb.E4 {
		return bb.E4{C: [4]*bb.Elem{&v[0], &v[1], &v[2], &v[3]}}
	}
	f.E4AssertEq(f.E4Mul(e(&c.A), e(&c.B)), e(&c.Expected))
	return nil
}

// TestKMulMatchesE4Mul is the differential between the Go constant-folding multiply (kMul) and the
// in-circuit E4Mul (which is independently validated against RISC0 in babybear.TestFp4OpsAgainstRisc0).
// For many seeded-random Fp4 pairs, the circuit asserts E4Mul(a,b) == kMul(a,b); any divergence makes
// the witness unsatisfiable. This proves the folding path is equivalent to the circuit path on a wide
// input range, not just the single seal. Deterministic (fixed seed).
func TestKMulMatchesE4Mul(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5713e7))
	p := big.NewInt(2013265921)
	randElem := func() uint64 { return rng.Uint64() % p.Uint64() }

	for iter := 0; iter < 24; iter++ {
		a := b4(randElem(), randElem(), randElem(), randElem())
		b := b4(randElem(), randElem(), randElem(), randElem())
		exp := kMul(a, b) // value under test; E4Mul (the oracle) must reproduce it

		var c kmulDiffCircuit
		for i := 0; i < 4; i++ {
			c.A[i] = emulated.ValueOf[bb.Base](a[i])
			c.B[i] = emulated.ValueOf[bb.Base](b[i])
			c.Expected[i] = emulated.ValueOf[bb.Base](exp[i])
		}
		if err := test.IsSolved(&kmulDiffCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("iter %d: kMul disagrees with E4Mul: %v", iter, err)
		}
	}
}

// TestKMulNeg confirms the differential is not vacuous: a deliberately wrong kMul output must be
// rejected by E4Mul (so TestKMulMatchesE4Mul could actually fail on a real folding bug).
func TestKMulNeg(t *testing.T) {
	a := b4(100, 200, 300, 400)
	b := b4(5, 6, 7, 8)
	exp := kMul(a, b)
	exp[0] = new(big.Int).Add(exp[0], big.NewInt(1)) // corrupt one limb

	var c kmulDiffCircuit
	for i := 0; i < 4; i++ {
		c.A[i] = emulated.ValueOf[bb.Base](a[i])
		c.B[i] = emulated.ValueOf[bb.Base](b[i])
		c.Expected[i] = emulated.ValueOf[bb.Base](exp[i])
	}
	if err := test.IsSolved(&kmulDiffCircuit{}, &c, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected corrupted kMul output to be rejected by E4Mul")
	}
}
