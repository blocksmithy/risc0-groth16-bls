package poseidon_bls

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// BabyBear modulus p = 0x78000001 = 15·2²⁷ + 1, the trace field whose elements the transcript
// squeezes. Source: risc0 v3.0.5@8eb06ab0, risc0/core/src/field/baby_bear.rs (const P).
// Checked by `make verify-constants` (against the same source and the 15·2²⁷+1 identity).
var babyBearModulus = big.NewInt(2013265921)

// pow2ModP[i] = 2^i mod p (BabyBear), for i in [0,160), used by RandomElem.
var (
	pow2ModP     [160]*big.Int
	pow2ModPOnce sync.Once
)

func initPow2() {
	pow2ModPOnce.Do(func() {
		v := big.NewInt(1)
		for i := 0; i < 160; i++ {
			pow2ModP[i] = new(big.Int).Set(v)
			v = new(big.Int).Lsh(v, 1)
			v.Mod(v, babyBearModulus)
		}
	})
}

// divmodHint returns (q, r) with inputs[0] = q*inputs[1] + r, 0 <= r < inputs[1].
func divmodHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].DivMod(inputs[0], inputs[1], outputs[1])
	return nil
}

func init() { solver.RegisterHint(divmodHint) }

// Sponge is the poseidon_bls Fiat-Shamir transcript (risc0 ReadIOP Rng), a t=3 Poseidon
// sponge over BLS12-381 Fr. State is zero-initialized; cells[0] is capacity, cells[1..2]
// are rate. Mirrors risc0 poseidon_bls/mod.rs PoseidonBlsRng exactly.
type Sponge struct {
	cells [Cells]frontend.Variable
}

// NewSponge returns a fresh zero-initialized transcript.
func NewSponge() *Sponge {
	return &Sponge{cells: [Cells]frontend.Variable{0, 0, 0}}
}

func (s *Sponge) permute(api frontend.API) {
	s.cells = Permute(api, s.cells)
}

// Mix absorbs a digest (already represented as a native BLS-Fr field element) by adding it
// into cells[1] then permuting. Mirrors `mix`: cells[1] += digest_to_fr(d); poseidon_mix.
func (s *Sponge) Mix(api frontend.API, digest frontend.Variable) {
	s.cells[1] = api.Add(s.cells[1], digest)
	s.permute(api)
}

// RandomBits squeezes the low `n` bits of cells[2] (read before permuting) as a native
// integer in [0, 2^n). Mirrors `random_bits`.
func (s *Sponge) RandomBits(api frontend.API, n int) frontend.Variable {
	source := s.cells[2]
	s.permute(api)
	bits := api.ToBinary(source)
	return api.FromBinary(bits[:n]...)
}

// RandomElem squeezes a BabyBear field element from the low 160 bits of cells[2], computed
// as (sum_{i<160} bit_i * 2^i) mod p. Returned as a native Variable in [0, p). Mirrors
// `random_elem`.
func (s *Sponge) RandomElem(api frontend.API) frontend.Variable {
	initPow2()
	source := s.cells[2]
	s.permute(api)
	bits := api.ToBinary(source)

	// Accumulate the 160-bit weighted sum natively (< 160*p < 2^39).
	sum := frontend.Variable(0)
	for i := 0; i < 160; i++ {
		sum = api.Add(sum, api.Mul(bits[i], pow2ModP[i]))
	}

	// Reduce sum mod p via a divmod hint, constrained.
	out, err := api.Compiler().NewHint(divmodHint, 2, sum, babyBearModulus)
	if err != nil {
		panic(err)
	}
	q, r := out[0], out[1]
	api.AssertIsEqual(sum, api.Add(api.Mul(q, babyBearModulus), r))
	// r in [0, p): r <= p-1.
	api.AssertIsLessOrEqual(r, new(big.Int).Sub(babyBearModulus, big.NewInt(1)))
	// q small: at most ceil(160*(p-1)/p) < 160 < 256.
	api.AssertIsLessOrEqual(q, big.NewInt(255))
	return r
}

// RandomExtElem squeezes an Fp4 element (4 consecutive RandomElem draws). Mirrors
// `random_ext_elem`. Returned as four native BabyBear Variables (subelems c0..c3).
func (s *Sponge) RandomExtElem(api frontend.API) [4]frontend.Variable {
	var out [4]frontend.Variable
	for i := 0; i < 4; i++ {
		out[i] = s.RandomElem(api)
	}
	return out
}

// HashPair compresses two field elements: cells = [0, a, b]; permute; out = cells[0].
// Mirrors `hash_pair`. Stateless (does not affect the transcript).
func HashPair(api frontend.API, a, b frontend.Variable) frontend.Variable {
	st := [Cells]frontend.Variable{0, a, b}
	st = Permute(api, st)
	return st[0]
}

// HashElemSlice hashes a slice of BabyBear elements (each given as a native Variable holding
// its integer value in [0,p)) via the unpadded sponge: it packs 8 elements per rate cell in
// base p (filling cells[1] then cells[2]); once 16 elements (idx==3) are absorbed it permutes
// and zeroes the rate cells; a final partial block is permuted. Returns cells[0]. Mirrors
// risc0 poseidon_bls/mod.rs `unpadded_hash`. Stateless.
func HashElemSlice(api frontend.API, elems []frontend.Variable) frontend.Variable {
	p := babyBearModulus
	cells := [Cells]frontend.Variable{0, 0, 0}
	mul := frontend.Variable(1)
	idx := 1
	count := 0
	for _, val := range elems {
		cells[idx] = api.Add(cells[idx], api.Mul(mul, val))
		mul = api.Mul(mul, p)
		count++
		if count == 8 {
			mul = 1
			count = 0
			idx++
		}
		if idx == 3 {
			cells = Permute(api, cells)
			cells[1] = 0
			cells[2] = 0
			idx = 1
		}
	}
	if idx != 1 || count != 0 {
		cells = Permute(api, cells)
	}
	return cells[0]
}
