// Package poseidon_bls implements, in-circuit over BLS12-381 Fr, the original
// Poseidon permutation (t=3, S-box x^5, 4 full / 57 partial / 4 full rounds) that the
// risc0 `poseidon_bls` hash suite uses for an identity_bls recursion seal. Because both
// sides share the canonical hadeshash constants (see consts.go), the in-circuit hashing
// matches the seal hashing byte-for-byte. Validated against the published known-answer
// vector perm([0,1,2]); see poseidon_test.go.
package poseidon_bls

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
)

var (
	roundConstants []*big.Int
	mds            []*big.Int
	parseOnce      sync.Once
)

func parseConsts() {
	parseOnce.Do(func() {
		roundConstants = make([]*big.Int, len(roundConstantsDec))
		for i, s := range roundConstantsDec {
			v, ok := new(big.Int).SetString(s, 10)
			if !ok {
				panic("poseidon_bls: bad round constant " + s)
			}
			roundConstants[i] = v
		}
		mds = make([]*big.Int, len(mdsDec))
		for i, s := range mdsDec {
			v, ok := new(big.Int).SetString(s, 10)
			if !ok {
				panic("poseidon_bls: bad mds entry " + s)
			}
			mds[i] = v
		}
	})
}

// sbox computes x^5 (4 multiplications), matching risc0 poseidon_bls/mod.rs.
func sbox(api frontend.API, x frontend.Variable) frontend.Variable {
	x2 := api.Mul(x, x)
	x4 := api.Mul(x2, x2)
	return api.Mul(x4, x)
}

func addRoundConstants(api frontend.API, state []frontend.Variable, round int) {
	for i := 0; i < Cells; i++ {
		state[i] = api.Add(state[i], roundConstants[round*Cells+i])
	}
}

// multiplyByMDS computes state <- M * state (row-major, no transpose), matching
// risc0 poseidon_bls/mod.rs `multiply_by_mds`.
func multiplyByMDS(api frontend.API, state []frontend.Variable) {
	out := make([]frontend.Variable, Cells)
	for i := 0; i < Cells; i++ {
		acc := frontend.Variable(0)
		for j := 0; j < Cells; j++ {
			acc = api.Add(acc, api.Mul(mds[i*Cells+j], state[j]))
		}
		out[i] = acc
	}
	copy(state, out)
}

// Permute applies the Poseidon permutation to a width-Cells state over the native
// (BLS12-381 Fr) field and returns the result.
func Permute(api frontend.API, in [Cells]frontend.Variable) [Cells]frontend.Variable {
	parseConsts()

	state := make([]frontend.Variable, Cells)
	for i := 0; i < Cells; i++ {
		state[i] = in[i]
	}

	round := 0
	for r := 0; r < RoundsHalfFull; r++ {
		addRoundConstants(api, state, round)
		for i := 0; i < Cells; i++ {
			state[i] = sbox(api, state[i])
		}
		multiplyByMDS(api, state)
		round++
	}
	for r := 0; r < RoundsPartial; r++ {
		addRoundConstants(api, state, round)
		state[0] = sbox(api, state[0])
		multiplyByMDS(api, state)
		round++
	}
	for r := 0; r < RoundsHalfFull; r++ {
		addRoundConstants(api, state, round)
		for i := 0; i < Cells; i++ {
			state[i] = sbox(api, state[i])
		}
		multiplyByMDS(api, state)
		round++
	}

	var out [Cells]frontend.Variable
	for i := 0; i < Cells; i++ {
		out[i] = state[i]
	}
	return out
}
