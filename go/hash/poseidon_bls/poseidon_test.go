package poseidon_bls

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type permCircuit struct {
	In  [Cells]frontend.Variable
	Out [Cells]frontend.Variable
}

func (c *permCircuit) Define(api frontend.API) error {
	got := Permute(api, c.In)
	for i := 0; i < Cells; i++ {
		api.AssertIsEqual(got[i], c.Out[i])
	}
	return nil
}

// TestPoseidonBlsGoldenVector checks the in-circuit permutation against the canonical
// IAIK hadeshash known-answer vector for poseidonperm_x5_255_3 (BLS12-381 Fr, t=3,
// alpha=5, M=128): perm([0,1,2]). This is the same vector the risc0 poseidon_bls Rust
// suite is tested against, so it anchors cross-language (seal <-> circuit) agreement.
func TestPoseidonBlsGoldenVector(t *testing.T) {
	assignment := &permCircuit{
		In: [Cells]frontend.Variable{0, 1, 2},
		Out: [Cells]frontend.Variable{
			"18456658763349757341014058622209659766100673761449600566550821987295786346378",
			"37068251774887509885063625701815026138353041152735229476479055620962268601796",
			"26763157702141528937904191329664859174584798817251788852101947537759678822298",
		},
	}
	if err := test.IsSolved(&permCircuit{}, assignment, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

// TestPoseidonRejectsWrongOutput is the single-mutation negative test: a
// wrong permutation output must be unsatisfiable, proving the output is actually constrained.
func TestPoseidonRejectsWrongOutput(t *testing.T) {
	bad := &permCircuit{
		In: [3]frontend.Variable{0, 1, 2},
		Out: [3]frontend.Variable{
			"0", // wrong: real is 18456658763349757341014058622209659766100673761449600566550821987295786346378
			"37068251774887509885063625701815026138353041152735229476479055620962268601796",
			"26763157702141528937904191329664859174584798817251788852101947537759678822298",
		},
	}
	if err := test.IsSolved(&permCircuit{}, bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong permutation output to be rejected")
	}
}

// TestPoseidonBlsMultiVector checks several additional inputs (incl. all-zeros and
// near-modulus edge cases) against the validated reference permutation, so a bug that
// happens to pass on [0,1,2] cannot survive.
func TestPoseidonBlsMultiVector(t *testing.T) {
	cases := []permCircuit{
		{In: [3]frontend.Variable{3, 1, 4}, Out: [3]frontend.Variable{
			"9673454533682772297625899646555260033741930263956304302904715970508048037267",
			"34842430386234139330548059343590671464734410364725015459976069606152731953750",
			"33845987520971510018634634988098301761523723895980883004022507718903969047700"}},
		{In: [3]frontend.Variable{0, 0, 0}, Out: [3]frontend.Variable{
			"39704413365395714732902920194612999065094381874203236779011164022408220537174",
			"7537180076518580051102512563888216212546078608480875576648073859804775902526",
			"29087945486755729827910435868127502118760962294783613045651279896888776139498"}},
		{In: [3]frontend.Variable{123456789, 987654321, 555}, Out: [3]frontend.Variable{
			"5644278445372796754411468722010627791465837925577347326750885883536638822265",
			"44658101140488474795237661449981834618174699271447408171753587179667765397774",
			"6490120028907166936096109575444751532923271490764233500789751947245838574272"}},
		{In: [3]frontend.Variable{
			"52435875175126190479447740508185965837690552500527637822603658699938581184512",
			"52435875175126190479447740508185965837690552500527637822603658699938581184511",
			"52435875175126190479447740508185965837690552500527637822603658699938581184510"},
			Out: [3]frontend.Variable{
				"14681712658820858907945861167857863651687351617225345403341763718879327792223",
				"23641702110595734896676819945020732507964058186020685034074384760301449043371",
				"36308696240926411152546400902635408362979211654268338224821554667660651626752"}},
	}
	for i := range cases {
		c := cases[i]
		if err := test.IsSolved(&permCircuit{}, &c, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}
