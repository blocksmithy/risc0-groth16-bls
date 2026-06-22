package poseidon_bls

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// spongeSeqCircuit reproduces a fixed sponge sequence:
// fresh sponge -> Mix(7) -> RandomElem, RandomElem, RandomBits(20), RandomExtElem.
type spongeSeqCircuit struct {
	Elem0 frontend.Variable
	Elem1 frontend.Variable
	Bits  frontend.Variable
	Ext   [4]frontend.Variable
}

func (c *spongeSeqCircuit) Define(api frontend.API) error {
	s := NewSponge()
	s.Mix(api, 7)
	api.AssertIsEqual(s.RandomElem(api), c.Elem0)
	api.AssertIsEqual(s.RandomElem(api), c.Elem1)
	api.AssertIsEqual(s.RandomBits(api, 20), c.Bits)
	ext := s.RandomExtElem(api)
	for i := 0; i < 4; i++ {
		api.AssertIsEqual(ext[i], c.Ext[i])
	}
	return nil
}

// TestSpongeSequence validates Mix + permute + RandomElem/RandomBits/RandomExtElem. The expected
// values cross-check with the Rust `poseidon_bls_hash_and_rng_kat`, but that KAT is mutually
// anchored with this Go port (not independent); the GENUINE non-circular anchor is
// stark.TestSealDriveReal, which recomputes this exact sponge over the real seal and matches all
// 76 of RISC0's actual transcript challenges (TR_* trace). A bug here would diverge there.
func TestSpongeSequence(t *testing.T) {
	assignment := &spongeSeqCircuit{
		Elem0: 1300068026,
		Elem1: 184628157,
		Bits:  952557,
		Ext:   [4]frontend.Variable{841616115, 60504970, 1475700026, 713203128},
	}
	if err := test.IsSolved(&spongeSeqCircuit{}, assignment, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

// TestSpongeRejectsWrongElem is the single-mutation negative test: a wrong
// drawn challenge must be unsatisfiable, proving the transcript output is constrained.
func TestSpongeRejectsWrongElem(t *testing.T) {
	bad := &spongeSeqCircuit{
		Elem0: 1300068027, // wrong: real is 1300068026
		Elem1: 184628157,
		Bits:  952557,
		Ext:   [4]frontend.Variable{841616115, 60504970, 1475700026, 713203128},
	}
	if err := test.IsSolved(&spongeSeqCircuit{}, bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong RandomElem to be rejected")
	}
}

// hashPairCircuit checks HashPair(7,9) == Permute([0,7,9])[0]. The expected value is the
// hadeshash-golden-vector-anchored permutation output (TestPoseidonBlsGoldenVector); HashPair's
// [0,a,b] convention is exercised non-circularly end-to-end by the real Merkle openings
// (stark.TestMerkleVerifyRealOpening / TestMerkleRootRealOpening, which fold via HashPair).
type hashPairCircuit struct {
	Exp frontend.Variable
}

func (c *hashPairCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(HashPair(api, 7, 9), c.Exp)
	return nil
}

// hashPair79Dec = Permute([0,7,9])[0] (the poseidon_bls hash_pair(Digest(7),Digest(9)) digest, LE).
const hashPair79Dec = "22542640253640812129716150660900105707981157064818525686169698091415696306508"

func TestHashPair(t *testing.T) {
	// Permute([0,7,9])[0] as a decimal field element, from the golden-vector-anchored permutation.
	assignment := &hashPairCircuit{Exp: hashPair79Dec}
	if err := test.IsSolved(&hashPairCircuit{}, assignment, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

// TestHashPairRejectsWrong is the single-mutation negative test: a wrong expected
// digest must be unsatisfiable, proving HashPair's output is constrained.
func TestHashPairRejectsWrong(t *testing.T) {
	bad := &hashPairCircuit{Exp: "0"}
	if err := test.IsSolved(&hashPairCircuit{}, bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong HashPair digest to be rejected")
	}
}
