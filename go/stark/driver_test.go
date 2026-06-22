package stark

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

type validityDriverCircuit struct {
	Globals  [33]frontend.Variable
	CodeTop  [32]frontend.Variable
	DataTop  [32]frontend.Variable
	AccumTop [32]frontend.Variable
	CheckTop [32]frontend.Variable
	UCoeffs  [2636]frontend.Variable
}

func (c *validityDriverCircuit) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	w := &SealPrefixVars{
		Globals:  c.Globals[:],
		CodeTop:  c.CodeTop[:],
		DataTop:  c.DataTop[:],
		AccumTop: c.AccumTop[:],
		CheckTop: c.CheckTop[:],
		UCoeffs:  c.UCoeffs[:],
	}
	VerifyValidity(api, f, w)
	return nil
}

func loadValidityWitness(t *testing.T) *validityDriverCircuit {
	t.Helper()
	seal := readSeal(t)
	if len(seal) != 55667 {
		t.Skipf("seal.bin is %d words, expected 55667", len(seal))
	}
	p, err := ParsePrefix(seal)
	if err != nil {
		t.Fatal(err)
	}
	var c validityDriverCircuit
	copy(c.Globals[:], p.Globals)
	copy(c.CodeTop[:], p.CodeTop)
	copy(c.DataTop[:], p.DataTop)
	copy(c.AccumTop[:], p.AccumTop)
	copy(c.CheckTop[:], p.CheckTop)
	copy(c.UCoeffs[:], p.UCoeffs)
	return &c
}

// TestVerifyValidityReal is the first top-level driver integration: it parses the real seal prefix,
// drives the Fiat-Shamir transcript IN-CIRCUIT to derive the challenges (poly_mix, z, accum mix -
// no longer fixture-fed), ingests the globals + U-coefficients (F1 canonicality + F2 native<->emulated
// binding), and enforces the DEEP-ALI validity check check == poly_ext(...). It must be satisfiable
// for the real seal (which RISC0 accepted) - proving the transcript->V1 composition is correct.
func TestVerifyValidityReal(t *testing.T) {
	c := loadValidityWitness(t)
	if err := test.IsSolved(&validityDriverCircuit{}, c, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("validity driver diverged from RISC0: %v", err)
	}
}

// TestVerifyValidityRejectsTamper is the single-mutation negative: corrupting one U-coefficient must
// make the circuit unsatisfiable - either the U-coeffs transcript commit diverges (wrong challenges)
// or the validity check check == result fails. Proves the V1 binding is real.
func TestVerifyValidityRejectsTamper(t *testing.T) {
	c := loadValidityWitness(t)
	c.UCoeffs[0] = bumpCanonical(c.UCoeffs[0])
	if err := test.IsSolved(&validityDriverCircuit{}, c, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected tampered U-coefficient to be rejected by the validity check")
	}
}

// TestVerifyValidityRejectsWrongPo2 is the negative for the in-circuit po2 binding (S3): a seal whose
// globals[32] is not decode(18) must be rejected, even though it is still a canonical field element.
func TestVerifyValidityRejectsWrongPo2(t *testing.T) {
	c := loadValidityWitness(t)
	c.Globals[32] = bumpCanonical(c.Globals[32]) // canonical but != decode(18)
	if err := test.IsSolved(&validityDriverCircuit{}, c, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected a seal with po2 != 18 to be rejected by the in-circuit po2 binding")
	}
}

// bumpCanonical returns (v+1) mod p - a different but still-canonical value, so the ingest
// canonicality check passes and the rejection comes from the validity/transcript binding itself.
// The parsed seal values are *big.Int.
func bumpCanonical(v frontend.Variable) frontend.Variable {
	bi := v.(*big.Int)
	return new(big.Int).Mod(new(big.Int).Add(bi, big.NewInt(1)), big.NewInt(2013265921))
}
