package stark

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// risc0ClaimDigest is RISC0's authoritative SHA-256 claim digest for the committed identity_bls
// seal (the ReceiptClaim digest of the proven receipt). Hardcoded as a self-contained KAT - it is
// the same value the Rust verify_bls receipt test pins - so this test depends on no external file.
const risc0ClaimDigest = "ebab934ddc79d3601d84192a471489b1dbc920753cc2a805fa274c801e4bf838"

// TestBindClaimMatchesRisc0Claim is the NON-CIRCULAR anchor for the claim binding: it reconstructs
// the SHA-256 claim digest from the seal globals (via read_sha_halfs' byte layout) and asserts it
// equals RISC0's authoritative value - pinning BindClaim's globals->claim_digest decoding to RISC0's
// actual claim, without recomputing it from the verifier code.
func TestBindClaimMatchesRisc0Claim(t *testing.T) {
	seal := readSeal(t)
	if len(seal) != 55667 {
		t.Skipf("seal.bin is %d words", len(seal))
	}
	p, err := ParsePrefix(seal)
	if err != nil {
		t.Fatal(err)
	}
	// read_sha_halfs byte layout: each half h -> bytes (h & 0xff), (h >> 8).
	var digest [32]byte
	for i := 0; i < 16; i++ {
		h := p.Globals[16+i].(*big.Int).Uint64()
		digest[2*i] = byte(h & 0xff)
		digest[2*i+1] = byte(h >> 8)
	}
	got := ""
	for _, b := range digest {
		got += hexByte(b)
	}
	if got != risc0ClaimDigest {
		t.Fatalf("reconstructed claim digest %s != RISC0 claim_digest %s", got, risc0ClaimDigest)
	}
}

func hexByte(b byte) string {
	const hx = "0123456789abcdef"
	return string([]byte{hx[b>>4], hx[b&0xf]})
}

// TestVerifyReceiptRejectsWrongPublic is the negative suite for the 5 public inputs (risc0 schema):
// each must be bound to the seal, so a wrong value for any of control_root / claim_digest /
// control_id must be rejected - a prover cannot prove an arbitrary statement, program, or platform
// against this seal.
func TestVerifyReceiptRejectsWrongPublic(t *testing.T) {
	bump := func(v frontend.Variable) frontend.Variable {
		return new(big.Int).Add(v.(*big.Int), big.NewInt(1))
	}
	cases := []struct {
		name   string
		mutate func(*ReceiptCircuit)
	}{
		{"control_root_low", func(c *ReceiptCircuit) { c.ControlRootLow = bump(c.ControlRootLow) }},
		{"control_root_high", func(c *ReceiptCircuit) { c.ControlRootHigh = bump(c.ControlRootHigh) }},
		{"claim_digest_low", func(c *ReceiptCircuit) { c.ClaimDigestLow = bump(c.ClaimDigestLow) }},
		{"claim_digest_high", func(c *ReceiptCircuit) { c.ClaimDigestHigh = bump(c.ClaimDigestHigh) }},
		{"control_id", func(c *ReceiptCircuit) { c.ControlID = bump(c.ControlID) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const nq = 1
			c := loadReceipt(t, nq)
			tc.mutate(c)
			if err := test.IsSolved(ReceiptTemplate(nq), c, ecc.BLS12_381.ScalarField()); err == nil {
				t.Fatalf("expected a wrong %s public input to be rejected", tc.name)
			}
		})
	}
}

// TestReceiptPublicsMatchPlatform confirms the seal's control_root and control_id (bound in-circuit
// to the public inputs) equal the expected platform constants - i.e. the on-chain check that the
// proof attests to ALLOWED_CONTROL_ROOT + BLS_IDENTITY_CONTROL_ID. (TestVerifyReceiptReal proves the
// seal actually satisfies these bindings; this asserts the witness publics ARE the platform values.)
func TestReceiptPublicsMatchPlatform(t *testing.T) {
	c := loadReceipt(t, 1)
	crLow, crHigh := ControlRootSplit()
	if c.ControlRootLow.(*big.Int).Cmp(crLow) != 0 || c.ControlRootHigh.(*big.Int).Cmp(crHigh) != 0 {
		t.Fatal("control_root public inputs != split(ALLOWED_CONTROL_ROOT)")
	}
	if c.ControlID.(*big.Int).Cmp(ControlIDFr()) != 0 {
		t.Fatal("control_id public input != BLS_IDENTITY_CONTROL_ID")
	}
}
