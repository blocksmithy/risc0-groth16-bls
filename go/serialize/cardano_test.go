package serialize

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/pitcon/stark-to-snark-bls/go/field/babybear"
)

// tinyCommitCircuit is a minimal circuit that (a) takes a NATIVE BLS12-381 public input and
// (b) routes it through the real IngestElem F2 binding, whose emulated range-checks make gnark
// inject exactly one bsb22 Pedersen commitment - the same nC=1 shape as the full receipt circuit.
// It lets the Cardano v2 encoders be validated end-to-end without the 5-minute receipt setup.
type tinyCommitCircuit struct {
	V frontend.Variable `gnark:",public"` // a canonical BabyBear value, native
}

func (c *tinyCommitCircuit) Define(api frontend.API) error {
	f, err := babybear.NewField(api)
	if err != nil {
		return err
	}
	native, emu := f.IngestElem(c.V)                   // range-check v∈[0,p) + emulated view (forces nC=1)
	f.AssertElemEq(emu, f.FromCanonicalNative(native)) // F2: native and emulated agree
	return nil
}

// TestCardanoV2RoundTripVerifies proves a real (nC=1, native-public) circuit, captures it as
// Cardano v2 bytes, parses them back BY HAND (the exact bytes the on-chain verifier consumes),
// and confirms gnark still verifies - i.e. the v2 format is lossless and complete.
func TestCardanoV2RoundTripVerifies(t *testing.T) {
	const vVal = 12345 // < BabyBear modulus

	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &tinyCommitCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	fullWit, err := frontend.NewWitness(&tinyCommitCircuit{V: vVal}, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pubWit, err := fullWit.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	proof, err := groth16.Prove(ccs, pk, fullWit)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, vk, pubWit); err != nil {
		t.Fatalf("baseline verify: %v", err)
	}

	cProof := proof.(*groth16bls.Proof)
	cVK := vk.(*groth16bls.VerifyingKey)
	if len(cProof.Commitments) != 1 {
		t.Fatalf("expected nC=1 (the commitment path under test), got %d", len(cProof.Commitments))
	}

	// 1. Encode to Cardano v2 bytes.
	var vkBuf, proofBuf, pubBuf bytes.Buffer
	if err := EncodeCardanoVK(&vkBuf, cVK); err != nil {
		t.Fatalf("EncodeCardanoVK: %v", err)
	}
	if err := EncodeCardanoProof(&proofBuf, cProof); err != nil {
		t.Fatalf("EncodeCardanoProof: %v", err)
	}
	pubBin, err := pubWit.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	if err := EncodeCardanoPublic(&pubBuf, pubBin, 1, NLimbsPerScalarNative); err != nil {
		t.Fatalf("EncodeCardanoPublic: %v", err)
	}

	// 2. Parse the bytes back by hand and reconstruct gnark types.
	roundVK, err := decodeVK(vkBuf.Bytes())
	if err != nil {
		t.Fatalf("decode vk: %v", err)
	}
	roundProof, err := decodeProof(proofBuf.Bytes())
	if err != nil {
		t.Fatalf("decode proof: %v", err)
	}
	if err := roundVK.Precompute(); err != nil { // rebuilds the unexported e=e(α,β), {δ,γ}Neg
		t.Fatalf("precompute: %v", err)
	}

	// 3. Round-tripped values must still verify.
	if err := groth16.Verify(roundProof, roundVK, pubWit); err != nil {
		t.Fatalf("v2 round-trip verify FAILED - format is lossy/incomplete: %v", err)
	}

	// 4. Public bytes decode to the original native scalar (n_inner=1, n_limbs=1).
	gotN, gotLimbs, scalars := decodePublic(t, pubBuf.Bytes())
	if gotN != 1 || gotLimbs != NLimbsPerScalarNative {
		t.Fatalf("public header = (n_inner=%d, n_limbs=%d), want (1, %d)", gotN, gotLimbs, NLimbsPerScalarNative)
	}
	if len(scalars) != 1 || scalars[0].Cmp(big.NewInt(vVal)) != 0 {
		t.Fatalf("public scalar = %v, want %d", scalars, vVal)
	}
}

// TestCardanoV2TamperRejected flips one proof byte and confirms verification fails - the format
// carries no redundancy that could mask a corrupted point.
func TestCardanoV2TamperRejected(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &tinyCommitCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	fullWit, _ := frontend.NewWitness(&tinyCommitCircuit{V: 12345}, ecc.BLS12_381.ScalarField())
	pubWit, _ := fullWit.Public()
	proof, err := groth16.Prove(ccs, pk, fullWit)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	var proofBuf bytes.Buffer
	if err := EncodeCardanoProof(&proofBuf, proof.(*groth16bls.Proof)); err != nil {
		t.Fatalf("encode: %v", err)
	}
	tampered := proofBuf.Bytes()
	tampered[80] ^= 0x01 // somewhere inside b_g2

	roundVK := vk.(*groth16bls.VerifyingKey)
	if err := roundVK.Precompute(); err != nil {
		t.Fatalf("precompute: %v", err)
	}
	roundProof, derr := decodeProof(tampered)
	if derr != nil {
		return // decode itself rejected the bad point - acceptable rejection
	}
	if err := groth16.Verify(roundProof, roundVK, pubWit); err == nil {
		t.Fatal("tampered proof verified - the v2 format must not mask corruption")
	}
}

// ---- hand-rolled decoders (mirror the on-chain reader; deliberately not gnark's deserialiser) ----

func readG1(r *bytes.Reader) (bls.G1Affine, error) {
	var buf [48]byte
	if _, err := r.Read(buf[:]); err != nil {
		return bls.G1Affine{}, err
	}
	var p bls.G1Affine
	_, err := p.SetBytes(buf[:])
	return p, err
}

func readG2(r *bytes.Reader) (bls.G2Affine, error) {
	var buf [96]byte
	if _, err := r.Read(buf[:]); err != nil {
		return bls.G2Affine{}, err
	}
	var p bls.G2Affine
	_, err := p.SetBytes(buf[:])
	return p, err
}

func decodeVK(data []byte) (*groth16bls.VerifyingKey, error) {
	r := bytes.NewReader(data)
	vk := &groth16bls.VerifyingKey{}
	var err error
	if vk.G1.Alpha, err = readG1(r); err != nil {
		return nil, err
	}
	if vk.G2.Beta, err = readG2(r); err != nil {
		return nil, err
	}
	if vk.G2.Gamma, err = readG2(r); err != nil {
		return nil, err
	}
	if vk.G2.Delta, err = readG2(r); err != nil {
		return nil, err
	}
	var ic uint32
	if err := binary.Read(r, binary.BigEndian, &ic); err != nil {
		return nil, err
	}
	vk.G1.K = make([]bls.G1Affine, ic)
	for i := range vk.G1.K {
		if vk.G1.K[i], err = readG1(r); err != nil {
			return nil, err
		}
	}
	var nC uint32
	if err := binary.Read(r, binary.BigEndian, &nC); err != nil {
		return nil, err
	}
	vk.CommitmentKeys = make([]pedersen.VerifyingKey, nC)
	vk.PublicAndCommitmentCommitted = make([][]int, nC)
	for j := range vk.CommitmentKeys {
		if vk.CommitmentKeys[j].G, err = readG2(r); err != nil {
			return nil, err
		}
		if vk.CommitmentKeys[j].GSigmaNeg, err = readG2(r); err != nil {
			return nil, err
		}
		var nIdx uint32
		if err := binary.Read(r, binary.BigEndian, &nIdx); err != nil {
			return nil, err
		}
		vk.PublicAndCommitmentCommitted[j] = make([]int, nIdx)
		for k := range vk.PublicAndCommitmentCommitted[j] {
			var idx uint32
			if err := binary.Read(r, binary.BigEndian, &idx); err != nil {
				return nil, err
			}
			vk.PublicAndCommitmentCommitted[j][k] = int(idx)
		}
	}
	return vk, nil
}

func decodeProof(data []byte) (*groth16bls.Proof, error) {
	r := bytes.NewReader(data)
	p := &groth16bls.Proof{}
	var err error
	if p.Ar, err = readG1(r); err != nil {
		return nil, err
	}
	if p.Bs, err = readG2(r); err != nil {
		return nil, err
	}
	if p.Krs, err = readG1(r); err != nil {
		return nil, err
	}
	var nC uint32
	if err := binary.Read(r, binary.BigEndian, &nC); err != nil {
		return nil, err
	}
	p.Commitments = make([]bls.G1Affine, nC)
	for j := range p.Commitments {
		if p.Commitments[j], err = readG1(r); err != nil {
			return nil, err
		}
		var unc [96]byte
		if _, err := r.Read(unc[:]); err != nil {
			return nil, err
		}
		var fromUnc bls.G1Affine
		if _, err := fromUnc.SetBytes(unc[:]); err != nil {
			return nil, err
		}
		if !fromUnc.Equal(&p.Commitments[j]) {
			return nil, errMismatch
		}
	}
	if p.CommitmentPok, err = readG1(r); err != nil {
		return nil, err
	}
	return p, nil
}

func decodePublic(t *testing.T, data []byte) (nInner, nLimbs uint32, scalars []*big.Int) {
	t.Helper()
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.BigEndian, &nInner); err != nil {
		t.Fatalf("read n_inner: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &nLimbs); err != nil {
		t.Fatalf("read n_limbs: %v", err)
	}
	for i := uint32(0); i < nInner*nLimbs; i++ {
		var s [32]byte
		if _, err := r.Read(s[:]); err != nil {
			t.Fatalf("read scalar %d: %v", i, err)
		}
		scalars = append(scalars, new(big.Int).SetBytes(s[:]))
	}
	return
}

var errMismatch = errPair("commitment compressed/uncompressed encode different points")

type errPair string

func (e errPair) Error() string { return string(e) }
