// Package serialize writes the BLS12-381 Groth16 artifacts in the Cardano-minimal v2 byte
// format - the on-chain encoding shared with BN254-wrap proofs, so STARK-direct proofs verify
// under the same Cardano Groth16 verifier. Compressed G1/G2 use
// gnark-crypto's `.Bytes()` (IETF/Zcash, matching Cardano's bls12_381_*_uncompress builtins).
//
// v2 carries the Pedersen commitment fields gnark's full verification equation needs:
//
//	kSum = K[0] + Σ public[i]·K[i+1] + Σ h_j·K[nbPublic+1+j] + Σ commitment[j]
//	main:     e(A,B) == e(α,β) · e(kSum,γ) · e(C,δ)
//	pedersen: e(commitment_folded, GSigmaNeg) · e(pok_folded, G) == 1   (nC=1: fold is identity)
//	h_j = HashToField(DST="bsb22-commitment", commitment[j].Marshal()(96B) ‖ committed_values)
//
// This circuit carries exactly nC=1 (gnark emulated-field range-checks inject one bsb22
// commitment). The public inputs are NATIVE BLS12-381 scalars, so n_limbs_per_scalar = 1
// (an emulated-BN254 wrap uses 4).
package serialize

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/witness"
)

// NLimbsPerScalarNative is the Cardano public-input limb count for our circuit: the 5 risc0-schema
// inputs are native BLS12-381 scalars, one limb each (vs 4 for an emulated-BN254 wrap).
const NLimbsPerScalarNative = 1

// EncodeCardanoVK writes the v2 VK layout:
//
//	[α]_1(48) || [β]_2(96) || [γ]_2(96) || [δ]_2(96)
//	|| u32 ic_count || ([K_i]_1, 48)×ic_count
//	|| u32 nC || for j<nC: pedersen_G_2(96) || pedersen_GSigmaNeg_2(96)
//	                       || u32 len(committed_j) || committed_j (u32 BE, 1-indexed)×len
func EncodeCardanoVK(w io.Writer, vk *groth16bls.VerifyingKey) error {
	if err := writeG1(w, vk.G1.Alpha); err != nil {
		return fmt.Errorf("alpha_g1: %w", err)
	}
	if err := writeG2(w, vk.G2.Beta); err != nil {
		return fmt.Errorf("beta_g2: %w", err)
	}
	if err := writeG2(w, vk.G2.Gamma); err != nil {
		return fmt.Errorf("gamma_g2: %w", err)
	}
	if err := writeG2(w, vk.G2.Delta); err != nil {
		return fmt.Errorf("delta_g2: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(vk.G1.K))); err != nil {
		return fmt.Errorf("ic_count: %w", err)
	}
	for i := range vk.G1.K {
		if err := writeG1(w, vk.G1.K[i]); err != nil {
			return fmt.Errorf("ic[%d]: %w", i, err)
		}
	}
	nC := uint32(len(vk.CommitmentKeys))
	if err := binary.Write(w, binary.BigEndian, nC); err != nil {
		return fmt.Errorf("nC: %w", err)
	}
	if len(vk.PublicAndCommitmentCommitted) != int(nC) {
		return fmt.Errorf("vk has %d CommitmentKeys but %d PublicAndCommitmentCommitted slots", nC, len(vk.PublicAndCommitmentCommitted))
	}
	for j := range vk.CommitmentKeys {
		if err := writeG2(w, vk.CommitmentKeys[j].G); err != nil {
			return fmt.Errorf("pedersen_G[%d]: %w", j, err)
		}
		if err := writeG2(w, vk.CommitmentKeys[j].GSigmaNeg); err != nil {
			return fmt.Errorf("pedersen_GSigmaNeg[%d]: %w", j, err)
		}
		idxs := vk.PublicAndCommitmentCommitted[j]
		if err := binary.Write(w, binary.BigEndian, uint32(len(idxs))); err != nil {
			return fmt.Errorf("committed_count[%d]: %w", j, err)
		}
		for _, idx := range idxs {
			if idx < 0 {
				return fmt.Errorf("PublicAndCommitmentCommitted[%d] contains negative index %d", j, idx)
			}
			if err := binary.Write(w, binary.BigEndian, uint32(idx)); err != nil {
				return fmt.Errorf("committed_index[%d][%d]: %w", j, idx, err)
			}
		}
	}
	return nil
}

// EncodeCardanoProof writes the v2 proof layout:
//
//	a_g1(48) || b_g2(96) || c_g1(48) || u32 nC
//	|| for j<nC: commitment_g1_compressed(48) || commitment_g1_uncompressed(96)
//	|| commitment_pok_g1(48)
//
// The commitment is dual-encoded: the compressed copy feeds pairing arithmetic; the 96-byte
// uncompressed copy (x_be||y_be) is the EXACT input gnark's HashToField consumes for h_j.
func EncodeCardanoProof(w io.Writer, p *groth16bls.Proof) error {
	if err := writeG1(w, p.Ar); err != nil {
		return fmt.Errorf("a_g1: %w", err)
	}
	if err := writeG2(w, p.Bs); err != nil {
		return fmt.Errorf("b_g2: %w", err)
	}
	if err := writeG1(w, p.Krs); err != nil {
		return fmt.Errorf("c_g1: %w", err)
	}
	nC := uint32(len(p.Commitments))
	if err := binary.Write(w, binary.BigEndian, nC); err != nil {
		return fmt.Errorf("nC: %w", err)
	}
	for j := range p.Commitments {
		if err := writeG1(w, p.Commitments[j]); err != nil {
			return fmt.Errorf("commitment[%d] compressed: %w", j, err)
		}
		raw := p.Commitments[j].Marshal() // 96 B uncompressed (x_be(48)||y_be(48)) - gnark's hash input
		if len(raw) != 96 {
			return fmt.Errorf("commitment[%d] uncompressed: got %d B, expected 96", j, len(raw))
		}
		if _, err := w.Write(raw); err != nil {
			return fmt.Errorf("commitment[%d] uncompressed: %w", j, err)
		}
	}
	if err := writeG1(w, p.CommitmentPok); err != nil {
		return fmt.Errorf("commitment_pok: %w", err)
	}
	return nil
}

// EncodeCardanoPublic strips the 12-byte gnark witness header (nbPublic, nbSecret, vector_len) and
// re-wraps the limb data with the Cardano two-uint32 header:
//
//	u32 n_inner_pub || u32 n_limbs_per_scalar || (n_inner_pub·n_limbs) scalars, each 32 B BE
func EncodeCardanoPublic(w io.Writer, witnessBin []byte, nInnerPub, nLimbsPerScalar uint32) error {
	const gnarkHeader = 12
	const scalarBytes = 32
	want := int(nInnerPub) * int(nLimbsPerScalar)
	gotScalarBytes := len(witnessBin) - gnarkHeader
	if gotScalarBytes < 0 || gotScalarBytes%scalarBytes != 0 {
		return fmt.Errorf("witness binary length %d is not a valid gnark public-witness", len(witnessBin))
	}
	if gotScalars := gotScalarBytes / scalarBytes; gotScalars != want {
		return fmt.Errorf("witness has %d scalars but n_inner_pub*n_limbs = %d", gotScalars, want)
	}
	if err := binary.Write(w, binary.BigEndian, nInnerPub); err != nil {
		return fmt.Errorf("n_inner_pub: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, nLimbsPerScalar); err != nil {
		return fmt.Errorf("n_limbs_per_scalar: %w", err)
	}
	if _, err := w.Write(witnessBin[gnarkHeader:]); err != nil {
		return fmt.Errorf("limb bytes: %w", err)
	}
	return nil
}

func writeG1(w io.Writer, p curve.G1Affine) error {
	b := p.Bytes()
	_, err := w.Write(b[:])
	return err
}

func writeG2(w io.Writer, p curve.G2Affine) error {
	b := p.Bytes()
	_, err := w.Write(b[:])
	return err
}

// ---- file wrappers ----

// WriteCardanoVK writes the v2 VK bytes to path and returns the byte count.
func WriteCardanoVK(path string, vk *groth16bls.VerifyingKey) (int64, error) {
	return writeFile(path, func(w io.Writer) error { return EncodeCardanoVK(w, vk) })
}

// WriteCardanoProof writes the v2 proof bytes to path and returns the byte count.
func WriteCardanoProof(path string, p *groth16bls.Proof) (int64, error) {
	return writeFile(path, func(w io.Writer) error { return EncodeCardanoProof(w, p) })
}

// WriteCardanoPublic writes the v2 public bytes to path from a gnark public witness.
func WriteCardanoPublic(path string, pub witness.Witness, nInnerPub, nLimbsPerScalar uint32) (int64, error) {
	bin, err := pub.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("marshal witness: %w", err)
	}
	return writeFile(path, func(w io.Writer) error {
		return EncodeCardanoPublic(w, bin, nInnerPub, nLimbsPerScalar)
	})
}

func writeFile(path string, enc func(io.Writer) error) (n int64, err error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create %q: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if err = enc(f); err != nil {
		return 0, err
	}
	if err = f.Sync(); err != nil { // durable before a reader (RISC0 / on-chain tooling) consumes it
		return 0, fmt.Errorf("sync %q: %w", path, err)
	}
	st, serr := f.Stat()
	if serr != nil {
		return 0, fmt.Errorf("stat %q: %w", path, serr)
	}
	return st.Size(), nil
}
