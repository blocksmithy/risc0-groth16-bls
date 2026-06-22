package stark

import (
	"github.com/consensys/gnark/frontend"

	pbls "github.com/pitcon/stark-to-snark-bls/go/hash/poseidon_bls"
)

// ProtocolInfo context strings committed first into the transcript. 16 bytes each, encoded
// one BabyBear element per byte (risc0 zkp/src/adapter.rs::ProtocolInfo::encode). These are
// circuit constants - any change forces a new VK. Values verified byte-for-byte against the
// pinned risc0 v3.0.5 source and re-checked by `make verify-constants`:
//   - PROOF_SYSTEM_INFO = b"RISC0_STARK:v1__"  (risc0/zkp/src/adapter.rs:120)
//   - CIRCUIT_INFO      = b"RECURSION:rev1v1"  (risc0/circuit/recursion/src/info.rs:23)
var (
	ProofSystemInfo = []byte("RISC0_STARK:v1__")
	CircuitInfo     = []byte("RECURSION:rev1v1")
)

// encodeInfo encodes a (≤16-byte) context string as 16 BabyBear field elements, one per byte,
// zero-padded - matching risc0 ProtocolInfo::encode (adapter.rs:98).
func encodeInfo(info []byte) []frontend.Variable {
	out := make([]frontend.Variable, 16)
	for i := 0; i < 16; i++ {
		if i < len(info) {
			out[i] = int(info[i])
		} else {
			out[i] = 0
		}
	}
	return out
}

// Transcript is the in-circuit Fiat-Shamir transcript driver. It reproduces risc0's
// verify::ReadIOP commit/challenge sequence over the poseidon_bls sponge (go/hash/poseidon_bls).
// Commits absorb digests; challenge draws squeeze the sponge - both byte-identical to RISC0,
// so the in-circuit challenges match the seal's prover-side challenges.
type Transcript struct {
	sponge *pbls.Sponge
}

// NewTranscript creates a fresh transcript (zero-initialized sponge), matching ReadIOP::new.
func NewTranscript() *Transcript {
	return &Transcript{sponge: pbls.NewSponge()}
}

// Commit absorbs a digest into the transcript (ReadIOP::commit -> rng.mix).
func (tr *Transcript) Commit(api frontend.API, digest frontend.Variable) {
	tr.sponge.Mix(api, digest)
}

// CommitInfo commits hash_elem_slice(encode(info)) - the ProtocolInfo commit that opens the
// verify sequence (PROOF_SYSTEM_INFO then CIRCUIT_INFO).
func (tr *Transcript) CommitInfo(api frontend.API, info []byte) {
	tr.Commit(api, pbls.HashElemSlice(api, encodeInfo(info)))
}

// RandomElem draws a BabyBear challenge (ReadIOP::random_elem).
func (tr *Transcript) RandomElem(api frontend.API) frontend.Variable {
	return tr.sponge.RandomElem(api)
}

// RandomBits draws n low bits as an integer challenge (ReadIOP::random_bits).
func (tr *Transcript) RandomBits(api frontend.API, n int) frontend.Variable {
	return tr.sponge.RandomBits(api, n)
}

// RandomExtElem draws an Fp4 challenge as 4 BabyBear subelements (ReadIOP::random_ext_elem).
func (tr *Transcript) RandomExtElem(api frontend.API) [4]frontend.Variable {
	return tr.sponge.RandomExtElem(api)
}
