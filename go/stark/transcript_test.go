package stark

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	pbls "github.com/pitcon/stark-to-snark-bls/go/hash/poseidon_bls"
)

type infoCommitCircuit struct {
	PsiCommit frontend.Variable
	CiCommit  frontend.Variable
}

func (c *infoCommitCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(pbls.HashElemSlice(api, encodeInfo(ProofSystemInfo)), c.PsiCommit)
	api.AssertIsEqual(pbls.HashElemSlice(api, encodeInfo(CircuitInfo)), c.CiCommit)
	return nil
}

// Expected info-commit digests = hash_elem_slice(encode(info)), computed by the validated reference
// permutation (prototype/poseidon_bls), and cross-checked against RISC0's first two transcript
// commits (TR_COMMIT) for the real seal - see TestTranscriptReplayReal / TestSealDriveReal.
const (
	psiCommitDec = "47111718791148848215997666075242489832167625779131387327189410198822607382783"
	ciCommitDec  = "46229179393720329029149952200033672161506975620272904380086932890783580083821"
)

// TestInfoCommit validates the ProtocolInfo encoding + commit (the opening of the verify
// transcript) against independently-computed expected digests.
func TestInfoCommit(t *testing.T) {
	good := &infoCommitCircuit{PsiCommit: psiCommitDec, CiCommit: ciCommitDec}
	if err := test.IsSolved(&infoCommitCircuit{}, good, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatal(err)
	}
	// Single-mutation negative test.
	bad := &infoCommitCircuit{PsiCommit: "0", CiCommit: ciCommitDec}
	if err := test.IsSolved(&infoCommitCircuit{}, bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected wrong info commit to be rejected")
	}
}
