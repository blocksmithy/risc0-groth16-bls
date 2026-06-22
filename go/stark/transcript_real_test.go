package stark

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// transcriptReplayCircuit replays RISC0's exact verify-transcript op sequence (confirmed by
// the TR_* trace structure: 2 info + globals + code/data roots, 20 accum-mix elems, accum
// root, poly_mix, check root, z, U-coeffs, fri_mix, 3×(round root + mix), final coeffs,
// 50 query positions) over the in-circuit Transcript, feeding RISC0's actual committed
// digests and asserting every drawn challenge matches the seal's prover-side challenge.
type transcriptReplayCircuit struct {
	Commits [12]frontend.Variable
	Elems   [20]frontend.Variable
	Ext     [6][4]frontend.Variable
	Bits    [50]frontend.Variable
}

func (c *transcriptReplayCircuit) Define(api frontend.API) error {
	tr := NewTranscript()
	assertExt := func(got [4]frontend.Variable, want [4]frontend.Variable) {
		for i := 0; i < 4; i++ {
			api.AssertIsEqual(got[i], want[i])
		}
	}

	// PROOF_SYSTEM_INFO, CIRCUIT_INFO, globals hash, code root, data root.
	for i := 0; i < 5; i++ {
		tr.Commit(api, c.Commits[i])
	}
	// 20 accum-mix challenges (read_rng MIX_SIZE).
	for i := 0; i < 20; i++ {
		api.AssertIsEqual(tr.RandomElem(api), c.Elems[i])
	}
	tr.Commit(api, c.Commits[5])               // accum root
	assertExt(tr.RandomExtElem(api), c.Ext[0]) // poly_mix
	tr.Commit(api, c.Commits[6])               // check root
	assertExt(tr.RandomExtElem(api), c.Ext[1]) // z (DEEP point)
	tr.Commit(api, c.Commits[7])               // U-coeffs hash
	assertExt(tr.RandomExtElem(api), c.Ext[2]) // fri batch mix
	// 3 FRI rounds: commit round root, then draw round mix.
	for r := 0; r < 3; r++ {
		tr.Commit(api, c.Commits[8+r])
		assertExt(tr.RandomExtElem(api), c.Ext[3+r])
	}
	tr.Commit(api, c.Commits[11]) // final coeffs hash
	// 50 query positions (random_bits(20)).
	for i := 0; i < 50; i++ {
		api.AssertIsEqual(tr.RandomBits(api, 20), c.Bits[i])
	}
	return nil
}

// TestTranscriptReplayReal validates the WHOLE Fiat-Shamir driver (commit ordering +
// challenge derivation) against RISC0's actual transcript trace for the real seal - every
// one of the 76 challenges must match. Non-circular: commits and expected challenges are
// RISC0's, captured via the armed ReadIOP instrumentation.
func TestTranscriptReplayReal(t *testing.T) {
	data, err := os.ReadFile("testdata/transcript_real.json")
	if err != nil {
		t.Skipf("transcript trace not generated yet: %v", err)
	}
	var ref struct {
		Commits []string   `json:"commits"`
		Elems   []string   `json:"elems"`
		Ext     [][]string `json:"ext"`
		Bits    []string   `json:"bits"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}

	var a transcriptReplayCircuit
	for i := 0; i < 12; i++ {
		a.Commits[i] = ref.Commits[i]
	}
	for i := 0; i < 20; i++ {
		a.Elems[i] = ref.Elems[i]
	}
	for i := 0; i < 6; i++ {
		for j := 0; j < 4; j++ {
			a.Ext[i][j] = ref.Ext[i][j]
		}
	}
	for i := 0; i < 50; i++ {
		a.Bits[i] = ref.Bits[i]
	}
	if err := test.IsSolved(&transcriptReplayCircuit{}, &a, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("transcript replay diverged from RISC0: %v", err)
	}

	// Single-mutation negative: corrupting one committed digest must change a later challenge.
	bad := a
	bad.Commits[0] = "123456789"
	if err := test.IsSolved(&transcriptReplayCircuit{}, &bad, ecc.BLS12_381.ScalarField()); err == nil {
		t.Fatal("expected a corrupted commit to diverge the challenge sequence")
	}
}
