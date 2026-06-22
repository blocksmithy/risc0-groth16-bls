package stark

import (
	"os"
	"testing"
)

// TestFixturesPresent hard-FAILS (does not Skip) if the committed real-seal fixture is missing or
// the wrong size. The non-circular KAT/negative suite (TestSealDriveReal, the whole DEEP suite,
// TestVerifyReceiptReal, every *Tamper* test) calls t.Skipf when seal.bin is absent or len!=55667 -
// so without this guard a deleted or corrupted fixture would silently turn the entire real-seal
// suite GREEN. This test makes that impossible: if it fails, the KATs are not actually running.
func TestFixturesPresent(t *testing.T) {
	data, err := os.ReadFile("../../testdata/identity_bls/seal.bin")
	if err != nil {
		t.Fatalf("seal.bin fixture missing - the real-seal KAT/negative suite would silently SKIP: %v", err)
	}
	if w := len(data) / 4; w != 55667 {
		t.Fatalf("seal.bin is %d words, expected 55667 (po2=18) - the real-seal suite would silently SKIP", w)
	}
	for _, f := range []string{
		"transcript_real.json", "merkle_real.json", "fri_query_real.json", "fri_round_real.json",
		"deep_real.json", "taps.json", "polyext_def.json",
	} {
		if _, err := os.Stat("testdata/" + f); err != nil {
			t.Fatalf("fixture testdata/%s missing - dependent KATs would silently skip: %v", f, err)
		}
	}
}
