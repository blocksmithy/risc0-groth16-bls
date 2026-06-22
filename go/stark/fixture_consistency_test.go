package stark

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// TestFixtureConsistency guards against the fixture-drift failure mode: the
// *_real.json KAT fixtures and seal.bin are randomized per RISC0 run (ZK), so a fixture
// regenerated from a different run is internally self-consistent yet no longer attests to the
// committed seal. TestSealDriveReal already binds transcript_real.json + seal.bin; this test
// binds the FRI and Merkle fixtures into the same run by cross-checking the shared query-0
// position. If any one fixture is regenerated alone, this fails. Regenerate atomically via
// `make kat-regen` (single armed dump -> convert_transcript.py + convert_real_dump.py + genfri).
func TestFixtureConsistency(t *testing.T) {
	readJSON := func(name string, v interface{}) {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Skipf("%s missing: %v", name, err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	var tr struct {
		Bits []string `json:"bits"`
	}
	readJSON("transcript_real.json", &tr)

	var fq struct {
		Pos0 int `json:"pos0"`
	}
	readJSON("fri_query_real.json", &fq)

	var mk struct {
		Idx int `json:"idx"`
	}
	readJSON("merkle_real.json", &mk)

	// Query 0's FRI position == transcript's first random_bits(20) draw.
	bits0, err := strconv.Atoi(tr.Bits[0])
	if err != nil {
		t.Fatal(err)
	}
	if fq.Pos0 != bits0 {
		t.Fatalf("fixture drift: fri_query pos0=%d != transcript bits[0]=%d (fixtures from different runs)", fq.Pos0, bits0)
	}

	// The first armed Merkle opening is query 0's main-group open at the full position (the
	// trace columns span the full 2^20 domain, so group == pos). Binds merkle_real.json to the
	// same query-0 of the same seal.
	if mk.Idx != fq.Pos0 {
		t.Fatalf("fixture drift: merkle idx=%d != fri_query pos0=%d (fixtures from different runs)", mk.Idx, fq.Pos0)
	}

	// Bind deep_real.json to the same run: its poly_mix/z must equal the transcript's ext[0]/ext[1]
	// (re-checking convert_deep.py's cross-check in Go so deep_real.json drift is caught by this
	// fast guard, not only by the heavy DEEP KAT circuits). And back_one must match the friBackOne
	// constant the gadgets use (= ROU_REV[18]).
	var deep struct {
		PolyMix []string `json:"poly_mix"`
		Z       []string `json:"z"`
		BackOne string   `json:"back_one"`
	}
	readJSON("deep_real.json", &deep)
	var tr2 struct {
		Ext [][]string `json:"ext"`
	}
	readJSON("transcript_real.json", &tr2)
	for j := 0; j < 4; j++ {
		if deep.PolyMix[j] != tr2.Ext[0][j] {
			t.Fatalf("fixture drift: deep poly_mix[%d]=%s != transcript ext[0][%d]=%s", j, deep.PolyMix[j], j, tr2.Ext[0][j])
		}
		if deep.Z[j] != tr2.Ext[1][j] {
			t.Fatalf("fixture drift: deep z[%d]=%s != transcript ext[1][%d]=%s", j, deep.Z[j], j, tr2.Ext[1][j])
		}
	}
	if deep.BackOne != friBackOne.String() {
		t.Fatalf("deep back_one=%s != friBackOne constant %s (ROU_REV[18] mismatch)", deep.BackOne, friBackOne.String())
	}
}
