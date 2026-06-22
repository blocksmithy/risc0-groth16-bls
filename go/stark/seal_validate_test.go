package stark

import "testing"

// TestValidateSealRejectsMalformed is the single-mutation negative suite for the seal parser
// (truncated, extended, or wrong-po2 seals must be rejected, never panic). It
// mirrors RISC0's read_iop bounds + verify_complete (no trailing data) + po2 ≤ MAX_CYCLES_PO2.
func TestValidateSealRejectsMalformed(t *testing.T) {
	good := readSeal(t)
	if len(good) != sealWordsPo2_18 {
		t.Skipf("seal.bin is %d words, expected %d", len(good), sealWordsPo2_18)
	}
	if err := ValidateSeal(good); err != nil {
		t.Fatalf("valid seal rejected: %v", err)
	}

	cases := []struct {
		name string
		seal []uint32
	}{
		{"truncated", good[:len(good)-1]},
		{"extended (trailing data)", append(append([]uint32{}, good...), 0)},
		{"empty", []uint32{}},
		{"wrong po2", func() []uint32 {
			s := append([]uint32{}, good...)
			s[nGlobals-1] = 0 // zero the po2 word -> decodes to a non-18 value
			return s
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSeal(tc.seal); err == nil {
				t.Fatalf("expected %s seal to be rejected", tc.name)
			}
			// And the parsers must propagate the error, not panic.
			if _, err := ParsePrefix(tc.seal); err == nil {
				t.Fatalf("ParsePrefix accepted %s seal", tc.name)
			}
			if _, err := ParseQueries(tc.seal); err == nil {
				t.Fatalf("ParseQueries accepted %s seal", tc.name)
			}
		})
	}
}
