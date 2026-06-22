package stark

import (
	"math/rand"
	"testing"
)

// TestAssignReceiptHostileSealNoPanic feeds valid-length but garbage seals (random content, with the
// po2 word forced to the expected 18 so we get PAST ValidateSeal into the parser/driver) and asserts
// AssignReceipt never PANICS - it must return an error (or a witness that the solver later rejects),
// never crash the prover subprocess. The seal is attacker-influenceable input.
func TestAssignReceiptHostileSealNoPanic(t *testing.T) {
	const sealLen = 55667
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 64; iter++ {
		seal := make([]uint32, sealLen)
		for i := range seal {
			seal[i] = rng.Uint32()
		}
		seal[32] = 18 // po2 word: pass ValidateSeal so the driver/parser actually runs on garbage

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("iter %d: AssignReceipt PANICKED on hostile seal: %v", iter, r)
				}
			}()
			// Error return is fine and expected; panic is not.
			_, _ = AssignReceipt(seal, nQueriesFuzz)
		}()
	}
}

// nQueriesFuzz keeps the fuzz fast; AssignReceipt's parsing/driver paths are exercised regardless.
const nQueriesFuzz = 1
