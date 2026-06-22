package stark

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Claim/control binding constants. Source: risc0 v3.0.5.
//
//   - controlRootWords: the 8 little-endian u32 words of ALLOWED_CONTROL_ROOT
//     (recursion/src/control_id.rs: a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56),
//     which is the inner poseidon2 control root. The succinct receipt's seal encodes this in the
//     even-indexed slots of globals[0:16] (succinct.rs:179-185); each word is a canonical BabyBear
//     element. Checked by `make verify-constants`.
//   - blsIdentityControlIDFr: BLS_IDENTITY_CONTROL_ID interpreted as a poseidon_bls digest Fr value
//     (digest_to_fr = little-endian bytes -> Fr) - the control_id of the identity_bls program. The
//     seal's CODE-group Merkle root (the program control_id, succinct.rs check_code) must equal it.
var (
	controlRootWords = []*big.Int{
		big.NewInt(1523076517), big.NewInt(478519241), big.NewInt(1841944466), big.NewInt(1101994099),
		big.NewInt(432072667), big.NewInt(936173390), big.NewInt(708988395), big.NewInt(1444908185),
	}
	blsIdentityControlIDFr, _ = new(big.Int).SetString(
		"47300707290156507355121462570254503547066278021772901893111879097443343094619", 10)
)

// BindClaim ties the verified seal output (globals) and program identity to the circuit's public
// inputs and trust-anchor constants, mirroring risc0 succinct.rs verify_integrity_with_context
// (the control-root/control-id checks + the read_sha_halfs claim extraction). It assumes the
// globals have already been ingested (canonical) and the seal Merkle/FRI-verified, so the globals
// are reliable.
//
//   - inner control root: the even-indexed globals[0,2,…,14] must equal ALLOWED_CONTROL_ROOT - the
//     receipt was produced by the standard recursion circuit (succinct.rs:179-196);
//   - program control_id: the CODE-group root (= the program's control_id) must equal
//     BLS_IDENTITY_CONTROL_ID - the seal is an identity_bls re-proof and nothing else
//     (succinct.rs check_code; the control-inclusion proof to the outer root is subsumed by pinning
//     the single allowed program here);
//   - claim digest: globals[16:32] are 16 SHA half-words (each range-checked < 2^16, mirroring
//     RISC0 read_sha_halfs' `(half>>8) as u8`); they reconstruct the 8-word claim digest, packed
//     into the two public-input scalars claimLo/claimHi (low/high 128 bits, < 2^128 by the half
//     range checks). See PUBLIC_INPUTS.md.
//
// The five public inputs match risc0's Groth16 receipt schema exactly (just over BLS12-381 instead
// of BN254). SOURCE OF TRUTH: risc0-groth16 `src/verifier.rs::Verifier::new` builds
// `&[a0, a1, c0, c1, id_bn254_fr]` and `split_digest` - risc0 v3.0.4. Order:
//
//	[0] control_root_low   [1] control_root_high   (the inner poseidon2 recursion control root)
//	[2] claim_digest_low   [3] claim_digest_high   (the ReceiptClaim digest - guest + journal)
//	[4] control_id                                  (the recursion program's control_id = code root)
//
// risc0 `split_digest` reverses the 32-byte digest image to big-endian and returns (low=be[16:32],
// high=be[0:16]); for an 8-u32-word digest that equals packing words[0..4] (low) and words[4..8]
// (high) little-endian, verified against the source. control_id = `from_be(reverse(as_bytes))` =
// `from_le(as_bytes)` = digest_to_fr. Keeping control_root/control_id/claim_digest as PUBLIC INPUTS
// (not baked constants) is what makes one VK agnostic of the risc0 version, the allowed control set,
// and the guest program - the on-chain verifier checks the inputs against the expected platform
// constants (ALLOWED_CONTROL_ROOT, BLS_IDENTITY_CONTROL_ID) without a new circuit/ceremony.
func BindClaim(api frontend.API, globals []frontend.Variable,
	codeRoot, controlRootLow, controlRootHigh, claimDigestLow, claimDigestHigh, controlID frontend.Variable) {

	// pack 4 little-endian 32-bit words into a 128-bit value (word[k]·2^(32k)); < 2^128, no Fr wrap.
	pack := func(ws []frontend.Variable) frontend.Variable {
		acc := frontend.Variable(0)
		shift := big.NewInt(1)
		for _, w := range ws {
			acc = api.Add(acc, api.Mul(w, shift))
			shift = new(big.Int).Lsh(shift, 32)
		}
		return acc
	}

	// Inner control root = the 8 even-indexed words of globals[0:16] (poseidon2 digest words, each a
	// canonical BabyBear elem < p < 2^32). Bind its split to public inputs [0],[1].
	cr := []frontend.Variable{globals[0], globals[2], globals[4], globals[6],
		globals[8], globals[10], globals[12], globals[14]}
	api.AssertIsEqual(pack(cr[0:4]), controlRootLow)
	api.AssertIsEqual(pack(cr[4:8]), controlRootHigh)

	// Claim digest from globals[16:32] = 16 SHA half-words. word[j] = half[2j] + half[2j+1]·2^16,
	// each half range-checked < 2^16 (read_sha_halfs rejects halves that don't fit in 16 bits).
	// Bind its split to public inputs [2],[3].
	two16 := big.NewInt(1 << 16)
	cd := make([]frontend.Variable, 8)
	for j := 0; j < 8; j++ {
		lo := globals[16+2*j]
		hi := globals[16+2*j+1]
		api.ToBinary(lo, 16) // < 2^16
		api.ToBinary(hi, 16) // < 2^16
		cd[j] = api.Add(lo, api.Mul(hi, two16))
	}
	api.AssertIsEqual(pack(cd[0:4]), claimDigestLow)
	api.AssertIsEqual(pack(cd[4:8]), claimDigestHigh)

	// Program control_id = the CODE-group Merkle root. Bind to public input [4]. (The circuit does
	// NOT hardcode BLS_IDENTITY_CONTROL_ID - that keeps the VK agnostic of which recursion program;
	// the on-chain verifier checks this input against the expected program control_id.)
	api.AssertIsEqual(codeRoot, controlID)
}

// claimDigestFromGlobals reconstructs the (lo, hi) claim-digest public scalars from the parsed seal
// globals - witness preparation (off-circuit, over concrete *big.Int values), matching BindClaim's
// in-circuit reconstruction: word[j] = half[2j] + half[2j+1]·2^16 over globals[16:32], then
// lo = words[0..4], hi = words[4..8] packed little-endian.
func claimDigestFromGlobals(globals []frontend.Variable) (lo, hi *big.Int) {
	g := func(i int) *big.Int { return globals[i].(*big.Int) }
	words := make([]*big.Int, 8)
	for j := 0; j < 8; j++ {
		words[j] = new(big.Int).Add(g(16+2*j), new(big.Int).Lsh(g(16+2*j+1), 16))
	}
	lo, hi = new(big.Int), new(big.Int)
	for k := 0; k < 4; k++ {
		lo.Add(lo, new(big.Int).Lsh(words[k], uint(32*k)))
		hi.Add(hi, new(big.Int).Lsh(words[4+k], uint(32*k)))
	}
	return
}

// ControlRootSplit returns the (low, high) 128-bit halves of ALLOWED_CONTROL_ROOT in risc0
// split_digest order - the EXPECTED values of public inputs [0],[1]. The on-chain verifier checks
// the proof's control_root inputs against these platform constants.
func ControlRootSplit() (low, high *big.Int) {
	lo, hi := new(big.Int), new(big.Int)
	for k := 0; k < 4; k++ {
		lo.Add(lo, new(big.Int).Lsh(controlRootWords[k], uint(32*k)))
		hi.Add(hi, new(big.Int).Lsh(controlRootWords[4+k], uint(32*k)))
	}
	return lo, hi
}

// ControlIDFr returns BLS_IDENTITY_CONTROL_ID as the Fr public input [4] - the expected program
// control_id the on-chain verifier checks the proof's control_id input against.
func ControlIDFr() *big.Int { return new(big.Int).Set(blsIdentityControlIDFr) }
