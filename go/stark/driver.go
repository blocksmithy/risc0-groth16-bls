package stark

import (
	"github.com/consensys/gnark/frontend"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
	pbls "github.com/pitcon/stark-to-snark-bls/go/hash/poseidon_bls"
)

// SealPrefixVars is the parsed seal prefix as native circuit variables - the off-circuit parser
// (ParsePrefix) fills these from the raw seal; the driver ingests + binds them in-circuit. Field
// elements are canonical BabyBear values; the *Top arrays and Final are as read.
type SealPrefixVars struct {
	Globals  []frontend.Variable // 33 (out[32] + po2)
	CodeTop  []frontend.Variable // 32 digests
	DataTop  []frontend.Variable
	AccumTop []frontend.Variable
	CheckTop []frontend.Variable
	UCoeffs  []frontend.Variable    // 2636 (659 Fp4)
	FriTops  [3][]frontend.Variable // 32 digests each
	Final    []frontend.Variable    // 256
}

// emulExt converts the 4 native components of an extension-field challenge into an emulated Fp4
// value. The components are sponge draws (RandomElem), whose `< p` canonicality is already proven
// by the divmod binding, so FromCanonicalNative (the F2 binding only) is used - re-checking
// canonicality here would be redundant.
func emulExt(f *bb.Field, v [4]frontend.Variable) bb.E4 {
	var c [4]*bb.Elem
	for i := 0; i < 4; i++ {
		c[i] = f.FromCanonicalNative(v[i])
	}
	return bb.E4{C: c}
}

// ingestSliceEmul ingests each native seal element (canonicality + native<->emulated binding, F1/F2)
// and returns the emulated representations. The native values are unchanged (== input), so the
// caller keeps using the input slice for the hash/Merkle (native) side.
func ingestSliceEmul(f *bb.Field, vs []frontend.Variable) []*bb.Elem {
	out := make([]*bb.Elem, len(vs))
	for i, v := range vs {
		_, out[i] = f.IngestElem(v)
	}
	return out
}

// ValidityState carries the transcript position and the values the FRI phase needs after the
// DEEP-ALI validity check: the FRI mixing challenge, the ingested U-coefficients (for combo_u), and
// the DEEP point z (for fri_eval_taps).
type ValidityState struct {
	Tr       *Transcript
	FriMix   bb.E4
	CoeffU   []bb.E4
	Z        bb.E4
	CodeRoot frontend.Variable // = MerkleRoot(CodeTop) = the program's control_id; bound by BindClaim
}

// VerifyValidity drives the Fiat-Shamir transcript from the parsed seal prefix and enforces the
// DEEP-ALI validity check (V1), mirroring risc0 verify::verify up to and including verify_validity:
//
//   - it re-derives every commitment in-circuit (globals/U-coeffs hashes, group/check/FRI Merkle
//     roots) and the challenges (20 accum-mix, poly_mix, z, fri_mix) in RISC0's exact order, so the
//     challenges are bound to the seal by Fiat-Shamir (not supplied as witness);
//   - it ingests the globals and U-coefficients (F1 canonicality + F2 native<->emulated binding), so
//     the values hashed into the transcript and the values fed to poly_ext are provably identical;
//   - it computes eval_u + poly_ext(result) + check and asserts check == result - the constraint
//     that the STARK's constraints were satisfied.
//
// It returns the transcript positioned after the fri_mix draw plus the fri_mix challenge, ready for
// the FRI phase. The caller supplies the FRI round roots / final commit and the per-query openings.
func VerifyValidity(api frontend.API, f *bb.Field, w *SealPrefixVars) *ValidityState {
	// Elements used in BOTH the native (hash) and emulated (arithmetic) paths are ingested once.
	globalsEmul := ingestSliceEmul(f, w.Globals)
	uCoeffsEmul := ingestSliceEmul(f, w.UCoeffs)

	// po2 binding (in-circuit, inside the security boundary - not relying on off-circuit
	// ValidateSeal). This circuit supports ONLY the po2=18 recursion receipt: the taps/poly_ext
	// tables, back_one = ROU_REV[18], and the (3z)^(2^18) check factor are all po2=18 constants.
	// RISC0 reads po2 from globals[32] via to_u32_words (the raw Montgomery word = 18,
	// read_slice_with_po2); the parser holds its canonical field value, so a po2=18 receipt must
	// have globals[32] == decode(18). Reject any other po2. (The claim binding additionally commits
	// SystemState.po2 to the public input.)
	api.AssertIsEqual(w.Globals[len(w.Globals)-1], decodeMont(18))

	tr := NewTranscript()
	tr.CommitInfo(api, ProofSystemInfo)
	tr.CommitInfo(api, CircuitInfo)
	tr.Commit(api, pbls.HashElemSlice(api, w.Globals))
	codeRoot := MerkleRoot(api, w.CodeTop)
	tr.Commit(api, codeRoot)
	tr.Commit(api, MerkleRoot(api, w.DataTop))

	accumMixEmul := make([]*bb.Elem, 20)
	for i := 0; i < 20; i++ {
		// accum-mix is squeezed from the transcript (RandomElem, already proven < p), not read from
		// the seal - bind to emulated without a redundant canonicality re-check.
		accumMixEmul[i] = f.FromCanonicalNative(tr.RandomElem(api))
	}
	tr.Commit(api, MerkleRoot(api, w.AccumTop))

	polyMix := emulExt(f, tr.RandomExtElem(api))
	tr.Commit(api, MerkleRoot(api, w.CheckTop))
	z := emulExt(f, tr.RandomExtElem(api))
	tr.Commit(api, pbls.HashElemSlice(api, w.UCoeffs))

	// V1 validity check, driven by the in-circuit-derived challenges (poly_mix, z) and the ingested
	// coefficients/globals/accum-mix. check == result iff the trace satisfied the circuit's
	// constraints (verify/mod.rs:393).
	coeffU := CoeffUFromUCoeffs(f, uCoeffsEmul)
	evalU := EvalU(f, coeffU, z)
	result := PolyExt(f, polyMix, evalU, globalsEmul[:32], accumMixEmul)
	check := ComputeCheck(f, coeffU, z, 18)
	f.E4AssertEq(check, result)

	friMix := emulExt(f, tr.RandomExtElem(api))
	return &ValidityState{Tr: tr, FriMix: friMix, CoeffU: coeffU, Z: z, CodeRoot: codeRoot}
}

// QueryVars holds one query's openings as native circuit variables (as produced by ParseQueries):
// the four main-group column leaves + Merkle paths and the three FRI-round column leaves + paths.
type QueryVars struct {
	MainLeaf [4][]frontend.Variable // accum(12), code(23), data(128), check(16)
	MainPath [4][]frontend.Variable // 15 digests each
	FriLeaf  [3][]frontend.Variable // 64 each
	FriPath  [3][]frontend.Variable // 11, 7, 3 digests
}

// friGroupBits[r] = log2(FRI round-r domain) for the recursion circuit (po2=18): the number of low
// position bits that index round r's Merkle tree (and form `group`); rounds fold the domain by
// FRI_FOLD=16, so 2^20 -> 2^16 -> 2^12 -> 2^8.
var friGroupBits = [3]int{16, 12, 8}

// VerifyFRIPhase continues the transcript from the validity state and verifies the FRI proof for the
// given queries, mirroring risc0 verify/fri.rs::fri_verify. It commits the 3 FRI round roots + draws
// their mixes, commits the final-coeffs hash, then per query draws the position and:
//   - Merkle-opens the 4 main tap rows at the position against the committed group roots (M1),
//     ingesting each leaf (F1 canonicality + F2 native<->emulated binding);
//   - computes goal0 = fri_eval_taps over those rows (combo_u is QUERY-INDEPENDENT and computed
//     ONCE here, never per query);
//   - Merkle-opens the 3 FRI column leaves at the folded positions against the round roots;
//   - runs VerifyFRIQuery (3 fold + quotient checks + the final-layer evaluation).
//
// queries must be all QUERIES openings for a complete verification (the transcript draws one
// position per query); a shorter slice verifies a prefix (used by fast tests).
func VerifyFRIPhase(api frontend.API, f *bb.Field, vs *ValidityState, prefix *SealPrefixVars, queries []QueryVars) {
	comboU, tapMixPows, checkMixPows := ComboU(f, vs.CoeffU, vs.FriMix)

	friTops := [3][]frontend.Variable{prefix.FriTops[0], prefix.FriTops[1], prefix.FriTops[2]}
	var roundMixes [3]bb.E4
	for r := 0; r < 3; r++ {
		vs.Tr.Commit(api, MerkleRoot(api, friTops[r]))
		roundMixes[r] = emulExt(f, vs.Tr.RandomExtElem(api))
	}
	finalEmul := ingestSliceEmul(f, prefix.Final)
	vs.Tr.Commit(api, pbls.HashElemSlice(api, prefix.Final))

	groupTops := [4][]frontend.Variable{prefix.AccumTop, prefix.CodeTop, prefix.DataTop, prefix.CheckTop}
	for q := range queries {
		pos := vs.Tr.RandomBits(api, 20)
		posBits := api.ToBinary(pos, 20)
		qv := &queries[q]

		// Main tap rows: ingest + Merkle-verify at the full position against the group roots.
		// rows index = group id (0=accum, 1=code, 2=data); index 3 = the check row.
		var rows [3][]*bb.Elem
		var checkRow []*bb.Elem
		for g := 0; g < 4; g++ {
			leafEmul := ingestSliceEmul(f, qv.MainLeaf[g])
			MerkleVerify(api, pos, 20, qv.MainLeaf[g], qv.MainPath[g], groupTops[g])
			if g < 3 {
				rows[g] = leafEmul
			} else {
				checkRow = leafEmul
			}
		}

		goal0 := FriEvalTaps(f, comboU, checkRow, DeepQueryX(f, posBits), vs.Z, rows, tapMixPows, checkMixPows)

		// FRI column leaves: ingest + Merkle-verify at the folded positions against the round roots.
		var friLeaves [3][]*bb.Elem
		for r := 0; r < 3; r++ {
			leafEmul := ingestSliceEmul(f, qv.FriLeaf[r])
			gb := friGroupBits[r]
			groupPos := api.FromBinary(posBits[:gb]...)
			MerkleVerify(api, groupPos, gb, qv.FriLeaf[r], qv.FriPath[r], friTops[r])
			friLeaves[r] = leafEmul
		}

		VerifyFRIQuery(api, f, pos, goal0, friLeaves, roundMixes, finalEmul)
	}
}

// VerifyReceipt is the full in-circuit verifier: the validity spine (D2 transcript + F1/F2 ingest +
// V1 validity), the FRI phase, and the claim/control public-input binding. It is satisfiable exactly
// when the RISC0 Rust verifier accepts the identity_bls seal these witness values were parsed from
// AND the seal's claim digest equals the public (claimLo, claimHi). The seal-emitted control root
// and program control_id are bound to compile-time constants (BindClaim).
func VerifyReceipt(api frontend.API, f *bb.Field, prefix *SealPrefixVars, queries []QueryVars,
	controlRootLow, controlRootHigh, claimDigestLow, claimDigestHigh, controlID frontend.Variable) {
	vs := VerifyValidity(api, f, prefix)
	VerifyFRIPhase(api, f, vs, prefix, queries)
	BindClaim(api, prefix.Globals, vs.CodeRoot,
		controlRootLow, controlRootHigh, claimDigestLow, claimDigestHigh, controlID)
}
