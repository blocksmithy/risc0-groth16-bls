package stark

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Seal size + po2 for the supported identity_bls recursion receipt (po2=18). RISC0 rejects any
// seal of a different size or with trailing data (read_iop.rs verify_complete) and any po2 >
// MAX_CYCLES_PO2; we mirror that exactly - no lenient parsing. The total is
// queryStart + QUERIES·queryWords = 4717 + 50·1019.
const (
	sealWordsPo2_18 = queryStart + 50*queryWords // 55667
	expectedPo2     = 18
)

// ValidateSeal checks the seal is well-formed for the supported po2=18 recursion receipt: exactly
// the expected length (rejecting both truncation and trailing data) and a committed po2 of 18. It
// returns a descriptive error and never panics, so it is safe on fully adversarial input
// ParsePrefix/ParseQueries call it before indexing.
func ValidateSeal(seal []uint32) error {
	if len(seal) != sealWordsPo2_18 {
		return fmt.Errorf("malformed seal: length %d words, expected exactly %d (po2=18); truncated or trailing data rejected", len(seal), sealWordsPo2_18)
	}
	// globals[32] holds the po2. RISC0 reads it via to_u32_words() (the raw word self.0), NOT the
	// canonical decode - read_slice_with_po2 in verify/mod.rs. So the po2 is the raw seal word.
	if po2 := seal[nGlobals-1]; po2 != expectedPo2 {
		return fmt.Errorf("malformed seal: committed po2 = %d, expected %d", po2, expectedPo2)
	}
	return nil
}

// Seal field-element / digest decoding (off-circuit witness preparation).
//
// RISC0 reads seal field elements via from_u32_words(val) = Self(val[0]), i.e. the seal stores
// BabyBear elements in MONTGOMERY form (self.0). hash_elem_slice uses as_u32() = decode(self.0),
// so the canonical value fed to the hash is decode(m) = m·R⁻¹ mod p, R = 2³² mod p
// (risc0 core/src/field/baby_bear.rs). Digests are read via read_pod_slice (raw [u32;8]) and
// interpreted as the little-endian 32-byte field representation (digest_to_fr), with no decode.
var (
	babyBearP = big.NewInt(2013265921)
	montRInv  *big.Int
)

func init() {
	r := new(big.Int).Mod(new(big.Int).Lsh(big.NewInt(1), 32), babyBearP)
	montRInv = new(big.Int).ModInverse(r, babyBearP)
}

// decodeMont converts a Montgomery-form seal word to the canonical BabyBear value.
func decodeMont(m uint32) frontend.Variable {
	v := new(big.Int).Mul(big.NewInt(int64(m)), montRInv)
	return v.Mod(v, babyBearP)
}

// digestFromWords interprets 8 consecutive u32 (little-endian within each word) as the
// 32-byte little-endian field representation of a poseidon_bls digest (an Fr value).
func digestFromWords(w []uint32) frontend.Variable {
	var b [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(b[4*i:], w[i])
	}
	// b is little-endian; SetBytes wants big-endian, so reverse.
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return new(big.Int).SetBytes(b[:])
}

// SealPrefix holds the parsed, witness-ready prefix of an identity_bls seal (everything read
// before the 50 query openings): globals, the four register/check group top rows, the DEEP-ALI
// U coefficients, the FRI round top rows, and the FRI final-layer coefficients. Field elements
// are canonical BabyBear values; group/FRI tops are Fr digests. Sizes are for the recursion
// circuit at po2=18 (domain 2²⁰): top_size=32, U=659 Fp4, 3 FRI rounds, final=256.
type SealPrefix struct {
	Globals  []frontend.Variable // 33 canonical (out[32] + po2)
	CodeTop  []frontend.Variable // 32 digests
	DataTop  []frontend.Variable
	AccumTop []frontend.Variable
	CheckTop []frontend.Variable
	UCoeffs  []frontend.Variable   // 659*4 = 2636 canonical (Fp4 subelements, flattened)
	FriTops  [][]frontend.Variable // 3 × 32 digests
	Final    []frontend.Variable   // 256 canonical
}

// prefixLayout is the fixed word layout of the seal prefix (recursion, po2=18). Each Merkle
// top row is 32 digests × 8 words = 256 words.
const (
	nGlobals  = 33
	topWords  = 32 * 8 // 256
	nUCoeffs  = 659 * 4
	nFinal    = 256
	nFriRound = 3
)

// ParsePrefix splits the seal's fixed prefix into witness-ready pieces (the query openings that
// follow are parsed separately). It mirrors RISC0's read order in verify::verify exactly. It
// validates the seal first (ValidateSeal) and returns an error rather than panicking on malformed
// input.
func ParsePrefix(seal []uint32) (SealPrefix, error) {
	if err := ValidateSeal(seal); err != nil {
		return SealPrefix{}, err
	}
	off := 0
	readField := func(n int) []frontend.Variable {
		out := make([]frontend.Variable, n)
		for i := 0; i < n; i++ {
			out[i] = decodeMont(seal[off+i])
		}
		off += n
		return out
	}
	readTop := func() []frontend.Variable {
		out := make([]frontend.Variable, 32)
		for i := 0; i < 32; i++ {
			out[i] = digestFromWords(seal[off+8*i : off+8*i+8])
		}
		off += topWords
		return out
	}

	var p SealPrefix
	p.Globals = readField(nGlobals)
	p.CodeTop = readTop()
	p.DataTop = readTop()
	p.AccumTop = readTop()
	p.CheckTop = readTop()
	p.UCoeffs = readField(nUCoeffs)
	p.FriTops = make([][]frontend.Variable, nFriRound)
	for r := 0; r < nFriRound; r++ {
		p.FriTops[r] = readTop()
	}
	p.Final = readField(nFinal)
	return p, nil
}

// QueryOpening holds one query's openings, in RISC0's read order: the four main-group opens
// (accum, code, data, check - each a col_size leaf + 15-sibling path to the group's top row),
// then the three FRI-round opens (each a 64-element leaf + a round-specific path). Leaves are
// canonical BabyBear values; paths are Fr digests.
type QueryOpening struct {
	MainLeaf [4][]frontend.Variable // accum(12), code(23), data(128), check(16)
	MainPath [4][]frontend.Variable // each 15 digests
	FriLeaf  [3][]frontend.Variable // each 64
	FriPath  [3][]frontend.Variable // 11, 7, 3 digests
}

// Per-query word layout (recursion, po2=18), all sizes fixed.
const (
	queryStart = 4717
	queryWords = 1019
)

var (
	mainCols = [4]int{12, 23, 128, 16}
	mainPath = 15
	friPath  = [3]int{11, 7, 3}
	friCol   = 64
)

// ParseQueries splits the seal's query-opening region into 50 QueryOpenings, mirroring the read
// order in fri_verify (inner: accum/code/data/check via merkle_verifiers.iter() then check; then
// per-FRI-round verify_query). The query positions come from the transcript (random_bits), not
// the seal.
func ParseQueries(seal []uint32) ([]QueryOpening, error) {
	if err := ValidateSeal(seal); err != nil {
		return nil, err
	}
	digestsAt := func(off, n int) []frontend.Variable {
		out := make([]frontend.Variable, n)
		for i := 0; i < n; i++ {
			out[i] = digestFromWords(seal[off+8*i : off+8*i+8])
		}
		return out
	}
	fieldsAt := func(off, n int) []frontend.Variable {
		out := make([]frontend.Variable, n)
		for i := 0; i < n; i++ {
			out[i] = decodeMont(seal[off+i])
		}
		return out
	}

	out := make([]QueryOpening, 50)
	for q := 0; q < 50; q++ {
		base := queryStart + q*queryWords
		off := base
		var qo QueryOpening
		for g := 0; g < 4; g++ {
			qo.MainLeaf[g] = fieldsAt(off, mainCols[g])
			off += mainCols[g]
			qo.MainPath[g] = digestsAt(off, mainPath)
			off += mainPath * 8
		}
		for r := 0; r < 3; r++ {
			qo.FriLeaf[r] = fieldsAt(off, friCol)
			off += friCol
			qo.FriPath[r] = digestsAt(off, friPath[r])
			off += friPath[r] * 8
		}
		out[q] = qo
	}
	return out, nil
}
