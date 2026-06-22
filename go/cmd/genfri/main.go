// Command genfri regenerates the FRI KAT fixtures (fri_round_real.json, fri_query_real.json)
// from a single armed RISC0 run, so they attest to the committed testdata/identity_bls/seal.bin.
//
// Provenance (non-circular):
//   - leaves / final-coeffs are raw witness bytes read from the SAME seal.bin via the validated
//     go/stark seal parser (ParsePrefix/ParseQueries) - input data, not computed expectations;
//   - goal0 / fold-goals / mixes / positions / group / quot / rpo2 are RISC0's authoritative
//     values, taken from the verify/fri.rs FRI_GOAL0 + FRI_GOAL trace of the same run.
//
// The fixtures cover query 0 (the first query RISC0 processes; its seal opening is ParseQueries()[0]).
// A consistency check asserts the trace's query-0 position equals transcript bits[0] of the same run.
//
// Usage:  go run ./cmd/genfri <fixture_trace.log>
// (re-run by `make kat-regen` after dumping a fresh seal+trace; see testdata/README.md).
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/pitcon/stark-to-snark-bls/go/stark"
)

const babyBearP = 2013265921

// montDecode mirrors seal.go decodeMont: canonical = m·R⁻¹ mod p, R = 2³² mod p. Used only for
// the goal/mix values dumped by to_u32_words (Montgomery form). Positions are plain u32.
var montRInv = func() int64 {
	r := (int64(1) << 32) % babyBearP
	// modular inverse of r mod p via Fermat (p prime)
	res, base, exp := int64(1), r%babyBearP, int64(babyBearP-2)
	for exp > 0 {
		if exp&1 == 1 {
			res = res * base % babyBearP
		}
		base = base * base % babyBearP
		exp >>= 1
	}
	return res
}()

func montDecode(m uint64) string {
	return strconv.FormatInt(int64(m%babyBearP)*montRInv%babyBearP, 10)
}

var (
	reGoal0 = regexp.MustCompile(`FRI_GOAL0 pos=(\d+) goal=\[(\d+), (\d+), (\d+), (\d+)\]`)
	reGoal  = regexp.MustCompile(`FRI_GOAL \[(\d+), (\d+), (\d+), (\d+)\] group=(\d+) quot=(\d+) rpo2=(\d+) mix=\[(\d+), (\d+), (\d+), (\d+)\]`)
	reBits  = regexp.MustCompile(`TR_BITS (\d+) (\d+)`)
)

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func varStr(v interface{}) string { return fmt.Sprintf("%v", v) }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: genfri <fixture_trace.log>")
		os.Exit(2)
	}
	logPath := os.Args[1]

	// Locate testdata relative to this source file's package (go/cmd/genfri -> go/stark/testdata).
	root := repoGoDir()
	sealPath := filepath.Join(root, "..", "testdata", "identity_bls", "seal.bin")
	outDir := filepath.Join(root, "stark", "testdata")

	seal := readSeal(sealPath)
	prefix, err := stark.ParsePrefix(seal)
	if err != nil {
		panic(err)
	}
	queries, err := stark.ParseQueries(seal)
	if err != nil {
		panic(err)
	}
	q0 := queries[0]

	// --- Parse the RISC0 trace for query 0 (first FRI_GOAL0 + the next three FRI_GOAL). ---
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		panic(err)
	}
	log := string(logBytes)

	g0 := reGoal0.FindStringSubmatch(log)
	if g0 == nil {
		panic("no FRI_GOAL0 line in trace")
	}
	pos0 := mustAtoi(g0[1])
	goal0 := []string{montDecode(parseU64(g0[2])), montDecode(parseU64(g0[3])), montDecode(parseU64(g0[4])), montDecode(parseU64(g0[5]))}

	allGoals := reGoal.FindAllStringSubmatch(log, -1)
	if len(allGoals) < 3 {
		panic("fewer than 3 FRI_GOAL lines in trace")
	}

	// Consistency check: the query-0 position must equal transcript bits[0] of the SAME run.
	bits0 := reBits.FindStringSubmatch(log)
	if bits0 == nil {
		panic("no TR_BITS line in trace")
	}
	if mustAtoi(bits0[2]) != pos0 {
		panic(fmt.Sprintf("FRI query-0 pos %d != transcript bits[0] %d - fixtures from different runs", pos0, mustAtoi(bits0[2])))
	}

	type round struct {
		Goal  []string `json:"goal"`
		Mix   []string `json:"mix"`
		Leaf  []string `json:"leaf"`
		Group int      `json:"group"`
		Quot  int      `json:"quot"`
		Rpo2  int      `json:"rpo2"`
	}
	rounds := map[string]round{}
	var mixes [3][]string
	var leaves [3][]string
	for r := 0; r < 3; r++ {
		m := allGoals[r]
		goal := []string{montDecode(parseU64(m[1])), montDecode(parseU64(m[2])), montDecode(parseU64(m[3])), montDecode(parseU64(m[4]))}
		mix := []string{montDecode(parseU64(m[8])), montDecode(parseU64(m[9])), montDecode(parseU64(m[10])), montDecode(parseU64(m[11]))}
		leaf := make([]string, 64)
		for i := 0; i < 64; i++ {
			leaf[i] = varStr(q0.FriLeaf[r][i])
		}
		rounds[strconv.Itoa(r)] = round{
			Goal: goal, Mix: mix, Leaf: leaf,
			Group: mustAtoi(m[5]), Quot: mustAtoi(m[6]), Rpo2: mustAtoi(m[7]),
		}
		mixes[r] = mix
		leaves[r] = leaf
	}

	writeJSON(filepath.Join(outDir, "fri_round_real.json"), rounds)

	final := make([]string, len(prefix.Final))
	for i := range prefix.Final {
		final[i] = varStr(prefix.Final[i])
	}
	query := map[string]interface{}{
		"pos0":   pos0,
		"goal0":  goal0,
		"leaves": leaves,
		"mixes":  mixes,
		"final":  final,
	}
	writeJSON(filepath.Join(outDir, "fri_query_real.json"), query)

	fmt.Printf("wrote fri_round_real.json + fri_query_real.json: pos0=%d (== transcript bits[0]), 3 rounds, final=%d\n", pos0, len(final))
}

func parseU64(s string) uint64 {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		panic(err)
	}
	return n
}

func readSeal(path string) []uint32 {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	if len(b)%4 != 0 {
		panic("seal.bin length not a multiple of 4")
	}
	out := make([]uint32, len(b)/4)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	return out
}

func writeJSON(path string, v interface{}) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
}

// repoGoDir returns the absolute path of the go/ module directory (parent of cmd/genfri).
func repoGoDir() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	// `go run ./cmd/genfri` executes with CWD = module dir (go/).
	if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
		return wd
	}
	panic("run from the go/ module directory (go run ./cmd/genfri <log>)")
}
