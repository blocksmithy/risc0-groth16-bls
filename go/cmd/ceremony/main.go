// Command ceremony drives a Groth16 Phase-1 + Phase-2 MPC trusted setup for the frozen
// stark-to-snark-bls circuit (stark.ReceiptTemplate(50)), using gnark's mpcsetup. It produces the
// SAME key files groth16bls consumes (ccs/pk/vk.bin + vk.cardano.bin), but with NO known toxic
// waste: the setup is sound as long as at least one contributor honestly discarded their secret.
//
// Security model: the trapdoor is the product of every contributor's secret;
// one honest contributor who securely destroys theirs makes it unrecoverable. Diversity of
// contributors + a public closing beacon + a published, verifiable transcript are what make it
// credible to outsiders.
//
// Subcommands (file-passing protocol; pass each .bin between participants):
//
//	PHASE 1 (universal powers of tau; circuit-independent, reusable):
//	  phase1-init      --power N --out p1_0000.bin
//	  phase1-contribute --in PREV.bin --out NEXT.bin                 (each participant; secret is internal+discarded)
//	  phase1-seal      --power N --beacon HEX --out commons.bin  C1.bin C2.bin ... CN.bin
//
//	PHASE 2 (circuit-specific; keys THIS circuit):
//	  phase2-init      --commons commons.bin --out p2_0000.bin
//	  phase2-contribute --in PREV.bin --out NEXT.bin                 (each participant)
//	  phase2-finalize  --commons commons.bin --beacon HEX --keys DIR  C1.bin C2.bin ... CN.bin
//
//	verify-circuit     --keys DIR        (recompute the circuit fingerprint; compare to circuit_id.json)
//
// The beacon is a public random value of moderate entropy fixed AFTER the last contribution (e.g. a
// pre-announced future Bitcoin block hash, or a drand round). Same beacon must be used by everyone
// verifying.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	mpcsetup "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"

	"github.com/pitcon/stark-to-snark-bls/go/serialize"
	"github.com/pitcon/stark-to-snark-bls/go/stark"
)

// nQueries MUST match groth16bls (the production circuit). Keep in sync.
const nQueries = 50

func main() {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger())
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "phase1-init":
		phase1Init(os.Args[2:])
	case "phase1-contribute":
		phase1Contribute(os.Args[2:])
	case "phase1-seal":
		phase1Seal(os.Args[2:])
	case "phase2-init":
		phase2Init(os.Args[2:])
	case "phase2-contribute":
		phase2Contribute(os.Args[2:])
	case "phase2-finalize":
		phase2Finalize(os.Args[2:])
	case "verify-circuit":
		verifyCircuit(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ceremony <phase1-init|phase1-contribute|phase1-seal|"+
		"phase2-init|phase2-contribute|phase2-finalize|verify-circuit> [flags]")
	os.Exit(2)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ceremony: "+format+"\n", a...)
	os.Exit(1)
}

// compileCircuit compiles the frozen production circuit and returns the BLS12-381 R1CS.
func compileCircuit() *cs.R1CS {
	t := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, stark.ReceiptTemplate(nQueries))
	if err != nil {
		die("compile circuit: %v", err)
	}
	fmt.Fprintf(os.Stderr, "compiled circuit: %d constraints in %s\n", ccs.GetNbConstraints(), time.Since(t).Round(time.Second))
	r, ok := ccs.(*cs.R1CS)
	if !ok {
		die("unexpected constraint-system type %T (want *bls12-381.R1CS)", ccs)
	}
	return r
}

func readFrom(path string, v io.ReaderFrom) {
	f, err := os.Open(path)
	if err != nil {
		die("open %s: %v", path, err)
	}
	defer f.Close()
	if _, err := v.ReadFrom(f); err != nil {
		die("read %s: %v", path, err)
	}
}

func writeTo(path string, v io.WriterTo) {
	f, err := os.Create(path)
	if err != nil {
		die("create %s: %v", path, err)
	}
	if _, err := v.WriteTo(f); err != nil {
		_ = f.Close()
		die("write %s: %v", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		die("sync %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		die("close %s: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", path)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		die("--beacon must be a non-empty hex string (a public random beacon fixed AFTER the last contribution)")
	}
	return b
}

// ---- Phase 1 ----

func phase1Init(args []string) {
	fs := flag.NewFlagSet("phase1-init", flag.ExitOnError)
	power := fs.Uint64("power", 0, "log2 of the SRS size; must be >= log2(circuit constraints). For the production circuit use 23 (2^23 >= 4.58M).")
	out := fs.String("out", "p1_0000.bin", "output: the initial (uncontributed) Phase1 state")
	_ = fs.Parse(args)
	if *power == 0 {
		die("--power is required (production circuit needs 23)")
	}
	n := uint64(1) << *power
	fmt.Fprintf(os.Stderr, "initializing Phase1 SRS for 2^%d = %d\n", *power, n)
	var p1 mpcsetup.Phase1
	p1.Initialize(n)
	writeTo(*out, &p1)
	fmt.Fprintln(os.Stderr, "OK - distribute this to the first contributor.")
}

func phase1Contribute(args []string) {
	fs := flag.NewFlagSet("phase1-contribute", flag.ExitOnError)
	in := fs.String("in", "", "previous Phase1 state (from the prior contributor or phase1-init)")
	out := fs.String("out", "", "your contributed Phase1 state (pass to the next contributor)")
	_ = fs.Parse(args)
	if *in == "" || *out == "" {
		die("--in and --out are required")
	}
	var p1 mpcsetup.Phase1
	readFrom(*in, &p1)
	fmt.Fprintln(os.Stderr, "contributing (generating + folding in fresh secret randomness)...")
	p1.Contribute() // secret randomness is generated internally and dropped when this returns
	writeTo(*out, &p1)
	fmt.Fprintln(os.Stderr, "OK - your secret was used and discarded with this process. Pass --out to the next contributor.")
}

func phase1Seal(args []string) {
	fs := flag.NewFlagSet("phase1-seal", flag.ExitOnError)
	power := fs.Uint64("power", 0, "log2 SRS size used at init (must match)")
	beacon := fs.String("beacon", "", "public random beacon (hex), fixed AFTER the last contribution")
	out := fs.String("out", "commons.bin", "output: the sealed phase-1 SrsCommons (input to phase 2)")
	_ = fs.Parse(args)
	contribs := fs.Args()
	if *power == 0 || *beacon == "" || len(contribs) == 0 {
		die("--power, --beacon and at least one contribution file are required")
	}
	n := uint64(1) << *power
	ps := make([]*mpcsetup.Phase1, len(contribs))
	for i, c := range contribs {
		ps[i] = new(mpcsetup.Phase1)
		readFrom(c, ps[i])
	}
	fmt.Fprintf(os.Stderr, "verifying %d phase-1 contributions + applying beacon...\n", len(ps))
	commons, err := mpcsetup.VerifyPhase1(n, mustHex(*beacon), ps...)
	if err != nil {
		die("phase-1 verification FAILED: %v", err)
	}
	writeTo(*out, &commons)
	fmt.Fprintln(os.Stderr, "OK - phase 1 sealed. This SrsCommons is circuit-independent and reusable.")
}

// ---- Phase 2 ----

func phase2Init(args []string) {
	fs := flag.NewFlagSet("phase2-init", flag.ExitOnError)
	commonsPath := fs.String("commons", "commons.bin", "sealed phase-1 commons")
	out := fs.String("out", "p2_0000.bin", "output: the initial (uncontributed) Phase2 state")
	_ = fs.Parse(args)
	var commons mpcsetup.SrsCommons
	readFrom(*commonsPath, &commons)
	r := compileCircuit()
	var p2 mpcsetup.Phase2
	_ = p2.Initialize(r, &commons) // evals are recomputed at finalize; not persisted
	writeTo(*out, &p2)
	fmt.Fprintln(os.Stderr, "OK - distribute this to the first phase-2 contributor.")
}

func phase2Contribute(args []string) {
	fs := flag.NewFlagSet("phase2-contribute", flag.ExitOnError)
	in := fs.String("in", "", "previous Phase2 state")
	out := fs.String("out", "", "your contributed Phase2 state")
	_ = fs.Parse(args)
	if *in == "" || *out == "" {
		die("--in and --out are required")
	}
	var p2 mpcsetup.Phase2
	readFrom(*in, &p2)
	fmt.Fprintln(os.Stderr, "contributing (generating + folding in fresh secret randomness)...")
	p2.Contribute()
	writeTo(*out, &p2)
	fmt.Fprintln(os.Stderr, "OK - your secret was used and discarded with this process. Pass --out to the next contributor.")
}

func phase2Finalize(args []string) {
	fs := flag.NewFlagSet("phase2-finalize", flag.ExitOnError)
	commonsPath := fs.String("commons", "commons.bin", "sealed phase-1 commons")
	beacon := fs.String("beacon", "", "public random beacon (hex), fixed AFTER the last phase-2 contribution")
	keys := fs.String("keys", "", "output keys dir (writes ccs/pk/vk.bin + vk.cardano.bin)")
	_ = fs.Parse(args)
	contribs := fs.Args()
	if *beacon == "" || *keys == "" || len(contribs) == 0 {
		die("--commons, --beacon, --keys and at least one contribution file are required")
	}
	var commons mpcsetup.SrsCommons
	readFrom(*commonsPath, &commons)
	r := compileCircuit()
	ps := make([]*mpcsetup.Phase2, len(contribs))
	for i, c := range contribs {
		ps[i] = new(mpcsetup.Phase2)
		readFrom(c, ps[i])
	}
	fmt.Fprintf(os.Stderr, "verifying %d phase-2 contributions + applying beacon -> deriving pk/vk...\n", len(ps))
	pk, vk, err := mpcsetup.VerifyPhase2(r, &commons, mustHex(*beacon), ps...)
	if err != nil {
		die("phase-2 verification FAILED: %v", err)
	}

	if err := os.MkdirAll(*keys, 0o755); err != nil {
		die("mkdir keys dir: %v", err)
	}
	// Re-serialize the constraint system so the keys dir is self-contained for groth16bls.
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, stark.ReceiptTemplate(nQueries))
	if err != nil {
		die("recompile ccs: %v", err)
	}
	writeTo(filepath.Join(*keys, "ccs.bin"), ccs)
	writeTo(filepath.Join(*keys, "pk.bin"), pk)
	writeTo(filepath.Join(*keys, "vk.bin"), vk)
	cvk, ok := vk.(*groth16bls.VerifyingKey)
	if !ok {
		die("unexpected vk type %T", vk)
	}
	if _, err := serialize.WriteCardanoVK(filepath.Join(*keys, "vk.cardano.bin"), cvk); err != nil {
		die("write vk.cardano.bin: %v", err)
	}
	// NO INSECURE_DEV marker: these are ceremony keys.

	// The fingerprint groth16bls' production gate checks: sha256(canonical Cardano encoding of vk).
	fp := cardanoVKSHA256(cvk)
	fmt.Fprintf(os.Stderr, "\nCEREMONY COMPLETE. Keys written to %s (NO dev marker).\n", *keys)
	fmt.Fprintf(os.Stderr, "Set this so the prover accepts ONLY these keys:\n  export RISC0_GROTH16_BLS_VK_SHA256=%s\n", fp)
	fmt.Println(fp)
}

func cardanoVKSHA256(vk *groth16bls.VerifyingKey) string {
	var buf vkBuf
	if err := serialize.EncodeCardanoVK(&buf, vk); err != nil {
		die("encode cardano vk: %v", err)
	}
	h := sha256.Sum256(buf.b)
	return hex.EncodeToString(h[:])
}

type vkBuf struct{ b []byte }

func (w *vkBuf) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }

// verifyCircuit recompiles the frozen circuit and prints its fingerprint so the coordinator can
// confirm (against circuit_id.json) that the ceremony keyed the right circuit.
func verifyCircuit(args []string) {
	fs := flag.NewFlagSet("verify-circuit", flag.ExitOnError)
	_ = fs.Parse(args)
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, stark.ReceiptTemplate(nQueries))
	if err != nil {
		die("compile: %v", err)
	}
	h := sha256.New()
	if _, err := ccs.WriteTo(h); err != nil {
		die("serialize: %v", err)
	}
	fmt.Fprintf(os.Stderr, "constraints=%d\n", ccs.GetNbConstraints())
	fmt.Fprintf(os.Stderr, "ccs_sha256=%s  (compare to circuit_id.json)\n", hex.EncodeToString(h.Sum(nil)))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
}
