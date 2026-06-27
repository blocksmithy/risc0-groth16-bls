// Command groth16bls is the BLS12-381 Groth16 prover for RISC0 identity_bls seals - the gnark
// analogue of rapidsnark in RISC0's BN254 stark2snark path. RISC0's host invokes it as a subprocess
// (ReceiptKind::Groth16Bls): it takes a seal, proves the VerifyReceipt circuit, and writes the proof
// + the 5 public inputs (risc0 schema). It is NOT a standalone product - it is the proving backend.
//
// Subcommands:
//
//	setup --dev          compile + INSECURE dev Setup -> write ccs/pk/vk to the keys dir (+DEV marker)
//	prove --seal s.bin   load keys, prove the seal, write proof.bin + public.bin
//	circuit-id [--check] print the frozen-circuit fingerprint (sha256 of the R1CS the ceremony keys);
//	                     --check <pin.json> fails on drift.
//
// Keys directory (the "component dir"): --keys flag > $RISC0_GROTH16_BLS_HOME > ~/.risc0/groth16-bls.
// Holds ccs.bin, pk.bin, vk.bin (+ an INSECURE_DEV marker for dev keys).
//
// Dev-mode gating (per the integration contract): a real `prove` (no --dev) fails CLOSED before the
// costly proof - it proves only if the SHA-256 of the canonical Cardano-v2 encoding of the keys'
// vk.bin equals the pinned ceremony value in $RISC0_GROTH16_BLS_VK_SHA256. It fingerprints the
// actual proving VK (not a standalone, desyncable vk.cardano.bin file, and not the absence of a
// marker), and the post-prove self-verify ties pk.bin to that VK - so toxic-waste dev keys cannot
// be used for a production proof.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"

	"github.com/pitcon/stark-to-snark-bls/go/keys"
	"github.com/pitcon/stark-to-snark-bls/go/serialize"
	"github.com/pitcon/stark-to-snark-bls/go/stark"
)

const (
	nQueries  = 50 // full verification (all FRI queries)
	nPublic   = 5  // risc0 5-input schema (control_root_lo/hi, claim_digest_lo/hi, control_id)
	devMarker = "INSECURE_DEV"
	ccsFile   = "ccs.bin"
	pkFile    = "pk.bin"
	vkFile    = "vk.bin"
	// ceremonyVKEnv pins the SHA-256 (hex) of the canonical Cardano-v2 encoding of the trusted
	// ceremony verifying key. A non-dev prove fails closed unless the keys' vk.bin canonicalizes to
	// this value.
	ceremonyVKEnv = "RISC0_GROTH16_BLS_VK_SHA256"
)

func main() {
	// Silent by default (keeps stdout machine-clean). GROTH16BLS_VERBOSE=1 enables gnark's logger,
	// which surfaces the ICICLE GPU backend's device warm-up ("ICICLE … CUDA device") - the visible
	// evidence that the prove ran on the GPU rather than the CPU fallback.
	if os.Getenv("GROTH16BLS_VERBOSE") == "1" {
		logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger())
	} else {
		logger.Set(zerolog.Nop())
	}
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "setup":
		cmdSetup(os.Args[2:])
	case "prove":
		cmdProve(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "circuit-id":
		cmdCircuitID(os.Args[2:])
	case "emit-ccs":
		cmdEmitCCS(os.Args[2:])
	case "dump":
		cmdDump(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: groth16bls <setup|prove|verify|circuit-id|emit-ccs|dump> [flags]")
	os.Exit(2)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "groth16bls: "+format+"\n", a...)
	os.Exit(1)
}

// keysDir resolves the component dir: --keys flag > $RISC0_GROTH16_BLS_HOME > ~/.risc0/groth16-bls.
func keysDir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if e := os.Getenv("RISC0_GROTH16_BLS_HOME"); e != "" {
		return e
	}
	home, err := os.UserHomeDir()
	if err != nil {
		die("cannot resolve home dir for default keys location: %v", err)
	}
	return filepath.Join(home, ".risc0", "groth16-bls")
}

func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	keys := fs.String("keys", "", "keys/component dir (default: $RISC0_GROTH16_BLS_HOME or ~/.risc0/groth16-bls)")
	dev := fs.Bool("dev", false, "INSECURE dev setup (toxic waste in-memory) - for risc0 dev mode only")
	_ = fs.Parse(args)
	dir := keysDir(*keys)
	if !*dev {
		die("non-dev setup is unsupported: production keys come from the Phase-2 MPC ceremony and must "+
			"be placed in %s (ccs.bin/pk.bin/vk.bin). Use --dev for an insecure dev setup.", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		die("mkdir keys dir: %v", err)
	}

	t := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, stark.ReceiptTemplate(nQueries))
	if err != nil {
		die("compile: %v", err)
	}
	fmt.Fprintf(os.Stderr, "compiled %d constraints in %s\n", ccs.GetNbConstraints(), time.Since(t).Round(time.Second))

	t = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		die("setup: %v", err)
	}
	fmt.Fprintf(os.Stderr, "INSECURE dev setup done in %s (toxic waste is known - NOT for production)\n", time.Since(t).Round(time.Second))

	writeTo(filepath.Join(dir, ccsFile), ccs)
	writeTo(filepath.Join(dir, pkFile), pk)
	writeTo(filepath.Join(dir, vkFile), vk)
	if _, err := serialize.WriteCardanoVK(filepath.Join(dir, "vk.cardano.bin"), vk.(*groth16bls.VerifyingKey)); err != nil {
		die("write vk.cardano.bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, devMarker), []byte("insecure dev keys; do not use for production proofs\n"), 0o644); err != nil {
		die("write dev marker: %v", err)
	}
	fmt.Printf("wrote dev keys to %s (ccs/pk/vk + vk.cardano.bin + %s)\n", dir, devMarker)
}

func cmdProve(args []string) {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	keysDirFlag := fs.String("keys", "", "explicit keys dir (advanced; overrides the built-in manifest)")
	keySet := fs.String("key", "", "manifest key-set to use (default: the active one)")
	seal := fs.String("seal", "", "path to the identity_bls seal.bin")
	out := fs.String("out", ".", "output dir for proof.bin + public.bin")
	dev := fs.Bool("dev", false, "allow INSECURE dev keys (risc0 dev mode)")
	_ = fs.Parse(args)
	if *seal == "" {
		die("--seal is required")
	}

	// Resolve the verifying key (loaded) plus the constraint-system and proving-key paths.
	// Three modes:
	//   default      committed vk + pk/ccs fetched from the manifest's active key-set
	//                (SHA-256-verified, cached). No flags, no env var, no dev key.
	//   --key NAME   same, selecting a different key-set from the manifest.
	//   --keys DIR   an explicit keys dir (advanced/custom keys); --dev allows insecure dev keys.
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	var ccsPath, pkPath string

	if *keysDirFlag != "" || *dev {
		dir := keysDir(*keysDirFlag)
		if !haveKeys(dir) {
			if *dev {
				die("no keys at %s - run: groth16bls setup --dev --keys %s", dir, dir)
			}
			die("no Groth16 keys at %s - omit --keys to use the built-in manifest, run a ceremony, or use --dev", dir)
		}
		readFrom(filepath.Join(dir, vkFile), vk)
		if !*dev {
			// FAIL CLOSED against an explicit dir: it must match the ceremony VK pinned in $ENV
			// (the canonical Cardano-v2 encoding of THIS vk.bin).
			want := strings.ToLower(strings.TrimSpace(os.Getenv(ceremonyVKEnv)))
			if want == "" {
				die("production proving from --keys requires the ceremony VK fingerprint in $%s "+
					"(or omit --keys to use the built-in manifest)", ceremonyVKEnv)
			}
			if got := sha256Hex(cardanoVKBytes(vk)); got != want {
				die("keys at %s do NOT match the ceremony VK pinned in $%s\n  want %s\n  got  %s\n"+
					"refusing to prove with an untrusted (possibly INSECURE dev) key", dir, ceremonyVKEnv, want, got)
			}
		}
		ccsPath = filepath.Join(dir, ccsFile)
		pkPath = filepath.Join(dir, pkFile)
	} else {
		man, err := keys.Load()
		if err != nil {
			die("%v", err)
		}
		ks, err := man.Resolve(*keySet)
		if err != nil {
			die("%v", err)
		}
		fmt.Fprintf(os.Stderr, "key-set %q (%d-participant ceremony, finalized %s)\n",
			ks.Name, ks.Ceremony.Participants, ks.Ceremony.Finalized)
		// The verifying key is committed (embedded). Its Cardano encoding must match the manifest's
		// pinned gate value ($ENV overrides) - this binds the binary to the published key.
		vkBytes, err := ks.VKBytes()
		if err != nil {
			die("read embedded vk: %v", err)
		}
		if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
			die("parse embedded vk: %v", err)
		}
		want := strings.ToLower(strings.TrimSpace(os.Getenv(ceremonyVKEnv)))
		if want == "" {
			want = ks.VKGateSHA256
		}
		if got := sha256Hex(cardanoVKBytes(vk)); got != want {
			die("embedded vk for key-set %q does NOT match the pinned gate value\n  want %s\n  got  %s",
				ks.Name, want, got)
		}
		// The proving key + constraint system are fetched on first use, SHA-256-verified, cached.
		cache, err := ks.CacheDir("")
		if err != nil {
			die("%v", err)
		}
		logf := func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
		if ccsPath, err = ks.EnsureCCS(cache, logf); err != nil {
			die("%v", err)
		}
		if pkPath, err = ks.EnsurePK(cache, logf); err != nil {
			die("%v", err)
		}
	}

	ccs := groth16.NewCS(ecc.BLS12_381)
	tCcs := time.Now()
	readFrom(ccsPath, ccs)
	fmt.Fprintf(os.Stderr, "ccs loaded in %s\n", time.Since(tCcs).Round(time.Millisecond))
	pk := newProvingKey() // CPU or ICICLE pk type, per build tag
	loadProvingKey(pk, pkPath)

	sealWords := readSeal(*seal)
	assignment, err := stark.AssignReceipt(sealWords, nQueries)
	if err != nil {
		die("assign witness from seal: %v", err)
	}
	fullWit, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		die("witness: %v", err)
	}
	pubWit, err := fullWit.Public()
	if err != nil {
		die("public witness: %v", err)
	}

	t := time.Now()
	proof, err := proveBackend(ccs, pk, fullWit) // CPU, or GPU under -tags icicle
	if err != nil {
		die("prove: %v", err)
	}
	fmt.Fprintf(os.Stderr, "proved (%s) in %s\n", proverBackend, time.Since(t).Round(time.Millisecond))

	if err := groth16.Verify(proof, vk, pubWit); err != nil {
		die("self-verify failed (this should never happen): %v", err)
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		die("mkdir out: %v", err)
	}
	// gnark-native (canonical, round-trippable) ...
	writeTo(filepath.Join(*out, "proof.bin"), proof)
	writeTo(filepath.Join(*out, "public.bin"), pubWit)
	// ... plus Cardano-minimal v2 (commitment-aware on-chain format).
	if _, err := serialize.WriteCardanoProof(filepath.Join(*out, "proof.cardano.bin"), proof.(*groth16bls.Proof)); err != nil {
		die("write proof.cardano.bin: %v", err)
	}
	if _, err := serialize.WriteCardanoPublic(filepath.Join(*out, "public.cardano.bin"), pubWit, nPublic, serialize.NLimbsPerScalarNative); err != nil {
		die("write public.cardano.bin: %v", err)
	}
	// vk.cardano.bin too, so the out dir is self-contained for the on-chain verifier.
	if _, err := serialize.WriteCardanoVK(filepath.Join(*out, "vk.cardano.bin"), vk.(*groth16bls.VerifyingKey)); err != nil {
		die("write vk.cardano.bin: %v", err)
	}
	fmt.Printf("wrote proof.bin/public.bin (gnark) + proof/public/vk.cardano.bin (v2) to %s "+
		"(5 public inputs, risc0 schema, nC=1)\n", *out)
}

// cmdVerify checks a gnark-native proof.bin against vk.bin + public.bin. RISC0's Groth16Bls
// verify_integrity shells out to this (same Go-binary contract as prove), so we never duplicate
// the gnark verifier in Rust. The authoritative on-chain check is the Aiken/Cardano verifier.
func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keys := fs.String("keys", "", "keys/component dir (for vk.bin, if --vk not given)")
	vkPath := fs.String("vk", "", "path to vk.bin (default: <keys>/vk.bin)")
	proofPath := fs.String("proof", "", "path to proof.bin (gnark-native)")
	pubPath := fs.String("public", "", "path to public.bin (gnark-native)")
	_ = fs.Parse(args)
	if *proofPath == "" || *pubPath == "" {
		die("--proof and --public are required")
	}
	vkp := *vkPath
	if vkp == "" {
		vkp = filepath.Join(keysDir(*keys), vkFile)
	}

	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	readFrom(vkp, vk)
	proof := groth16.NewProof(ecc.BLS12_381)
	readFrom(*proofPath, proof)
	pubWit, err := witness.New(ecc.BLS12_381.ScalarField())
	if err != nil {
		die("new witness: %v", err)
	}
	readFrom(*pubPath, pubWit)

	if err := groth16.Verify(proof, vk, pubWit); err != nil {
		die("VERIFY FAILED: %v", err)
	}
	fmt.Println("OK: proof verifies against vk + public (5 inputs, risc0 schema)")
}

// ---- key-dir helpers ----

func haveKeys(dir string) bool {
	for _, f := range []string{ccsFile, pkFile, vkFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return false
		}
	}
	return true
}

// sha256Hex returns the lowercase hex SHA-256 of bytes.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// cardanoVKBytes returns the canonical Cardano-v2 encoding of a verifying key - the form the
// production fingerprint and the receipt's verifier_parameters are both taken over.
func cardanoVKBytes(vk groth16.VerifyingKey) []byte {
	var buf bytes.Buffer
	if err := serialize.EncodeCardanoVK(&buf, vk.(*groth16bls.VerifyingKey)); err != nil {
		die("encode vk for fingerprint: %v", err)
	}
	return buf.Bytes()
}

// ---- gnark (de)serialization (canonical WriteTo/ReadFrom) ----

func writeTo(path string, v io.WriterTo) {
	f, err := os.Create(path)
	if err != nil {
		die("create %s: %v", path, err)
	}
	if _, err := v.WriteTo(f); err != nil {
		_ = f.Close()
		die("write %s: %v", path, err)
	}
	// fsync + a checked Close so a crash or a deferred write-back error can't leave a silently
	// truncated key/proof file that later "looks" present.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		die("sync %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		die("close %s: %v", path, err)
	}
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

// ---- fast proving-key load (gnark raw dump; no point decompression) ----
//
// ReadFrom/WriteTo are the canonical COMPRESSED format: each curve point is decompressed on
// load (a sqrt per point), which for a multi-million-constraint key is minutes of CPU. gnark's
// WriteDump/ReadDump are a RAW memory dump — no decompression — loading in seconds. The ICICLE
// proving key inherits both from its embedded gnark base key (provingkey.go embeds
// groth16_bls12381.ProvingKey), so this works for both the CPU and the -tags icicle build.

type dumpReadable interface{ ReadDump(io.Reader) error }
type dumpWritable interface{ WriteDump(io.Writer) error }

// dumpFormatTag is the first token of a dump header; bump it to invalidate older dumps wholesale.
const dumpFormatTag = "risc0-groth16bls-dump1"

// gnarkVersion reports the gnark module version this binary was built against. A raw dump made by a
// different gnark may have a different in-memory layout, so it is part of the dump's identity.
func gnarkVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/consensys/gnark" {
				return d.Version
			}
		}
	}
	return "unknown"
}

// dumpHeader is the one-line, self-describing header written at the front of a `<pk>.dump`. gnark's raw
// dump is build-, arch-, and version-specific and skips every check, so the header pins the dump to the
// exact binary and pk that produced it. A CPU-built dump fed to the GPU prover (or vice versa) carries
// a different backend here and is rejected, instead of being mis-read into a crash.
func dumpHeader(pkPath string) string {
	var size int64 = -1
	if fi, err := os.Stat(pkPath); err == nil {
		size = fi.Size()
	}
	return fmt.Sprintf("%s backend=%s goarch=%s gnark=%s pksize=%d\n",
		dumpFormatTag, proverBackend, runtime.GOARCH, gnarkVersion(), size)
}

// openMatchingDump opens dumpPath and checks its header against the running binary. On a match it
// returns a reader positioned at the raw dump (ready for ReadDump) plus the open file for the caller to
// close. On any mismatch - different build/arch/gnark, a changed pk, an old headerless dump, or an
// unreadable file - it logs the reason, closes the file, and returns ok=false so the caller falls back
// to the safe compressed ReadFrom.
func openMatchingDump(dumpPath, pkPath string) (io.Reader, *os.File, bool) {
	f, err := os.Open(dumpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pk dump %s: %v; using ReadFrom\n", dumpPath, err)
		return nil, nil, false
	}
	br := bufio.NewReaderSize(f, 1<<22)
	got, err := br.ReadString('\n')
	want := dumpHeader(pkPath)
	if err != nil || got != want {
		fmt.Fprintf(os.Stderr, "ignoring pk dump (header mismatch): got %q want %q; using ReadFrom\n",
			strings.TrimSpace(got), strings.TrimSpace(want))
		_ = f.Close()
		return nil, nil, false
	}
	return br, f, true
}

// loadProvingKey loads pk from a raw `<pkPath>.dump` (WriteDump format) when one is present whose
// header matches this binary, else the compressed pkPath via ReadFrom. Generate the dump once with
// `groth16bls dump` so prove never pays the decompression cost.
//
// The raw dump is build-, arch-, and gnark-version-specific and skips subgroup checks; a dump produced
// by a different build (e.g. the CPU binary feeding the GPU prover) is NOT interchangeable and would be
// mis-read into a crash. Each dump carries a header (see dumpHeader); loadProvingKey uses it only on an
// exact match via openMatchingDump and otherwise falls back to ReadFrom, so a mismatched or stale dump
// is ignored rather than trusted.
func loadProvingKey(pk groth16.ProvingKey, pkPath string) {
	dumpPath := pkPath + ".dump"
	if fi, err := os.Stat(dumpPath); err == nil && fi.Size() > 0 {
		if r, f, ok := openMatchingDump(dumpPath, pkPath); ok {
			defer f.Close()
			dr, ok := pk.(dumpReadable)
			if !ok {
				die("proving key type %T does not support ReadDump", pk)
			}
			t := time.Now()
			if err := dr.ReadDump(r); err != nil {
				die("ReadDump %s: %v", dumpPath, err)
			}
			fmt.Fprintf(os.Stderr, "pk loaded (dump, no decompression) in %s\n", time.Since(t).Round(time.Millisecond))
			return
		}
	}
	t := time.Now()
	readFrom(pkPath, pk)
	fmt.Fprintf(os.Stderr, "pk loaded (compressed ReadFrom) in %s\n", time.Since(t).Round(time.Millisecond))
}

func writeDump(path, header string, dw dumpWritable) {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		die("create %s: %v", tmp, err)
	}
	bw := bufio.NewWriterSize(f, 1<<22)
	t := time.Now()
	fail := func(format string, a ...any) {
		_ = f.Close()
		_ = os.Remove(tmp)
		die(format, a...)
	}
	if _, err := bw.WriteString(header); err != nil {
		fail("write dump header %s: %v", tmp, err)
	}
	if err := dw.WriteDump(bw); err != nil {
		fail("WriteDump %s: %v", tmp, err)
	}
	if err := bw.Flush(); err != nil {
		fail("flush %s: %v", tmp, err)
	}
	if err := f.Sync(); err != nil {
		fail("sync %s: %v", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		die("close %s: %v", tmp, err)
	}
	// Publish atomically: a crashed dump leaves only <path>.tmp, which loadProvingKey ignores.
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		die("rename %s -> %s: %v", tmp, path, err)
	}
	fmt.Fprintf(os.Stderr, "WriteDump %s in %s\n", path, time.Since(t).Round(time.Second))
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		die("open %s: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, bufio.NewReaderSize(f, 1<<22)); err != nil {
		die("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cmdDump converts the compressed pk.bin into a raw `pk.bin.dump` (gnark WriteDump) that prove
// loads via ReadDump without per-point decompression. Run ONCE (e.g. at image build); the slow
// ReadFrom is paid here, not on every prove. With --check it additionally round-trips the dump
// (ReadDump -> re-WriteDump) and asserts byte-identity, validating that the dump faithfully
// restores the real ceremony key (no dev keys, no vk, no prove needed).
func cmdDump(args []string) {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	keysDirFlag := fs.String("keys", "", "explicit keys dir containing pk.bin")
	keySet := fs.String("key", "", "manifest key-set (when --keys is not given)")
	check := fs.Bool("check", false, "round-trip the dump and assert byte-identity")
	_ = fs.Parse(args)

	var pkPath string
	if *keysDirFlag != "" {
		pkPath = filepath.Join(*keysDirFlag, pkFile)
	} else {
		man, err := keys.Load()
		if err != nil {
			die("%v", err)
		}
		ks, err := man.Resolve(*keySet)
		if err != nil {
			die("%v", err)
		}
		cache, err := ks.CacheDir("")
		if err != nil {
			die("%v", err)
		}
		logf := func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
		if pkPath, err = ks.EnsurePK(cache, logf); err != nil {
			die("%v", err)
		}
	}

	pk := newProvingKey()
	t := time.Now()
	readFrom(pkPath, pk)
	fmt.Fprintf(os.Stderr, "pk ReadFrom (compressed) in %s\n", time.Since(t).Round(time.Second))

	dw, ok := pk.(dumpWritable)
	if !ok {
		die("proving key type %T does not support WriteDump", pk)
	}
	dumpPath := pkPath + ".dump"
	header := dumpHeader(pkPath)
	writeDump(dumpPath, header, dw)
	fmt.Printf("wrote %s\n", dumpPath)

	if *check {
		pk2 := newProvingKey()
		dr, ok := pk2.(dumpReadable)
		if !ok {
			die("proving key type %T does not support ReadDump", pk2)
		}
		r, f, ok := openMatchingDump(dumpPath, pkPath)
		if !ok {
			die("dump header check failed for %s", dumpPath)
		}
		t = time.Now()
		if err := dr.ReadDump(r); err != nil {
			die("ReadDump (check): %v", err)
		}
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "ReadDump (check) in %s\n", time.Since(t).Round(time.Millisecond))
		dw2, ok := pk2.(dumpWritable)
		if !ok {
			die("reloaded key type %T does not support WriteDump", pk2)
		}
		checkPath := dumpPath + ".check"
		writeDump(checkPath, header, dw2)
		a := sha256File(dumpPath)
		b := sha256File(checkPath)
		_ = os.Remove(checkPath)
		if a != b {
			die("ROUND-TRIP MISMATCH: dump %s != re-dump %s", a, b)
		}
		fmt.Printf("round-trip OK: dump sha256 %s stable across ReadDump->WriteDump\n", a)
	}
}

func readSeal(path string) []uint32 {
	b, err := os.ReadFile(path)
	if err != nil {
		die("read seal %s: %v", path, err)
	}
	if len(b)%4 != 0 {
		die("seal length %d not a multiple of 4", len(b))
	}
	w := make([]uint32, len(b)/4)
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	return w
}
