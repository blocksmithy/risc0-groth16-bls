package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/pitcon/stark-to-snark-bls/go/stark"
)

// CircuitID is the canonical identity of the frozen Groth16 circuit - the exact R1CS the Phase-2
// ceremony keys. It is the SHA-256 of the gnark-canonical serialization of `ccs` (byte-identical to
// the `ccs.bin` written by `setup`), alongside the constraint/variable counts. A ceremony is only
// meaningful for ONE circuit; if any of these change, the keys are invalidated and the ceremony
// must be redone.
type CircuitID struct {
	Curve         string `json:"curve"`
	NQueries      int    `json:"n_queries"`
	NbConstraints int    `json:"nb_constraints"`
	NbPublic      int    `json:"nb_public_variables"`
	NbSecret      int    `json:"nb_secret_variables"`
	NbInternal    int    `json:"nb_internal_variables"`
	CCSBytes      int    `json:"ccs_serialized_bytes"`
	CCSSHA256     string `json:"ccs_sha256"`
}

// computeCircuitID compiles the production circuit (stark.ReceiptTemplate(nQueries), identical to
// `setup`) and fingerprints its canonical serialization. The hash is computed over the SAME bytes
// `setup` writes to ccs.bin (constraint.ConstraintSystem.WriteTo), so it identifies precisely what
// gets keyed.
func computeCircuitID() (CircuitID, error) {
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, stark.ReceiptTemplate(nQueries))
	if err != nil {
		return CircuitID{}, fmt.Errorf("compile: %w", err)
	}
	// Hash the gnark-canonical serialization while measuring its length.
	h := sha256.New()
	n, err := ccs.WriteTo(h)
	if err != nil {
		return CircuitID{}, fmt.Errorf("serialize: %w", err)
	}
	return CircuitID{
		Curve:         "BLS12-381",
		NQueries:      nQueries,
		NbConstraints: ccs.GetNbConstraints(),
		NbPublic:      ccs.GetNbPublicVariables(),
		NbSecret:      ccs.GetNbSecretVariables(),
		NbInternal:    ccs.GetNbInternalVariables(),
		CCSBytes:      int(n),
		CCSSHA256:     hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// cmdEmitCCS compiles the production circuit and writes its canonical serialization to a file
// (ccs.bin) - the circuit-agnostic input the gnark-mpc-ceremony tool keys in Phase 2. The bytes are
// identical to what `setup` writes, so its SHA-256 equals the pinned circuit-id (CCSSHA256).
func cmdEmitCCS(args []string) {
	fs := flag.NewFlagSet("emit-ccs", flag.ExitOnError)
	out := fs.String("out", "ccs.bin", "output path for the serialized constraint system")
	_ = fs.Parse(args)

	t := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, stark.ReceiptTemplate(nQueries))
	if err != nil {
		die("emit-ccs: compile: %v", err)
	}
	f, err := os.Create(*out)
	if err != nil {
		die("emit-ccs: create %s: %v", *out, err)
	}
	n, err := ccs.WriteTo(f)
	if err != nil {
		_ = f.Close()
		die("emit-ccs: write %s: %v", *out, err)
	}
	if err := f.Close(); err != nil {
		die("emit-ccs: close %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes, %d constraints) in %s\n", *out, n, ccs.GetNbConstraints(), time.Since(t).Round(time.Second))
}

// cmdCircuitID prints the frozen-circuit fingerprint as JSON. With --check <file> it instead
// recomputes the id and fails (non-zero) if it differs from the pinned JSON - the freeze guard.
func cmdCircuitID(args []string) {
	fs := flag.NewFlagSet("circuit-id", flag.ExitOnError)
	check := fs.String("check", "", "compare against a pinned circuit-id JSON file; exit non-zero on any drift")
	_ = fs.Parse(args)

	t := time.Now()
	id, err := computeCircuitID()
	if err != nil {
		die("circuit-id: %v", err)
	}
	fmt.Fprintf(os.Stderr, "compiled + fingerprinted in %s\n", time.Since(t).Round(time.Second))

	out, _ := json.MarshalIndent(id, "", "  ")

	if *check == "" {
		fmt.Println(string(out))
		return
	}

	pinnedBytes, err := os.ReadFile(*check)
	if err != nil {
		die("read pinned id %s: %v", *check, err)
	}
	var pinned CircuitID
	if err := json.Unmarshal(pinnedBytes, &pinned); err != nil {
		die("parse pinned id %s: %v", *check, err)
	}
	if pinned != id {
		fmt.Fprintln(os.Stderr, "CIRCUIT DRIFT - the frozen circuit changed; any ceremony keys are invalidated:")
		fmt.Fprintf(os.Stderr, "  pinned:  %+v\n", pinned)
		fmt.Fprintf(os.Stderr, "  current: %+v\n", id)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "circuit-id matches the pinned freeze")
	fmt.Println(string(out))
}
