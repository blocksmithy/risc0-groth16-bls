package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenMatchingDump checks the dump-header guard that prevents a dump produced by a different build
// (the CPU/GPU cross-build that crashed the ICICLE prover) from being read raw: a matching header is
// accepted with the reader positioned at the raw dump, and any non-matching or headerless dump is
// rejected so loadProvingKey falls back to the compressed ReadFrom.
func TestOpenMatchingDump(t *testing.T) {
	dir := t.TempDir()
	pkPath := filepath.Join(dir, "pk.bin")
	if err := os.WriteFile(pkPath, []byte("placeholder pk bytes (only the size is read)"), 0o644); err != nil {
		t.Fatal(err)
	}
	dumpPath := pkPath + ".dump"
	body := "RAW-GNARK-DUMP-BYTES"

	writeDumpFile := func(header string) {
		f, err := os.Create(dumpPath)
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriter(f)
		if _, err := w.WriteString(header + body); err != nil {
			t.Fatal(err)
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	// Matching header (this binary, this pk): accepted, reader at the raw dump.
	writeDumpFile(dumpHeader(pkPath))
	r, f, ok := openMatchingDump(dumpPath, pkPath)
	if !ok {
		t.Fatal("dump with a matching header was rejected")
	}
	got, err := io.ReadAll(r)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("reader not positioned at the raw dump: got %q, want %q", got, body)
	}

	// A header from a different build/arch/gnark (e.g. CPU dump on the GPU prover): rejected.
	writeDumpFile(dumpFormatTag + " backend=other goarch=zzz gnark=v0.0.0 pksize=1\n")
	if _, _, ok := openMatchingDump(dumpPath, pkPath); ok {
		t.Fatal("cross-build dump was accepted; it must be rejected so prove falls back to ReadFrom")
	}

	// An old, headerless (raw gnark) dump: rejected.
	writeDumpFile("")
	if _, _, ok := openMatchingDump(dumpPath, pkPath); ok {
		t.Fatal("headerless dump was accepted; it must be rejected")
	}

	// A header that matches except the pk changed size (stale dump): rejected.
	writeDumpFile(dumpHeader(pkPath))
	if err := os.WriteFile(pkPath, []byte("a different pk of a different length entirely"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := openMatchingDump(dumpPath, pkPath); ok {
		t.Fatal("dump for a changed pk was accepted; it must be rejected")
	}
}
