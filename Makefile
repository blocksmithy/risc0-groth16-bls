# Makefile - keep these green at all times.
# The Go module lives under ./go; targets cd there. GOTOOLCHAIN=auto picks Go 1.25.7 for gnark.

GO      := GOTOOLCHAIN=auto go
GODIR   := go

.PHONY: build lint test test-negative kat kat-regen deep-tables diff verify-constants constraints-report prove-e2e groth16bls groth16bls-gpu install-groth16bls all

# Install prefix for the groth16bls prover binary (RISC0's shrink_wrap_bls finds it on $PATH).
PREFIX  ?= $(HOME)/.local/bin

# Path to the risc0 clone holding the armed fixture-dump test (override with RISC0_CLONE=...).
# local checkout of the risc0 fork: git clone -b v3.0.5-bls.1 https://github.com/blocksmithy/risc0 ../risc0-poseidon-bls
RISC0_CLONE ?= ../risc0-poseidon-bls

all: verify-constants build lint test ## default sanity sweep

build: ## go build ./...
	cd $(GODIR) && $(GO) build ./...

lint: ## go vet (+ golangci-lint if installed)
	cd $(GODIR) && $(GO) vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && (cd $(GODIR) && golangci-lint run) \
		|| echo "note: golangci-lint not installed - vet only"

test: ## unit + circuit solver tests
	cd $(GODIR) && $(GO) test ./... -count=1

test-negative: ## single-mutation rejection suite
	cd $(GODIR) && $(GO) test ./... -run 'Reject|Tamper|Canonical|Negative' -count=1 -v

kat: ## known-answer tests vs pinned RISC0 reference values / real openings
	cd $(GODIR) && $(GO) test ./... -run 'GoldenVector|AgainstRisc0|RealOpening|Sequence|HashElemSlice|HashPair' -count=1 -v

kat-regen: ## ATOMICALLY regenerate seal.bin + all *_real.json from ONE armed RISC0 run
	@echo ">> dumping fresh seal + trace from the armed identity_bls fixture test..."
	cd $(RISC0_CLONE) && RUST_LOG=error cargo test -p risc0-zkvm --features prove,fixture-dump \
		dump_identity_bls_fixture -- --nocapture > /tmp/kat_regen.log 2>&1
	@grep -q 'test result: ok' /tmp/kat_regen.log || (echo "fixture dump FAILED - see /tmp/kat_regen.log" && exit 1)
	python3 prototype/transcript/convert_transcript.py /tmp/kat_regen.log
	python3 prototype/merkle/convert_real_dump.py /tmp/kat_regen.log
	cd $(GODIR) && $(GO) run ./cmd/genfri /tmp/kat_regen.log
	python3 prototype/deep/convert_deep.py /tmp/kat_regen.log
	cd $(GODIR) && $(GO) test ./stark/ -run 'Real|FixtureConsistency' -count=1
	@echo ">> all *_real.json regenerated from one seal; TestFixtureConsistency green"

deep-tables: ## regenerate the STATIC DEEP-ALI tables (taps.json + polyext_def.json) from the risc0 circuit
	@echo ">> dumping recursion taps + poly_ext DEF (changes only with the circuit version)..."
	cd $(RISC0_CLONE) && cargo test -p risc0-circuit-recursion dump_polyext_and_taps -- --nocapture
	cd $(GODIR) && $(GO) test ./stark/ -run 'EvalU|PolyExt|ComputeCheck|FriEvalTaps' -count=1
	@echo ">> taps.json + polyext_def.json regenerated; DEEP-ALI KATs green"

verify-constants: ## re-extract constants from the pinned reference and diff
	./tools/verify_constants.sh

constraints-report: ## regenerate constraints.txt (per-gadget R1CS counts); diff must be explained
	cd $(GODIR) && $(GO) run ./cmd/constraints > ../constraints.txt
	@echo "wrote constraints.txt - review the diff"

circuit-id: ## print the frozen-circuit fingerprint (sha256 of the R1CS the ceremony keys) as JSON
	cd $(GODIR) && $(GO) run ./cmd/groth16bls circuit-id

circuit-freeze-check: ## fail if the production circuit drifted from the pinned circuit_id.json (pre-ceremony guard)
	cd $(GODIR) && $(GO) run ./cmd/groth16bls circuit-id --check ../circuit_id.json

# --- not yet implemented (gated on the STARK driver / full circuit) ---

diff: ## differential vs the pinned RISC0 Rust verifier - PARTIAL
	@echo ">> partial differential: single-mutation seals RISC0 rejects must be rejected in-circuit"
	cd $(GODIR) && $(GO) test ./... -run 'Reject|Tamper|Malformed|WrongPo2|WrongClaim|RejectsNonCanonical' -count=1 -v
	@echo ">> NOTE: this is the negative half of the differential (reject-set agreement)."
	@echo ">> TODO (release blocker, charter §8): a full corpus run through BOTH the pinned RISC0"
	@echo ">> Rust verify_integrity AND this circuit, asserting accept/reject matches on every input."
	@echo ">> Needs a Go<->Rust harness that feeds mutated seal.bin files to the risc0 verifier."

prove-e2e: ## full compile -> setup -> prove -> verify the real seal Groth16 proof (release gate)
	cd $(GODIR) && $(GO) run ./cmd/provee2e   # NQ=50 (full); setup is the INSECURE dev setup - production uses the ceremony

pipeline-e2e: ## cross-language gate: real seal -> groth16bls(dev) -> native Rust verify (accept + tamper-reject)
	./tools/pipeline_e2e.sh

groth16bls: ## build the CPU BLS Groth16 prover binary (RISC0's shrink_wrap_bls backend)
	cd $(GODIR) && $(GO) build -o groth16bls ./cmd/groth16bls

groth16bls-gpu: ## build the GPU (ICICLE) BLS Groth16 prover; needs CGO + the ICICLE CUDA libs + an NVIDIA GPU
	cd $(GODIR) && CGO_ENABLED=1 $(GO) build -tags icicle -o groth16bls-gpu ./cmd/groth16bls

install-groth16bls: groth16bls ## install the CPU prover to $(PREFIX) (set PREFIX or RISC0_GROTH16_BLS_BIN to relocate)
	install -d $(PREFIX) && install -m 0755 $(GODIR)/groth16bls $(PREFIX)/groth16bls

ceremony: ## build the MPC trusted-setup tool (phase-1/2; produces ceremony keys)
	cd $(GODIR) && $(GO) build -o ../bin/ceremony ./cmd/ceremony
	@echo "built bin/ceremony - run './bin/ceremony verify-circuit'"
