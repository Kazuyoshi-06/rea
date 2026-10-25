# SBOM scanner: fixtures and ground truth (S1), tests (make sbom-test), offline
# vulnerability index (make vulndb), measurements and comparisons (S2–S7). Toolchains are
# bring-your-own (see PROBE.md). Run from this directory. The comparison oracle is optional:
# oracle/rea.mk (included at the end) holds its targets.
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

SBOM := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
# This tree must work on its own (S5 B7, S7 C): only its own .nvmrc is read.
NODE_VERSION := $(shell cat $(SBOM)/.nvmrc)
NVM_NODE_DIR := /opt/nvm/versions/node/v$(NODE_VERSION)/bin
# Prefer the pinned Node from nvm when present, then whatever is on PATH.
export PATH := $(if $(wildcard $(NVM_NODE_DIR)/node),$(NVM_NODE_DIR):,)$(PATH)
export NODE_BIN := $(dir $(shell command -v node))

OUT := $(SBOM)/corpus/out
STAMP := $(OUT)/.built

.PHONY: all corpus truth repro clean sbom-test sbom-real sbom-oracle-s5 sbom-measure-s3 stdlib-names vulndb sbom-measure-s4 sbom-oracle sbom-compare-syft extract
# Default: the test suite (S7; it was `baseline` before, which needs the optional oracle).
all: sbom-test

$(STAMP):
	scripts/build_corpus.sh
	cd $(OUT) && find . -type f ! -name .built -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > $(SBOM)/corpus/DIGESTS.txt
	touch $@

# Force a rebuild of every fixture and refresh corpus/DIGESTS.txt.
corpus:
	rm -f $(STAMP)
	$(MAKE) $(STAMP)

# Regenerate sbom/truth/*.json from native ecosystem tools (needs built Go binaries).
truth: $(STAMP)
	node scripts/gen_truth.mjs

# Rebuild twice from scratch and report artifacts whose sha256 differs between builds.
repro:
	scripts/check_repro.sh

clean:
	rm -rf $(OUT) .work

# --- S2/S3: SBOM core (Go, Rust, npm, .NET, PyInstaller). `make sbom-test` from a clean clone, inside sbom/. ---
TEST_STAMP := $(OUT)/.built-s3

# Every fixture the tests use. .NET needs the SDK (apt dotnet-sdk-8.0 where dot.net is blocked),
# PyInstaller needs python3 3.13 + venv and PyPI access.
$(TEST_STAMP):
	scripts/build_corpus.sh go rust npm dotnet python
	node scripts/check_s2_digests.mjs
	touch $@

# Test-only dependencies (Ajv + formats, @electron/asar for synthetic archives).
node_modules/.package-lock.json: package.json package-lock.json
	npm ci --no-audit --no-fund

# In-house readers only; no oracle, no network once the fixtures are built.
sbom-test: $(TEST_STAMP) node_modules/.package-lock.json
	SBOM_REQUIRE_FIXTURES=1 node --test 'test/*.test.mjs'

# S3: precision/recall, time and peak RSS (/usr/bin/time -v) of .NET and PyInstaller scans,
# including the .NET variant without deps.json (writes s3/measurements.json).
sbom-measure-s3: $(TEST_STAMP) node_modules/.package-lock.json
	node scripts/measure_s3.mjs

# Record sys.stdlib_module_names of the fixtures' Python as data/stdlib-module-names-<X.Y>.json.
stdlib-names:
	node scripts/gen_stdlib_names.mjs python3

# --- S4: offline vulnerability matching (OSV). ---
# Download the OSV exports of Go, crates.io, npm, NuGet and PyPI into vulndb/ (gitignored, ~275 MB)
# and build the index; vulndb/SNAPSHOT.json (committed) records each archive's date and sha256.
# VULNDB_FLAGS=--no-download rebuilds the index from the archives already present.
vulndb:
	node scripts/vulndb.mjs $(VULNDB_FLAGS)

# Index load time, scan time and peak RSS with --vulns (/usr/bin/time -v) → s4/measurements.json.
sbom-measure-s4: $(TEST_STAMP)
	node scripts/measure_s4.mjs

# Independent oracles (osv-scanner, npm audit, pip-audit, dotnet list package --vulnerable) against
# --vulns on every vulnerable fixture → s4/oracle.json (needs network for the oracles).
sbom-oracle: $(TEST_STAMP)
	node scripts/oracle_s4.mjs

# --- S5: real binaries (B6) and resource tests (C). ---
# Build pinned public Go and Rust tools into .work/real/ and compare the in-house readers with
# `go version -m` and rust-audit-info → s5/real-binaries.json (needs network for the builds).
sbom-real:
	scripts/build_real_binaries.sh
	node scripts/real_binaries.mjs

# S5 part D: govulncheck (pinned v1.1.4, binary mode) and cargo-audit on the Go/Rust corpus and
# real binaries → s5/oracle.json; risky OSV ranges checked against api.osv.dev →
# test/data/risky-ranges.json (replayed offline by make sbom-test). Needs make vulndb and network.
sbom-oracle-s5: $(TEST_STAMP)
	GOTOOLCHAIN=local GOBIN=$(SBOM)/.work/real/tools go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	test -x .work/real/cargo/bin/cargo-audit || cargo install cargo-audit --locked --version 0.22.2 --root .work/real/cargo
	node scripts/oracle_s5.mjs
	node scripts/risky_ranges.mjs

# --- S7: comparison with syft (A) and standalone extraction (C). ---
# syft v1.42.0 (latest release whose go.mod accepts go1.24.7) via go install into .work/s7/tools,
# then sbom-scan and syft on the corpus, the S5 real binaries and 3 cross targets against the
# ground truth → s7/compare.json; timings cold / warm (needs root for drop_caches) → s7/measurements.json.
SYFT_VERSION := v1.42.0
sbom-compare-syft: $(TEST_STAMP)
	test -x .work/s7/tools/syft || GOTOOLCHAIN=local GOBIN=$(SBOM)/.work/s7/tools go install github.com/anchore/syft/cmd/syft@$(SYFT_VERSION)
	scripts/build_real_binaries.sh
	scripts/build_cross.sh windows/amd64 darwin/arm64 linux/s390x
	node scripts/compare_syft_s7.mjs
	node scripts/measure_s7.mjs

# Standalone copy: make extract DEST=<empty dir> NAME=<npm name> (see DECISIONS_PROPRIETAIRE.md).
extract:
	scripts/extract.sh "$(DEST)" "$(NAME)"

# Optional oracle targets (rea, baseline, sbom-test-diff, sbom-measure).
include $(SBOM)/oracle/rea.mk
