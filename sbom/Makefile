# SBOM S1 corpus: build fixtures, generate ground truth, measure raw REA.
# Toolchains are bring-your-own (see PROBE.md). Run from sbom/: `make baseline`.
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

SBOM := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO := $(abspath $(SBOM)/..)
# sbom/ must work copied alone (S5 B7): the repository's .nvmrc when there is one, else sbom/.nvmrc.
NODE_VERSION := $(shell cat $(REPO)/.nvmrc 2>/dev/null || cat $(SBOM)/.nvmrc)
NVM_NODE_DIR := /opt/nvm/versions/node/v$(NODE_VERSION)/bin
# Prefer the pinned Node from nvm when present, then whatever is on PATH.
export PATH := $(if $(wildcard $(NVM_NODE_DIR)/node),$(NVM_NODE_DIR):,)$(PATH)
export NODE_BIN := $(dir $(shell command -v node))

OUT := $(SBOM)/corpus/out
STAMP := $(OUT)/.built
REA_DIST := $(REPO)/dist/cli-runtime
OXFMT := $(REPO)/node_modules/.bin/oxfmt

.PHONY: all corpus truth rea baseline repro clean sbom-test sbom-test-diff sbom-real sbom-measure sbom-measure-s3 stdlib-names vulndb sbom-measure-s4 sbom-oracle
all: baseline

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

$(REA_DIST):
	cd $(REPO) && npm ci --no-audit --no-fund && npm run build:cached

rea: $(REA_DIST)

# Run REA on every fixture, keep raw outputs, compare with committed truth, write BASELINE.md.
baseline: $(STAMP) $(REA_DIST)
	@ls truth/*.json >/dev/null 2>&1 || node scripts/gen_truth.mjs
	node scripts/run_rea.mjs
	node scripts/measure_baseline.mjs
	@# Keep generated files byte-stable under the repository formatter (lint-staged runs oxfmt).
	@if [ -x $(OXFMT) ]; then $(OXFMT) BASELINE.md baseline/summary.json >/dev/null; fi

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

# S5: no REA needed (in-house Go buildinfo and cargo-auditable readers).
sbom-test: $(TEST_STAMP) node_modules/.package-lock.json
	SBOM_REQUIRE_FIXTURES=1 node --test 'test/*.test.mjs'

# S5: differential test, in-house readers vs REA (oracle/rea.mjs) on every Go and Rust fixture,
# stripped ones included, plus test/data/real-binaries.txt when present. Needs REA built.
sbom-test-diff: $(TEST_STAMP) $(REA_DIST) node_modules/.package-lock.json
	SBOM_REQUIRE_FIXTURES=1 SBOM_REQUIRE_REA=1 node --test 'test/differential/*.test.mjs'

# Time and peak RSS per REA call and per sbom-scan run (writes s2/measurements.json).
sbom-measure: $(TEST_STAMP) $(REA_DIST)
	node scripts/measure_s2.mjs

# S3: precision/recall, time and peak RSS (/usr/bin/time -v) of .NET and PyInstaller scans,
# including the .NET variant without deps.json (writes s3/measurements.json). No REA needed.
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
