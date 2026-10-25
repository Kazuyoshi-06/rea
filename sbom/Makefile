# SBOM S1 corpus: build fixtures, generate ground truth, measure raw REA.
# Toolchains are bring-your-own (see PROBE.md). Run from sbom/: `make baseline`.
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

SBOM := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO := $(abspath $(SBOM)/..)
NODE_VERSION := $(shell cat $(REPO)/.nvmrc)
NVM_NODE_DIR := /opt/nvm/versions/node/v$(NODE_VERSION)/bin
# Prefer the pinned Node from nvm when present, then whatever is on PATH.
export PATH := $(if $(wildcard $(NVM_NODE_DIR)/node),$(NVM_NODE_DIR):,)$(PATH)
export NODE_BIN := $(dir $(shell command -v node))

OUT := $(SBOM)/corpus/out
STAMP := $(OUT)/.built
REA_DIST := $(REPO)/dist/cli-runtime
OXFMT := $(REPO)/node_modules/.bin/oxfmt

.PHONY: all corpus truth rea baseline repro clean
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
