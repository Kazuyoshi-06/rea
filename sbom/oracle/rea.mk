# Optional comparison oracle: REA (S7 C), included by ../Makefile. Only these targets use it;
# `make sbom-test` never does. SBOM_REA_ROOT: a REA checkout; default: the parent directory when
# this tree sits inside one (oracle/rea.mjs applies the same rule). REA's formatter (oxfmt) keeps
# the generated baseline byte-stable under REA's own commit hook.
SBOM_REA_ROOT ?= $(if $(wildcard $(SBOM)/../scripts/rea.mjs),$(abspath $(SBOM)/..),)
export SBOM_REA_ROOT
REA_DIST := $(if $(SBOM_REA_ROOT),$(SBOM_REA_ROOT)/dist/cli-runtime,rea-oracle-missing)
OXFMT := $(SBOM_REA_ROOT)/node_modules/.bin/oxfmt

.PHONY: rea baseline sbom-test-diff sbom-measure

$(REA_DIST):
	@test -n "$(SBOM_REA_ROOT)" || { echo "REA oracle not found: set SBOM_REA_ROOT to a REA checkout (only the differential tests and the S1 baseline need it; make sbom-test does not)" >&2; exit 1; }
	cd $(SBOM_REA_ROOT) && npm ci --no-audit --no-fund && npm run build:cached

rea: $(REA_DIST)

# Run REA on every fixture, keep raw outputs, compare with committed truth, write BASELINE.md.
baseline: $(STAMP) $(REA_DIST)
	@ls truth/*.json >/dev/null 2>&1 || node scripts/gen_truth.mjs
	node scripts/run_rea.mjs
	node scripts/measure_baseline.mjs
	@# Keep generated files byte-stable under the repository formatter (lint-staged runs oxfmt).
	@if [ -n "$(SBOM_REA_ROOT)" ] && [ -x $(OXFMT) ]; then $(OXFMT) BASELINE.md baseline/summary.json >/dev/null; fi

# S5: differential test, in-house readers vs REA (oracle/rea.mjs) on every Go and Rust fixture,
# stripped ones included, plus test/data/real-binaries.txt when present. Needs REA built.
sbom-test-diff: $(TEST_STAMP) $(REA_DIST) node_modules/.package-lock.json
	SBOM_REQUIRE_FIXTURES=1 SBOM_REQUIRE_REA=1 node --test 'test/differential/*.test.mjs'

# Time and peak RSS per REA call and per sbom-scan run (writes s2/measurements.json).
sbom-measure: $(TEST_STAMP) $(REA_DIST)
	node scripts/measure_s2.mjs
