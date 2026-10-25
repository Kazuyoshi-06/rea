#!/usr/bin/env bash
# Build the corpus REPRO_BUILDS times (default 3) from a clean output state and report every file
# whose sha256 is not identical across all builds. Writes sbom/corpus/REPRO.txt.
# Build caches (Go, cargo registry, NuGet, pip venvs) stay warm. Three builds, because PyInstaller
# was observed alternating between two outputs (A, B, A): two builds can miss it.
set -euo pipefail
SBOM="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$SBOM/corpus/out"
WORK="$SBOM/.work"
N="${REPRO_BUILDS:-3}"
digests() { (cd "$OUT" && find . -type f ! -name .built -print0 | LC_ALL=C sort -z | xargs -0 sha256sum); }

mkdir -p "$WORK"
for n in $(seq 1 "$N"); do
  rm -rf "$OUT" "$WORK"/cargo-* "$WORK"/dotnet-* "$WORK"/pyi-* "$WORK"/stage-*
  "$SBOM/scripts/build_corpus.sh" >/dev/null 2>&1
  digests > "$WORK/repro-$n.txt"
  sleep 2 # distinct wall-clock second between builds exposes embedded timestamps
done

{
  echo "# Rebuild comparison ($(date -u +%Y-%m-%dT%H:%M:%SZ)): $N builds, same machine, same paths"
  # Distinct (path, sha256) pairs per path: more than one pair means the file changed between builds.
  sort -u -k2,2 -k1,1 "$WORK"/repro-*.txt | awk '{ count[$2]++ } END {
    total = 0; bad = 0
    for (f in count) { total++; if (count[f] > 1) { bad++; printf "  NON-DETERMINISTIC %s (%d distinct sha256)\n", f, count[f] } }
    printf "Identical across all builds: %d / %d files\n", total - bad, total }' | LC_ALL=C sort
} | tee "$SBOM/corpus/REPRO.txt"
digests > "$SBOM/corpus/DIGESTS.txt"
touch "$OUT/.built"
