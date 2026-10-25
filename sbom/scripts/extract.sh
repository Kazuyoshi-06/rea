#!/usr/bin/env bash
# S7 C1: copy this tree into <target-dir> as a standalone project, without git history.
# Usage: scripts/extract.sh <target-dir> <project-name>
#   <target-dir>    must not exist, or be an empty directory
#   <project-name>  npm package name (lowercase; the owner chooses it, see DECISIONS_PROPRIETAIRE.md)
# Files: the tracked and untracked-but-not-ignored files of this tree when it is in a git work
# tree (git ls-files), else every file minus the generated outputs listed in .gitignore. Nothing
# outside this tree is read. package.json and package-lock.json get the given name, version 0.0.0
# and private: true (no publication until the owner decides). The copy then lists, by grep, the
# references to REA or to a parent directory that remain in the shipped code (oracle excluded).
set -euo pipefail

usage() { echo "usage: scripts/extract.sh <target-dir> <project-name>" >&2; exit 2; }
[ $# -eq 2 ] || usage
TARGET=$1
NAME=$2
SRC="$(cd "$(dirname "$0")/.." && pwd)"

if ! [[ $NAME =~ ^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$ ]] || [ ${#NAME} -gt 214 ]; then
  echo "extract: invalid npm package name: $NAME" >&2
  exit 2
fi
if [ -e "$TARGET" ] && [ -n "$(ls -A "$TARGET" 2>/dev/null)" ]; then
  echo "extract: $TARGET exists and is not empty" >&2
  exit 1
fi
mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd)"
case "$TARGET/" in "$SRC"/*)
  echo "extract: $TARGET is inside the source tree" >&2
  exit 1
  ;;
esac

LIST=$(mktemp)
trap 'rm -f "$LIST"' EXIT
if git -C "$SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  # Paths relative to this tree; deleted-but-tracked files are skipped below.
  git -C "$SRC" ls-files -z --cached --others --exclude-standard -- . >"$LIST"
else
  (cd "$SRC" && find . -type f \
    ! -path './corpus/out/*' ! -path './.work/*' ! -path './node_modules/*' \
    ! -path './tools/node_modules/*' ! -path './baseline/raw/npm-*' \
    \( ! -path './vulndb/*' -o -path './vulndb/SNAPSHOT.json' \) -print0 |
    sed -z 's|^\./||') >"$LIST"
fi
(cd "$SRC" && while IFS= read -r -d '' f; do [ -f "$f" ] && printf '%s\0' "$f"; done <"$LIST" |
  tar --null -T - -cf -) | (cd "$TARGET" && tar -xf -)

# Package identity: given name, 0.0.0, private (lockfile root entries kept in step).
NODE=${NODE:-node}
"$NODE" - "$TARGET" "$NAME" <<'JS'
const { readFileSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const [dir, name] = process.argv.slice(2);
const edit = (file, change) => {
  const path = join(dir, file);
  const doc = JSON.parse(readFileSync(path, "utf8"));
  change(doc);
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
};
edit("package.json", (p) => {
  p.name = name;
  p.version = "0.0.0";
  p.private = true;
  p.description =
    "Offline SBOM scanner for built artifacts (Go, Rust, npm ASAR, .NET, PyInstaller), CycloneDX 1.6, OSV matching";
});
edit("package-lock.json", (l) => {
  l.name = name;
  l.version = "0.0.0";
  if (l.packages?.[""]) {
    l.packages[""].name = name;
    l.packages[""].version = "0.0.0";
  }
});
JS

echo "extract: $(tr -cd '\0' <"$LIST" | wc -c) paths listed, copied to $TARGET as $NAME (version 0.0.0, private)"

# Residual references in the shipped code. The REA oracle is optional and listed apart: oracle/
# (module and make targets), test/differential/, the tests and S1–S3 scripts that run REA or read
# its recorded outputs (baseline/raw/). Documentation (*.md) is not code and is not scanned.
cd "$TARGET"
CODE=(lib bin scripts test oracle Makefile package.json package-lock.json)
ORACLE='^(oracle/|test/differential/|test/binary-adapters\.test\.mjs|scripts/(run_rea|measure_baseline|measure_s2|measure_s3)\.mjs)'
PATTERN='\bREA\b|\brea\.mjs\b|dist/cli-runtime|SBOM_REA_ROOT|\$\(SBOM\)/\.\.|dirname\(SBOM\)|join\(SBOM, "\.\."'
# This script names the patterns it looks for: not a residual reference.
hits=$(grep -rnIE "$PATTERN" "${CODE[@]}" 2>/dev/null | grep -v '^test/data/' | grep -v '^scripts/extract\.sh:' || true)
oracle=$(grep -E "$ORACLE" <<<"$hits" || true)
rest=$(grep -vE "$ORACLE" <<<"$hits" | grep -v '^$' || true)
count() { grep -c . <<<"$1" || true; }
echo "extract: REA references in the optional oracle: $(count "$oracle") lines in $(cut -d: -f1 <<<"$oracle" | sort -u | grep -c . || true) files ($(cut -d: -f1 <<<"$oracle" | sort -u | tr '\n' ' '))"
if [ -n "$rest" ]; then
  echo "extract: REA references outside the oracle ($(count "$rest") lines):"
  echo "$rest" | cut -c1-160
else
  echo "extract: no REA reference outside the oracle"
fi
# The BOM property namespace (rea-sbom:*) and reader names are a format decision of the owner
# (DECISIONS_PROPRIETAIRE.md): counted, not changed.
echo "extract: 'rea-sbom' (format namespace, owner decision) in lib/: $(grep -rIo 'rea-sbom' lib | wc -l) occurrences"
