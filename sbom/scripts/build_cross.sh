#!/usr/bin/env bash
# S6 A1: cross-compile the pinned public Go tools of S5 (CGO_ENABLED=0) for non-linux/amd64
# targets into .work/cross/<goos>-<goarch>/ (gitignored), plus a stripped (-s -w) build of
# stringer per target. Oracle: `go version -m` (scripts/cross_binaries.mjs).
# Existing binaries are kept; each build runs once (no retry loop); a failure is logged, not fatal.
set -uo pipefail
SBOM="$(cd "$(dirname "$0")/.." && pwd)"
C="$SBOM/.work/cross"
SRC="$SBOM/.work/cross-src"
mkdir -p "$C" "$SRC"
export GOTOOLCHAIN=local GOFLAGS="-trimpath -buildvcs=false" CGO_ENABLED=0

TARGETS=(windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/arm64 linux/386 linux/s390x linux/ppc64)

# Module sources, fetched once: module zip for stringer, yq and prometheus (same pins as S5).
fetch() { # name module@version
  [ -d "$SRC/$1" ] && return
  dir=$(go mod download -json "$2" | sed -n 's/.*"Dir": "\(.*\)".*/\1/p')
  [ -n "$dir" ] && cp -r "$dir" "$SRC/$1" && chmod -R u+w "$SRC/$1"
}
fetch stringer golang.org/x/tools@v0.26.0
fetch yq github.com/mikefarah/yq/v4@v4.44.3
fetch prometheus github.com/prometheus/prometheus@v0.54.1

build() { # goos goarch name package [ldflags] [suffix]
  local out="$C/$1-$2/$3${6:-}"
  [ "$1" = windows ] && out="$out.exe"
  [ -s "$out" ] && return
  mkdir -p "$C/$1-$2"
  (cd "$SRC/$3" && GOOS=$1 GOARCH=$2 go build ${5:+-ldflags="$5"} -o "$out" "$4") \
    >"$C/$1-$2/$3${6:-}.log" 2>&1 || echo "FAILED $1/$2 $3${6:-}: $(tail -3 "$C/$1-$2/$3${6:-}.log")" >&2
}

for t in "${TARGETS[@]}"; do
  os=${t%/*} arch=${t#*/}
  build "$os" "$arch" stringer ./cmd/stringer
  build "$os" "$arch" stringer ./cmd/stringer "-s -w" -stripped
  build "$os" "$arch" yq .
  build "$os" "$arch" prometheus ./cmd/prometheus
done
ls -l "$C"/*/ | grep -v '\.log$'
