#!/usr/bin/env bash
# S5 B6: build pinned public tools into .work/real/ (gitignored) for scripts/real_binaries.mjs.
# Go: go install (stringer, yq) and go build from the module zip (prometheus: module replace,
# terraform: local-directory replaces). Rust: cargo auditable install --locked (ripgrep, fd)
# and the oracle rust-audit-info. Existing binaries are kept; each build runs once (no retry loop).
set -uo pipefail
SBOM="$(cd "$(dirname "$0")/.." && pwd)"
R="$SBOM/.work/real"
mkdir -p "$R/go" "$R/cargo"
export GOTOOLCHAIN=local GOFLAGS=-trimpath CGO_ENABLED=0

goinstall() { [ -x "$R/go/$1" ] || GOBIN="$R/go" go install "$2" || echo "FAILED $1" >&2; }
gobuild() { # name module@version package
  [ -x "$R/go/$1" ] && return
  dir=$(go mod download -json "$2" | sed -n 's/.*"Dir": "\(.*\)".*/\1/p')
  rm -rf "$R/src-$1" && cp -r "$dir" "$R/src-$1" && chmod -R u+w "$R/src-$1"
  (cd "$R/src-$1" && go build -buildvcs=false -o "$R/go/$1" "$3") || echo "FAILED $1" >&2
}
cargoinstall() { # binary crate@version [auditable]
  [ -x "$R/cargo/bin/$1" ] && return
  if [ "${3:-}" = auditable ]; then cargo auditable install --locked "$2" --root "$R/cargo"
  else cargo install --locked "$2" --root "$R/cargo"; fi || echo "FAILED $1" >&2
}

goinstall stringer golang.org/x/tools/cmd/stringer@v0.26.0
goinstall yq github.com/mikefarah/yq/v4@v4.44.3
gobuild prometheus github.com/prometheus/prometheus@v0.54.1 ./cmd/prometheus
# Terraform's replaces point to nested modules that module zips exclude: build from the git tag.
if [ ! -x "$R/go/terraform" ]; then
  rm -rf "$R/src-terraform"
  git clone -q --depth 1 --branch v1.9.8 https://github.com/hashicorp/terraform "$R/src-terraform" &&
    (cd "$R/src-terraform" && go build -buildvcs=false -o "$R/go/terraform" .) || echo "FAILED terraform" >&2
fi
cargoinstall rust-audit-info rust-audit-info@0.5.4
cargoinstall rg ripgrep@14.1.1 auditable
cargoinstall fd fd-find@10.2.0 auditable
