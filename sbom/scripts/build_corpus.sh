#!/usr/bin/env bash
# Build every S1 corpus fixture into sbom/corpus/out/<fixture>/.
# Usage: build_corpus.sh [ecosystem...]   (go rust dotnet npm python; default: all)
# Toolchains are bring-your-own; a missing toolchain skips its ecosystem with a message.
set -euo pipefail

SBOM="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$SBOM/corpus/src"
OUT="$SBOM/corpus/out"
WORK="$SBOM/.work"
NODE_BIN="${NODE_BIN:-$(dirname "$(command -v node)")}"
mkdir -p "$OUT" "$WORK"

have() { command -v "$1" >/dev/null 2>&1; }
skip() { echo "SKIP $1: $2" >&2; }

build_go() {
  have go || { skip go "go not found"; return; }
  for f in go-uuid go-jwt; do
    mkdir -p "$OUT/$f" "$OUT/$f-stripped"
    (cd "$SRC/$f" && CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false \
      -o "$OUT/$f/$f" .)
    (cd "$SRC/$f" && CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags="-s -w" -o "$OUT/$f-stripped/$f" .)
  done
}

build_rust() {
  have cargo || { skip rust "cargo not found"; return; }
  cargo auditable --help >/dev/null 2>&1 || { skip rust "cargo-auditable not installed"; return; }
  for f in rust-small rust-vuln; do
    mkdir -p "$OUT/$f"
    (cd "$SRC/$f" && CARGO_TARGET_DIR="$WORK/cargo-$f" \
      RUSTFLAGS="--remap-path-prefix=$SRC/$f=/src --remap-path-prefix=$HOME=/home" \
      cargo auditable build --release --locked --quiet)
    cp "$WORK/cargo-$f/release/$f" "$OUT/$f/$f"
  done
}

build_dotnet() {
  have dotnet || { skip dotnet "dotnet not found"; return; }
  export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
  for f in dotnet-json dotnet-serilog; do
    rm -rf "$OUT/$f"
    (cd "$SRC/$f" && dotnet publish -c Release -p:RestoreLockedMode=true -p:DebugType=none \
      -p:PathMap="$SBOM=/sbom" \
      -p:BaseIntermediateOutputPath="$WORK/dotnet-$f/obj/" \
      -p:BaseOutputPath="$WORK/dotnet-$f/bin/" -o "$OUT/$f" --nologo -v q)
    rm -rf "$SRC/$f/obj" "$SRC/$f/bin"
  done
}

build_npm() {
  [ -x "$NODE_BIN/npm" ] || { skip npm "npm not found"; return; }
  (cd "$SBOM/tools" && "$NODE_BIN/npm" ci --no-audit --no-fund --silent)
  for f in npm-electron npm-cli; do
    stage="$WORK/stage-$f"
    rm -rf "$stage" && mkdir -p "$stage" "$OUT/$f"
    (cd "$SRC/$f" && cp package.json package-lock.json ./*.js "$stage/")
    # Production dependencies only: devDependencies (electron) are never packed.
    (cd "$stage" && "$NODE_BIN/npm" ci --omit=dev --ignore-scripts --no-audit --no-fund --silent)
    # npm ci --omit=dev was observed leaving empty scope directories of omitted dev packages
    # (@electron, @types, ...) in some builds only; they hold no package, drop them for stable bytes.
    find "$stage/node_modules" -mindepth 1 -type d -empty -delete
    rm -f "$OUT/$f/app.asar"
    "$SBOM/tools/node_modules/.bin/asar" pack "$stage" "$OUT/$f/app.asar"
  done
}

build_python() {
  have python3 || { skip python "python3 not found"; return; }
  for f in py-requests py-yaml; do
    venv="$WORK/venv-$f"
    if [ ! -x "$venv/bin/pyinstaller" ]; then
      python3 -m venv "$venv"
      "$venv/bin/pip" install -q --disable-pip-version-check -r "$SRC/$f/requirements.txt"
      "$venv/bin/pip" install -q --disable-pip-version-check -r "$SBOM/tools/requirements-build.txt"
    fi
    mkdir -p "$OUT/$f"
    (cd "$WORK" && SOURCE_DATE_EPOCH=0 "$venv/bin/pyinstaller" --onefile --noconfirm --clean \
      --log-level WARN --distpath "$OUT/$f" --workpath "$WORK/pyi-$f" --specpath "$WORK/pyi-$f" \
      -n "$f" "$SRC/$f/app.py")
  done
}

ecos=("$@")
[ ${#ecos[@]} -eq 0 ] && ecos=(go rust dotnet npm python)
for e in "${ecos[@]}"; do echo "== build $e" >&2; "build_$e"; done
