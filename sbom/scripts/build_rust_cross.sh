#!/usr/bin/env bash
# S6 A3: cargo auditable cross builds of a pinned tool (ripgrep 14.1.1, --locked) into
# .work/rust-cross/<target>/ (gitignored); oracle rust-audit-info 0.5.4 (scripts/build_real_binaries.sh).
# Linkers: mingw-w64 (x86_64-pc-windows-gnu), gcc-aarch64-linux-gnu (aarch64-unknown-linux-gnu), from apt.
# Mach-O targets are not attempted: no Apple linker or SDK in this Linux container.
# Each target is built once (no retry loop); a failure is logged, not fatal.
set -uo pipefail
SBOM="$(cd "$(dirname "$0")/.." && pwd)"
R="$SBOM/.work/rust-cross"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
for target in x86_64-pc-windows-gnu aarch64-unknown-linux-gnu; do
  ls "$R/$target/bin/rg"* >/dev/null 2>&1 && continue
  cargo auditable install --locked ripgrep@14.1.1 --target "$target" --root "$R/$target" \
    >"$R/$target.log" 2>&1 || echo "FAILED $target: $(tail -5 "$R/$target.log")" >&2
done
