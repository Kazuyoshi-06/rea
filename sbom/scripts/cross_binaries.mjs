#!/usr/bin/env node
// S6 A1/A2: in-house readers on real cross-compiled Go binaries (scripts/build_cross.sh) and on
// the fat Mach-O assembled by scripts/make_fat.mjs, against `go version -m` (oracle).
// Per binary: reader facts identical to the oracle (version, main, deps, replacements, build
// settings), and SBOM precision / recall (scripts/real_binaries.mjs compareGo). Also records
// the container the structure reader saw (format, bits, byte order). Writes s6/cross-binaries.json.
import {
  existsSync,
  mkdirSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { withSource } from "../lib/files.mjs";
import { readExecutable } from "../lib/readers/executable.mjs";
import { readGoBuildInfo } from "../lib/readers/gobuildinfo.mjs";
import { scanArtifact } from "../lib/scan.mjs";
import { compareGo, compareRust } from "./real_binaries.mjs";

const SBOM = join(import.meta.dirname, "..");
const CROSS = join(SBOM, ".work/cross");
const RUST_CROSS = join(SBOM, ".work/rust-cross");
const FAT = join(SBOM, ".work/fat");

function container(path) {
  const exe = withSource(path, readExecutable);
  if (!exe.ok) return { error: exe.error };
  return {
    format: exe.value.format,
    images: exe.value.images.map((im) => ({
      format: im.format,
      bits: im.bits,
      endian: im.littleEndian ? "little" : "big",
      sections: im.sections.length,
    })),
  };
}

const pct = (x) =>
  x === null || x === undefined ? "—" : `${(x * 100).toFixed(1)} %`;

const results = [];
for (const target of readdirSync(CROSS).sort()) {
  for (const name of readdirSync(join(CROSS, target)).sort()) {
    if (name.endsWith(".log")) continue;
    const path = join(CROSS, target, name);
    const tool = name.replace(/\.exe$/, "");
    const r = {
      target,
      tool,
      bytes: statSync(path).size,
      container: container(path),
    };
    const facts = readGoBuildInfo(path);
    r.locatedBy = facts.ok ? facts.value.locatedBy : facts.error;
    try {
      Object.assign(r, compareGo({ id: tool }, path));
    } catch (error) {
      r.oracleError = error.message.slice(0, 500);
    }
    results.push(r);
  }
}
// A2: fat Mach-O assembled by scripts/make_fat.mjs from the darwin/amd64 + darwin/arm64 builds
// (mismatch-*: two different tools, an error is expected). Each fat must give exactly the
// components of each of its slices scanned alone.
const componentKeys = (path) => {
  const scan = scanArtifact(path);
  if (!scan.ok) return { error: scan.error };
  return {
    components: scan.value.components
      .map((c) => `${c.name}@${c.version}`)
      .sort(),
    platforms: scan.value.platforms,
  };
};
const fat = [];
for (const name of existsSync(FAT) ? readdirSync(FAT).sort() : []) {
  const path = join(FAT, name);
  const whole = componentKeys(path);
  const r = {
    tool: name,
    bytes: statSync(path).size,
    container: container(path),
  };
  if (name.startsWith("mismatch-")) r.expectedError = true;
  else {
    r.slices = ["darwin-amd64", "darwin-arm64"].map((target) => {
      const slice = componentKeys(join(CROSS, target, name));
      return {
        target,
        sameComponents:
          JSON.stringify(slice.components) === JSON.stringify(whole.components),
      };
    });
  }
  r.result = whole.error ?? {
    components: whole.components.length,
    platforms: whole.platforms,
  };
  fat.push(r);
}

// A3: cargo auditable cross builds (scripts/build_rust_cross.sh), oracle rust-audit-info.
const rust = [];
for (const target of existsSync(RUST_CROSS) ? readdirSync(RUST_CROSS) : []) {
  const dir = join(RUST_CROSS, target, "bin");
  if (!existsSync(dir)) continue;
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    const r = {
      target,
      tool: name,
      bytes: statSync(path).size,
      container: container(path),
    };
    try {
      Object.assign(r, compareRust({ id: name }, path));
    } catch (error) {
      r.oracleError = error.message.slice(0, 500);
    }
    rust.push(r);
  }
}
mkdirSync(join(SBOM, "s6"), { recursive: true });
writeFileSync(
  join(SBOM, "s6/rust-cross-binaries.json"),
  `${JSON.stringify(rust, null, 2)}\n`,
);
writeFileSync(
  join(SBOM, "s6/fat-binaries.json"),
  `${JSON.stringify(fat, null, 2)}\n`,
);
for (const r of fat)
  console.log(
    [
      "fat",
      r.tool,
      JSON.stringify(r.slices ?? "expected error"),
      JSON.stringify(r.result),
    ].join("\t"),
  );
for (const r of rust)
  console.log(
    [
      r.target,
      r.tool,
      r.container.format ?? r.container.error?.tag,
      r.oracleError
        ? `oracle error ${r.oracleError}`
        : `reader identical: ${r.reader.identical} (${r.reader.diffs?.length} diffs)`,
      `P ${pct(r.sbom?.precision)} R ${pct(r.sbom?.recall)} (${r.sbom?.found}/${r.sbom?.oracle})`,
    ].join("\t"),
  );
writeFileSync(
  join(SBOM, "s6/cross-binaries.json"),
  `${JSON.stringify(results, null, 2)}\n`,
);
for (const r of results)
  console.log(
    [
      r.target,
      r.tool,
      r.container.format ?? r.container.error?.tag,
      r.locatedBy?.tag ?? r.locatedBy,
      r.oracleError
        ? `oracle error ${r.oracleError}`
        : `reader identical: ${r.reader.identical} (${r.reader.diffs.length} diffs)`,
      r.sbom?.error
        ? `scan error ${r.sbom.error.tag}: ${r.sbom.error.message}`
        : `P ${pct(r.sbom?.precision)} R ${pct(r.sbom?.recall)} (${r.sbom?.found}/${r.sbom?.oracle}) stdlib ${r.sbom?.stdlibMatchesOracle}`,
    ].join("\t"),
  );
if (!existsSync(CROSS))
  console.log("no .work/cross (run scripts/build_cross.sh)");
