// Artifact detection and scan orchestration.
// One pass over a file computes its sha256 and looks for format markers:
//   ASAR      pickle prefix (u32le 4, consistent sizes, JSON "{")
//   Go        build-information magic "\xff Go buildinf:"
//   Rust      cargo-auditable section name ".dep-v0" (ELF/PE) or "__dep_v0" (Mach-O)
// A directory is scanned as an npm install root (its node_modules).
//   PyInstaller  cookie magic "MEI\014\013\012\013\016" (the bootloader embeds it too; the reader validates)
//   .NET         PE file ("MZ") with a CLI header; a directory with *.deps.json or managed top-level files
// Markers are byte matches: a match only selects a reader; the reader decides.
import { createHash } from "node:crypto";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { scanDotnetAssembly, scanDotnetDirectory } from "./adapters/dotnet.mjs";
import { scanGo } from "./adapters/go.mjs";
import { scanNpm } from "./adapters/npm.mjs";
import { scanPyInstaller } from "./adapters/pyinstaller.mjs";
import { scanRust } from "./adapters/rust.mjs";
import { forEachChunk } from "./files.mjs";
import { finalizeScan } from "./model.mjs";
import { err, ok } from "./result.mjs";
import { isManagedPe } from "./readers/cli-metadata.mjs";
import { COOKIE_MAGIC } from "./readers/pyinstaller.mjs";
import { asarTree, directoryTree, looksLikeAsar } from "./tree.mjs";

const MARKERS = [
  { ecosystem: "golang", bytes: Buffer.from("\xff Go buildinf:", "latin1") },
  { ecosystem: "cargo", bytes: Buffer.from(".dep-v0") },
  { ecosystem: "cargo", bytes: Buffer.from("__dep_v0") },
  { ecosystem: "pypi", bytes: COOKIE_MAGIC },
];
const OVERLAP = Math.max(...MARKERS.map((m) => m.bytes.length)) - 1;

/** sha256, size, ASAR prefix check and binary markers in a single read of the file. */
export function fingerprint(path) {
  const hash = createHash("sha256");
  const found = new Set();
  let bytes = 0;
  let prefix = null;
  forEachChunk(path, OVERLAP, (view, start) => {
    const fresh = view.subarray(Math.max(0, bytes - start));
    hash.update(fresh);
    if (prefix === null) prefix = Buffer.from(view.subarray(0, 17));
    bytes = start + view.length;
    for (const marker of MARKERS)
      if (!found.has(marker.ecosystem) && view.includes(marker.bytes))
        found.add(marker.ecosystem);
  });
  const size = bytes;
  const asar = prefix !== null && looksLikeAsar(prefix, size);
  if (!asar && prefix?.[0] === 0x4d && prefix[1] === 0x5a && isManagedPe(path))
    found.add("nuget");
  return {
    sha256: hash.digest("hex"),
    bytes: size,
    kind: asar ? "asar" : "binary",
    ecosystems: asar ? ["npm"] : [...found].sort(),
  };
}

const BINARY_ADAPTERS = {
  golang: scanGo,
  cargo: scanRust,
  nuget: scanDotnetAssembly,
  pypi: scanPyInstaller,
};

function emptyScan(artifact, ecosystems) {
  return {
    artifact,
    ecosystems,
    root: null,
    components: [],
    unknowns: [],
    exclusions: [],
    limitations: [],
    calls: [],
  };
}

function absorb(scan, part) {
  scan.root ??= part.root;
  scan.components.push(...part.components);
  scan.unknowns.push(...part.unknowns);
  scan.exclusions.push(...part.exclusions);
  scan.limitations.push(...part.limitations);
  scan.calls.push(...(part.calls ?? []));
}

function scanBinary(artifact, ecosystems) {
  if (ecosystems.length === 0)
    return err(
      "unsupported-artifact",
      "no ASAR header, Go build information, cargo-auditable section, PyInstaller cookie or .NET assembly found",
    );
  const scan = emptyScan(artifact, ecosystems);
  const failures = [];
  for (const ecosystem of ecosystems) {
    const part = BINARY_ADAPTERS[ecosystem](artifact);
    if (part.ok) absorb(scan, part.value);
    else failures.push(part.error);
  }
  if (failures.length === ecosystems.length)
    return { ok: false, error: failures[0] };
  for (const f of failures)
    scan.limitations.push(
      `reader failed after a marker match: ${f.tag}: ${f.message}`,
    );
  return ok(finalizeScan(scan));
}

/** A directory is .NET when it has a *.deps.json or a managed assembly at its top level. */
function directoryEcosystems(path) {
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch {
    return [];
  }
  const ecosystems = [];
  const files = entries.filter((e) => e.isFile()).map((e) => e.name);
  if (
    files.some((n) => /\.deps\.json$/i.test(n)) ||
    files.some((n) => /\.(?:dll|exe)$/i.test(n) && isManagedPe(join(path, n)))
  )
    ecosystems.push("nuget");
  if (entries.some((e) => e.name === "node_modules")) ecosystems.push("npm");
  // Previous behaviour kept: a directory with neither is read as an (empty) npm install root.
  return ecosystems.length > 0 ? ecosystems : ["npm"];
}

function scanDirectory(path) {
  const artifact = { path, sha256: null, bytes: null, kind: "directory" };
  const ecosystems = directoryEcosystems(path);
  const scan = emptyScan(artifact, ecosystems);
  if (ecosystems.includes("nuget")) absorb(scan, scanDotnetDirectory(artifact));
  if (ecosystems.includes("npm"))
    absorb(scan, scanNpm(artifact, directoryTree(path)));
  return ok(finalizeScan(scan));
}

/** Scan a file or directory. Returns Result<scan model>. */
export function scanArtifact(path) {
  let stat;
  try {
    stat = statSync(path);
  } catch (error) {
    return err("unreadable-artifact", error.message);
  }
  if (stat.isDirectory()) return scanDirectory(path);
  const print = fingerprint(path);
  const artifact = {
    path,
    sha256: print.sha256,
    bytes: print.bytes,
    kind: print.kind,
  };
  if (print.kind !== "asar") return scanBinary(artifact, print.ecosystems);
  const tree = asarTree(path);
  if (!tree.ok) return tree;
  const scan = emptyScan(artifact, ["npm"]);
  absorb(scan, scanNpm(artifact, tree.value));
  return ok(finalizeScan(scan));
}
