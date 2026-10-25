// Artifact detection and scan orchestration.
// One pass over a file computes its sha256 and looks for format markers:
//   ASAR      pickle prefix (u32le 4, consistent sizes, JSON "{")
//   Go        build-information magic "\xff Go buildinf:"
//   Rust      cargo-auditable section name ".dep-v0" (ELF/PE) or "__dep_v0" (Mach-O)
// A directory is scanned as an npm install root (its node_modules).
//   PyInstaller  cookie magic "MEI\014\013\012\013\016" (the bootloader embeds it too; the reader validates)
//   .NET         PE file ("MZ") with a CLI header; a directory with *.deps.json or managed top-level files
// Then the container structure (lib/readers/executable.mjs) decides Go and Rust when it can:
//   Go    ELF / Mach-O with a section table: a ".go.buildinfo" / "__go_buildinfo" section, whatever
//         the bytes say (the go command itself embeds the magic as a string constant); PE: the
//         marker (the header lives in .data, the reader searches it there)
//   Rust  any container with a section table: a ".dep-v0" / "__dep_v0" section (a tool that only
//         mentions the name, such as rust-audit-info, is not a match)
// Without a section table (sstrip, unknown container) the markers decide. A packed executable
// (UPX) is unsupported-artifact with that reason: its sections are compressed.
// Markers are byte matches: a match only selects a reader; the reader decides.
// Integrity (S6 C): the sha256 and size of the fingerprint pass identify the artifact in the
// BOM. Adapters reopen the file afterwards, so once they are done the file is hashed again; a
// different size or sha256 fails the scan (artifact-changed) instead of describing bytes that
// the reported sha256 does not identify. A change undone before the second hash (A → B → A) is
// not seen; a change after it does not affect the BOM, which describes the verified bytes.
import { createHash } from "node:crypto";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { scanDotnetAssembly, scanDotnetDirectory } from "./adapters/dotnet.mjs";
import { scanGo } from "./adapters/go.mjs";
import { scanNpm } from "./adapters/npm.mjs";
import { scanPyInstaller } from "./adapters/pyinstaller.mjs";
import { scanRust } from "./adapters/rust.mjs";
import { forEachChunk, sha256File, withSource } from "./files.mjs";
import { finalizeScan } from "./model.mjs";
import { err, ok } from "./result.mjs";
import { isManagedPe } from "./readers/cli-metadata.mjs";
import { findSections, readExecutable } from "./readers/executable.mjs";
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
  const structure = asar ? null : containerStructure(path);
  if (structure !== null)
    for (const [ecosystem, present] of Object.entries(structure.decides))
      if (present) found.add(ecosystem);
      else found.delete(ecosystem);
  return {
    sha256: hash.digest("hex"),
    bytes: size,
    kind: asar ? "asar" : "binary",
    ecosystems: asar ? ["npm"] : [...found].sort(),
    container: structure?.summary ?? null,
  };
}

const GO_SECTIONS = { elf: ".go.buildinfo", macho: "__go_buildinfo" };
const RUST_SECTIONS = { elf: ".dep-v0", pe: ".dep-v0", macho: "__dep_v0" };

/**
 * What the executable structure says about Go and Rust: `decides` maps an ecosystem to
 * true / false only where the structure is conclusive (see the header); `summary` is the
 * container format, packer, or why the structure could not be read.
 */
function containerStructure(path) {
  const exe = withSource(path, readExecutable);
  if (!exe.ok) return { decides: {}, summary: { error: exe.error } };
  const { format, packer, images } = exe.value;
  const summary = { format, packer };
  if (packer !== null) return { decides: {}, summary };
  const decides = {};
  const sectioned = images.every((im) => im.sections.length > 0);
  if (!sectioned) return { decides, summary };
  const has = (table) =>
    images.some(
      (im) =>
        table[im.format] !== undefined &&
        findSections({ images: [im] }, table[im.format]).length > 0,
    );
  if (format !== "pe") decides.golang = has(GO_SECTIONS);
  decides.cargo = has(RUST_SECTIONS);
  return { decides, summary };
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
    platforms: [],
    calls: [],
  };
}

function absorb(scan, part) {
  scan.root ??= part.root;
  scan.components.push(...part.components);
  scan.unknowns.push(...part.unknowns);
  scan.exclusions.push(...part.exclusions);
  scan.limitations.push(...part.limitations);
  scan.platforms.push(...(part.platforms ?? []));
  scan.calls.push(...(part.calls ?? []));
}

function scanBinary(artifact, ecosystems, container) {
  if (container?.packer)
    return err(
      "unsupported-artifact",
      `${container.packer.toUpperCase()}-packed ${container.format} executable: its sections are compressed and are not unpacked (unpack it first, e.g. upx -d)`,
    );
  if (ecosystems.length === 0)
    return err(
      "unsupported-artifact",
      `no ASAR header, Go build information, cargo-auditable section, PyInstaller cookie or .NET assembly found${container?.error ? ` (container: ${container.error.tag}: ${container.error.message})` : ""}`,
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

/** artifact-changed unless the file still has the size and sha256 of the fingerprint pass. */
function verifyUnchanged(artifact) {
  let now;
  try {
    now = sha256File(artifact.path);
  } catch (error) {
    return err(
      "artifact-changed",
      `artifact unreadable after the scan: ${error.message}`,
    );
  }
  if (now.bytes !== artifact.bytes)
    return err(
      "artifact-changed",
      `artifact size changed during the scan (${artifact.bytes} → ${now.bytes} bytes)`,
    );
  if (now.sha256 !== artifact.sha256)
    return err(
      "artifact-changed",
      `artifact content changed during the scan (sha256 ${artifact.sha256} → ${now.sha256})`,
    );
  return ok(artifact);
}

/** The scan result, unless the artifact changed while it was read. */
const verified = (artifact, result) => {
  if (!result.ok) return result;
  const check = verifyUnchanged(artifact);
  return check.ok ? result : check;
};

/**
 * Scan a file or directory. Returns Result<scan model>.
 * `hooks.afterFingerprint(fingerprint)` runs between detection and the adapters (tests).
 */
export function scanArtifact(path, hooks = {}) {
  const progress = { fingerprinted: false };
  try {
    return scanPath(path, hooks, progress);
  } catch (error) {
    // System errors (ENOENT, EACCES, EIO…) from a read: before the fingerprint the file is
    // unreadable; after it, the file changed under the scan. Programming errors propagate.
    if (typeof error?.code !== "string") throw error;
    return progress.fingerprinted
      ? err(
          "artifact-changed",
          `artifact unreadable during the scan: ${error.message}`,
        )
      : err("unreadable-artifact", error.message);
  }
}

function scanPath(path, hooks, progress) {
  let stat;
  try {
    stat = statSync(path);
  } catch (error) {
    return err("unreadable-artifact", error.message);
  }
  if (stat.isDirectory()) return scanDirectory(path);
  const print = fingerprint(path);
  progress.fingerprinted = true;
  hooks.afterFingerprint?.(print);
  const artifact = {
    path,
    sha256: print.sha256,
    bytes: print.bytes,
    kind: print.kind,
  };
  if (print.kind !== "asar")
    return verified(
      artifact,
      scanBinary(artifact, print.ecosystems, print.container),
    );
  const tree = asarTree(path);
  if (!tree.ok) return tree;
  const scan = emptyScan(artifact, ["npm"]);
  absorb(scan, scanNpm(artifact, tree.value));
  return verified(artifact, ok(finalizeScan(scan)));
}
