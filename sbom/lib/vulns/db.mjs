// Offline vulnerability index built from the OSV per-ecosystem exports.
//
// Layout of sbom/vulndb/ (only SNAPSHOT.json is committed):
//   <Ecosystem>.zip          OSV export, as downloaded (https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip)
//   SNAPSHOT.json            per archive: URL, Last-Modified, download time, sha256, counts; snapshot id
//   index/<eco>.ndjson       one line per package, sorted by key: [key, [advisory…]]
//   index/<eco>.dir          line 1: JSON header {format, snapshot, ecosystem, archiveSha256};
//                            then one line per package, sorted: key TAB offset TAB length
//                            (looked up by binary search on the text: no parse of the whole
//                            directory, which has 226 000 keys for npm)
// <eco> is the model ecosystem (golang, cargo, npm, nuget, pypi). The package key is the
// model's identityName (NuGet lowercased, PyPI PEP 503, others exact), so lookups use the same
// identity rule as component merging.
// Compact advisory: {id, aliases[], summary, modified, withdrawn?,
//                    affected: [{ranges, versions?, fixed[], platforms?: [{goos?, goarch?}]}]}
// with only the `affected[]` entries of this ecosystem and package.
import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { identityName } from "../model.mjs";
import { err, ok } from "../result.mjs";
import { OSV_ECOSYSTEM } from "./osv.mjs";

// /2 (S6): affected entries keep their platform restrictions (`platforms`).
export const INDEX_FORMAT = "rea-sbom-osv-index/2";
const SUMMARY_MAX = 240;

function summaryOf(doc) {
  if (typeof doc.summary === "string" && doc.summary.trim() !== "")
    return doc.summary.trim();
  const first =
    typeof doc.details === "string" ? doc.details.trim().split(/\r?\n/)[0] : "";
  return first.length > SUMMARY_MAX
    ? `${first.slice(0, SUMMARY_MAX - 1)}…`
    : first;
}

const stringList = (v) =>
  Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === "string")
    ? [...v].sort()
    : null;

/**
 * Platform restrictions of an affected entry (Go: ecosystem_specific.imports[].goos / goarch),
 * one {goos?, goarch?} per import, kept only when at least one import names a platform (an
 * import without goos / goarch applies everywhere and is kept as {}). Null: no restriction
 * recorded, the entry applies to every platform. A goos / goarch that is not a non-empty list
 * of strings is not a restriction (fail open: the alert stays).
 */
function importPlatforms(entry) {
  const imports = entry?.ecosystem_specific?.imports;
  if (!Array.isArray(imports) || imports.length === 0) return null;
  const platforms = imports.map((i) => {
    const out = {};
    const goos = stringList(i?.goos);
    const goarch = stringList(i?.goarch);
    if (goos) out.goos = goos;
    if (goarch) out.goarch = goarch;
    return out;
  });
  return platforms.some((p) => p.goos || p.goarch) ? platforms : null;
}

/**
 * Index OSV records for one model ecosystem. `docs` yields parsed OSV JSON objects.
 * Returns {packages: Map<key, advisory[]>, stats}.
 */
export function indexAdvisories(docs, ecosystem) {
  const osvName = OSV_ECOSYSTEM[ecosystem];
  const packages = new Map();
  const stats = { records: 0, advisories: 0, withdrawn: 0, skipped: 0 };
  for (const doc of docs) {
    stats.records += 1;
    if (typeof doc?.id !== "string" || !Array.isArray(doc.affected)) {
      stats.skipped += 1;
      continue;
    }
    const byKey = new Map();
    for (const entry of doc.affected) {
      const pkg = entry?.package;
      if (pkg?.ecosystem !== osvName || typeof pkg.name !== "string") continue;
      const key = identityName({ ecosystem, name: pkg.name });
      const ranges = (entry.ranges ?? []).map((r) => ({
        type: r.type,
        events: r.events ?? [],
      }));
      const fixed = ranges.flatMap((r) =>
        r.type === "GIT"
          ? []
          : r.events.filter((e) => "fixed" in e).map((e) => e.fixed),
      );
      const compact = { ranges, fixed: [...new Set(fixed)] };
      if (Array.isArray(entry.versions) && entry.versions.length > 0)
        compact.versions = entry.versions;
      const platforms = importPlatforms(entry);
      if (platforms !== null) compact.platforms = platforms;
      if (!byKey.has(key)) byKey.set(key, []);
      byKey.get(key).push(compact);
    }
    if (byKey.size === 0) continue;
    stats.advisories += 1;
    if (doc.withdrawn) stats.withdrawn += 1;
    for (const [key, affected] of byKey) {
      const advisory = {
        id: doc.id,
        aliases: [...new Set(doc.aliases ?? [])].sort(),
        summary: summaryOf(doc),
        modified: doc.modified ?? null,
      };
      if (doc.withdrawn) advisory.withdrawn = doc.withdrawn;
      advisory.affected = affected;
      if (!packages.has(key)) packages.set(key, []);
      packages.get(key).push(advisory);
    }
  }
  for (const list of packages.values())
    list.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { packages, stats };
}

/** Serialize an index: {ndjson: Buffer, directory: string}. Keys sorted, byte-stable. */
export function serializeIndex(packages, header) {
  const keys = [...packages.keys()].sort();
  const chunks = [];
  const lines = [JSON.stringify({ format: INDEX_FORMAT, ...header })];
  let offset = 0;
  for (const key of keys) {
    if (/[\t\n]/.test(key))
      throw new Error(
        `package key with a tab or newline: ${JSON.stringify(key)}`,
      );
    const line = Buffer.from(
      `${JSON.stringify([key, packages.get(key)])}\n`,
      "utf8",
    );
    lines.push(`${key}\t${offset}\t${line.length}`);
    offset += line.length;
    chunks.push(line);
  }
  return { ndjson: Buffer.concat(chunks), directory: `${lines.join("\n")}\n` };
}

/** Binary search of `key` in the sorted directory body. Returns [offset, length] or null. */
function findSlot(text, bodyStart, key) {
  let lo = bodyStart;
  let hi = text.length;
  // Invariant: the line holding `key`, if any, starts in [lo, hi); lo is a line start.
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    const start = Math.max(lo, text.lastIndexOf("\n", mid - 1) + 1);
    let end = text.indexOf("\n", start);
    if (end < 0) end = text.length;
    const line = text.slice(start, end);
    const tab = line.indexOf("\t");
    const lineKey = line.slice(0, tab);
    if (lineKey === key) {
      const [offset, length] = line
        .slice(tab + 1)
        .split("\t")
        .map(Number);
      return [offset, length];
    }
    if (lineKey < key) lo = end + 1;
    else hi = start;
  }
  return null;
}

/**
 * Write the index and SNAPSHOT.json under `dir`. `built` maps a model ecosystem to
 * {packages (from indexAdvisories), archive: {sha256, …metadata recorded in SNAPSHOT.json}}.
 * The snapshot id is derived from the archives' sha256 only. Returns the snapshot object.
 */
export function writeVulnDb(dir, built, source) {
  const archives = {};
  for (const [ecosystem, { archive }] of Object.entries(built))
    archives[OSV_ECOSYSTEM[ecosystem]] = archive;
  const names = Object.keys(archives).sort();
  const id = `osv-${createHash("sha256")
    .update(names.map((k) => `${k}:${archives[k].sha256}\n`).join(""))
    .digest("hex")
    .slice(0, 16)}`;
  mkdirSync(join(dir, "index"), { recursive: true });
  for (const [ecosystem, { packages, archive }] of Object.entries(built)) {
    const { ndjson, directory } = serializeIndex(packages, {
      snapshot: id,
      ecosystem,
      archiveSha256: archive.sha256,
    });
    writeFileSync(join(dir, "index", `${ecosystem}.ndjson`), ndjson);
    writeFileSync(join(dir, "index", `${ecosystem}.dir`), directory);
  }
  const sorted = Object.fromEntries(names.map((k) => [k, archives[k]]));
  const snapshot = { format: INDEX_FORMAT, id, source, archives: sorted };
  writeFileSync(
    join(dir, "SNAPSHOT.json"),
    `${JSON.stringify(snapshot, null, 2)}\n`,
  );
  return snapshot;
}

/**
 * Open the index under `dir`. Ecosystem directories load lazily on first lookup.
 * Result<{snapshot, lookup(ecosystem, name) → Result<advisory[]>, loadMs()}>.
 */
export function openVulnDb(dir) {
  const snapshotFile = join(dir, "SNAPSHOT.json");
  if (!existsSync(snapshotFile))
    return err("vulndb-missing", `${snapshotFile} not found (run make vulndb)`);
  let snapshot;
  try {
    snapshot = JSON.parse(readFileSync(snapshotFile, "utf8"));
  } catch (error) {
    return err("vulndb-invalid", `SNAPSHOT.json: ${error.message}`);
  }
  if (snapshot.format !== INDEX_FORMAT || typeof snapshot.id !== "string")
    return err("vulndb-invalid", "SNAPSHOT.json has an unknown format");
  // SNAPSHOT.json is committed; the index is not. A fresh clone has the first without the second.
  const missing = Object.keys(OSV_ECOSYSTEM).filter(
    (ecosystem) =>
      snapshot.archives?.[OSV_ECOSYSTEM[ecosystem]] !== undefined &&
      !existsSync(join(dir, "index", `${ecosystem}.dir`)),
  );
  if (missing.length > 0)
    return err(
      "vulndb-missing",
      `${join(dir, "index")}: no index for ${missing.join(", ")} (run make vulndb)`,
    );
  const loaded = new Map();
  let loadNs = 0n;
  const directoryOf = (ecosystem) => {
    if (loaded.has(ecosystem)) return loaded.get(ecosystem);
    const started = process.hrtime.bigint();
    const file = join(dir, "index", `${ecosystem}.dir`);
    let result;
    if (!existsSync(file))
      result = err("vulndb-missing", `${file} not found (run make vulndb)`);
    else {
      try {
        const text = readFileSync(file, "utf8");
        const bodyStart = text.indexOf("\n") + 1;
        const header = JSON.parse(text.slice(0, bodyStart));
        const expected = snapshot.archives?.[OSV_ECOSYSTEM[ecosystem]]?.sha256;
        if (header.format !== INDEX_FORMAT || header.snapshot !== snapshot.id)
          result = err(
            "vulndb-stale",
            `${file} was not built for snapshot ${snapshot.id} (run make vulndb)`,
          );
        else if (header.archiveSha256 !== expected)
          result = err(
            "vulndb-stale",
            `${file}: archive sha256 differs from SNAPSHOT.json`,
          );
        else result = ok({ text, bodyStart });
      } catch (error) {
        result = err("vulndb-invalid", `${file}: ${error.message}`);
      }
    }
    loaded.set(ecosystem, result);
    loadNs += process.hrtime.bigint() - started;
    return result;
  };
  const lookup = (ecosystem, name) => {
    const directory = directoryOf(ecosystem);
    if (!directory.ok) return directory;
    const key = identityName({ ecosystem, name });
    const slot = findSlot(directory.value.text, directory.value.bodyStart, key);
    if (slot === null) return ok([]);
    const fd = openSync(join(dir, "index", `${ecosystem}.ndjson`), "r");
    try {
      const buf = Buffer.alloc(slot[1]);
      readSync(fd, buf, 0, slot[1], slot[0]);
      const [lineKey, advisories] = JSON.parse(buf.toString("utf8"));
      if (lineKey !== key)
        return err("vulndb-invalid", `index line for ${key} names ${lineKey}`);
      return ok(advisories);
    } catch (error) {
      return err("vulndb-invalid", `${ecosystem} index: ${error.message}`);
    } finally {
      closeSync(fd);
    }
  };
  return ok({ snapshot, lookup, loadMs: () => Number(loadNs) / 1e6 });
}
