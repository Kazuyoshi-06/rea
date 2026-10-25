#!/usr/bin/env node
// make vulndb: download the OSV exports of the five ecosystems into sbom/vulndb/ and build the
// offline index (lib/vulns/db.mjs). Writes vulndb/SNAPSHOT.json (committed) with the date and
// sha256 of every archive. The archives and the index are gitignored.
//   node scripts/vulndb.mjs              download (curl, 2 attempts per archive) then index
//   node scripts/vulndb.mjs --no-download  index the archives already in vulndb/
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { openZip } from "../lib/readers/zip.mjs";
import { indexAdvisories, writeVulnDb } from "../lib/vulns/db.mjs";
import { OSV_ECOSYSTEM } from "../lib/vulns/osv.mjs";

const SBOM = join(import.meta.dirname, "..");
const DIR = process.env.VULNDB_DIR ?? join(SBOM, "vulndb");
const BASE = "https://osv-vulnerabilities.storage.googleapis.com";
const noDownload = process.argv.includes("--no-download");

function download(osvName) {
  const url = `${BASE}/${encodeURIComponent(osvName)}/all.zip`;
  const target = join(DIR, `${osvName}.zip`);
  const headers = join(DIR, `${osvName}.headers`);
  if (noDownload) {
    if (!existsSync(target))
      throw new Error(`${target} missing (--no-download)`);
    return { url, target, headers };
  }
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const res = spawnSync(
      "curl",
      ["-sS", "--fail", "-o", `${target}.part`, "-D", headers, url],
      { stdio: ["ignore", "inherit", "pipe"] },
    );
    if (res.status === 0) {
      renameSync(`${target}.part`, target);
      return { url, target, headers };
    }
    process.stderr.write(
      `vulndb: ${osvName} attempt ${attempt}: ${res.stderr}`,
    );
  }
  throw new Error(`${osvName}: download failed twice`);
}

function lastModified(headersFile) {
  if (!existsSync(headersFile)) return null;
  const line = readFileSync(headersFile, "utf8")
    .split(/\r?\n/)
    .find((l) => /^last-modified:/i.test(l));
  return line
    ? new Date(line.slice(line.indexOf(":") + 1).trim()).toISOString()
    : null;
}

function* records(zip, stats) {
  for (const entry of zip.entries) {
    if (!entry.name.endsWith(".json")) continue;
    const data = zip.read(entry);
    if (!data.ok) {
      stats.unreadable += 1;
      continue;
    }
    try {
      yield JSON.parse(data.value.toString("utf8"));
    } catch {
      stats.unreadable += 1;
    }
  }
}

mkdirSync(join(DIR, "index"), { recursive: true });
const built = {};
for (const [ecosystem, osvName] of Object.entries(OSV_ECOSYSTEM)) {
  const started = process.hrtime.bigint();
  const { url, target, headers } = download(osvName);
  const bytes = readFileSync(target);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const zip = openZip(target);
  if (!zip.ok) throw new Error(`${osvName}: ${zip.error.message}`);
  const extra = { unreadable: 0 };
  const { packages, stats } = indexAdvisories(
    records(zip.value, extra),
    ecosystem,
  );
  built[ecosystem] = {
    packages,
    archive: {
      url,
      lastModified: lastModified(headers),
      downloadedAt: statSync(target).mtime.toISOString(),
      sha256,
      bytes: bytes.length,
      zipEntries: zip.value.entries.length,
      osvRecords: stats.records,
      unreadableRecords: extra.unreadable,
      indexedAdvisories: stats.advisories,
      withdrawnAdvisories: stats.withdrawn,
      packages: packages.size,
    },
  };
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  process.stderr.write(
    `vulndb: ${osvName}: ${stats.advisories} advisories, ${packages.size} packages, ${Math.round(ms)} ms\n`,
  );
}

const snapshot = writeVulnDb(
  DIR,
  built,
  "OSV per-ecosystem exports (https://google.github.io/osv.dev/data/#data-dumps)",
);
process.stderr.write(`vulndb: snapshot ${snapshot.id} written to ${DIR}\n`);
