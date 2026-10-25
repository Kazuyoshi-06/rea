#!/usr/bin/env node
// S5 D3: risky OSV ranges (pre-releases in events, last_affected, limit) taken from the real
// snapshot, evaluated by lib/vulns/osv.mjs and by an independent oracle, the OSV.dev API
// (POST https://api.osv.dev/v1/querybatch: OSV's own range evaluation, on its current data).
// Writes test/data/risky-ranges.json (committed): each case keeps the compact `affected` entries
// we evaluate, the version, our verdict and the oracle's, so test/risky-ranges.test.mjs replays
// them offline. Needs `make vulndb` and network.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { identityName } from "../lib/model.mjs";
import { evaluateAffected, OSV_ECOSYSTEM } from "../lib/vulns/osv.mjs";

const SBOM = join(import.meta.dirname, "..");
const INDEX = join(SBOM, "vulndb/index");
const PER_ECOSYSTEM = { pre: 4, last_affected: 2, limit: 1 };
const PRE = {
  golang: /-/,
  cargo: /-/,
  npm: /-/,
  nuget: /-/,
  pypi: /(a|b|c|rc|alpha|beta|pre|preview|dev)\d*/i,
};

const events = (affected) =>
  affected.flatMap((e) =>
    e.ranges.filter((r) => r.type !== "GIT").flatMap((r) => r.events),
  );
const kindOf = (ecosystem, affected) => {
  const evs = events(affected);
  if (evs.some((e) => "limit" in e)) return "limit";
  if (evs.some((e) => "last_affected" in e)) return "last_affected";
  if (
    evs.some((e) =>
      Object.values(e).some((v) => v !== "0" && PRE[ecosystem].test(v)),
    )
  )
    return "pre";
  return null;
};

/** Versions around every event value: the value, its release base, a pre-release of it, the next patch. */
function probeVersions(ecosystem, affected) {
  const out = new Set();
  for (const e of events(affected)) {
    const v = Object.values(e)[0];
    if (v === "0") continue;
    out.add(v);
    const base =
      ecosystem === "pypi"
        ? v.replace(/(\.?(a|b|c|rc|alpha|beta|pre|preview|dev)\d*)+$/i, "")
        : v.split(/[-+]/)[0];
    out.add(base);
    out.add(
      ecosystem === "pypi"
        ? `${base}rc1`
        : ecosystem === "nuget"
          ? `${base}-alpha`
          : `${base}-0`,
    );
    const parts = base.split(".");
    if (/^\d+$/.test(parts.at(-1)))
      out.add(
        [...parts.slice(0, -1), String(Number(parts.at(-1)) + 1)].join("."),
      );
  }
  return [...out]
    .filter((v) => v !== "")
    .sort()
    .slice(0, 12);
}

function pick(ecosystem) {
  const lines = readFileSync(join(INDEX, `${ecosystem}.ndjson`), "utf8").split(
    "\n",
  );
  const want = { ...PER_ECOSYSTEM };
  const picked = [];
  const packages = new Set();
  for (const line of lines) {
    if (!line) continue;
    const [key, advisories] = JSON.parse(line);
    if (packages.has(key)) continue;
    for (const a of advisories) {
      if (a.withdrawn || a.id.startsWith("MAL-")) continue;
      const kind = kindOf(ecosystem, a.affected);
      if (kind === null || !(want[kind] > 0)) continue;
      want[kind] -= 1;
      packages.add(key);
      picked.push({ key, advisory: a, kind });
      break;
    }
    if (Object.values(want).every((n) => n <= 0)) break;
  }
  return picked;
}

function oracle(queries) {
  const body = JSON.stringify({ queries });
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const res = spawnSync(
      "curl",
      [
        "-sS",
        "--fail",
        "-X",
        "POST",
        "https://api.osv.dev/v1/querybatch",
        "--data-binary",
        "@-",
      ],
      { input: body, maxBuffer: 64 << 20 },
    );
    if (res.status === 0) return JSON.parse(res.stdout.toString()).results;
    process.stderr.write(`querybatch attempt ${attempt}: ${res.stderr}\n`);
  }
  throw new Error("api.osv.dev unreachable twice");
}

/** The package name as the record spells it (the index key is an identity, lowercased for NuGet). */
function recordName(ecosystem, id, key) {
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const res = spawnSync(
      "curl",
      ["-sS", "--fail", `https://api.osv.dev/v1/vulns/${id}`],
      { maxBuffer: 64 << 20 },
    );
    if (res.status !== 0) continue;
    const entry = JSON.parse(res.stdout.toString()).affected.find(
      (e) =>
        e.package.ecosystem === OSV_ECOSYSTEM[ecosystem] &&
        identityName({ ecosystem, name: e.package.name }) === key,
    );
    if (entry) return entry.package.name;
  }
  throw new Error(`${id}: no affected entry for ${key}`);
}

const cases = [];
for (const ecosystem of Object.keys(OSV_ECOSYSTEM)) {
  for (const { key, advisory, kind } of pick(ecosystem)) {
    const name = recordName(ecosystem, advisory.id, key);
    for (const version of probeVersions(ecosystem, advisory.affected)) {
      const results = advisory.affected.map((entry) =>
        evaluateAffected(ecosystem, entry, version),
      );
      const ours = results.some((r) => r.affected)
        ? true
        : results.some((r) => r.unevaluated.length > 0)
          ? "unevaluated"
          : false;
      cases.push({
        ecosystem,
        package: name,
        id: advisory.id,
        kind,
        modified: advisory.modified,
        version,
        ours,
        affected: advisory.affected,
      });
    }
  }
}
// OSV.dev matches package names exactly (constaté: "akka" finds nothing, "Akka" does), hence
// recordName above.
const results = oracle(
  cases.map((c) => ({
    package: { name: c.package, ecosystem: OSV_ECOSYSTEM[c.ecosystem] },
    version: c.version,
  })),
);
results.forEach((r, i) => {
  const hit = (r.vulns ?? []).find((v) => v.id === cases[i].id);
  cases[i].oracle = Boolean(hit);
  cases[i].oracleModified = hit?.modified ?? null;
  cases[i].oraclePaged = Boolean(r.next_page_token);
});
const disagreements = cases.filter((c) => c.ours !== c.oracle);
const advisories = {};
for (const c of cases)
  advisories[c.id] ??= {
    ecosystem: c.ecosystem,
    package: c.package,
    kind: c.kind,
    modified: c.modified,
    oracleModified: c.oracleModified,
    affected: c.affected,
  };
writeFileSync(
  join(SBOM, "test/data/risky-ranges.json"),
  `${JSON.stringify(
    {
      oracle: "api.osv.dev /v1/querybatch",
      generated: new Date().toISOString().slice(0, 10),
      advisories,
      cases: cases.map((c) => ({
        id: c.id,
        version: c.version,
        ours: c.ours,
        oracle: c.oracle,
      })),
    },
    null,
    1,
  )}\n`,
);
const by = (f) =>
  Object.entries(Object.groupBy(cases, f))
    .map(([k, v]) => `${k}: ${v.length}`)
    .join(", ");
console.log(
  `cases ${cases.length} (${by((c) => c.ecosystem)}), packages ${new Set(cases.map((c) => `${c.ecosystem}:${c.package}`)).size}, kinds ${by((c) => c.kind)}`,
);
console.log(`disagreements ${disagreements.length}`);
for (const d of disagreements)
  console.log(
    `  ${d.ecosystem} ${d.package} ${d.id} ${d.version}: ours ${d.ours}, oracle ${d.oracle}${d.oraclePaged ? " (oracle paged)" : ""}`,
  );
