// Boundary tests on the real OSV snapshot (only when `make vulndb` has been run; skipped
// otherwise, also under make sbom-test). For at least 200 advisories per ecosystem, taken from
// the index itself, with one range [introduced X, fixed Y]:
//   just before Y → alert; Y → no alert; just before X → no alert (when X is not "0").
// "Just before" is built from the version string, not from the comparator under test:
//   SemVer / NuGet: "Y-0" (smallest pre-release of Y) and, when the last non-zero numeric part
//   can be decremented, that decremented release; PEP 440: "Y.dev0" and the decremented release.
// A candidate below X is dropped (that drop uses the comparator); cases whose `versions` list
// contradicts the expectation are counted and skipped, never forced.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { makeComponent } from "../lib/model.mjs";
import { ok } from "../lib/result.mjs";
import { openVulnDb } from "../lib/vulns/db.mjs";
import { matchComponents } from "../lib/vulns/match.mjs";
import { compareNugetParsed, parseNuget } from "../lib/versions/nuget.mjs";
import { comparePep440Parsed, parsePep440 } from "../lib/versions/pep440.mjs";
import { compareSemverParsed, parseSemver } from "../lib/versions/semver.mjs";
import { SBOM } from "./support.mjs";

const DIR = process.env.SBOM_VULNDB ?? join(SBOM, "vulndb");
const SAMPLE = 300;
const MIN = 200;

const semverPrev = (v) => {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v);
  if (!m) return [];
  const parts = m.slice(1).map(Number);
  const out = [`${v}-0`];
  const i = parts.findLastIndex((p) => p > 0);
  if (i >= 0 && parts.every(Number.isSafeInteger)) {
    const dec = [...parts];
    dec[i] -= 1;
    out.push(dec.join("."));
  }
  return out;
};
const nugetPrev = (v) => {
  if (!/^\d+(?:\.\d+){0,3}$/.test(v)) return [];
  const parts = v.split(".").map(Number);
  const out = [`${v}-0`];
  const i = parts.findLastIndex((p) => p > 0);
  if (i >= 0 && parts.every(Number.isSafeInteger)) {
    const dec = [...parts];
    dec[i] -= 1;
    out.push(dec.join("."));
  }
  return out;
};
const pep440Prev = (v) => {
  if (!/^\d+(?:\.\d+)*$/.test(v)) return [];
  const parts = v.split(".").map(Number);
  const out = [`${v}.dev0`];
  const i = parts.findLastIndex((p) => p > 0);
  if (i >= 0 && parts.every(Number.isSafeInteger)) {
    const dec = [...parts];
    dec[i] -= 1;
    out.push(dec.join("."));
  }
  return out;
};

const SEMVER = {
  prev: semverPrev,
  parse: (v) => parseSemver(v),
  cmp: compareSemverParsed,
};
const ECOSYSTEMS = {
  golang: { ...SEMVER, toComponent: (v) => `v${v}` },
  cargo: SEMVER,
  npm: SEMVER,
  nuget: { prev: nugetPrev, parse: parseNuget, cmp: compareNugetParsed },
  pypi: { prev: pep440Prev, parse: parsePep440, cmp: comparePep440Parsed },
};

const available = existsSync(join(DIR, "SNAPSHOT.json")) && openVulnDb(DIR).ok;

/** Cases [{advisory, entry, introduced, fixed}] with exactly one range [introduced, fixed]. */
function cases(ecosystem) {
  const out = [];
  const text = readFileSync(join(DIR, "index", `${ecosystem}.ndjson`), "utf8");
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const [key, advisories] = JSON.parse(line);
    for (const advisory of advisories) {
      if (advisory.withdrawn || advisory.affected.length !== 1) continue;
      const [entry] = advisory.affected;
      if (entry.ranges.length !== 1) continue;
      const [range] = entry.ranges;
      if (range.type === "GIT" || range.events.length !== 2) continue;
      const [a, b] = range.events;
      if (!("introduced" in a) || !("fixed" in b)) continue;
      out.push({
        key,
        advisory,
        entry,
        introduced: a.introduced,
        fixed: b.fixed,
        type: range.type,
      });
    }
  }
  // Prefer cases that also exercise "before introduced", then spread the sample over the index.
  out.sort(
    (x, y) => Number(x.introduced === "0") - Number(y.introduced === "0"),
  );
  if (out.length <= SAMPLE) return out;
  const step = out.length / SAMPLE;
  return Array.from({ length: SAMPLE }, (_, i) => out[Math.floor(i * step)]);
}

const alerts = (ecosystem, c, version) => {
  const component = makeComponent({
    ecosystem,
    name: c.key,
    version: ECOSYSTEMS[ecosystem].toComponent?.(version) ?? version,
    source: "bounds",
    evidence: {},
  });
  const db = { lookup: () => ok([{ ...c.advisory, affected: [c.entry] }]) };
  return matchComponents([component], db).alerts.length;
};

for (const ecosystem of Object.keys(ECOSYSTEMS)) {
  test(`${ecosystem}: ≥${MIN} advisories of the snapshot, bounds around introduced and fixed`, (t) => {
    if (!available) {
      t.skip(`no vulnerability index in ${DIR} (run make vulndb)`);
      return;
    }
    const eco = ECOSYSTEMS[ecosystem];
    const listed = (c, v) => (c.entry.versions ?? []).includes(v);
    const tally = {
      advisories: 0,
      checks: 0,
      beforeIntroduced: 0,
      skipped: 0,
      failures: [],
    };
    for (const c of cases(ecosystem)) {
      const intro = c.introduced === "0" ? null : eco.parse(c.introduced);
      if (intro !== null && !intro.ok) {
        tally.skipped += 1;
        continue;
      }
      const before = eco
        .prev(c.fixed)
        .filter((v) => eco.parse(v).ok)
        .filter(
          (v) =>
            intro === null || eco.cmp(eco.parse(v).value, intro.value) >= 0,
        );
      if (before.length === 0 || listed(c, c.fixed)) {
        tally.skipped += 1;
        continue;
      }
      const expect = (version, want, what) => {
        tally.checks += 1;
        const got = alerts(ecosystem, c, version);
        if (got !== want)
          tally.failures.push(
            `${c.advisory.id} ${c.key}@${version} (${what}): ${got} alert(s)`,
          );
      };
      for (const v of before) expect(v, 1, `before fixed ${c.fixed}`);
      expect(c.fixed, 0, "fixed");
      if (intro !== null)
        for (const v of eco.prev(c.introduced)) {
          if (!eco.parse(v).ok || listed(c, v)) continue;
          tally.beforeIntroduced += 1;
          expect(v, 0, `before introduced ${c.introduced}`);
        }
      tally.advisories += 1;
    }
    t.diagnostic(JSON.stringify({ ...tally, failures: tally.failures.length }));
    assert.deepEqual(tally.failures, []);
    assert.ok(
      tally.advisories >= MIN,
      `${ecosystem}: only ${tally.advisories} advisories`,
    );
  });
}
