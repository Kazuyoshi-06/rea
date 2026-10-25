// Offline vulnerability matching: OSV range evaluation, index, matcher and CLI, on the committed
// mini OSV corpus (test/data/osv-mini). No network, no real snapshot needed.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { makeComponent, makeUnknown } from "../lib/model.mjs";
import { indexAdvisories, openVulnDb, writeVulnDb } from "../lib/vulns/db.mjs";
import {
  groupAlerts,
  matchComponents,
  primaryId,
} from "../lib/vulns/match.mjs";
import {
  evaluateAffected,
  evaluateRange,
  OSV_ECOSYSTEM,
} from "../lib/vulns/osv.mjs";
import {
  OUT,
  S2_FIXTURES,
  S3_DOTNET_FIXTURES,
  S3_PYTHON_FIXTURES,
  SBOM,
  SCAN_BIN,
  fixtureGate,
  fixturePath,
  schemaErrors,
} from "./support.mjs";

const MINI = join(SBOM, "test/data/osv-mini");
const scratch = mkdtempSync(join(tmpdir(), "sbom-vulns-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

/** Build an index of the mini corpus under `dir` (same code path as make vulndb). */
function buildMiniDb(dir) {
  const docs = readdirSync(MINI)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(MINI, f), "utf8")));
  const built = {};
  for (const ecosystem of Object.keys(OSV_ECOSYSTEM)) {
    const { packages } = indexAdvisories(docs, ecosystem);
    built[ecosystem] = {
      packages,
      archive: {
        sha256: `${ecosystem}-mini`,
        lastModified: "2026-01-01T00:00:00.000Z",
      },
    };
  }
  return writeVulnDb(dir, built, "test/data/osv-mini");
}

const DB_DIR = join(scratch, "db");
const SNAPSHOT = buildMiniDb(DB_DIR);
const db = () => openVulnDb(DB_DIR).value;

const ev = {
  artifact: { path: "x", sha256: "0" },
  location: { kind: "file", path: "x" },
};
const component = (ecosystem, name, version, extra = {}) =>
  makeComponent({
    ecosystem,
    name,
    version,
    source: "test",
    evidence: ev,
    ...extra,
  });
const ids = (result) =>
  result.alerts.map(
    (a) => `${a.id} ${a.component.name}@${a.component.version}`,
  );

// --- Range evaluation -----------------------------------------------------------------

test("osv: introduced/fixed/last_affected/limit replayed in version order", () => {
  const range = {
    type: "SEMVER",
    // deliberately unsorted: evaluation sorts the events
    events: [
      { introduced: "2.0.0" },
      { last_affected: "2.1.0" },
      { introduced: "1.0.0" },
      { fixed: "1.2.0" },
    ],
  };
  const affected = (v) => evaluateRange("npm", range, v).value.affected;
  assert.equal(affected("0.9.9"), false, "before introduced");
  assert.equal(affected("1.0.0"), true, "introduced is affected");
  assert.equal(affected("1.1.9"), true, "just before fixed");
  assert.equal(affected("1.2.0"), false, "fixed");
  assert.equal(affected("1.9.9"), false, "between intervals");
  assert.equal(affected("2.1.0"), true, "last_affected is affected");
  assert.equal(affected("2.1.1-0"), false, "after last_affected");
  const limit = {
    type: "SEMVER",
    events: [{ introduced: "3.0.0" }, { limit: "3.5.0" }],
  };
  assert.equal(evaluateRange("npm", limit, "3.4.9").value.affected, true);
  assert.equal(evaluateRange("npm", limit, "3.5.0").value.affected, false);
  const zero = {
    type: "ECOSYSTEM",
    events: [{ introduced: "0" }, { fixed: "2.0" }],
  };
  assert.equal(evaluateRange("pypi", zero, "0.0.1.dev0").value.affected, true);
  assert.equal(
    evaluateRange("pypi", zero, "2.0.0").value.affected,
    false,
    "PEP 440: 2.0.0 == 2.0",
  );
  assert.equal(
    evaluateRange("pypi", zero, "2.0rc1").value.affected,
    true,
    "pre-release of fixed",
  );
  assert.equal(evaluateRange("nuget", zero, "1.9.9.9").value.affected, true);
  assert.equal(evaluateRange("nuget", zero, "2.0.0.0").value.affected, false);
});

test("osv: GIT ranges and unparseable versions are unevaluated, never guessed", () => {
  const git = { type: "GIT", events: [{ introduced: "0" }, { fixed: "abc" }] };
  assert.equal(evaluateRange("pypi", git, "1.0").ok, false);
  let r = evaluateAffected("pypi", { ranges: [git] }, "1.0");
  assert.deepEqual([r.affected, r.unevaluated.length], [false, 1]);
  // GIT range next to an explicit versions list: the list decides, the GIT range is not reported
  r = evaluateAffected(
    "pypi",
    { ranges: [git], versions: ["1.0", "1.1.post1"] },
    "1.0.0",
  );
  assert.deepEqual([r.affected, r.via, r.unevaluated], [true, "versions", []]);
  r = evaluateAffected("pypi", { ranges: [git], versions: ["1.0"] }, "1.0.1");
  assert.deepEqual([r.affected, r.unevaluated], [false, []]);
  const bad = {
    type: "SEMVER",
    events: [{ introduced: "0" }, { fixed: "1.x" }],
  };
  r = evaluateAffected("cargo", { ranges: [bad] }, "1.0.0");
  assert.equal(r.affected, false);
  assert.match(r.unevaluated[0].reason, /fixed event: not a SemVer version/);
  r = evaluateAffected(
    "npm",
    { ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] },
    "1.2",
  );
  assert.match(r.unevaluated[0].reason, /component version/);
});

// --- Index and matcher ----------------------------------------------------------------

test("index: lookups use the model identity (PEP 503, NuGet case) and verify the snapshot", () => {
  const d = db();
  assert.equal(d.snapshot.id, SNAPSHOT.id);
  assert.deepEqual(
    d.lookup("pypi", "some.PKG").value.map((a) => a.id),
    ["REA-TEST-0002", "REA-TEST-0003", "REA-TEST-0007"],
  );
  assert.deepEqual(
    d.lookup("nuget", "SERILOG").value.map((a) => a.id),
    ["REA-TEST-0004"],
  );
  assert.deepEqual(d.lookup("npm", "Serilog").value, [], "npm names are exact");
  assert.deepEqual(d.lookup("cargo", "absent").value, []);
  const lodash = d.lookup("npm", "lodash").value[0];
  assert.equal(lodash.id, "GHSA-35jh-r3h4-6jhm");
  assert.deepEqual(lodash.affected[0].fixed, ["4.17.21"]);
  assert.ok(lodash.aliases.includes("CVE-2021-23337"));
  // an index that does not belong to SNAPSHOT.json is refused
  const other = join(scratch, "stale");
  buildMiniDb(other);
  const json = JSON.parse(readFileSync(join(other, "SNAPSHOT.json"), "utf8"));
  json.archives.npm.sha256 = "changed";
  json.id = "osv-0000000000000000";
  writeFileSync(join(other, "SNAPSHOT.json"), JSON.stringify(json));
  assert.equal(
    openVulnDb(other).value.lookup("npm", "lodash").error.tag,
    "vulndb-stale",
  );
  assert.equal(
    openVulnDb(join(scratch, "nowhere")).error.tag,
    "vulndb-missing",
  );
  // A fresh clone: committed SNAPSHOT.json, no index.
  const bare = join(scratch, "snapshot-only");
  cpSync(join(DB_DIR, "SNAPSHOT.json"), join(bare, "SNAPSHOT.json"));
  assert.equal(openVulnDb(bare).error.tag, "vulndb-missing");
});

test("index: binary search finds every key of a large directory and nothing else", () => {
  const packages = new Map();
  for (let i = 0; i < 5000; i += 1) {
    const name = `p${(i * 7919) % 5000}-${"x".repeat(i % 13)}`;
    packages.set(name, [
      {
        id: `T-${name}`,
        aliases: [],
        summary: "",
        modified: null,
        affected: [],
      },
    ]);
  }
  packages.set("@scope/a", [
    {
      id: "T-@scope/a",
      aliases: [],
      summary: "",
      modified: null,
      affected: [],
    },
  ]);
  const dir = join(scratch, "large");
  writeVulnDb(dir, { npm: { packages, archive: { sha256: "large" } } }, "test");
  const large = openVulnDb(dir).value;
  for (const name of packages.keys())
    assert.deepEqual(
      large.lookup("npm", name).value.map((a) => a.id),
      [`T-${name}`],
      name,
    );
  for (const miss of [
    "",
    "a",
    "p",
    "p0",
    "p0-x",
    "zzz",
    "@scope",
    "@scope/b",
    "p9999-",
  ])
    assert.deepEqual(large.lookup("npm", miss).value, [], miss);
});

test("matcher: alerts inherit confidence; withdrawn, no-purl and unknowns never alert", () => {
  const components = [
    component("npm", "multi", "1.1.0", { confidence: "medium" }),
    component("npm", "multi", "2.1.0"),
    component("npm", "multi", "1.2.0"),
    component("pypi", "some_pkg", "1.0.0", { confidence: "low" }),
    component("nuget", "Serilog", "3.1.1"),
    component("cargo", "regex", "1.5.4", { noPurl: "source git" }),
    component("cargo", "regex", "1.5.5"),
    component("golang", "example.com/mod", "v2.0.0+incompatible"),
    component("golang", "example.com/mod", "v2.0.1+incompatible"),
    component("golang", "stdlib", "1.24.7", { role: "language-runtime" }),
  ];
  const result = matchComponents(components, db());
  assert.deepEqual(ids(result), [
    "GO-2025-4006 stdlib@1.24.7",
    "REA-TEST-0001 multi@1.1.0",
    "REA-TEST-0001 multi@2.1.0",
    "REA-TEST-0004 Serilog@3.1.1",
    "REA-TEST-0006 example.com/mod@v2.0.0+incompatible",
    "REA-TEST-0007 some_pkg@1.0.0",
  ]);
  const byName = (n) => result.alerts.find((a) => a.component.name === n);
  assert.equal(byName("multi").confidence, "medium");
  assert.equal(byName("some_pkg").confidence, "low");
  assert.deepEqual(byName("multi").fixed, ["1.2.0"]);
  assert.equal(result.stats.withdrawnIgnored, 1, "REA-TEST-0003 is withdrawn");
  assert.equal(result.stats.skippedNoPurl, 1, "git-sourced crate not matched");
  // RUSTSEC-2022-0013 fixes regex in 1.5.5; REA-TEST-0005 has an unparseable event
  assert.deepEqual(
    result.unevaluated.map(
      (u) => `${u.id} ${u.component.name}@${u.component.version}`,
    ),
    ["REA-TEST-0002 some_pkg@1.0.0", "REA-TEST-0005 regex@1.5.5"],
  );
  // An unknown is not a component: there is nothing to pass to the matcher.
  const unknown = makeUnknown({
    ecosystem: "nuget",
    name: "Serilog",
    reason: "x",
    evidence: ev,
  });
  assert.equal("version" in unknown, false);
});

// --- CLI on the corpus with the mini index --------------------------------------------

function scan(path, extra = []) {
  const res = spawnSync(
    process.execPath,
    [
      SCAN_BIN,
      path,
      "--format",
      "cyclonedx",
      "--vulns",
      "--db",
      DB_DIR,
      "--timestamp",
      "0",
      ...extra,
    ],
    { maxBuffer: 64 << 20 },
  );
  assert.equal(res.status, 0, res.stderr.toString("utf8"));
  return res.stdout;
}

// One entry per alias group, primary id CVE > GHSA > first (A1, format-version 3).
const EXPECTED = {
  "go-jwt": ["CVE-2020-26160", "CVE-2022-32149", "CVE-2025-61725"],
  "rust-vuln": ["CVE-2022-24713"],
  "npm-electron": ["CVE-2021-23337"],
  "npm-cli": ["CVE-2021-44906"],
  "dotnet-json": ["CVE-2024-21907"],
  "dotnet-serilog": ["REA-TEST-0004"],
  "py-requests": ["CVE-2023-45803", "CVE-2024-35195"],
  "py-yaml": ["CVE-2020-14343"],
};
const FIXTURES = [
  ...S2_FIXTURES,
  ...S3_DOTNET_FIXTURES,
  ...S3_PYTHON_FIXTURES,
].filter((f) => Object.hasOwn(EXPECTED, f.id));

for (const fx of FIXTURES) {
  test(`${fx.id}: --vulns with the mini index is schema-valid, deterministic, versioned refs only`, (t) => {
    if (!fixtureGate(t, fx)) return;
    const first = scan(fixturePath(fx));
    assert.ok(first.equals(scan(fixturePath(fx))), "two runs differ");
    const bom = JSON.parse(first.toString("utf8"));
    assert.deepEqual(schemaErrors(bom), []);
    assert.deepEqual(
      bom.vulnerabilities.map((v) => v.id),
      EXPECTED[fx.id],
    );
    const refs = new Map(bom.components.map((c) => [c["bom-ref"], c]));
    for (const v of bom.vulnerabilities) {
      const c = refs.get(v.affects[0].ref);
      assert.ok(c?.version, `${v.id}: alert on a component without version`);
      const confidence = (x) =>
        x.properties.find((p) => p.name === "rea-sbom:confidence").value;
      assert.equal(
        confidence(v),
        confidence(c),
        `${v.id}: confidence not inherited`,
      );
    }
    for (const v of bom.vulnerabilities) {
      const confidence = v.properties.find(
        (p) => p.name === "rea-sbom:confidence",
      ).value;
      assert.equal(
        v.analysis?.state,
        confidence === "low" ? "in_triage" : undefined,
        `${v.id}: low confidence ⇔ in_triage`,
      );
      assert.ok(
        v.properties.some((p) => p.name === "rea-sbom:osv-record"),
        `${v.id}: matched OSV records listed`,
      );
      assert.ok(
        !(v.references ?? []).some((r) => r.id === v.id),
        "primary id not repeated in references",
      );
    }
    const meta = new Map(bom.metadata.properties.map((p) => [p.name, p.value]));
    assert.equal(meta.get("rea-sbom:format-version"), "3");
    assert.equal(meta.get("rea-sbom:vulndb-snapshot"), SNAPSHOT.id);
    assert.equal(
      meta.get("rea-sbom:vuln-count"),
      String(bom.vulnerabilities.length),
    );
  });
}

test("A1: alias groups (GO-/GHSA-/CVE- linked transitively), primary id CVE > GHSA > first", () => {
  assert.equal(primaryId(["GO-1", "GHSA-b", "CVE-2", "CVE-1"]), "CVE-1");
  assert.equal(primaryId(["PYSEC-1", "GHSA-b", "GHSA-a"]), "GHSA-a");
  assert.equal(primaryId(["RUSTSEC-2", "PYSEC-1"]), "PYSEC-1");
  const c1 = component("golang", "a", "v1.0.0");
  const c2 = component("golang", "b", "v1.0.0");
  const alert = (id, aliases, c) => ({
    id,
    aliases,
    summary: id,
    modified: null,
    component: c,
    via: ["SEMVER"],
    fixed: [],
    confidence: "high",
  });
  const groups = groupAlerts([
    alert("GO-1", ["GHSA-x"], c1),
    alert("GHSA-x", ["CVE-9"], c1),
    alert("GHSA-y", ["CVE-9"], c2), // linked through CVE-9 only
    alert("GO-2", [], c1),
  ]);
  assert.deepEqual(
    groups.map((g) => [g.id, g.records, g.ids]),
    [
      [
        "CVE-9",
        ["GHSA-x", "GHSA-y", "GO-1"],
        ["CVE-9", "GHSA-x", "GHSA-y", "GO-1"],
      ],
      ["GO-2", ["GO-2"], ["GO-2"]],
    ],
  );
});

test("A2: Go stdlib alerts carry rea-sbom:scope=language-runtime; --no-runtime-vulns drops them", (t) => {
  const fx = S2_FIXTURES.find((f) => f.id === "go-jwt");
  if (!fixtureGate(t, fx)) return;
  const all = JSON.parse(scan(fixturePath(fx)).toString("utf8"));
  const scope = (v) =>
    v.properties.find((p) => p.name === "rea-sbom:scope")?.value ?? null;
  assert.deepEqual(
    all.vulnerabilities.map((v) => [v.id, scope(v)]),
    [
      ["CVE-2020-26160", null],
      ["CVE-2022-32149", null],
      ["CVE-2025-61725", "language-runtime"],
    ],
  );
  const lib = JSON.parse(
    scan(fixturePath(fx), ["--no-runtime-vulns"]).toString("utf8"),
  );
  assert.deepEqual(schemaErrors(lib), []);
  assert.deepEqual(
    lib.vulnerabilities.map((v) => v.id),
    ["CVE-2020-26160", "CVE-2022-32149"],
  );
  const meta = new Map(lib.metadata.properties.map((p) => [p.name, p.value]));
  assert.equal(meta.get("rea-sbom:vuln-runtime-excluded-count"), "1");
  const usage = spawnSync(process.execPath, [
    SCAN_BIN,
    fixturePath(fx),
    "--no-runtime-vulns",
  ]);
  assert.equal(usage.status, 2, "--no-runtime-vulns requires --vulns");
});

test("A3: an alert on a low-confidence component is in_triage", (t) => {
  const fx = S3_PYTHON_FIXTURES.find((f) => f.id === "py-requests");
  if (!fixtureGate(t, fx)) return;
  const bom = JSON.parse(scan(fixturePath(fx)).toString("utf8"));
  assert.ok(bom.vulnerabilities.length > 0);
  for (const v of bom.vulnerabilities)
    assert.equal(v.analysis.state, "in_triage", v.id);
});

test("unknowns are never matched: .NET fallback with pre-release candidates against introduced: 0", (t) => {
  const fx = S3_DOTNET_FIXTURES.find((f) => f.id === "dotnet-serilog");
  if (!fixtureGate(t, fx)) return;
  const dir = join(scratch, "serilog-nodeps");
  cpSync(join(OUT, fx.id), dir, {
    recursive: true,
    filter: (s) => !s.endsWith(".deps.json"),
  });
  const bom = JSON.parse(scan(dir).toString("utf8"));
  assert.deepEqual(bom.components, []);
  assert.equal(
    bom.metadata.properties.filter(
      (p) => p.name === "rea-sbom:unknown-component",
    ).length,
    2,
  );
  assert.deepEqual(
    bom.vulnerabilities,
    [],
    "REA-TEST-0004 affects every Serilog version",
  );
});

test("CLI: --db requires --vulns, a missing index is an error (exit 1)", (t) => {
  const usage = spawnSync(process.execPath, [
    SCAN_BIN,
    SCAN_BIN,
    "--db",
    DB_DIR,
  ]);
  assert.equal(usage.status, 2);
  const fx = S2_FIXTURES.find((f) => f.id === "npm-cli");
  if (!fixtureGate(t, fx)) return;
  const missing = spawnSync(process.execPath, [
    SCAN_BIN,
    fixturePath(fx),
    "--vulns",
    "--db",
    join(scratch, "nowhere"),
  ]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr.toString(), /vulndb-missing/);
});
