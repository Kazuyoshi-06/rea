// S6 B: platform filter of the Go alerts (GOOS / GOARCH of the binary against the OSV
// ecosystem_specific.imports restrictions), on test/data/osv-platform (two real records that S5
// found reported on Linux binaries although they only concern Windows, plus synthetic edge cases).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { targetPlatforms } from "../lib/adapters/go.mjs";
import { makeComponent } from "../lib/model.mjs";
import { indexAdvisories, openVulnDb, writeVulnDb } from "../lib/vulns/db.mjs";
import { matchComponents, platformExcluded } from "../lib/vulns/match.mjs";
import {
  S2_FIXTURES,
  SBOM,
  SCAN_BIN,
  fixtureGate,
  fixturePath,
  schemaErrors,
} from "./support.mjs";

const DATA = join(SBOM, "test/data/osv-platform");
const scratch = mkdtempSync(join(tmpdir(), "sbom-platform-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

const DB_DIR = join(scratch, "db");
{
  const docs = readdirSync(DATA)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(DATA, f), "utf8")));
  writeVulnDb(
    DB_DIR,
    {
      golang: {
        packages: indexAdvisories(docs, "golang").packages,
        archive: { sha256: "golang-platform", lastModified: null },
      },
    },
    "test/data/osv-platform",
  );
}
const db = openVulnDb(DB_DIR).value;

const ev = {
  artifact: { path: "x", sha256: "0" },
  location: { kind: "file", path: "x" },
};
// The go-uuid fixture's x/sys and toolchain (Go 1.24.7).
const COMPONENTS = [
  makeComponent({
    ecosystem: "golang",
    name: "golang.org/x/sys",
    version: "v0.0.0-20220715151400-c0bba94af5f8",
    source: "test",
    evidence: ev,
  }),
  makeComponent({
    ecosystem: "golang",
    name: "stdlib",
    version: "1.24.7",
    source: "test",
    role: "language-runtime",
    evidence: ev,
  }),
];
const ALL = [
  "CVE-2026-39824", // GO-2026-5024, x/sys, goos windows
  "CVE-2026-56857", // GO-2026-6604, stdlib, goos windows
  "SYN-PLAT-0001", // windows-only record + alias twin without platform information
  "SYN-PLAT-0003", // goarch arm64
  "SYN-PLAT-0004", // one windows import, one unrestricted
  "SYN-PLAT-0005", // linux/arm64 on one import
];
const run = (platforms, options = {}) =>
  matchComponents(COMPONENTS, db, { platforms, ...options });
const kept = (result) => result.groups.map((g) => g.id);
const removed = (result) => result.platform.filtered.map((g) => g.id);
const without = (...ids) => ALL.filter((id) => !ids.includes(id));

test("B1: the index keeps goos / goarch restrictions; entries without them carry none", () => {
  const stdlib = db.lookup("golang", "stdlib").value;
  const byId = new Map(stdlib.map((a) => [a.id, a.affected[0].platforms]));
  assert.deepEqual(byId.get("GO-2026-6604"), [
    { goos: ["windows"] },
    { goos: ["windows"] },
  ]);
  assert.equal(byId.get("SYN-PLAT-0002"), undefined);
  assert.deepEqual(byId.get("SYN-PLAT-0004"), [{ goos: ["windows"] }, {}]);
  assert.deepEqual(byId.get("SYN-PLAT-0005"), [
    { goarch: ["arm64"], goos: ["linux"] },
  ]);
});

test("B1: GO-2026-5024 and GO-2026-6604 (windows only) are absent for linux, present for windows", () => {
  const linux = run([{ goos: "linux", goarch: "amd64" }]);
  assert.equal(linux.platform.filter, "applied");
  assert.deepEqual(removed(linux), [
    "CVE-2026-39824",
    "CVE-2026-56857",
    "SYN-PLAT-0003",
    "SYN-PLAT-0005",
  ]);
  assert.deepEqual(kept(linux), ["SYN-PLAT-0001", "SYN-PLAT-0004"]);
  const windows = run([{ goos: "windows", goarch: "amd64" }]);
  assert.deepEqual(kept(windows), without("SYN-PLAT-0003", "SYN-PLAT-0005"));
  assert.deepEqual(kept(run([{ goos: "linux", goarch: "arm64" }])), [
    "SYN-PLAT-0001",
    "SYN-PLAT-0003",
    "SYN-PLAT-0004",
    "SYN-PLAT-0005",
  ]);
  // Removed groups keep their records and components: nothing disappears without a trace.
  const gone = linux.platform.filtered.find((g) => g.id === "CVE-2026-39824");
  assert.deepEqual(gone.records, ["GO-2026-5024"]);
  assert.equal(gone.alerts[0].component.name, "golang.org/x/sys");
  assert.deepEqual(gone.alerts[0].requires, { goos: ["windows"] });
  assert.equal(
    linux.alerts.length +
      linux.platform.filtered.flatMap((g) => g.alerts).length,
    run([], {}).alerts.length,
  );
});

test("B1: without platform information, or with --all-platforms, every alert stays", () => {
  const none = run([]);
  assert.equal(none.platform.filter, "no-platform");
  assert.deepEqual(kept(none), ALL);
  const disabled = run([{ goos: "linux", goarch: "amd64" }], {
    allPlatforms: true,
  });
  assert.equal(disabled.platform.filter, "disabled");
  assert.deepEqual(kept(disabled), ALL);
  assert.deepEqual(removed(disabled), []);
  // An unknown GOARCH excludes nothing on that axis.
  assert.deepEqual(kept(run([{ goos: "linux", goarch: null }])), [
    "SYN-PLAT-0001",
    "SYN-PLAT-0003",
    "SYN-PLAT-0004",
    "SYN-PLAT-0005",
  ]);
});

test("B1: a fat binary keeps an alert that concerns any of its slices", () => {
  const fat = run([
    { goos: "darwin", goarch: "amd64" },
    { goos: "darwin", goarch: "arm64" },
  ]);
  assert.deepEqual(removed(fat), [
    "CVE-2026-39824",
    "CVE-2026-56857",
    "SYN-PLAT-0005",
  ]);
  assert.equal(
    platformExcluded(
      [{ platforms: [{ goarch: ["arm64"] }] }],
      [{ goos: "darwin", goarch: "amd64" }],
    ),
    true,
  );
  assert.equal(platformExcluded([{ ranges: [] }], [{ goos: "linux" }]), false);
});

test("B1: target platforms come from the GOOS / GOARCH build settings, one per fat slice", () => {
  const settings = (goos, goarch) => [
    { key: "-trimpath", value: "true" },
    ...(goarch ? [{ key: "GOARCH", value: goarch }] : []),
    ...(goos ? [{ key: "GOOS", value: goos }] : []),
  ];
  assert.deepEqual(targetPlatforms({ settings: settings("linux", "s390x") }), [
    { goos: "linux", goarch: "s390x" },
  ]);
  assert.deepEqual(targetPlatforms({ settings: settings(null, null) }), []);
  assert.deepEqual(
    targetPlatforms({
      slices: [
        { settings: settings("darwin", "arm64") },
        { settings: settings("darwin", "amd64") },
      ],
    }),
    [
      { goos: "darwin", goarch: "amd64" },
      { goos: "darwin", goarch: "arm64" },
    ],
  );
});

function scan(path, extra = []) {
  const res = spawnSync(process.execPath, [
    SCAN_BIN,
    path,
    "--vulns",
    "--db",
    DB_DIR,
    "--timestamp",
    "0",
    ...extra,
  ]);
  assert.equal(res.status, 0, res.stderr.toString());
  return res.stdout;
}

test("B2: go-uuid (linux/amd64): filtered alerts listed in metadata, --all-platforms restores them", (t) => {
  const fx = S2_FIXTURES.find((f) => f.id === "go-uuid");
  if (!fixtureGate(t, fx)) return;
  const first = scan(fixturePath(fx));
  assert.ok(first.equals(scan(fixturePath(fx))), "two runs differ");
  const bom = JSON.parse(first.toString("utf8"));
  assert.deepEqual(schemaErrors(bom), []);
  const meta = (b, name) =>
    b.metadata.properties.filter((p) => p.name === name).map((p) => p.value);
  assert.deepEqual(meta(bom, "rea-sbom:target-platform"), ["linux/amd64"]);
  assert.deepEqual(meta(bom, "rea-sbom:platform-filter"), ["applied"]);
  assert.deepEqual(meta(bom, "rea-sbom:platform-filtered-count"), ["4"]);
  assert.deepEqual(
    meta(bom, "rea-sbom:platform-filtered").map((v) => JSON.parse(v)),
    [
      {
        id: "CVE-2026-39824",
        records: ["GO-2026-5024"],
        affects: [
          "pkg:golang/golang.org/x/sys@v0.0.0-20220715151400-c0bba94af5f8",
        ],
        requires: { goos: ["windows"] },
      },
      {
        id: "CVE-2026-56857",
        records: ["GO-2026-6604"],
        affects: ["pkg:golang/stdlib@1.24.7"],
        requires: { goos: ["windows"] },
      },
      {
        id: "SYN-PLAT-0003",
        records: ["SYN-PLAT-0003"],
        affects: ["pkg:golang/stdlib@1.24.7"],
        requires: { goarch: ["arm64"] },
      },
      {
        id: "SYN-PLAT-0005",
        records: ["SYN-PLAT-0005"],
        affects: ["pkg:golang/stdlib@1.24.7"],
        requires: { goarch: ["arm64"], goos: ["linux"] },
      },
    ],
  );
  assert.deepEqual(
    bom.vulnerabilities.map((v) => v.id),
    ["SYN-PLAT-0001", "SYN-PLAT-0004"],
  );
  assert.deepEqual(meta(bom, "rea-sbom:vuln-count"), ["2"]);
  const all = JSON.parse(
    scan(fixturePath(fx), ["--all-platforms"]).toString("utf8"),
  );
  assert.deepEqual(schemaErrors(all), []);
  assert.deepEqual(
    all.vulnerabilities.map((v) => v.id),
    ALL,
  );
  assert.deepEqual(meta(all, "rea-sbom:platform-filter"), ["disabled"]);
  assert.deepEqual(meta(all, "rea-sbom:platform-filtered-count"), ["0"]);
  const usage = spawnSync(process.execPath, [
    SCAN_BIN,
    fixturePath(fx),
    "--all-platforms",
  ]);
  assert.equal(usage.status, 2, "--all-platforms requires --vulns");
});
