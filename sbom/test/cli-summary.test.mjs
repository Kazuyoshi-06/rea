// S7 B: stderr summary lines of sbom-scan (platform filter, exclusions, unknowns) and --quiet.
// stdout must be byte-identical with and without --quiet; the lines only repeat BOM facts.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { summaryLines } from "../lib/cli.mjs";
import { indexAdvisories, writeVulnDb } from "../lib/vulns/db.mjs";
import {
  S2_FIXTURES,
  S3_DOTNET_FIXTURES,
  SBOM,
  SCAN_BIN,
  fixtureGate,
  fixturePath,
} from "./support.mjs";

const scratch = mkdtempSync(join(tmpdir(), "sbom-cli-summary-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

// The platform records of test/platform.test.mjs (two real Windows-only Go records + synthetic).
const DB_DIR = join(scratch, "db");
{
  const data = join(SBOM, "test/data/osv-platform");
  const docs = readdirSync(data)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(data, f), "utf8")));
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

const run = (args) => {
  const res = spawnSync(process.execPath, [
    SCAN_BIN,
    ...args,
    "--timestamp",
    "0",
  ]);
  assert.equal(res.status, 0, res.stderr.toString());
  return { stdout: res.stdout, stderr: res.stderr.toString("utf8") };
};

const scanModel = (over) => ({
  exclusions: [],
  unknowns: [],
  ...over,
});

test("B1: summaryLines — nothing to say, nothing written", () => {
  assert.deepEqual(summaryLines(scanModel({})), []);
  const disabled = {
    platform: {
      filter: "disabled",
      targets: [{ goos: "linux", goarch: "amd64" }],
      filtered: [],
    },
  };
  assert.deepEqual(summaryLines(scanModel({ vulnerabilities: disabled })), []);
});

test("B1: summaryLines — platform filter, exclusions grouped by reason, unknowns", () => {
  const lines = summaryLines(
    scanModel({
      vulnerabilities: {
        platform: {
          filter: "applied",
          targets: [
            { goos: "darwin", goarch: "amd64" },
            { goos: "darwin", goarch: "arm64" },
          ],
          filtered: [{ id: "CVE-1" }, { id: "CVE-2" }],
        },
      },
      exclusions: [
        { reason: "kind=build" },
        { reason: "kind=build" },
        { reason: "PyInstaller runtime module" },
      ],
      unknowns: [{ name: "x" }],
    }),
  );
  assert.deepEqual(lines, [
    "sbom-scan: platform filter removed 2 alerts whose vulnerable imports only exist on platforms other than darwin/amd64, darwin/arm64 (listed as rea-sbom:platform-filtered; --all-platforms keeps them)\n",
    "sbom-scan: 3 components excluded from the BOM (listed as rea-sbom:excluded-component): 2 kind=build; 1 PyInstaller runtime module\n",
    "sbom-scan: 1 component detected without a version, reported as unknowns (rea-sbom:unknown-component), not matched against vulnerabilities\n",
  ]);
});

test("B1: go-uuid --vulns — platform line on stderr, stdout identical with --quiet", (t) => {
  const fx = S2_FIXTURES.find((f) => f.id === "go-uuid");
  if (!fixtureGate(t, fx)) return;
  const args = [fixturePath(fx), "--vulns", "--db", DB_DIR];
  const loud = run(args);
  const quiet = run([...args, "--quiet"]);
  assert.ok(loud.stdout.equals(quiet.stdout), "stdout differs with --quiet");
  assert.equal(quiet.stderr, "");
  assert.equal(
    loud.stderr,
    "sbom-scan: platform filter removed 4 alerts whose vulnerable imports only exist on platforms other than linux/amd64 (listed as rea-sbom:platform-filtered; --all-platforms keeps them)\n",
  );
  const bom = JSON.parse(loud.stdout.toString("utf8"));
  const count = bom.metadata.properties.find(
    (p) => p.name === "rea-sbom:platform-filtered-count",
  );
  assert.equal(count.value, "4", "the line repeats the BOM count");
  // --all-platforms: nothing removed, nothing said.
  const all = run([...args, "--all-platforms"]);
  assert.equal(all.stderr, "");
});

test("B1: rust-vuln — kind=build exclusion line, stdout identical with --quiet", (t) => {
  const fx = S2_FIXTURES.find((f) => f.id === "rust-vuln");
  if (!fixtureGate(t, fx)) return;
  const loud = run([fixturePath(fx)]);
  const quiet = run([fixturePath(fx), "--quiet"]);
  assert.ok(loud.stdout.equals(quiet.stdout), "stdout differs with --quiet");
  assert.equal(quiet.stderr, "");
  const bom = JSON.parse(loud.stdout.toString("utf8"));
  const excluded = bom.metadata.properties.filter(
    (p) => p.name === "rea-sbom:excluded-component",
  ).length;
  assert.ok(excluded > 0, "rust-vuln has build-only packages");
  assert.match(
    loud.stderr,
    new RegExp(
      `^sbom-scan: ${excluded} components? excluded from the BOM .*kind=build`,
    ),
  );
});

test("B1: --output — summary still on stderr, file identical with --quiet", (t) => {
  const fx = S2_FIXTURES.find((f) => f.id === "rust-vuln");
  if (!fixtureGate(t, fx)) return;
  const a = join(scratch, "a.json");
  const b = join(scratch, "b.json");
  const loud = run([fixturePath(fx), "--output", a]);
  const quiet = run([fixturePath(fx), "--output", b, "--quiet"]);
  assert.equal(loud.stdout.length, 0);
  assert.ok(readFileSync(a).equals(readFileSync(b)));
  assert.match(loud.stderr, /excluded from the BOM/);
  assert.equal(quiet.stderr, "");
});

test("B1: dotnet-serilog without deps.json — unknowns line, stdout identical with --quiet", (t) => {
  const fx = S3_DOTNET_FIXTURES.find((f) => f.id === "dotnet-serilog");
  if (!fixtureGate(t, fx)) return;
  // Assembly metadata only: Serilog's informational versions carry pre-release labels (S3).
  const dir = join(scratch, "dotnet-serilog-nodeps");
  cpSync(fixturePath(fx), dir, {
    recursive: true,
    filter: (src) => !src.endsWith(".deps.json"),
  });
  const loud = run([dir]);
  const quiet = run([dir, "--quiet"]);
  assert.ok(loud.stdout.equals(quiet.stdout), "stdout differs with --quiet");
  assert.equal(quiet.stderr, "");
  const bom = JSON.parse(loud.stdout.toString("utf8"));
  const unknowns = bom.metadata.properties.find(
    (p) => p.name === "rea-sbom:unknown-count",
  ).value;
  assert.equal(unknowns, "2");
  assert.equal(
    loud.stderr,
    "sbom-scan: 2 components detected without a version, reported as unknowns (rea-sbom:unknown-component), not matched against vulnerabilities\n",
  );
});
