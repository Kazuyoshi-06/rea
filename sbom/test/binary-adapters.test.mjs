// Go and Rust adapters on REA reports recorded by S1 (baseline/raw) and on synthetic facts.
// No REA process runs here; corpus.test.mjs covers the live REA path.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { gunzipSync } from "node:zlib";
import { goScanFromFacts } from "../lib/adapters/go.mjs";
import { rustScanFromFacts } from "../lib/adapters/rust.mjs";
import {
  parseCargoAuditableReport,
  parseGoBuildInfoReport,
} from "../lib/rea.mjs";
import { SBOM, readTruth } from "./support.mjs";

const recorded = (id) =>
  JSON.parse(
    gunzipSync(
      readFileSync(join(SBOM, "baseline/raw", `${id}.json.gz`)),
    ).toString("utf8"),
  );
const artifact = { path: "artifact", sha256: "0".repeat(64) };
const ids = (items) => items.map((c) => `${c.name}@${c.version}`).sort();
const truthIds = (id) =>
  readTruth(id)
    .map((c) => `${c.name}@${c.version}`)
    .sort();

function facts(parse, report) {
  const result = parse(report);
  assert.equal(result.ok, true, JSON.stringify(result.error));
  return result.value;
}

for (const id of ["go-uuid", "go-uuid-stripped", "go-jwt", "go-jwt-stripped"]) {
  test(`go ${id}: recorded REA report maps to the truth`, () => {
    const scan = goScanFromFacts(
      facts(parseGoBuildInfoReport, recorded(id)),
      artifact,
      null,
    );
    const libraries = scan.components.filter((c) => c.role === "library");
    assert.deepEqual(ids(libraries), truthIds(id));
    const stdlib = scan.components.filter((c) => c.role === "language-runtime");
    assert.deepEqual(ids(stdlib), ["stdlib@1.24.7"]);
    assert.equal(stdlib[0].purl, "pkg:golang/stdlib@1.24.7");
    assert.equal(scan.root.version, null, "(devel) main module has no version");
    assert.equal(scan.root.rawVersion, "(devel)");
    assert.deepEqual(scan.unknowns, []);
    const ev = libraries[0].evidence[0];
    assert.equal(
      ev.reader.command,
      "rea inspect-go-binary <artifact> --format json",
    );
    assert.equal(ev.location.kind, "file-range");
    assert.ok(
      Number.isSafeInteger(ev.location.offset) && ev.location.bytes > 0,
    );
  });
}

const goFacts = (overrides) => ({
  reader: { tool: "rea", command: "x", provider: "p" },
  artifactSha256: null,
  goVersion: "go1.24.7",
  moduleLocation: { offset: 1, bytes: 2 },
  main: { path: "example.com/app", version: "v1.2.3", replacement: null },
  dependencies: [],
  complete: true,
  unparsedLines: [],
  unparsedBinaryLines: 0,
  ...overrides,
});

test("go: replace directives, local replacements and odd versions", () => {
  const scan = goScanFromFacts(
    goFacts({
      goVersion: "devel go1.25-abcdef",
      dependencies: [
        {
          path: "a.example/x",
          version: "v1.0.0",
          replacement: { path: "fork.example/x", version: "v1.0.1" },
        },
        {
          path: "a.example/local",
          version: "v0.1.0",
          replacement: { path: "../local", version: "" },
        },
        { path: "a.example/devel", version: "(devel)", replacement: null },
      ],
      unparsedLines: ["dep\tbroken", "weird line"],
      complete: false,
    }),
    artifact,
    null,
  );
  assert.deepEqual(ids(scan.components), ["fork.example/x@v1.0.1"]);
  assert.deepEqual(scan.components[0].evidence[0].replaces, {
    path: "a.example/x",
    version: "v1.0.0",
  });
  const reasons = Object.fromEntries(
    scan.unknowns.map((u) => [u.name, u.reason]),
  );
  assert.match(reasons["a.example/local"], /local directory/);
  assert.match(reasons["a.example/devel"], /no module version/);
  assert.match(reasons.stdlib, /not goX\.Y\.Z/);
  assert.match(reasons.broken, /unparsed/);
  assert.equal(scan.root.purl, "pkg:golang/example.com/app@v1.2.3");
  assert.ok(scan.limitations.some((l) => l.includes("incomplete")));
  assert.ok(scan.limitations.some((l) => l.includes("1 unrecognized")));
});

test("go: reports without build information are errors, not empty scans", () => {
  const report = recorded("go-jwt");
  assert.equal(
    parseGoBuildInfoReport({ ...report, operation: "other" }).ok,
    false,
  );
  const none = structuredClone(report);
  none.normalized_result.build_info = null;
  assert.equal(parseGoBuildInfoReport(none).error.tag, "no-go-buildinfo");
});

for (const [id, excluded] of [
  [
    "rust-small",
    ["proc-macro2", "quote", "serde_derive", "syn", "unicode-ident"],
  ],
  ["rust-vuln", ["autocfg"]],
]) {
  test(`rust ${id}: kind=build excluded and counted in evidence`, () => {
    const scan = rustScanFromFacts(
      facts(parseCargoAuditableReport, recorded(id)),
      artifact,
      null,
    );
    assert.deepEqual(ids(scan.components), truthIds(id));
    assert.deepEqual(scan.exclusions.map((x) => x.name).sort(), excluded);
    for (const c of scan.components) {
      assert.equal(c.evidence[0].excludedBuildCount, excluded.length);
      assert.equal(c.evidence[0].kind, null);
      assert.equal(
        c.evidence[0].kindInterpretation,
        "omitted kind treated as runtime",
      );
      assert.match(c.purl, /^pkg:cargo\//);
    }
    assert.equal(scan.root.name, id);
    assert.equal(scan.root.purl, null, "local root crate has no registry purl");
    assert.ok(scan.limitations.some((l) => l.includes("dev-dependencies")));
  });
}

test("rust: unrecognized kinds kept, non-crates.io sources without purl, no-version unknown", () => {
  const scan = rustScanFromFacts(
    {
      reader: { tool: "rea", command: "x", provider: "p" },
      artifactSha256: null,
      section: { name: ".dep-v0", offset: 0, bytes: 1, formatVersion: 1 },
      packages: [
        {
          name: "app",
          version: "0.1.0",
          source: "local",
          kind: null,
          root: true,
        },
        {
          name: "future",
          version: "1.0.0",
          source: "crates.io",
          kind: "dev",
          root: false,
        },
        {
          name: "gitdep",
          version: "0.2.0",
          source: "git",
          kind: "runtime",
          root: false,
        },
        {
          name: "empty",
          version: "",
          source: "crates.io",
          kind: null,
          root: false,
        },
        {
          name: "bld",
          version: "1.0.0",
          source: "crates.io",
          kind: "build",
          root: false,
        },
      ],
    },
    artifact,
    null,
  );
  assert.deepEqual(ids(scan.components), ["future@1.0.0", "gitdep@0.2.0"]);
  const future = scan.components.find((c) => c.name === "future");
  assert.equal(future.evidence[0].kindInterpretation, "unrecognized kind kept");
  const gitdep = scan.components.find((c) => c.name === "gitdep");
  assert.equal(gitdep.purl, null);
  assert.match(gitdep.purlStatus, /not crates\.io/);
  assert.deepEqual(
    scan.unknowns.map((u) => u.name),
    ["empty"],
  );
  assert.equal(scan.exclusions.length, 1);
  assert.equal(future.evidence[0].excludedBuildCount, 1);
});
