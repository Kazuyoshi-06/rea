// End-to-end: public CLI on every S3 fixture (.NET publish directories, PyInstaller onefile).
// No REA is involved in these scans. Fixtures come from `make sbom-test`.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  S3_DOTNET_FIXTURES,
  S3_PYTHON_FIXTURES,
  SCAN_BIN,
  compareToTruth,
  fixtureGate,
  fixturePath,
  readTruth,
  schemaErrors,
} from "./support.mjs";
import { buildPyInstaller, requirePython313 } from "./support/py.mjs";

function runCli(args, env = {}) {
  const started = process.hrtime.bigint();
  const res = spawnSync(process.execPath, [SCAN_BIN, ...args], {
    env: { ...process.env, ...env },
    maxBuffer: 64 << 20,
  });
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.equal(res.status, 0, res.stderr.toString("utf8"));
  return { stdout: res.stdout, ms };
}

const prop = (bom, name) =>
  bom.metadata.properties.filter((p) => p.name === name).map((p) => p.value);
const componentProp = (c, name) =>
  c.properties.find((p) => p.name === name)?.value;

for (const fx of [...S3_DOTNET_FIXTURES, ...S3_PYTHON_FIXTURES]) {
  test(`${fx.id}: CLI output is schema-valid, byte-identical across runs, no invented version`, (t) => {
    if (!fixtureGate(t, fx)) return;
    const args = [
      fixturePath(fx),
      "--format",
      "cyclonedx",
      "--timestamp",
      "2026-01-01T00:00:00Z",
    ];
    const first = runCli(args);
    const second = runCli(args);
    assert.ok(first.stdout.equals(second.stdout), "two runs differ");
    const bom = JSON.parse(first.stdout.toString("utf8"));
    assert.deepEqual(schemaErrors(bom), []);
    assert.deepEqual(prop(bom, "rea-sbom:detected-ecosystem"), [fx.ecosystem]);

    const found = bom.components.map((c) => ({
      name: c.name,
      version: c.version,
    }));
    const m = compareToTruth(fx.ecosystem, found, readTruth(fx.id));
    assert.deepEqual(m.equivalent.extra, [], `extra: ${m.equivalent.extra}`);
    const expected = {
      "dotnet-json": [1, 1, "high"],
      "dotnet-serilog": [1, 1, "high"],
      "py-requests-meta": [1, 1, "high"],
      "py-requests": [1, 1, "low"],
      "py-yaml": [1, 1, "low"],
    }[fx.id];
    assert.equal(m.strict.precision, expected[0], `${fx.id} strict precision`);
    assert.equal(m.equivalent.recall, 1, `missing: ${m.equivalent.missing}`);
    assert.equal(m.strict.recall, 1);
    for (const c of bom.components) {
      assert.equal(
        componentProp(c, "rea-sbom:confidence"),
        expected[2],
        c.name,
      );
      assert.ok(c.purl.startsWith(`pkg:${fx.ecosystem}/`), c.purl);
    }
    assert.deepEqual(prop(bom, "rea-sbom:unknown-count"), ["0"]);
    // The BOM names the reader that produced the facts: no REA command anywhere.
    assert.equal(
      prop(bom, "rea-sbom:reader").some((r) => r.startsWith("rea ")),
      false,
    );
  });
}

test("a bytecode-only unknown reaches the BOM as a property, never as a component", (t) => {
  if (!requirePython313(t)) return;
  const dir = mkdtempSync(join(tmpdir(), "sbom-s3-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const output = join(dir, "app.bin");
  buildPyInstaller({
    output,
    entries: [],
    modules: [
      { name: "mystery", source: "__version__ = '9.9.9'", ispkg: true },
      { name: "yaml", source: "__version__ = '6.0.1'", ispkg: true },
    ],
  });
  const bom = JSON.parse(
    runCli([output, "--timestamp", "2026-01-01T00:00:00Z"]).stdout.toString(
      "utf8",
    ),
  );
  assert.deepEqual(schemaErrors(bom), []);
  assert.deepEqual(
    bom.components.map((c) => `${c.name}@${c.version}`),
    ["PyYAML@6.0.1"],
  );
  assert.deepEqual(prop(bom, "rea-sbom:unknown-count"), ["1"]);
  const unknown = JSON.parse(prop(bom, "rea-sbom:unknown-component")[0]);
  assert.equal(unknown.ecosystem, "pypi");
  assert.equal(unknown.name, "mystery");
  assert.match(unknown.reason, /not in the module table/);
  assert.equal(JSON.stringify(bom).includes('"mystery","version"'), false);
});
