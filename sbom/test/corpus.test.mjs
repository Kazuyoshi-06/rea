// End-to-end: public CLI on every S2 corpus fixture (in-house Go and Rust readers, no REA).
// Requires the built corpus (make sbom-test builds it); skipped per fixture otherwise.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import {
  S2_FIXTURES,
  SCAN_BIN,
  fixtureGate,
  fixturePath,
  readTruth,
  schemaErrors,
} from "./support.mjs";

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

const roleOf = (c) =>
  c.properties.find((p) => p.name === "rea-sbom:role")?.value ?? "library";
const prop = (bom, name) =>
  bom.metadata.properties.filter((p) => p.name === name).map((p) => p.value);

for (const fx of S2_FIXTURES) {
  test(`${fx.id}: 100% precision/recall, schema-valid, byte-identical reruns`, (t) => {
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

    const found = new Set(
      bom.components
        .filter((c) => roleOf(c) === "library")
        .map((c) => `${c.name}@${c.version}`),
    );
    const truth = new Set(
      readTruth(fx.id).map((c) => `${c.name}@${c.version}`),
    );
    const tp = [...found].filter((x) => truth.has(x)).length;
    assert.equal(
      tp / found.size,
      1,
      `precision: extra ${[...found].filter((x) => !truth.has(x))}`,
    );
    assert.equal(
      tp / truth.size,
      1,
      `recall: missing ${[...truth].filter((x) => !found.has(x))}`,
    );
    assert.deepEqual(prop(bom, "rea-sbom:unknown-count"), ["0"]);
    assert.deepEqual(prop(bom, "rea-sbom:detected-ecosystem"), [fx.ecosystem]);
    for (const c of bom.components)
      assert.ok(c.purl?.startsWith(`pkg:${fx.ecosystem}/`), c.name);

    if (fx.ecosystem === "golang") {
      const runtime = bom.components.filter(
        (c) => roleOf(c) === "language-runtime",
      );
      assert.deepEqual(
        runtime.map((c) => c.name),
        ["stdlib"],
      );
      assert.match(runtime[0].version, /^\d+\.\d+\.\d+$/);
      assert.equal(
        bom.metadata.component.version,
        undefined,
        "(devel) main module has no version",
      );
    }
    if (fx.ecosystem === "cargo") {
      const excluded = Number(prop(bom, "rea-sbom:excluded-count")[0]);
      assert.ok(excluded > 0);
      for (const c of bom.components) {
        const context = JSON.parse(c.evidence.occurrences[0].additionalContext);
        assert.equal(context.excludedBuildCount, excluded);
      }
    }
    if (fx.id === "npm-electron")
      assert.ok(first.ms < 10_000, `npm-electron took ${first.ms} ms`);
  });
}

test("SOURCE_DATE_EPOCH fixes the timestamp when --timestamp is absent", (t) => {
  const fx = S2_FIXTURES.find((f) => f.id === "npm-cli");
  if (!fixtureGate(t, fx)) return;
  const env = { SOURCE_DATE_EPOCH: "1700000000" };
  const a = runCli([fixturePath(fx)], env);
  const b = runCli([fixturePath(fx)], env);
  assert.ok(a.stdout.equals(b.stdout));
  assert.equal(JSON.parse(a.stdout).metadata.timestamp, "2023-11-14T22:13:20Z");
});

test("unsupported artifacts and bad usage fail with distinct exit codes", () => {
  const unsupported = spawnSync(process.execPath, [SCAN_BIN, SCAN_BIN]);
  assert.equal(unsupported.status, 1);
  assert.match(unsupported.stderr.toString(), /unsupported-artifact/);
  const usage = spawnSync(process.execPath, [
    SCAN_BIN,
    SCAN_BIN,
    "--format",
    "spdx",
  ]);
  assert.equal(usage.status, 2);
});
