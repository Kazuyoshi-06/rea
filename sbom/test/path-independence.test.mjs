// The BOM never carries the artifact path as given: the same artifact scanned from two
// directories (different depth, absolute and relative) gives exactly the same bytes.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative } from "node:path";
import { test } from "node:test";
import {
  S2_FIXTURES,
  S3_DOTNET_FIXTURES,
  S3_PYTHON_FIXTURES,
  SCAN_BIN,
  fixtureGate,
  fixturePath,
} from "./support.mjs";

const scratch = mkdtempSync(join(tmpdir(), "sbom-paths-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

function scan(path) {
  const res = spawnSync(
    process.execPath,
    [SCAN_BIN, path, "--format", "cyclonedx", "--timestamp", "1700000000"],
    { maxBuffer: 64 << 20 },
  );
  assert.equal(res.status, 0, res.stderr.toString("utf8"));
  return res.stdout;
}

// One fixture per reader: Go, Rust, ASAR, .NET directory, PyInstaller onefile.
const FIXTURES = [
  S2_FIXTURES.find((f) => f.id === "go-jwt"),
  S2_FIXTURES.find((f) => f.id === "rust-vuln"),
  S2_FIXTURES.find((f) => f.id === "npm-cli"),
  S3_DOTNET_FIXTURES.find((f) => f.id === "dotnet-serilog"),
  S3_PYTHON_FIXTURES.find((f) => f.id === "py-requests"),
];

for (const fx of FIXTURES) {
  test(`${fx.id}: same bytes from two directories, no path in the BOM`, (t) => {
    if (!fixtureGate(t, fx)) return;
    const source = fixturePath(fx);
    const name = basename(source);
    const near = join(scratch, `${fx.id}-a`);
    const far = join(scratch, `${fx.id}-b`, "deeper", "still");
    mkdirSync(near, { recursive: true });
    mkdirSync(far, { recursive: true });
    cpSync(source, join(near, name), { recursive: true });
    cpSync(source, join(far, name), { recursive: true });
    const a = scan(join(near, name));
    const b = scan(relative(process.cwd(), join(far, name)));
    assert.ok(a.equals(b), `${fx.id}: BOM depends on the artifact path`);
    const text = a.toString("utf8");
    assert.equal(text.includes(scratch), false, "absolute path leaked");
    assert.equal(text.includes(`${fx.id}-a`), false, "directory name leaked");
    const bom = JSON.parse(text);
    assert.deepEqual(
      bom.metadata.component.properties.find(
        (p) => p.name === "rea-sbom:artifact-name",
      ).value,
      name,
    );
  });
}
