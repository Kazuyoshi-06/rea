// Differential test (make sbom-test-diff, not part of make sbom-test): the in-house Go buildinfo
// and cargo-auditable readers must extract exactly the facts REA extracts, field by field, on
// every Go and Rust fixture (stripped ones included) and on the extra binaries listed in
// SBOM_DIFF_BINARIES (colon-separated paths, e.g. the real binaries of scripts/real_binaries.mjs).
// Needs REA built (npm run build:cached at the repository root); skipped otherwise, failed under
// SBOM_REQUIRE_REA=1.
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { readCargoAuditable } from "../../lib/readers/cargoauditable.mjs";
import { readGoBuildInfo } from "../../lib/readers/gobuildinfo.mjs";
import * as rea from "../../oracle/rea.mjs";
import { S2_FIXTURES, SBOM, fixtureGate, fixturePath } from "../support.mjs";

const REA_BUILT = existsSync(join(dirname(SBOM), "dist/cli-runtime"));

function reaGate(t) {
  if (REA_BUILT) return true;
  if (process.env.SBOM_REQUIRE_REA === "1")
    throw new Error("REA is not built (make rea)");
  t.skip("REA not built");
  return false;
}

const GO_FIELDS = [
  "goVersion",
  "moduleLocation",
  "main",
  "dependencies",
  "complete",
  "unparsedLines",
  "unparsedBinaryLines",
];
const RUST_FIELDS = ["section", "packages"];

function compare(ours, theirs, fields) {
  assert.equal(
    ours.ok,
    theirs.ok,
    `ours ${JSON.stringify(ours.error)} vs REA ${JSON.stringify(theirs.error)}`,
  );
  if (!ours.ok) return;
  for (const field of fields)
    assert.deepEqual(ours.value[field], theirs.value[field], field);
}

const extra = (process.env.SBOM_DIFF_BINARIES ?? "")
  .split(":")
  .filter(Boolean)
  .map((path) => ({ id: path, path, ecosystem: null }));
const targets = [
  ...S2_FIXTURES.filter((f) => f.ecosystem !== "npm").map((f) => ({
    id: f.id,
    fx: f,
    path: fixturePath(f),
    ecosystem: f.ecosystem,
  })),
  ...extra,
];

for (const target of targets) {
  test(`${target.id}: in-house reader = REA, field by field`, (t) => {
    if (target.fx && !fixtureGate(t, target.fx)) return;
    if (!reaGate(t)) return;
    const kinds =
      target.ecosystem === null ? ["golang", "cargo"] : [target.ecosystem];
    let compared = 0;
    for (const kind of kinds) {
      const [ours, theirs, fields] =
        kind === "golang"
          ? [
              readGoBuildInfo(target.path),
              rea.readGoBuildInfo(target.path),
              GO_FIELDS,
            ]
          : [
              readCargoAuditable(target.path),
              rea.readCargoAuditable(target.path),
              RUST_FIELDS,
            ];
      // Both readers refusing the same binary is agreement (e.g. rust-audit-info, which names
      // .dep-v0 in its code but was not built with cargo auditable).
      compare(ours, theirs, fields);
      compared += 1;
    }
    assert.ok(compared > 0);
  });
}
