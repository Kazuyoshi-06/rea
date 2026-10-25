// make vulndb format guard (A5): thresholds and known advisories (test/data/osv-guard.json).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { checkGuard } from "../lib/vulns/guard.mjs";
import { OSV_ECOSYSTEM } from "../lib/vulns/osv.mjs";
import { SBOM } from "./support.mjs";

const GUARD = JSON.parse(
  readFileSync(join(SBOM, "test/data/osv-guard.json"), "utf8"),
);
const SNAPSHOT = JSON.parse(
  readFileSync(join(SBOM, "vulndb/SNAPSHOT.json"), "utf8"),
);

test("committed guard: every ecosystem, ≥ 3 known advisories, a margin under the snapshot", () => {
  for (const [ecosystem, osvName] of Object.entries(OSV_ECOSYSTEM)) {
    const rule = GUARD.ecosystems[ecosystem];
    assert.ok(rule, ecosystem);
    assert.ok(rule.known.length >= 3, `${ecosystem}: ≥ 3 known ids`);
    const indexed = SNAPSHOT.archives[osvName].indexedAdvisories;
    assert.ok(
      rule.minAdvisories < indexed,
      `${ecosystem}: threshold < snapshot`,
    );
    assert.ok(
      rule.minAdvisories >= Math.floor(indexed * 0.5),
      `${ecosystem}: threshold not meaninglessly low`,
    );
  }
});

test("checkGuard: passes, then names a low count and a vanished known advisory", () => {
  const guard = {
    ecosystems: {
      golang: {
        minAdvisories: 2,
        known: [{ id: "GO-1", package: "a" }],
      },
    },
  };
  const packages = new Map([
    ["a", [{ id: "GO-1" }]],
    ["b", [{ id: "GO-2" }]],
  ]);
  assert.deepEqual(
    checkGuard(guard, "golang", { indexedAdvisories: 2, packages }),
    [],
  );
  const failures = checkGuard(guard, "golang", {
    indexedAdvisories: 1,
    packages: new Map([["a", [{ id: "GO-3" }]]]),
  });
  assert.equal(failures.length, 2);
  assert.match(failures[0], /1 advisories indexed, guard minimum is 2/);
  assert.match(
    failures[1],
    /known advisory GO-1 is no longer indexed under package "a"/,
  );
  assert.deepEqual(
    checkGuard(guard, "npm", { indexedAdvisories: 9, packages }),
    ["npm: no guard entry"],
  );
});
