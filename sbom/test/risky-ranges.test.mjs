// S5 D3: risky OSV ranges from the real snapshot (pre-release events, last_affected), replayed
// offline. Each expectation is the verdict of an independent oracle, api.osv.dev, recorded by
// scripts/risky_ranges.mjs (test/data/risky-ranges.json). No network here.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { evaluateAffected } from "../lib/vulns/osv.mjs";
import { SBOM } from "./support.mjs";

const DATA = JSON.parse(
  readFileSync(join(SBOM, "test/data/risky-ranges.json"), "utf8"),
);

test("risky ranges: ≥ 5 real packages per ecosystem, every verdict equals api.osv.dev", () => {
  const packages = {};
  for (const a of Object.values(DATA.advisories))
    (packages[a.ecosystem] ??= new Set()).add(a.package);
  for (const eco of ["golang", "cargo", "npm", "nuget", "pypi"])
    assert.ok(
      packages[eco]?.size >= 5,
      `${eco}: ${packages[eco]?.size ?? 0} packages`,
    );
  const wrong = [];
  for (const c of DATA.cases) {
    const a = DATA.advisories[c.id];
    const results = a.affected.map((entry) =>
      evaluateAffected(a.ecosystem, entry, c.version),
    );
    const ours = results.some((r) => r.affected);
    if (ours !== c.oracle)
      wrong.push(
        `${a.ecosystem} ${a.package} ${c.id} ${c.version}: ours ${ours}, oracle ${c.oracle}`,
      );
  }
  assert.deepEqual(wrong, []);
  assert.ok(
    DATA.cases.some((c) => c.oracle) && DATA.cases.some((c) => !c.oracle),
  );
});
