// Offline matching of scanned components against the OSV index (lib/vulns/db.mjs).
//
// Rules:
// - only components are matched; unknowns (no version) never are, and a component without a
//   registry identity (purl: git or path source) is skipped and counted;
// - an alert inherits the confidence of its component;
// - withdrawn advisories are ignored (counted);
// - a range that cannot be decided (GIT range without a versions list, unparseable version) is
//   reported as unevaluated, never turned into an alert or a clean result.
// Go: modules match by module path; the standard library is the component "stdlib"
// (role language-runtime), which is also the OSV package name ("stdlib", purl pkg:golang/stdlib),
// with OSV versions written without "v" ("1.16.0-0", "1.16.1"). OSV's "toolchain" package (the
// go command) is not part of a built binary and is not matched.
import { compareStrings } from "../model.mjs";
import { evaluateAffected, osvVersion } from "./osv.mjs";

/**
 * Match finalized `scan.components` against `db`. Returns
 * {alerts, unevaluated, stats, failures} with alerts sorted by (advisory id, component).
 * alert: {id, aliases, summary, modified, component, via, fixed[], confidence}
 */
export function matchComponents(components, db) {
  const alerts = [];
  const unevaluated = [];
  const failures = new Set();
  const stats = {
    components: components.length,
    matched: 0,
    skippedNoPurl: 0,
    withdrawnIgnored: 0,
    advisoriesExamined: 0,
  };
  for (const component of components) {
    if (component.purl === null || typeof component.version !== "string") {
      stats.skippedNoPurl += 1;
      continue;
    }
    const found = db.lookup(component.ecosystem, component.name);
    if (!found.ok) {
      failures.add(`${found.error.tag}: ${found.error.message}`);
      continue;
    }
    const version = osvVersion(component.ecosystem, component.version);
    let hit = false;
    for (const advisory of found.value) {
      if (advisory.withdrawn) {
        stats.withdrawnIgnored += 1;
        continue;
      }
      stats.advisoriesExamined += 1;
      const results = advisory.affected.map((entry) =>
        evaluateAffected(component.ecosystem, entry, version),
      );
      const matched = results.filter((r) => r.affected);
      if (matched.length > 0) {
        hit = true;
        alerts.push({
          id: advisory.id,
          aliases: advisory.aliases,
          summary: advisory.summary,
          modified: advisory.modified,
          component,
          via: [...new Set(matched.map((r) => r.via))].sort(),
          fixed: [...new Set(matched.flatMap((r) => r.fixed))].sort(
            compareStrings,
          ),
          confidence: component.confidence,
        });
        continue;
      }
      const open = results.flatMap((r) => r.unevaluated);
      if (open.length > 0)
        unevaluated.push({
          id: advisory.id,
          component,
          reasons: [...new Set(open.map((u) => u.reason))].sort(),
        });
    }
    if (hit) stats.matched += 1;
  }
  const order = (a, b) =>
    compareStrings(a.id, b.id) ||
    compareStrings(componentKey(a.component), componentKey(b.component));
  alerts.sort(order);
  unevaluated.sort(order);
  return { alerts, unevaluated, stats, failures: [...failures].sort() };
}

const componentKey = (c) => `${c.ecosystem}:${c.role}:${c.name}@${c.version}`;
