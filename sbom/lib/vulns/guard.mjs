// make vulndb format guard (S5 A5). An OSV export whose layout or naming changes silently would
// make alerts disappear without an error (no alert ≠ no vulnerability). Before the index is
// written, every ecosystem must keep at least `minAdvisories` indexed advisories and must still
// index each known advisory under its package. The thresholds live in test/data/osv-guard.json.

/**
 * Check one built ecosystem against its guard entry.
 * `packages` is the Map<key, advisory[]> of indexAdvisories; returns a list of failure messages.
 */
export function checkGuard(guard, ecosystem, { indexedAdvisories, packages }) {
  const rule = guard.ecosystems?.[ecosystem];
  if (rule === undefined) return [`${ecosystem}: no guard entry`];
  const failures = [];
  if (!(indexedAdvisories >= rule.minAdvisories))
    failures.push(
      `${ecosystem}: ${indexedAdvisories} advisories indexed, guard minimum is ${rule.minAdvisories} (OSV export format or naming changed?)`,
    );
  for (const { id, package: name } of rule.known ?? []) {
    const advisories = packages.get(name) ?? [];
    if (!advisories.some((a) => a.id === id))
      failures.push(
        `${ecosystem}: known advisory ${id} is no longer indexed under package ${JSON.stringify(name)}`,
      );
  }
  return failures;
}
