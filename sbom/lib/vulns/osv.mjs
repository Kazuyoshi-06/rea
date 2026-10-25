// OSV affected-range evaluation (https://ossf.github.io/osv-schema/), one ecosystem at a time.
//
// A component version is affected by one `affected[]` entry when it is listed in `versions` or
// falls in one of its ranges. Ranges of type SEMVER use SemVer precedence; ECOSYSTEM uses the
// ecosystem's own order (Go, crates.io, npm: SemVer; NuGet: NuGet.Versioning; PyPI: PEP 440).
// GIT ranges name commits, not versions: they are skipped (a binary's version cannot be placed
// on a commit graph offline). When the entry also lists `versions` (OSV enumerates them from
// the GIT range, as PYSEC records do) the list stands in for it; otherwise the range is
// reported as unevaluated.
// Events are sorted by version ("introduced: 0" first) and replayed: introduced → affected,
// fixed (v >= fixed) and limit (v >= limit) → not affected, last_affected (v > it) → not affected.
// An event or component version the comparator cannot parse makes that range unevaluable: it is
// reported, never guessed into an alert or into a clean result.
import { err, ok } from "../result.mjs";
import { compareNugetParsed, parseNuget } from "../versions/nuget.mjs";
import { comparePep440Parsed, parsePep440 } from "../versions/pep440.mjs";
import { compareSemverParsed, parseSemver } from "../versions/semver.mjs";

/** Model ecosystem → OSV ecosystem name. */
export const OSV_ECOSYSTEM = {
  golang: "Go",
  cargo: "crates.io",
  npm: "npm",
  nuget: "NuGet",
  pypi: "PyPI",
};

const SEMVER = { parse: (t) => parseSemver(t), compare: compareSemverParsed };
const ORDER = {
  golang: SEMVER,
  cargo: SEMVER,
  npm: SEMVER,
  nuget: { parse: parseNuget, compare: compareNugetParsed },
  pypi: { parse: parsePep440, compare: comparePep440Parsed },
};

/**
 * The version as OSV writes it for this ecosystem: Go module versions drop their "v" prefix
 * (OSV Go data has none: "1.16.0-0", "0.0.0-2021…", "2.7.0-rc.0+incompatible").
 */
export function osvVersion(ecosystem, version) {
  return ecosystem === "golang" && version.startsWith("v")
    ? version.slice(1)
    : version;
}

function comparator(ecosystem, rangeType) {
  if (rangeType === "SEMVER") return SEMVER;
  if (rangeType === "ECOSYSTEM") return ORDER[ecosystem];
  return null;
}

/** Sort and replay the events of one range. Result<{affected, fixed[]}>. */
export function evaluateRange(ecosystem, range, version) {
  const order = comparator(ecosystem, range.type);
  if (order === null)
    return err("osv-range-type", `${range.type} range not evaluated`);
  const target = order.parse(version);
  if (!target.ok)
    return err("osv-version", `component version: ${target.error.message}`);
  const events = [];
  for (const event of range.events ?? []) {
    const [kind] = Object.keys(event);
    const value = event[kind];
    if (!["introduced", "fixed", "last_affected", "limit"].includes(kind))
      return err("osv-event", `unknown event ${JSON.stringify(kind)}`);
    if (kind === "introduced" && value === "0") {
      events.push({ kind, value, parsed: null });
      continue;
    }
    const parsed = order.parse(value);
    if (!parsed.ok)
      return err("osv-version", `${kind} event: ${parsed.error.message}`);
    events.push({ kind, value, parsed: parsed.value });
  }
  const cmp = (a, b) =>
    a.parsed === null
      ? b.parsed === null
        ? 0
        : -1
      : b.parsed === null
        ? 1
        : order.compare(a.parsed, b.parsed);
  events.sort(cmp);
  const v = target.value;
  let affected = false;
  for (const e of events) {
    if (e.kind === "introduced") {
      if (e.parsed === null || order.compare(v, e.parsed) >= 0) affected = true;
    } else if (e.kind === "fixed" || e.kind === "limit") {
      if (order.compare(v, e.parsed) >= 0) affected = false;
    } else if (order.compare(v, e.parsed) > 0) affected = false;
  }
  return ok({
    affected,
    fixed: events.filter((e) => e.kind === "fixed").map((e) => e.value),
  });
}

/** Is `version` one of the explicitly listed versions? Same order as ECOSYSTEM ranges. */
function listed(ecosystem, versions, version) {
  if (versions.includes(version)) return true;
  const order = ORDER[ecosystem];
  const target = order.parse(version);
  if (!target.ok) return false;
  return versions.some((listedVersion) => {
    const parsed = order.parse(listedVersion);
    return parsed.ok && order.compare(parsed.value, target.value) === 0;
  });
}

/**
 * Evaluate one OSV `affected[]` entry (already restricted to this ecosystem and package) for a
 * component version written the OSV way (see osvVersion).
 * Returns {affected, via, fixed[], unevaluated[]}: `via` is "versions" or the range type that
 * matched; `unevaluated` lists ranges that could not be decided (with the reason).
 */
export function evaluateAffected(ecosystem, entry, version) {
  const unevaluated = [];
  const fixed = [];
  let via = null;
  const versions = Array.isArray(entry.versions) ? entry.versions : [];
  if (versions.length > 0 && listed(ecosystem, versions, version))
    via = "versions";
  for (const range of entry.ranges ?? []) {
    if (range.type === "GIT" && versions.length > 0) continue;
    const result = evaluateRange(ecosystem, range, version);
    if (!result.ok) {
      unevaluated.push({ type: range.type, reason: result.error.message });
      continue;
    }
    fixed.push(...result.value.fixed);
    if (result.value.affected && via === null) via = range.type;
  }
  return {
    affected: via !== null,
    via,
    fixed: [...new Set(fixed)],
    unevaluated,
  };
}
