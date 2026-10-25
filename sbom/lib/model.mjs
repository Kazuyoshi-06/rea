// Component model shared by every adapter and exporter.
//
// Component  {purl, name, version, ecosystem, source, confidence, role, evidence[]}
// Unknown    {ecosystem, name, reason, evidence[]}  — detected, but no version to report.
// Exclusion  {ecosystem, name, version, reason}     — present in the artifact metadata,
//                                                    deliberately not a shipped component.
// Evidence   {artifact, location, sourceSha256, reader, ...adapter facts}
//
// confidence: one ordinal scale for every ecosystem, "high" / "medium" / "low" (property
// rea-sbom:confidence). "high" = read verbatim from a manifest or build record of the artifact
// (Go build info, cargo-auditable, package.json, deps.json, dist-info); "medium" = read but one
// part derived (npm name taken from the install directory, .NET id assumed = assembly name);
// "low" = a constant the package's own code binds (PyInstaller bytecode). Per-adapter rules in
// the adapters' headers. Vulnerability alerts inherit the confidence of their component.
// role: "library" or "language-runtime" (Go stdlib); TRUTH_RULES.md does not count runtimes.
import {
  cargoPurl,
  golangPurl,
  npmPurl,
  nugetPurl,
  pypiPurl,
} from "./purl.mjs";

const PURL_BUILDERS = {
  golang: golangPurl,
  cargo: cargoPurl,
  npm: npmPurl,
  nuget: nugetPurl,
  pypi: pypiPurl,
};

/**
 * Build one component. `purlName` overrides the name given to the purl builder (Go stdlib);
 * `noPurl` (a reason string) suppresses the purl when the registry identity is not known.
 */
export function makeComponent({
  ecosystem,
  name,
  version,
  source,
  confidence = "high",
  role = "library",
  evidence,
  noPurl = null,
  technique = null,
}) {
  const component = {
    purl: null,
    name,
    version,
    ecosystem,
    source,
    confidence,
    role,
    evidence: [evidence],
  };
  // Overrides the per-ecosystem CycloneDX evidence technique (e.g. deps.json vs CLI metadata).
  if (technique !== null) component.technique = technique;
  if (noPurl !== null) {
    component.purlStatus = noPurl;
    return component;
  }
  const purl = PURL_BUILDERS[ecosystem](name, version);
  if (purl.ok) component.purl = purl.value;
  else component.purlStatus = purl.error.message;
  return component;
}

export function makeUnknown({ ecosystem, name, reason, evidence }) {
  return { ecosystem, name, reason, evidence: [evidence] };
}

/**
 * Key under which two sightings are the same component. NuGet ids are case-insensitive; PyPI
 * names compare by PEP 503 ("-", "_" and "." runs equal, case-insensitive). Go, Cargo and npm
 * names are exact. The first sighting (in input order) keeps its own spelling in `name`.
 */
export function identityName({ ecosystem, name }) {
  if (ecosystem === "nuget") return name.toLowerCase();
  if (ecosystem === "pypi") return name.toLowerCase().replace(/[-_.]+/g, "-");
  return name;
}

export const compareStrings = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

const evidenceKey = (e) => JSON.stringify(e);

function mergeByKey(items, keyOf) {
  const byKey = new Map();
  for (const item of items) {
    const key = keyOf(item);
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, { ...item, evidence: [...item.evidence] });
      continue;
    }
    existing.evidence.push(...item.evidence);
  }
  const merged = [...byKey.entries()].sort(([a], [b]) => compareStrings(a, b));
  return merged.map(([, item]) => {
    const seen = new Map(item.evidence.map((e) => [evidenceKey(e), e]));
    const evidence = [...seen.entries()]
      .sort(([a], [b]) => compareStrings(a, b))
      .map(([, e]) => e);
    return { ...item, evidence };
  });
}

/** Merge duplicates (same identity seen at several locations) and sort everything stably. */
export function finalizeScan(scan) {
  return {
    ...scan,
    components: mergeByKey(scan.components, (c) =>
      JSON.stringify([c.ecosystem, c.role, identityName(c), c.version]),
    ),
    unknowns: mergeByKey(scan.unknowns, (u) =>
      JSON.stringify([u.ecosystem, identityName(u), u.reason]),
    ),
    exclusions: [...new Set(scan.exclusions.map((x) => JSON.stringify(x)))]
      .sort(compareStrings)
      .map((x) => JSON.parse(x)),
    limitations: [...new Set(scan.limitations)].sort(compareStrings),
  };
}
