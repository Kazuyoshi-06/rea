// Component model shared by every adapter and exporter.
//
// Component  {purl, name, version, ecosystem, source, confidence, role, evidence[]}
// Unknown    {ecosystem, name, reason, evidence[]}  — detected, but no version to report.
// Exclusion  {ecosystem, name, version, reason}     — present in the artifact metadata,
//                                                    deliberately not a shipped component.
// Evidence   {artifact, location, sourceSha256, reader, ...adapter facts}
//
// confidence: "observed" (read verbatim from the artifact) or "inferred" (derived, e.g. an npm
// name taken from the install directory because package.json had none).
// role: "library" or "language-runtime" (Go stdlib); TRUTH_RULES.md does not count runtimes.
import { cargoPurl, golangPurl, npmPurl } from "./purl.mjs";

const PURL_BUILDERS = { golang: golangPurl, cargo: cargoPurl, npm: npmPurl };

/**
 * Build one component. `purlName` overrides the name given to the purl builder (Go stdlib);
 * `noPurl` (a reason string) suppresses the purl when the registry identity is not known.
 */
export function makeComponent({
  ecosystem,
  name,
  version,
  source,
  confidence = "observed",
  role = "library",
  evidence,
  noPurl = null,
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
      JSON.stringify([c.ecosystem, c.role, c.name, c.version]),
    ),
    unknowns: mergeByKey(scan.unknowns, (u) =>
      JSON.stringify([u.ecosystem, u.name, u.reason]),
    ),
    exclusions: [...scan.exclusions].sort((a, b) =>
      compareStrings(JSON.stringify(a), JSON.stringify(b)),
    ),
    limitations: [...new Set(scan.limitations)].sort(compareStrings),
  };
}
