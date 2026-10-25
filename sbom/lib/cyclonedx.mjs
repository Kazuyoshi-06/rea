// CycloneDX 1.6 JSON export of a scan. Deterministic: every array is sorted by the model,
// object keys are emitted in a fixed order, the serial number is a UUIDv5 of the serialized
// BOM (serialNumber excluded, timestamp included) and the timestamp is injectable.
//
// Mapping:
//   scan root              → metadata.component (artifact sha256 in hashes)
//   artifact path          → never emitted: only its base name (rea-sbom:artifact-name) and
//                            sha256, so the same file scanned from two directories gives the
//                            same bytes. Evidence locations are relative to the artifact.
//   components             → components[] (type library); Go stdlib carries
//                            property rea-sbom:role=language-runtime
//   unknowns (no version)  → metadata.properties "rea-sbom:unknown-component" (JSON value),
//                            never components: no version is invented, and scanners do not
//                            match a versionless component against every version
//   exclusions             → metadata.properties "rea-sbom:excluded-component" (JSON value)
//   evidence               → components[].evidence (identity + occurrences)
//   vulnerability matches  → vulnerabilities[] (with --vulns): one entry per alias group of OSV
//                            records (GO-/GHSA-/CVE-/PYSEC-…), id = primary id (CVE, else GHSA,
//                            else first), every other id in references, affected components in
//                            affects[] with fixed versions as status "unaffected";
//                            rea-sbom:confidence = lowest of the components (low → analysis.state
//                            in_triage), rea-sbom:osv-record per matched record,
//                            rea-sbom:scope=language-runtime for Go stdlib alerts; the index
//                            snapshot id and archive dates go to metadata.properties
//                            (rea-sbom:vulndb-*)
//   target platform (Go)   → metadata.properties rea-sbom:target-platform "GOOS/GOARCH" (one per
//                            slice of a fat file), from the build settings
//   platform filter (Go)   → with --vulns: rea-sbom:platform-filter (applied | disabled |
//                            no-platform), rea-sbom:platform-filtered-count (groups removed)
//                            and one rea-sbom:platform-filtered per removed group (id, records,
//                            affected refs, required goos / goarch); --all-platforms disables it
//   format version         → metadata.properties rea-sbom:format-version (integer)
// No dependency graph is emitted: absence of "dependencies" means unknown, not none.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";

const SBOM_PACKAGE = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);
export const TOOL_VERSION = SBOM_PACKAGE.version;
// Version of the BOM layout (properties, ids, grouping) that consumers rely on; bumped on every
// breaking change, listed in README.md ("Format du BOM").
export const FORMAT_VERSION = 4;
const URL_NAMESPACE = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"; // RFC 4122 URL namespace

/** RFC 4122 version-5 (SHA-1, name-based) UUID. */
export function uuidV5(name, namespace = URL_NAMESPACE) {
  const ns = Buffer.from(namespace.replaceAll("-", ""), "hex");
  const digest = createHash("sha1").update(ns).update(name, "utf8").digest();
  digest[6] = (digest[6] & 0x0f) | 0x50;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = digest.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** ISO 8601 without milliseconds; accepts a Date, an ISO string or epoch seconds. */
export function formatTimestamp(value) {
  const date =
    typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime()))
    throw new Error(`invalid timestamp: ${value}`);
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

const prop = (name, value) => ({ name, value: String(value) });
const compact = (value) => JSON.stringify(value);

const TECHNIQUE = {
  golang: "binary-analysis",
  cargo: "binary-analysis",
  npm: "manifest-analysis",
  nuget: "manifest-analysis",
  pypi: "other",
};
// Numeric CycloneDX confidence of the high/medium/low scale; the values are a mapping choice,
// not a calibrated probability.
export const CONFIDENCE = {
  high: 1,
  medium: 0.6,
  low: 0.3,
};

function occurrence(evidence, artifactName) {
  const loc = evidence.location;
  const out = {
    location: loc && loc.kind !== "file-range" ? loc.path : artifactName,
  };
  if (loc && Number.isSafeInteger(loc.offset)) out.offset = loc.offset;
  const { artifact: _artifact, ...context } = evidence;
  out.additionalContext = compact(context);
  return out;
}

function componentEvidence(c, artifactName) {
  const confidence = CONFIDENCE[c.confidence] ?? 0;
  return {
    identity: [
      {
        field: c.purl === null ? "name" : "purl",
        confidence,
        methods: [
          {
            technique: c.technique ?? TECHNIQUE[c.ecosystem] ?? "other",
            confidence,
            value: c.source,
          },
        ],
      },
    ],
    occurrences: c.evidence.map((e) => occurrence(e, artifactName)),
  };
}

function componentProperties(c) {
  const props = [
    prop("rea-sbom:ecosystem", c.ecosystem),
    prop("rea-sbom:source", c.source),
    prop("rea-sbom:confidence", c.confidence),
  ];
  if (c.role !== "library") props.push(prop("rea-sbom:role", c.role));
  if (c.purlStatus) props.push(prop("rea-sbom:purl-status", c.purlStatus));
  return props;
}

/** bom-ref of every component (Map component → ref), unique within the BOM. */
function componentRefs(components) {
  const used = new Set();
  const refs = new Map();
  for (const c of components) {
    let ref = c.purl ?? `${c.ecosystem}:${c.name}@${c.version}`;
    if (used.has(ref)) ref = `${c.ecosystem}:${c.role}:${c.name}@${c.version}`;
    used.add(ref);
    refs.set(c, ref);
  }
  return refs;
}

function bomComponents(scan, refs) {
  return scan.components.map((c) => {
    const ref = refs.get(c);
    const out = {
      type: "library",
      "bom-ref": ref,
      name: c.name,
      version: c.version,
    };
    if (c.purl !== null) out.purl = c.purl;
    out.properties = componentProperties(c);
    out.evidence = componentEvidence(c, artifactName(scan.artifact));
    return out;
  });
}

const artifactName = (artifact) => basename(artifact.path);

function rootComponent(scan) {
  const { artifact, root } = scan;
  const out = {
    type: artifact.kind === "directory" ? "file" : "application",
    "bom-ref": "rea-sbom:subject",
    name: root?.name ?? artifactName(artifact),
  };
  if (root?.version) out.version = root.version;
  if (root?.purl) out.purl = root.purl;
  if (artifact.sha256)
    out.hashes = [{ alg: "SHA-256", content: artifact.sha256 }];
  out.properties = [
    prop("rea-sbom:artifact-name", artifactName(artifact)),
    prop("rea-sbom:artifact-kind", artifact.kind),
  ];
  if (artifact.bytes !== null)
    out.properties.push(prop("rea-sbom:artifact-bytes", artifact.bytes));
  if (root)
    out.properties.push(prop("rea-sbom:root-ecosystem", root.ecosystem));
  if (root?.rawVersion && root.rawVersion !== root.version)
    out.properties.push(prop("rea-sbom:root-raw-version", root.rawVersion));
  if (root?.source)
    out.properties.push(prop("rea-sbom:root-source", root.source));
  return out;
}

function metadataProperties(scan, refs) {
  const readers = new Set(
    scan.components.flatMap((c) => c.evidence.map((e) => e.reader?.command)),
  );
  return [
    prop("rea-sbom:format-version", FORMAT_VERSION),
    ...scan.ecosystems.map((e) => prop("rea-sbom:detected-ecosystem", e)),
    ...[...readers]
      .filter(Boolean)
      .sort()
      .map((r) => prop("rea-sbom:reader", r)),
    prop("rea-sbom:unknown-count", scan.unknowns.length),
    ...scan.unknowns.map((u) =>
      prop(
        "rea-sbom:unknown-component",
        compact({
          ecosystem: u.ecosystem,
          name: u.name,
          reason: u.reason,
          locations: u.evidence.map(
            (e) => e.location?.path ?? e.installPath ?? null,
          ),
        }),
      ),
    ),
    prop("rea-sbom:excluded-count", scan.exclusions.length),
    ...scan.exclusions.map((x) =>
      prop("rea-sbom:excluded-component", compact(x)),
    ),
    ...scan.limitations.map((l) => prop("rea-sbom:limitation", l)),
    ...(scan.platforms ?? []).map((p) =>
      prop("rea-sbom:target-platform", `${p.goos ?? "?"}/${p.goarch ?? "?"}`),
    ),
    ...vulnDbProperties(scan.vulnerabilities, refs),
    ...(scan.ecosystems.includes("golang")
      ? platformFilterProperties(scan.vulnerabilities, refs)
      : []),
  ];
}

function platformFilterProperties(vulns, refs) {
  if (!vulns) return [];
  const { filter, filtered } = vulns.platform;
  return [
    prop("rea-sbom:platform-filter", filter),
    prop("rea-sbom:platform-filtered-count", filtered.length),
    ...filtered.map((g) => {
      const requires = { goos: new Set(), goarch: new Set() };
      for (const a of g.alerts)
        for (const key of ["goos", "goarch"])
          for (const v of a.requires?.[key] ?? []) requires[key].add(v);
      return prop(
        "rea-sbom:platform-filtered",
        compact({
          id: g.id,
          records: g.records,
          affects: [
            ...new Set(g.alerts.map((a) => refs.get(a.component))),
          ].sort(),
          requires: Object.fromEntries(
            Object.entries(requires)
              .filter(([, set]) => set.size > 0)
              .map(([key, set]) => [key, [...set].sort()]),
          ),
        }),
      );
    }),
  ];
}

function vulnDbProperties(vulns, refs) {
  if (!vulns) return [];
  const archives = vulns.snapshot.archives ?? {};
  return [
    prop("rea-sbom:vulndb-snapshot", vulns.snapshot.id),
    ...Object.keys(archives)
      .sort()
      .map((name) =>
        prop(
          "rea-sbom:vulndb-archive",
          compact({
            ecosystem: name,
            lastModified: archives[name].lastModified,
            sha256: archives[name].sha256,
          }),
        ),
      ),
    prop("rea-sbom:vuln-count", vulns.groups.length),
    prop("rea-sbom:vuln-record-count", vulns.alerts.length),
    ...(vulns.runtimeExcluded
      ? [
          prop(
            "rea-sbom:vuln-runtime-excluded-count",
            vulns.stats.runtimeAlertsExcluded,
          ),
        ]
      : []),
    prop("rea-sbom:vuln-unevaluated-count", vulns.unevaluated.length),
    ...vulns.unevaluated.map((u) =>
      prop(
        "rea-sbom:vuln-unevaluated",
        compact({ id: u.id, ref: refs.get(u.component), reasons: u.reasons }),
      ),
    ),
    ...vulns.failures.map((f) => prop("rea-sbom:vuln-failure", f)),
  ];
}

const ALIAS_URL = [
  [/^CVE-/, "NVD", (id) => `https://nvd.nist.gov/vuln/detail/${id}`],
  [
    /^GHSA-/,
    "GitHub Advisory Database",
    (id) => `https://github.com/advisories/${id}`,
  ],
  [/./, "OSV", (id) => `https://osv.dev/vulnerability/${id}`],
];

function aliasSource(id) {
  const [, name, url] = ALIAS_URL.find(([re]) => re.test(id));
  return { name, url: url(id) };
}

const CONFIDENCE_ORDER = ["low", "medium", "high"];
const lowest = (levels) =>
  CONFIDENCE_ORDER.find((level) => levels.includes(level)) ?? levels[0];

/** One vulnerabilities[] entry per alias group (lib/vulns/match.mjs groupAlerts). */
function bomVulnerability(group, refs) {
  const affects = new Map();
  for (const a of group.alerts) {
    const ref = refs.get(a.component);
    const entry = affects.get(ref) ?? {
      component: a.component,
      fixed: new Set(),
    };
    for (const f of a.fixed) entry.fixed.add(f);
    affects.set(ref, entry);
  }
  const targets = [...affects.entries()].sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  const records = new Map(group.alerts.map((a) => [a.id, a]));
  const summary = group.records
    .map((id) => records.get(id).summary)
    .find((s) => s);
  const modified = group.alerts
    .map((a) => a.modified)
    .filter(Boolean)
    .sort()
    .at(-1);
  const out = {
    "bom-ref": `rea-sbom:vuln:${group.id}`,
    id: group.id,
    source: aliasSource(group.id),
  };
  const others = group.ids.filter((id) => id !== group.id);
  if (others.length > 0)
    out.references = others.map((id) => ({ id, source: aliasSource(id) }));
  if (summary) out.description = summary;
  const fixedText = targets
    .filter(([, t]) => t.fixed.size > 0)
    .map(([, t]) => [t.component, [...t.fixed].sort().join(", ")]);
  if (fixedText.length === 1 && targets.length === 1)
    out.recommendation = `Fixed in: ${fixedText[0][1]}`;
  else if (fixedText.length > 0)
    out.recommendation = fixedText
      .map(([c, text]) => `${c.name}@${c.version}: fixed in ${text}`)
      .join("; ");
  if (modified) out.updated = formatTimestamp(modified);
  const confidence = lowest(group.alerts.map((a) => a.confidence));
  if (confidence === "low")
    out.analysis = {
      state: "in_triage",
      detail:
        "The affected component's identity or version has low confidence (rea-sbom:confidence); confirm the shipped version before acting.",
    };
  out.affects = targets.map(([ref, t]) => ({
    ref,
    versions: [
      { version: t.component.version, status: "affected" },
      ...[...t.fixed]
        .sort()
        .map((version) => ({ version, status: "unaffected" })),
    ],
  }));
  out.properties = [
    prop("rea-sbom:confidence", confidence),
    ...[...new Set(group.alerts.flatMap((a) => a.via))]
      .sort()
      .map((v) => prop("rea-sbom:matched-by", v)),
    ...group.records.map((id) => prop("rea-sbom:osv-record", id)),
  ];
  if (targets.every(([, t]) => t.component.role === "language-runtime"))
    out.properties.push(prop("rea-sbom:scope", "language-runtime"));
  return out;
}

/** Build the CycloneDX 1.6 BOM object for a finalized scan. */
export function toCycloneDx(scan, { timestamp = new Date() } = {}) {
  const refs = componentRefs(scan.components);
  const bom = {
    $schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: null,
    version: 1,
    metadata: {
      timestamp: formatTimestamp(timestamp),
      lifecycles: [{ phase: "post-build" }],
      tools: {
        components: [
          { type: "application", name: "rea-sbom", version: TOOL_VERSION },
        ],
      },
      component: rootComponent(scan),
      properties: metadataProperties(scan, refs),
    },
    components: bomComponents(scan, refs),
  };
  if (scan.vulnerabilities)
    bom.vulnerabilities = scan.vulnerabilities.groups.map((g) =>
      bomVulnerability(g, refs),
    );
  const { serialNumber: _serial, ...content } = bom;
  const digest = createHash("sha256")
    .update(JSON.stringify(content))
    .digest("hex");
  bom.serialNumber = `urn:uuid:${uuidV5(`urn:rea-sbom:bom-sha256:${digest}`)}`;
  return bom;
}

export const serializeBom = (bom) => `${JSON.stringify(bom, null, 2)}\n`;
