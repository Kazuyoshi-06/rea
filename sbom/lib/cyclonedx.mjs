// CycloneDX 1.6 JSON export of a scan. Deterministic: every array is sorted by the model,
// object keys are emitted in a fixed order, the serial number is a UUIDv5 of the serialized
// BOM (serialNumber excluded, timestamp included) and the timestamp is injectable.
//
// Mapping:
//   scan root              → metadata.component (artifact sha256 in hashes)
//   components             → components[] (type library); Go stdlib carries
//                            property rea-sbom:role=language-runtime
//   unknowns (no version)  → metadata.properties "rea-sbom:unknown-component" (JSON value),
//                            never components: no version is invented, and scanners do not
//                            match a versionless component against every version
//   exclusions             → metadata.properties "rea-sbom:excluded-component" (JSON value)
//   evidence               → components[].evidence (identity + occurrences)
// No dependency graph is emitted: absence of "dependencies" means unknown, not none.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";

const SBOM_PACKAGE = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);
export const TOOL_VERSION = SBOM_PACKAGE.version;
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
// Numeric CycloneDX confidence. high/medium/low are the S3 scale (NuGet, PyPI); the values
// are a mapping choice, not a calibrated probability.
const CONFIDENCE = {
  observed: 1,
  inferred: 0.5,
  high: 1,
  medium: 0.6,
  low: 0.3,
};

function occurrence(evidence, artifactPath) {
  const loc = evidence.location;
  const out = {
    location: loc && loc.kind !== "file-range" ? loc.path : artifactPath,
  };
  if (loc && Number.isSafeInteger(loc.offset)) out.offset = loc.offset;
  const { artifact: _artifact, ...context } = evidence;
  out.additionalContext = compact(context);
  return out;
}

function componentEvidence(c, artifactPath) {
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
    occurrences: c.evidence.map((e) => occurrence(e, artifactPath)),
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

function bomComponents(scan) {
  const refs = new Set();
  return scan.components.map((c) => {
    let ref = c.purl ?? `${c.ecosystem}:${c.name}@${c.version}`;
    if (refs.has(ref)) ref = `${c.ecosystem}:${c.role}:${c.name}@${c.version}`;
    refs.add(ref);
    const out = {
      type: "library",
      "bom-ref": ref,
      name: c.name,
      version: c.version,
    };
    if (c.purl !== null) out.purl = c.purl;
    out.properties = componentProperties(c);
    out.evidence = componentEvidence(c, scan.artifact.path);
    return out;
  });
}

function rootComponent(scan) {
  const { artifact, root } = scan;
  const out = {
    type: artifact.kind === "directory" ? "file" : "application",
    "bom-ref": "rea-sbom:subject",
    name: root?.name ?? basename(artifact.path),
  };
  if (root?.version) out.version = root.version;
  if (root?.purl) out.purl = root.purl;
  if (artifact.sha256)
    out.hashes = [{ alg: "SHA-256", content: artifact.sha256 }];
  out.properties = [
    prop("rea-sbom:artifact-path", artifact.path),
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

function metadataProperties(scan) {
  const readers = new Set(
    scan.components.flatMap((c) => c.evidence.map((e) => e.reader?.command)),
  );
  return [
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
  ];
}

/** Build the CycloneDX 1.6 BOM object for a finalized scan. */
export function toCycloneDx(scan, { timestamp = new Date() } = {}) {
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
      properties: metadataProperties(scan),
    },
    components: bomComponents(scan),
  };
  const { serialNumber: _serial, ...content } = bom;
  const digest = createHash("sha256")
    .update(JSON.stringify(content))
    .digest("hex");
  bom.serialNumber = `urn:uuid:${uuidV5(`urn:rea-sbom:bom-sha256:${digest}`)}`;
  return bom;
}

export const serializeBom = (bom) => `${JSON.stringify(bom, null, 2)}\n`;
