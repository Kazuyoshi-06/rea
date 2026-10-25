import assert from "node:assert/strict";
import { test } from "node:test";
import {
  formatTimestamp,
  serializeBom,
  toCycloneDx,
  uuidV5,
} from "../lib/cyclonedx.mjs";
import { finalizeScan, makeComponent, makeUnknown } from "../lib/model.mjs";
import { schemaErrors } from "./support.mjs";

test("uuidV5 matches RFC 4122 reference values (Python uuid.uuid5)", () => {
  assert.equal(
    uuidV5("https://www.python.org"),
    "30709ed8-a35e-547c-8ef0-c6bf5e229681",
  );
  assert.equal(
    uuidV5("python.org", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
    "886313e1-3b8a-5372-9b90-0c9aee199e5d",
  );
});

test("timestamps: ISO, epoch seconds, invalid input", () => {
  assert.equal(
    formatTimestamp("2026-01-02T03:04:05.678Z"),
    "2026-01-02T03:04:05Z",
  );
  assert.equal(formatTimestamp(0), "1970-01-01T00:00:00Z");
  assert.throws(() => formatTimestamp("not a date"), /invalid timestamp/);
});

const evidence = (path) => ({
  artifact: { path: "app.asar", sha256: "a".repeat(64) },
  location: { kind: "asar-entry", path, offset: 100, size: 10 },
  sourceSha256: "b".repeat(64),
  reader: { tool: "rea-sbom", command: "asar-reader" },
});

function syntheticScan(order) {
  const components = [
    makeComponent({
      ecosystem: "npm",
      name: "zeta",
      version: "1.0.0",
      source: "s",
      evidence: evidence("node_modules/zeta/package.json"),
    }),
    makeComponent({
      ecosystem: "npm",
      name: "@scope/alpha",
      version: "2.0.0",
      source: "s",
      evidence: evidence("node_modules/@scope/alpha/package.json"),
    }),
    makeComponent({
      ecosystem: "npm",
      name: "zeta",
      version: "1.0.0",
      source: "s",
      evidence: evidence("node_modules/x/node_modules/zeta/package.json"),
    }),
    makeComponent({
      ecosystem: "cargo",
      name: "gitdep",
      version: "0.1.0",
      source: "s",
      evidence: evidence("x"),
      noPurl: "source git",
    }),
    makeComponent({
      ecosystem: "npm",
      name: "inferred",
      version: "1.0.0",
      source: "s",
      confidence: "inferred",
      evidence: evidence("node_modules/inferred/package.json"),
    }),
  ];
  return finalizeScan({
    artifact: {
      path: "app.asar",
      sha256: "a".repeat(64),
      bytes: 1234,
      kind: "asar",
    },
    ecosystems: ["npm"],
    root: {
      ecosystem: "npm",
      name: "app",
      version: "1.0.0",
      purl: null,
      evidence: evidence("package.json"),
    },
    components: order === "reversed" ? components.reverse() : components,
    unknowns: [
      makeUnknown({
        ecosystem: "npm",
        name: "nover",
        reason: "package.json has no version",
        evidence: evidence("node_modules/nover/package.json"),
      }),
    ],
    exclusions: [
      {
        ecosystem: "cargo",
        name: "autocfg",
        version: "1.1.0",
        reason: "kind=build",
      },
    ],
    limitations: ["b", "a", "b"],
    calls: [],
  });
}

const T = "2026-01-01T00:00:00Z";

test("export is schema-valid, sorted and independent of input order", () => {
  const a = serializeBom(
    toCycloneDx(syntheticScan("forward"), { timestamp: T }),
  );
  const b = serializeBom(
    toCycloneDx(syntheticScan("reversed"), { timestamp: T }),
  );
  assert.equal(a, b);
  const bom = JSON.parse(a);
  assert.deepEqual(schemaErrors(bom), []);
  assert.deepEqual(
    bom.components.map((c) => c["bom-ref"]),
    [
      "cargo:gitdep@0.1.0",
      "pkg:npm/%40scope/alpha@2.0.0",
      "pkg:npm/inferred@1.0.0",
      "pkg:npm/zeta@1.0.0",
    ],
  );
  const zeta = bom.components.find((c) => c.name === "zeta");
  assert.equal(zeta.evidence.occurrences.length, 2);
  assert.equal(zeta.evidence.occurrences[0].offset, 100);
  assert.equal(
    bom.components.find((c) => c.name === "inferred").evidence.identity[0]
      .confidence,
    0.5,
  );
  assert.equal(
    bom.components.find((c) => c.name === "gitdep").evidence.identity[0].field,
    "name",
  );
});

test("unknowns and exclusions stay out of components, in labelled metadata properties", () => {
  const bom = toCycloneDx(syntheticScan("forward"), { timestamp: T });
  assert.ok(
    !bom.components.some((c) => c.name === "nover" || c.name === "autocfg"),
  );
  const props = bom.metadata.properties;
  const unknown = props.filter((p) => p.name === "rea-sbom:unknown-component");
  assert.deepEqual(JSON.parse(unknown[0].value), {
    ecosystem: "npm",
    name: "nover",
    reason: "package.json has no version",
    locations: ["node_modules/nover/package.json"],
  });
  assert.equal(
    props.find((p) => p.name === "rea-sbom:unknown-count").value,
    "1",
  );
  assert.equal(
    props.find((p) => p.name === "rea-sbom:excluded-count").value,
    "1",
  );
  assert.deepEqual(
    props.filter((p) => p.name === "rea-sbom:limitation").map((p) => p.value),
    ["a", "b"],
  );
});

test("serial number derives from content and timestamp, never from randomness", () => {
  const scan = syntheticScan("forward");
  const first = toCycloneDx(scan, { timestamp: T });
  assert.equal(
    first.serialNumber,
    toCycloneDx(scan, { timestamp: T }).serialNumber,
  );
  assert.match(
    first.serialNumber,
    /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  assert.notEqual(
    first.serialNumber,
    toCycloneDx(scan, { timestamp: "2026-01-02T00:00:00Z" }).serialNumber,
  );
  const changed = structuredClone(scan);
  changed.components[0].version = "9.9.9";
  assert.notEqual(
    first.serialNumber,
    toCycloneDx(changed, { timestamp: T }).serialNumber,
  );
});
