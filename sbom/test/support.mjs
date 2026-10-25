// Shared test helpers: corpus paths, ground truth, CycloneDX 1.6 schema validation.
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

export const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
export const OUT = join(SBOM, "corpus/out");
export const SCAN_BIN = join(SBOM, "bin/sbom-scan");

// S2 fixtures: Go, Rust and npm (ASAR).
export const S2_FIXTURES = [
  { id: "go-uuid", artifact: "go-uuid", ecosystem: "golang" },
  { id: "go-uuid-stripped", artifact: "go-uuid", ecosystem: "golang" },
  { id: "go-jwt", artifact: "go-jwt", ecosystem: "golang" },
  { id: "go-jwt-stripped", artifact: "go-jwt", ecosystem: "golang" },
  { id: "rust-small", artifact: "rust-small", ecosystem: "cargo" },
  { id: "rust-vuln", artifact: "rust-vuln", ecosystem: "cargo" },
  { id: "npm-electron", artifact: "app.asar", ecosystem: "npm" },
  { id: "npm-cli", artifact: "app.asar", ecosystem: "npm" },
];

// S3 fixtures: .NET publish directories (artifact "" = the directory itself) and PyInstaller onefile.
export const S3_DOTNET_FIXTURES = [
  { id: "dotnet-json", artifact: "", ecosystem: "nuget" },
  { id: "dotnet-serilog", artifact: "", ecosystem: "nuget" },
];
export const S3_PYTHON_FIXTURES = [
  { id: "py-requests-meta", artifact: "py-requests-meta", ecosystem: "pypi" },
  { id: "py-requests", artifact: "py-requests", ecosystem: "pypi" },
  { id: "py-yaml", artifact: "py-yaml", ecosystem: "pypi" },
];

export const fixturePath = (fx) => join(OUT, fx.id, fx.artifact);

/** Missing corpus: fail under SBOM_REQUIRE_FIXTURES=1 (make sbom-test), skip otherwise. */
export function fixtureGate(t, fx) {
  if (existsSync(fixturePath(fx))) return true;
  if (process.env.SBOM_REQUIRE_FIXTURES === "1")
    throw new Error(
      `fixture not built: ${fixturePath(fx)} (run make sbom-test)`,
    );
  t.skip(`fixture not built: ${fx.id}`);
  return false;
}

export const readTruth = (id) =>
  JSON.parse(readFileSync(join(SBOM, "truth", `${id}.json`), "utf8"));

const schemaFile = (name) =>
  JSON.parse(
    gunzipSync(readFileSync(join(SBOM, "schemas", `${name}.gz`))).toString(
      "utf8",
    ),
  );

let validator = null;

/** Ajv validator for the pinned CycloneDX 1.6 schema (see schemas/README.md). */
export function cyclonedxValidator() {
  if (validator !== null) return validator;
  const require = createRequire(import.meta.url);
  const Ajv = require("ajv").default;
  const addFormats = require("ajv-formats").default;
  const addFormats2019 = require("ajv-formats-draft2019");
  const ajv = new Ajv({
    strict: false,
    allErrors: true,
    validateFormats: true,
  });
  addFormats(ajv);
  addFormats2019(ajv);
  ajv.addSchema(
    schemaFile("spdx.SNAPSHOT.schema.json"),
    "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json",
  );
  ajv.addSchema(
    schemaFile("jsf-0.82.SNAPSHOT.schema.json"),
    "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json",
  );
  validator = ajv.compile(schemaFile("bom-1.6.SNAPSHOT.schema.json"));
  return validator;
}

export function schemaErrors(bom) {
  const validate = cyclonedxValidator();
  return validate(bom) ? [] : validate.errors;
}

/**
 * Canonical form of a PEP 440 release for measurement only: lowercase, numeric segments without
 * leading zeros ("2023.07.22" → "2023.7.22"). Never applied to what the scanner emits.
 */
export function pep440Equivalent(version) {
  return version.toLowerCase().replace(/(?<![0-9])0+(?=[0-9])/g, "");
}

const nameKey = {
  nuget: (n) => n.toLowerCase(),
  pypi: (n) => n.toLowerCase().replace(/[-_.]+/g, "-"),
};

/**
 * Precision / recall of `found` [{name, version}] against `truth` [{name, version}] for one
 * ecosystem. `strict` compares the version strings; `equivalent` also accepts PEP 440 spellings
 * that differ only by leading zeros (PyPI).
 */
export function compareToTruth(ecosystem, found, truth) {
  const key = (c, canon) =>
    `${nameKey[ecosystem](c.name)}@${canon ? pep440Equivalent(c.version) : c.version}`;
  const measure = (canon) => {
    const truthKeys = new Set(truth.map((c) => key(c, canon)));
    const foundKeys = new Set(found.map((c) => key(c, canon)));
    const tp = [...foundKeys].filter((k) => truthKeys.has(k));
    return {
      found: foundKeys.size,
      truth: truthKeys.size,
      truePositives: tp.length,
      precision: foundKeys.size === 0 ? null : tp.length / foundKeys.size,
      recall: truthKeys.size === 0 ? null : tp.length / truthKeys.size,
      extra: [...foundKeys].filter((k) => !truthKeys.has(k)).sort(),
      missing: [...truthKeys].filter((k) => !foundKeys.has(k)).sort(),
    };
  };
  return { strict: measure(false), equivalent: measure(true) };
}
