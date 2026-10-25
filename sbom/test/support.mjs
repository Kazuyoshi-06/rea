// Shared test helpers: corpus paths, ground truth, CycloneDX 1.6 schema validation.
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

export const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
export const OUT = join(SBOM, "corpus/out");
export const SCAN_BIN = join(SBOM, "bin/sbom-scan");

// S2 fixtures: Go, Rust and npm (ASAR). .NET and PyInstaller are S3.
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
