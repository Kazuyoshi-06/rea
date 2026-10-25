#!/usr/bin/env node
// Record sys.stdlib_module_names of the Python that builds the PyInstaller fixtures as versioned
// reference data (data/stdlib-module-names-<major.minor>.json). Run by `make stdlib-names`.
// Usage: gen_stdlib_names.mjs [python3]
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
const python = process.argv[2] ?? "python3";
const info = JSON.parse(
  execFileSync(
    python,
    [
      "-I",
      "-c",
      "import json,sys;print(json.dumps({'version':'%d.%d.%d'%sys.version_info[:3],'minor':'%d.%d'%sys.version_info[:2],'names':sorted(sys.stdlib_module_names)}))",
    ],
    { encoding: "utf8" },
  ),
);
mkdirSync(join(SBOM, "data"), { recursive: true });
const file = join(SBOM, "data", `stdlib-module-names-${info.minor}.json`);
writeFileSync(
  file,
  `${JSON.stringify(
    {
      source: "sys.stdlib_module_names",
      python: info.version,
      note: "Top-level module names of the standard library of the Python that builds the PyInstaller fixtures; regenerate with `make stdlib-names`.",
      names: info.names,
    },
    null,
    2,
  )}\n`,
);
console.log(`${file}: ${info.names.length} names (Python ${info.version})`);
