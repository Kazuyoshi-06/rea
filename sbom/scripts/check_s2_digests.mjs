#!/usr/bin/env node
// Compare freshly built test fixtures with corpus/DIGESTS.txt. A mismatch is a warning: another
// toolchain version can change binary bytes (and the Go stdlib version) without changing the
// dependency truth, which the tests check independently.
// Checked: the S2 fixtures and the NuGet DLLs copied verbatim into the .NET publish directories.
// Not checked (known to vary, see README.md): the .NET application DLL (it embeds the git commit
// through SourceLink) and the PyInstaller executables (successive builds alternate between two
// outputs).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256File } from "../lib/files.mjs";
import { S2_FIXTURES } from "../test/support.mjs";

const CHECKED = [
  ...S2_FIXTURES.map((fx) => `${fx.id}/${fx.artifact}`),
  "dotnet-json/Newtonsoft.Json.dll",
  "dotnet-serilog/Serilog.dll",
  "dotnet-serilog/Serilog.Sinks.Console.dll",
];

const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
const expected = new Map(
  readFileSync(join(SBOM, "corpus/DIGESTS.txt"), "utf8")
    .trim()
    .split("\n")
    .map((line) => line.split(/\s+/))
    .map(([digest, path]) => [path.replace(/^\.\//, ""), digest]),
);
let mismatches = 0;
for (const rel of CHECKED) {
  const actual = sha256File(join(SBOM, "corpus/out", rel)).sha256;
  if (actual === expected.get(rel)) continue;
  mismatches += 1;
  console.warn(
    `WARN ${rel}: sha256 ${actual} differs from DIGESTS.txt ${expected.get(rel)}`,
  );
}
console.log(
  `fixtures matching DIGESTS.txt: ${CHECKED.length - mismatches}/${CHECKED.length}`,
);
