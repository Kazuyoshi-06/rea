#!/usr/bin/env node
// Compare freshly built S2 fixtures with corpus/DIGESTS.txt. A mismatch is a warning: another
// toolchain version can change binary bytes (and the Go stdlib version) without changing the
// dependency truth, which the tests check independently.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256File } from "../lib/files.mjs";
import { S2_FIXTURES } from "../test/support.mjs";

const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
const expected = new Map(
  readFileSync(join(SBOM, "corpus/DIGESTS.txt"), "utf8")
    .trim()
    .split("\n")
    .map((line) => line.split(/\s+/))
    .map(([digest, path]) => [path.replace(/^\.\//, ""), digest]),
);
let mismatches = 0;
for (const fx of S2_FIXTURES) {
  const rel = `${fx.id}/${fx.artifact}`;
  const actual = sha256File(join(SBOM, "corpus/out", rel)).sha256;
  if (actual === expected.get(rel)) continue;
  mismatches += 1;
  console.warn(
    `WARN ${rel}: sha256 ${actual} differs from DIGESTS.txt ${expected.get(rel)}`,
  );
}
console.log(
  `S2 fixtures matching DIGESTS.txt: ${S2_FIXTURES.length - mismatches}/${S2_FIXTURES.length}`,
);
