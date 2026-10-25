// Hostile-input smoke tests for the S3 readers: deterministic byte mutations must end in a
// Result (ok or a typed error), never an exception. Bounded iteration counts keep this fast.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { inflateSync } from "node:zlib";
import { scanPyInstaller } from "../lib/adapters/pyinstaller.mjs";
import { MarshalError, readMarshal } from "../lib/readers/marshal.mjs";
import { readCliAssembly } from "../lib/readers/cli-metadata.mjs";
import { OUT } from "./support.mjs";
import { buildPyInstaller, requirePython313 } from "./support/py.mjs";

const scratch = mkdtempSync(join(tmpdir(), "sbom-fuzz-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

/** Deterministic LCG in [0, 1). */
function prng(seed) {
  let state = seed;
  return () => {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return state / 0x7fffffff;
  };
}

test("CLI metadata reader survives mutated and truncated assemblies", (t) => {
  const source = join(OUT, "dotnet-serilog", "Serilog.Sinks.Console.dll");
  try {
    readFileSync(source);
  } catch {
    if (process.env.SBOM_REQUIRE_FIXTURES === "1")
      throw new Error(`fixture not built: ${source}`);
    t.skip("fixture not built");
    return;
  }
  const original = readFileSync(source);
  const random = prng(12345);
  const file = join(scratch, "mutant.dll");
  let typed = 0;
  for (let i = 0; i < 600; i += 1) {
    const bytes = Buffer.from(original);
    for (let k = 0, n = 1 + Math.floor(random() * 8); k < n; k += 1) {
      const nearEnd = random() < 0.5;
      const position = nearEnd
        ? bytes.length -
          1 -
          Math.floor(random() * Math.min(bytes.length, 60000))
        : Math.floor(random() * 1024);
      bytes[Math.max(0, position)] = Math.floor(random() * 256);
    }
    const input =
      random() < 0.2
        ? bytes.subarray(0, Math.floor(random() * bytes.length))
        : bytes;
    writeFileSync(file, input);
    const result = readCliAssembly(file);
    if (!result.ok) {
      typed += 1;
      assert.match(
        result.error.tag,
        /^(not-pe|no-cli-header|malformed-cli-metadata)$/,
      );
    }
  }
  assert.ok(typed > 0, "the mutations should break some files");
});

test("marshal reader only throws MarshalError on mutated code objects", (t) => {
  if (!requirePython313(t)) return;
  const file = join(scratch, "marshal.bin");
  buildPyInstaller({
    output: file,
    entries: [],
    modules: [
      {
        name: "m",
        source:
          "import os\n__version__ = '1.0'\nclass C:\n    x = (1, 2.5, b'z')\n",
      },
    ],
  });
  // Take the module's marshal data back out of the synthetic PYZ: zlib stream after the header.
  const bytes = readFileSync(file);
  const start = bytes.indexOf(Buffer.from([0x78, 0x9c]));
  const data = inflateSync(bytes.subarray(start), {
    finishFlush: 2 /* Z_SYNC_FLUSH */,
  });
  const random = prng(7);
  let rejected = 0;
  for (let i = 0; i < 600; i += 1) {
    const copy = Buffer.from(data);
    for (let k = 0, n = 1 + Math.floor(random() * 4); k < n; k += 1)
      copy[Math.floor(random() * copy.length)] = Math.floor(random() * 256);
    try {
      readMarshal(copy);
    } catch (error) {
      assert.ok(
        error instanceof MarshalError,
        `${error.constructor.name}: ${error.message}`,
      );
      rejected += 1;
    }
  }
  assert.ok(rejected > 0);
});

test("PyInstaller adapter survives mutated archives (cookie, TOC and entries)", (t) => {
  if (!requirePython313(t)) return;
  const base = join(scratch, "base.bin");
  buildPyInstaller({
    output: base,
    entries: [
      {
        name: "a-1.dist-info/METADATA",
        type: "x",
        text: "Name: a\nVersion: 1\n",
      },
    ],
    modules: [
      {
        name: "requests",
        source: "from .__version__ import __version__",
        ispkg: true,
      },
      { name: "requests.__version__", source: "__version__ = '2.31.0'" },
      { name: "yaml", source: "__version__ = '6.0'", ispkg: true },
    ],
  });
  const original = readFileSync(base);
  const random = prng(99);
  const file = join(scratch, "mutant.bin");
  let typed = 0;
  for (let i = 0; i < 600; i += 1) {
    const bytes = Buffer.from(original);
    for (let k = 0, n = 1 + Math.floor(random() * 6); k < n; k += 1) {
      const position =
        random() < 0.4
          ? bytes.length - 88 + Math.floor(random() * 88)
          : Math.floor(random() * bytes.length);
      bytes[position] = Math.floor(random() * 256);
    }
    writeFileSync(file, bytes);
    const result = scanPyInstaller({
      path: file,
      sha256: "0".repeat(64),
      bytes: bytes.length,
    });
    if (!result.ok) {
      typed += 1;
      assert.match(
        result.error.tag,
        /^(no-pyinstaller-cookie|malformed-pyinstaller-archive)$/,
      );
    }
  }
  assert.ok(typed > 0);
});
