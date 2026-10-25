// S5 part C: hostile inputs to the readers of untrusted files. Each case runs in its own process
// under GNU time (/usr/bin/time -v when installed) and must end with the expected typed error in
// bounded time and memory. SBOM_RESOURCE_REPORT=<file> writes the measurements as JSON.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { deflateRawSync, deflateSync } from "node:zlib";
import {
  auditSection,
  buildCArchive,
  buildElf,
  buildPe,
  buildPyz,
  buildZip,
  goBuildInfo,
} from "./support/binaries.mjs";
import { SBOM } from "./support.mjs";

const scratch = mkdtempSync(join(tmpdir(), "sbom-resources-"));
const TIME = "/usr/bin/time";
const RUNNER = join(SBOM, "test/support/resource_case.mjs");
// Budgets for one case: generous next to the measured values (S5_REPORT.md), far below what an
// unbounded allocation or loop would take.
const MAX_SECONDS = 5;
const MAX_RSS_MIB = 256;
const measured = [];
test.after(() => {
  rmSync(scratch, { recursive: true, force: true });
  if (process.env.SBOM_RESOURCE_REPORT)
    writeFileSync(
      process.env.SBOM_RESOURCE_REPORT,
      `${JSON.stringify(measured, null, 2)}\n`,
    );
});

// A zlib stream of `mib` MiB of zeros (~1 KiB of output per MiB of input).
const ZEROS = (mib) => Buffer.alloc(mib << 20);
const bomb = deflateSync(ZEROS(128));
const rawBomb = deflateRawSync(ZEROS(128));

function runCase(kind, bytes) {
  const file = join(scratch, `${kind}-${measured.length}`);
  writeFileSync(file, bytes);
  const timed = existsSync(TIME);
  const args = [process.execPath, RUNNER, kind, file];
  const started = process.hrtime.bigint();
  const res = timed
    ? spawnSync(TIME, ["-v", ...args])
    : spawnSync(args[0], args.slice(1));
  const wallS = Number(process.hrtime.bigint() - started) / 1e9;
  assert.equal(res.status, 0, res.stderr.toString());
  const log = res.stderr.toString();
  const rssKiB = timed
    ? Number(/Maximum resident set size \(kbytes\): (\d+)/.exec(log)[1])
    : null;
  const out = JSON.parse(res.stdout.toString());
  return {
    ...out,
    fileBytes: bytes.length,
    wallS: +wallS.toFixed(3),
    rssMiB: rssKiB === null ? null : +(rssKiB / 1024).toFixed(1),
  };
}

const CASES = [
  {
    name: "PYZ module: 1 KiB-ish zlib inflating to 128 MiB",
    kind: "pyz",
    bytes: () =>
      buildCArchive([
        { name: "PYZ-00.pyz", type: "z", data: buildPyz("bomb", bomb) },
      ]),
    tag: "malformed-pyinstaller-archive",
    message: /inflated data exceeds 67108864 bytes/,
  },
  {
    name: "CArchive entry: TOC declares 1 KiB, zlib inflates to 128 MiB",
    kind: "carchive",
    bytes: () =>
      buildCArchive([
        {
          name: "x.json",
          type: "x",
          data: bomb,
          compressed: true,
          uncompressedLength: 1024,
        },
      ]),
    tag: "malformed-pyinstaller-archive",
    message: /inflated data exceeds 1024 bytes/,
  },
  {
    name: "CArchive: TOC entry offset past the end of the file",
    kind: "carchive",
    bytes: () => {
      const b = buildCArchive([
        { name: "x", type: "x", data: Buffer.from("abc") },
      ]);
      b.writeUInt32BE(0x7fff0000, b.length - 88 - 32 + 4); // first TOC entry offset
      return b;
    },
    tag: "malformed-pyinstaller-archive",
    message: /outside/,
  },
  {
    name: "marshal: list announcing 2^31-1 items",
    kind: "marshal",
    bytes: () => Buffer.from([0x5b, 0xff, 0xff, 0xff, 0x7f, 0x4e]),
    tag: "MarshalError",
    message: /count 2147483647 exceeds remaining data/,
  },
  {
    name: "marshal: string announcing 4 GiB",
    kind: "marshal",
    bytes: () => Buffer.from([0x75, 0xff, 0xff, 0xff, 0xff, 0x61]),
    tag: "MarshalError",
    message: /truncated data/,
  },
  {
    name: "marshal: 200 000 nested lists",
    kind: "marshal",
    bytes: () =>
      Buffer.concat(
        Array.from({ length: 200_000 }, () => Buffer.from([0x5b, 1, 0, 0, 0])),
      ),
    tag: "MarshalError",
    message: /nesting too deep/,
  },
  {
    name: "ELF: e_shoff 1 TiB past a 300-byte file",
    kind: "executable",
    bytes: () => {
      const b = buildElf();
      b.writeBigUInt64LE(1n << 40n, 0x28);
      return b;
    },
    tag: "malformed-executable",
    message: /outside the file/,
  },
  {
    name: "ELF: 65 535 sections announced, table past the end",
    kind: "executable",
    bytes: () => {
      const b = buildElf();
      b.writeUInt16LE(0xffff, 0x3c);
      return b;
    },
    tag: "malformed-executable",
    message: /outside the file/,
  },
  {
    name: "ELF: extended numbering claims 2^32-1 sections",
    kind: "executable",
    bytes: () => {
      const b = buildElf({
        sections: [{ name: ".x", data: Buffer.from("x") }],
      });
      const shoff = Number(b.readBigUInt64LE(0x28));
      b.writeUInt16LE(0, 0x3c);
      b.writeBigUInt64LE(0xffffffffn, shoff + 32);
      return b;
    },
    tag: "malformed-executable",
    message: /sections \(limit 65535\)/,
  },
  {
    name: "PE: 65 535 sections announced",
    kind: "executable",
    bytes: () => buildPe({ sections: [], numberOfSections: 0xffff }),
    tag: "malformed-executable",
    message: /limit 96/,
  },
  {
    name: "PE: .dep-v0 raw data pointer at 2 GiB",
    kind: "cargo",
    bytes: () => {
      const b = buildPe({
        sections: [{ name: ".dep-v0", data: auditSection({ packages: [] }) }],
      });
      b.writeUInt32LE(0x7fffffff, 0x40 + 24 + 240 + 20); // PointerToRawData of section 0
      return b;
    },
    tag: "malformed-cargo-auditable",
    message: /outside the file/,
  },
  {
    name: "cargo-auditable: 64 KiB of zlib inflating to 128 MiB",
    kind: "cargo",
    bytes: () => buildElf({ sections: [{ name: ".dep-v0", data: bomb }] }),
    tag: "cargo-auditable-too-large",
    message: /exceeds 33554432 bytes/,
  },
  {
    name: "Go buildinfo: module information announcing 2^40 bytes",
    kind: "go",
    bytes: () => {
      const blob = goBuildInfo({ text: "x", moduleLength: 2 ** 40 });
      return buildElf({ sections: [{ name: ".go.buildinfo", data: blob }] });
    },
    tag: "malformed-go-buildinfo",
    message: /limit 8388608/,
  },
  {
    name: "ZIP: entry declares 1 KiB, inflates to 128 MiB",
    kind: "zip",
    bytes: () => buildZip("x.json", rawBomb, 1024),
    tag: "zip-too-large",
    message: /inflates past its declared 1024 bytes/,
  },
  {
    name: "ZIP: entry declares 4 GiB",
    kind: "zip",
    bytes: () => buildZip("x.json", rawBomb, 0xfffffffe),
    tag: "zip-too-large",
    message: /limit 67108864/,
  },
];

for (const c of CASES)
  test(`hostile input, ${c.name}: typed error in bounded time and memory`, () => {
    const result = runCase(c.kind, c.bytes());
    measured.push({ case: c.name, ...result });
    assert.equal(result.tag, c.tag, result.message);
    assert.match(result.message, c.message);
    assert.ok(result.wallS < MAX_SECONDS, `${result.wallS} s`);
    if (result.rssMiB !== null)
      assert.ok(result.rssMiB < MAX_RSS_MIB, `${result.rssMiB} MiB`);
  });
