// In-house executable, Go buildinfo and cargo-auditable readers (S5 part B) on synthetic
// containers of every supported layout, plus structure-based detection in lib/scan.mjs.
// Real binaries: corpus.test.mjs (end to end) and test/differential/ (against the optional oracle).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { withSource } from "../lib/files.mjs";
import { readCargoAuditable } from "../lib/readers/cargoauditable.mjs";
import { readExecutable } from "../lib/readers/executable.mjs";
import { readGoBuildInfo } from "../lib/readers/gobuildinfo.mjs";
import { fingerprint, scanArtifact } from "../lib/scan.mjs";
import {
  AUDIT_DOC,
  GO_TEXT,
  auditSection,
  buildElf,
  buildFat,
  buildMachO,
  buildPe,
  goBuildInfo,
} from "./support/binaries.mjs";
import {
  OUT,
  S2_FIXTURES,
  SCAN_BIN,
  fixtureGate,
  fixturePath,
} from "./support.mjs";

const scratch = mkdtempSync(join(tmpdir(), "sbom-readers-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));
let n = 0;
const file = (bytes) => {
  const path = join(scratch, `bin-${(n += 1)}`);
  writeFileSync(path, bytes);
  return path;
};

const GO_EXPECTED = {
  goVersion: "go1.24.7",
  main: { path: "example.com/app", version: "v1.2.3", replacement: null },
  dependencies: [
    { path: "github.com/a/b", version: "v1.0.0", replacement: null },
    {
      path: "github.com/c/d",
      version: "v0.1.0",
      replacement: { path: "github.com/fork/d", version: "v0.1.1" },
    },
    {
      path: "github.com/e/f",
      version: "v2.0.0",
      replacement: { path: "../local/f", version: "" },
    },
  ],
  complete: true,
  unparsedLines: [],
  unparsedBinaryLines: 0,
};
const pick = (facts, keys) =>
  Object.fromEntries(keys.map((k) => [k, facts[k]]));

const GO_LAYOUTS = [
  [
    "ELF64 LE",
    () =>
      buildElf({
        sections: [
          { name: ".go.buildinfo", data: goBuildInfo({ text: GO_TEXT }) },
        ],
      }),
  ],
  [
    "ELF32 BE",
    () =>
      buildElf({
        bits: 32,
        littleEndian: false,
        sections: [
          { name: ".go.buildinfo", data: goBuildInfo({ text: GO_TEXT }) },
        ],
      }),
  ],
  // S6: layouts of the real cross builds (s6/cross-binaries.json): linux/386 is ELF32 LE with
  // pointer size 4; linux/s390x and linux/ppc64 are ELF64 BE with header flags 3.
  [
    "ELF32 LE, pointer size 4 (linux/386)",
    () =>
      buildElf({
        bits: 32,
        sections: [
          {
            name: ".go.buildinfo",
            data: goBuildInfo({ text: GO_TEXT, pointerSize: 4 }),
          },
        ],
      }),
  ],
  [
    "ELF64 BE, flags 3 (linux/s390x, linux/ppc64)",
    () =>
      buildElf({
        littleEndian: false,
        sections: [
          {
            name: ".go.buildinfo",
            data: goBuildInfo({ text: GO_TEXT, bigEndian: true }),
          },
        ],
      }),
  ],
  [
    "PE32+ .data",
    () =>
      buildPe({
        sections: [
          { name: ".text", data: Buffer.alloc(64) },
          {
            name: ".data",
            data: Buffer.concat([
              Buffer.alloc(48),
              goBuildInfo({ text: GO_TEXT }),
            ]),
          },
        ],
      }),
  ],
  [
    "Mach-O 64",
    () =>
      buildMachO({
        sections: [
          { name: "__go_buildinfo", data: goBuildInfo({ text: GO_TEXT }) },
        ],
      }),
  ],
  [
    "Mach-O 32 BE",
    () =>
      buildMachO({
        bits: 32,
        littleEndian: false,
        sections: [
          { name: "__go_buildinfo", data: goBuildInfo({ text: GO_TEXT }) },
        ],
      }),
  ],
  [
    "fat Mach-O (same modules in both slices)",
    () =>
      buildFat([
        buildMachO({
          sections: [
            { name: "__go_buildinfo", data: goBuildInfo({ text: GO_TEXT }) },
          ],
        }),
        buildMachO({
          sections: [
            { name: "__go_buildinfo", data: goBuildInfo({ text: GO_TEXT }) },
          ],
        }),
      ]),
  ],
];

for (const [label, build] of GO_LAYOUTS)
  test(`go buildinfo: ${label}`, () => {
    const result = readGoBuildInfo(file(build()));
    assert.equal(result.ok, true, JSON.stringify(result.error));
    assert.deepEqual(pick(result.value, Object.keys(GO_EXPECTED)), GO_EXPECTED);
    assert.match(result.value.locatedBy, /^section /);
    assert.deepEqual(result.value.settings, [
      { key: "-trimpath", value: "true" },
    ]);
  });

test("go buildinfo: no section table → marker search; pointer format refused; no sentinels → incomplete", () => {
  const blob = goBuildInfo({ text: GO_TEXT });
  const bare = buildElf({
    sectionTable: false,
    tail: Buffer.concat([Buffer.alloc(5), blob]),
  });
  const found = readGoBuildInfo(file(bare));
  assert.equal(found.ok, true, JSON.stringify(found.error));
  assert.equal(found.value.locatedBy, "marker-search");
  assert.deepEqual(found.value.dependencies, GO_EXPECTED.dependencies);
  const location = found.value.moduleLocation;
  assert.equal(
    bare.subarray(location.offset + 16, location.offset + 20).toString(),
    "path",
  );

  const pointer = readGoBuildInfo(
    file(
      buildElf({
        sections: [
          { name: ".go.buildinfo", data: goBuildInfo({ inline: false }) },
        ],
      }),
    ),
  );
  assert.equal(pointer.ok, false);
  assert.equal(pointer.error.tag, "go-buildinfo-pointer-format");

  const raw = readGoBuildInfo(
    file(
      buildElf({
        sections: [
          {
            name: ".go.buildinfo",
            data: goBuildInfo({ text: GO_TEXT, sentinels: false }),
          },
        ],
      }),
    ),
  );
  assert.equal(raw.value.complete, false);
  assert.equal(raw.value.main, null);
  assert.deepEqual(raw.value.dependencies, []);

  assert.equal(
    readGoBuildInfo(file(buildElf({ sections: [] }))).error.tag,
    "no-go-buildinfo",
  );
});

test("go buildinfo: odd lines are kept, non-UTF-8 lines counted, orphan => unparsed", () => {
  const text = "=>\tx\tv1\nmod\tm\tv1\nweird line\ndep\tonly-path\n\xff\xfe\n";
  const data = goBuildInfo({ text: "" });
  const mod = Buffer.concat([
    Buffer.alloc(16, 0xaa),
    Buffer.from(text, "latin1"),
    Buffer.alloc(16, 0xaa),
  ]);
  const blob = Buffer.concat([
    data.subarray(0, 32 + 1 + 8),
    Buffer.from([mod.length]),
    mod,
  ]);
  const facts = readGoBuildInfo(
    file(buildElf({ sections: [{ name: ".go.buildinfo", data: blob }] })),
  );
  assert.equal(facts.ok, true, JSON.stringify(facts.error));
  assert.deepEqual(facts.value.unparsedLines, [
    "=>\tx\tv1",
    "weird line",
    "dep\tonly-path",
  ]);
  assert.equal(facts.value.unparsedBinaryLines, 1);
  assert.deepEqual(facts.value.main, {
    path: "m",
    version: "v1",
    replacement: null,
  });
});

const RUST_LAYOUTS = [
  [
    "ELF64 LE",
    () =>
      buildElf({
        sections: [{ name: ".dep-v0", data: auditSection(AUDIT_DOC) }],
      }),
  ],
  [
    "ELF32 BE",
    () =>
      buildElf({
        bits: 32,
        littleEndian: false,
        sections: [{ name: ".dep-v0", data: auditSection(AUDIT_DOC) }],
      }),
  ],
  [
    "PE32+",
    () =>
      buildPe({
        sections: [
          { name: ".text", data: Buffer.alloc(16) },
          { name: ".dep-v0", data: auditSection(AUDIT_DOC) },
        ],
      }),
  ],
  [
    "Mach-O 64",
    () =>
      buildMachO({
        sections: [{ name: "__dep_v0", data: auditSection(AUDIT_DOC) }],
      }),
  ],
  [
    "fat Mach-O (same packages in both slices)",
    () =>
      buildFat([
        buildMachO({
          sections: [{ name: "__dep_v0", data: auditSection(AUDIT_DOC) }],
        }),
        buildMachO({
          sections: [{ name: "__dep_v0", data: auditSection(AUDIT_DOC) }],
        }),
      ]),
  ],
];

for (const [label, build] of RUST_LAYOUTS)
  test(`cargo-auditable: ${label}`, () => {
    const result = readCargoAuditable(file(build()));
    assert.equal(result.ok, true, JSON.stringify(result.error));
    assert.equal(result.value.section.formatVersion, 1);
    assert.deepEqual(result.value.packages, [
      {
        name: "app",
        version: "0.1.0",
        source: "local",
        kind: null,
        dependencies: [1, 2],
        root: true,
      },
      {
        name: "regex",
        version: "1.5.4",
        source: "crates.io",
        kind: null,
        dependencies: [2],
        root: false,
      },
      {
        name: "regex-syntax",
        version: "0.6.29",
        source: "crates.io",
        kind: null,
        dependencies: [],
        root: false,
      },
      {
        name: "autocfg",
        version: "1.1.0",
        source: "crates.io",
        kind: "build",
        dependencies: [],
        root: false,
      },
    ]);
  });

test("cargo-auditable: absent format is 0; bad index, bad JSON and missing section are typed errors", () => {
  const read = (data) =>
    readCargoAuditable(
      file(buildElf({ sections: [{ name: ".dep-v0", data }] })),
    );
  assert.equal(
    read(auditSection({ packages: [] })).value.section.formatVersion,
    0,
  );
  assert.equal(
    read(
      auditSection({
        packages: [{ name: "a", version: "1", source: "x", dependencies: [3] }],
      }),
    ).error.tag,
    "malformed-cargo-auditable",
  );
  assert.equal(
    read(auditSection("{not json")).error.tag,
    "malformed-cargo-auditable",
  );
  assert.equal(
    read(Buffer.from("not zlib")).error.tag,
    "malformed-cargo-auditable",
  );
  assert.equal(
    readCargoAuditable(file(buildElf())).error.tag,
    "no-cargo-auditable",
  );
  assert.equal(
    readCargoAuditable(file(Buffer.from("plain text file"))).error.tag,
    "not-executable",
  );
});

test("executable: ELF extended section numbering and PE long names via the COFF string table", () => {
  const elf = buildElf({
    sections: [{ name: ".dep-v0", data: Buffer.from("x") }],
  });
  // Move e_shnum and e_shstrndx into section 0 (sh_size, sh_link).
  const shoff = Number(elf.readBigUInt64LE(0x28));
  const count = elf.readUInt16LE(0x3c);
  const strndx = elf.readUInt16LE(0x3e);
  elf.writeUInt16LE(0, 0x3c);
  elf.writeUInt16LE(0xffff, 0x3e);
  elf.writeBigUInt64LE(BigInt(count), shoff + 32);
  elf.writeUInt32LE(strndx, shoff + 40);
  const parsed = withSource(file(elf), readExecutable);
  assert.deepEqual(
    parsed.value.images[0].sections.map((s) => s.name),
    ["", ".dep-v0", ".shstrtab"],
  );

  const pe = buildPe({
    sections: [{ name: "/4", data: Buffer.from("payload") }],
  });
  const strings = Buffer.from("\0\0\0\0.a-long-name\0", "latin1");
  const withTable = Buffer.concat([pe, strings]);
  withTable.writeUInt32LE(pe.length, 0x40 + 12); // PointerToSymbolTable, 0 symbols
  const long = withSource(file(withTable), readExecutable);
  assert.equal(long.value.images[0].sections[0].name, ".a-long-name");
});

test("detection: structure decides when a section table exists, markers otherwise", () => {
  const mention = Buffer.from(
    "text that names .dep-v0 and \xff Go buildinf: in data",
    "latin1",
  );
  const sectioned = file(
    buildElf({ sections: [{ name: ".rodata", data: mention }] }),
  );
  assert.deepEqual(fingerprint(sectioned).ecosystems, []);
  const scan = scanArtifact(sectioned);
  assert.equal(scan.error.tag, "unsupported-artifact");
  const bare = file(buildElf({ sectionTable: false, tail: mention }));
  assert.deepEqual(
    fingerprint(bare).ecosystems,
    ["cargo", "golang"],
    "no section table: markers select readers",
  );
  const malformed = buildElf({ sections: [] });
  malformed.writeBigUInt64LE(1n << 40n, 0x28);
  const message = scanArtifact(file(malformed)).error.message;
  assert.match(message, /container: malformed-executable/);
});

test("detection: a UPX-packed Go binary is unsupported-artifact with the reason", (t) => {
  const fx = S2_FIXTURES.find((f) => f.id === "go-uuid");
  if (!fixtureGate(t, fx)) return;
  const upx = spawnSync("upx", ["--version"]);
  const packed = join(scratch, "go-uuid-upx");
  cpSync(fixturePath(fx), packed);
  if (upx.status === 0) {
    const res = spawnSync("upx", ["-q", packed]);
    assert.equal(res.status, 0, res.stderr.toString());
  } else {
    // Without upx: the UPX header magic in the first page is what the reader recognizes.
    const bytes = Buffer.from(readAll(packed));
    bytes.write("UPX!", 0x100, "latin1");
    writeFileSync(packed, bytes);
  }
  const res = spawnSync(process.execPath, [SCAN_BIN, packed]);
  assert.equal(res.status, 1);
  assert.match(
    res.stderr.toString(),
    /unsupported-artifact: UPX-packed elf executable/,
  );
});

function readAll(path) {
  return withSource(path, (s) => s.read(0, s.size));
}

test("corpus: every Go and Rust fixture is located through its section", (t) => {
  for (const fx of S2_FIXTURES.filter((f) => f.ecosystem !== "npm")) {
    if (!fixtureGate(t, fx)) return;
    const path = join(OUT, fx.id, fx.artifact);
    if (fx.ecosystem === "golang") {
      const facts = readGoBuildInfo(path);
      assert.equal(facts.value.locatedBy, "section .go.buildinfo", fx.id);
    } else assert.equal(readCargoAuditable(path).value.section.name, ".dep-v0");
  }
});

// --- S6 A2: a fat Mach-O is one SBOM only when its slices agree --------------------------

const goSlice = (text, goarch) =>
  buildMachO({
    sections: [
      {
        name: "__go_buildinfo",
        data: goBuildInfo({
          text: `${text}build\tGOARCH=${goarch}\nbuild\tGOOS=darwin\n`,
        }),
      },
    ],
  });

test("A2 fat: same modules → one result, each slice's build settings kept", () => {
  const result = readGoBuildInfo(
    file(buildFat([goSlice(GO_TEXT, "amd64"), goSlice(GO_TEXT, "arm64")])),
  );
  assert.equal(result.ok, true, JSON.stringify(result.error));
  assert.deepEqual(pick(result.value, Object.keys(GO_EXPECTED)), GO_EXPECTED);
  assert.deepEqual(
    result.value.slices.map((s) => [
      s.cpuType,
      s.settings.find((x) => x.key === "GOARCH").value,
    ]),
    [
      [0x01000007, "amd64"],
      [0x0100000c, "arm64"],
    ],
  );
});

test("A2 fat: different modules or a slice without build information → fat-slices-differ", () => {
  const other = GO_TEXT.replace("v1.0.0", "v1.0.1");
  assert.notEqual(other, GO_TEXT);
  const differ = readGoBuildInfo(
    file(buildFat([goSlice(GO_TEXT, "amd64"), goSlice(other, "arm64")])),
  );
  assert.equal(differ.ok, false);
  assert.equal(differ.error.tag, "fat-slices-differ");
  assert.match(differ.error.message, /differ in dependencies/);
  const missing = readGoBuildInfo(
    file(buildFat([goSlice(GO_TEXT, "amd64"), buildMachO({ sections: [] })])),
  );
  assert.equal(missing.error?.tag, "fat-slices-differ");
  assert.match(missing.error.message, /without Go build information/);
  const rust = readCargoAuditable(
    file(
      buildFat([
        buildMachO({ sections: [] }),
        buildMachO({
          sections: [{ name: "__dep_v0", data: auditSection(AUDIT_DOC) }],
        }),
      ]),
    ),
  );
  assert.equal(rust.error?.tag, "fat-slices-differ");
  const otherDoc = {
    ...AUDIT_DOC,
    packages: AUDIT_DOC.packages.map((p, i) =>
      i === 1 ? { ...p, version: "9.9.9" } : p,
    ),
  };
  const rustDiffer = readCargoAuditable(
    file(
      buildFat([
        buildMachO({
          sections: [{ name: "__dep_v0", data: auditSection(AUDIT_DOC) }],
        }),
        buildMachO({
          sections: [{ name: "__dep_v0", data: auditSection(otherDoc) }],
        }),
      ]),
    ),
  );
  assert.equal(rustDiffer.error?.tag, "fat-slices-differ");
  assert.match(rustDiffer.error.message, /different packages/);
});
