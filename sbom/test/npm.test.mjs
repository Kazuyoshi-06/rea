// npm adapter and ASAR reader on synthetic trees packed by the real @electron/asar packer.
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { sha256 } from "../lib/files.mjs";
import { scanArtifact } from "../lib/scan.mjs";
import { readAsarHeader } from "../lib/tree.mjs";

const asar = createRequire(import.meta.url)("@electron/asar");
const work = mkdtempSync(join(tmpdir(), "sbom-npm-"));
const app = join(work, "app");
const archive = join(work, "app.asar");

function pkg(dir, json) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "package.json"),
    typeof json === "string" ? json : JSON.stringify(json),
  );
}

before(async () => {
  const nm = join(app, "node_modules");
  pkg(app, { name: "synthetic-app", version: "0.0.1" });
  pkg(join(nm, "lodash"), { name: "lodash", version: "4.17.20" });
  // scoped package, and a nested node_modules holding a second version
  pkg(join(nm, "@scope/pkg"), { name: "@scope/pkg", version: "1.0.0" });
  pkg(join(nm, "@scope/pkg/node_modules/lodash"), {
    name: "lodash",
    version: "3.10.1",
  });
  pkg(join(nm, "@scope/pkg/node_modules/@inner/deep"), {
    name: "@inner/deep",
    version: "2.0.0",
  });
  // same identity at two locations: one component, two evidence entries
  pkg(join(nm, "a/node_modules/ms"), { name: "ms", version: "2.1.3" });
  pkg(join(nm, "ms"), { name: "ms", version: "2.1.3" });
  pkg(join(nm, "a"), { name: "a", version: "1.0.0" });
  // nested package.json inside a package is not a package
  pkg(join(nm, "a/lib/esm"), { type: "module" });
  // npm alias: installed as "alias", published as "real"
  pkg(join(nm, "alias"), { name: "real", version: "5.0.0" });
  // no name: identity inferred from the install directory
  pkg(join(nm, "noname"), { version: "1.2.3" });
  // detected without a version / unreadable: unknowns, never invented
  pkg(join(nm, "noversion"), { name: "noversion" });
  pkg(join(nm, "badjson"), "{not json");
  mkdirSync(join(nm, "nomanifest"), { recursive: true });
  writeFileSync(join(nm, "nomanifest/index.js"), "");
  // dot entries are npm metadata, not packages
  pkg(join(nm, ".bin"), { name: "bin", version: "9.9.9" });
  writeFileSync(join(nm, ".package-lock.json"), "{}");
  // unpacked package.json (asar --unpack) is read from app.asar.unpacked/
  pkg(join(nm, "native"), { name: "native", version: "0.3.0" });
  symlinkSync(join(nm, "lodash"), join(nm, "linked"));
  await asar.createPackageWithOptions(app, archive, {
    unpack: "**/node_modules/native/package.json",
  });
});

after(() => rmSync(work, { recursive: true, force: true }));

const ids = (scan) => scan.components.map((c) => `${c.name}@${c.version}`);
const EXPECTED = [
  "@inner/deep@2.0.0",
  "@scope/pkg@1.0.0",
  "a@1.0.0",
  "lodash@3.10.1",
  "lodash@4.17.20",
  "ms@2.1.3",
  "native@0.3.0",
  "noname@1.2.3",
  "real@5.0.0",
];

function scanOk(path) {
  const result = scanArtifact(path);
  assert.equal(result.ok, true, JSON.stringify(result.error));
  return result.value;
}

for (const [label, target] of [
  ["ASAR archive", () => archive],
  ["node_modules directory", () => app],
]) {
  test(`${label}: packages, scopes, nesting, aliases and unknowns`, () => {
    const scan = scanOk(target());
    assert.deepEqual(ids(scan).sort(), EXPECTED);
    const byId = Object.fromEntries(
      scan.components.map((c) => [`${c.name}@${c.version}`, c]),
    );
    assert.equal(byId["@scope/pkg@1.0.0"].purl, "pkg:npm/%40scope/pkg@1.0.0");
    assert.equal(byId["ms@2.1.3"].evidence.length, 2);
    assert.deepEqual(
      byId["ms@2.1.3"].evidence.map((e) => e.installPath),
      ["node_modules/a/node_modules/ms", "node_modules/ms"],
    );
    assert.equal(byId["real@5.0.0"].evidence[0].installedAs, "alias");
    assert.equal(byId["noname@1.2.3"].confidence, "inferred");
    assert.equal(byId["lodash@4.17.20"].confidence, "observed");
    const unknowns = Object.fromEntries(
      scan.unknowns.map((u) => [u.name, u.reason]),
    );
    assert.equal(unknowns.noversion, "package.json has no version");
    assert.match(unknowns.badjson, /JSON/);
    assert.match(unknowns.nomanifest, /no package\.json/);
    assert.deepEqual(scan.root && [scan.root.name, scan.root.version], [
      "synthetic-app",
      "0.0.1",
    ]);
  });
}

test("ASAR evidence: internal path, absolute offset, size and sha256 match the bytes", () => {
  const scan = scanOk(archive);
  const lodash = scan.components.find(
    (c) => c.name === "lodash" && c.version === "4.17.20",
  );
  const [ev] = lodash.evidence;
  const source = readFileSync(join(app, "node_modules/lodash/package.json"));
  assert.equal(ev.location.kind, "asar-entry");
  assert.equal(ev.location.path, "node_modules/lodash/package.json");
  assert.equal(ev.location.size, source.length);
  assert.equal(ev.sourceSha256, sha256(source));
  assert.equal(ev.location.asarIntegrity, "verified");
  const raw = readFileSync(archive).subarray(
    ev.location.offset,
    ev.location.offset + ev.location.size,
  );
  assert.deepEqual(raw, source);
  assert.equal(ev.artifact.sha256, sha256(readFileSync(archive)));
  const native = scan.components.find((c) => c.name === "native");
  assert.equal(native.evidence[0].location.kind, "asar-unpacked");
});

test("symbolic links are reported, not followed", () => {
  for (const target of [archive, app]) {
    const scan = scanOk(target);
    const linked = scan.unknowns.find((u) => u.name === "linked");
    assert.ok(linked, `linked unknown missing for ${target}`);
    assert.equal(linked.reason, "symbolic link not followed");
  }
});

test("tampered package.json is flagged by the ASAR integrity hash", () => {
  const bytes = Buffer.from(readFileSync(archive));
  const scan = scanOk(archive);
  const ev = scan.components.find((c) => c.name === "a").evidence[0];
  bytes[ev.location.offset + ev.location.size - 2] ^= 0x01; // keeps size, changes content
  const tampered = join(work, "tampered.asar");
  writeFileSync(tampered, bytes);
  const result = scanOk(tampered);
  const flagged = [...result.components, ...result.unknowns].find((c) =>
    c.evidence.some((e) => e.installPath === "node_modules/a"),
  );
  assert.equal(flagged.evidence[0].location.asarIntegrity, "mismatch");
  assert.ok(result.limitations.some((l) => l.includes("ASAR integrity")));
});

test("malformed ASAR headers fail closed", () => {
  const good = readFileSync(archive);
  const cases = {
    truncated: good.subarray(0, 40),
    "bad magic": Buffer.concat([Buffer.from([5, 0, 0, 0]), good.subarray(4)]),
    "header size beyond file": (() => {
      const b = Buffer.from(good.subarray(0, 64));
      b.writeUInt32LE(0xfffffff0, 4);
      return b;
    })(),
    "not JSON": (() => {
      const b = Buffer.from(good);
      b[17] = 0x00;
      return b;
    })(),
  };
  for (const [label, bytes] of Object.entries(cases)) {
    const file = join(work, `bad-${label.replaceAll(" ", "-")}.asar`);
    writeFileSync(file, bytes);
    const header = readAsarHeader(file);
    assert.equal(header.ok, false, label);
    const scan = scanArtifact(file);
    assert.equal(scan.ok, false, label);
  }
});

test("entry data outside the archive is an unknown, not a component", () => {
  const good = readFileSync(archive);
  const jsonLength = good.readUInt32LE(12);
  const header = JSON.parse(
    good.subarray(16, 16 + jsonLength).toString("utf8"),
  );
  header.files.node_modules.files.lodash.files["package.json"].offset =
    "999999999";
  const json = Buffer.from(JSON.stringify(header));
  // rebuild the pickle with the edited header, keeping the data section
  const padded = Buffer.alloc(Math.ceil(json.length / 4) * 4);
  json.copy(padded);
  const prefix = Buffer.alloc(16);
  prefix.writeUInt32LE(4, 0);
  prefix.writeUInt32LE(padded.length + 8, 4);
  prefix.writeUInt32LE(padded.length + 4, 8);
  prefix.writeUInt32LE(json.length, 12);
  const dataOffset = 8 + good.readUInt32LE(4);
  const file = join(work, "outside.asar");
  writeFileSync(
    file,
    Buffer.concat([prefix, padded, good.subarray(dataOffset)]),
  );
  const scan = scanOk(file);
  assert.ok(!ids(scan).includes("lodash@4.17.20"));
  const unknown = scan.unknowns.find((u) => u.name === "lodash");
  assert.match(unknown.reason, /outside the archive/);
  assert.ok(ids(scan).includes("lodash@3.10.1"));
});
