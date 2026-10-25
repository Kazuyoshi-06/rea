// .NET adapter: CLI metadata reader, deps.json path, assembly-attribute fallback, detection.
import assert from "node:assert/strict";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { versionFromAttributes } from "../lib/adapters/dotnet.mjs";
import { serializeBom, toCycloneDx } from "../lib/cyclonedx.mjs";
import { nugetPurl, parsePurl, pypiPurl } from "../lib/purl.mjs";
import { readCliAssembly } from "../lib/readers/cli-metadata.mjs";
import { scanArtifact } from "../lib/scan.mjs";
import {
  OUT,
  S3_DOTNET_FIXTURES,
  compareToTruth,
  fixtureGate,
  fixturePath,
  readTruth,
  schemaErrors,
} from "./support.mjs";

const scratch = mkdtempSync(join(tmpdir(), "sbom-dotnet-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

const gate = (t) => fixtureGate(t, S3_DOTNET_FIXTURES[1]);

/** Copy of a built fixture directory without any deps.json. */
function withoutDeps(id, name = `${id}-nodeps`) {
  const dir = join(scratch, name);
  cpSync(join(OUT, id), dir, {
    recursive: true,
    filter: (src) => !src.endsWith(".deps.json"),
  });
  return dir;
}

const summary = (scan) =>
  scan.components.map((c) => `${c.name}@${c.version}:${c.confidence}`);

test("purl: nuget keeps the published case; pypi is lowercased with _ → -", () => {
  assert.equal(
    nugetPurl("EnterpriseLibrary.Common", "6.0.1304").value,
    "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
  );
  assert.equal(
    nugetPurl("Serilog.Sinks.Console", "5.0.1-main-33be844").value,
    "pkg:nuget/Serilog.Sinks.Console@5.0.1-main-33be844",
  );
  assert.equal(
    nugetPurl("Foo", "1.0.0+meta").value,
    "pkg:nuget/Foo@1.0.0%2Bmeta",
  );
  assert.equal(
    pypiPurl("Django_package", "1.11.1.dev1").value,
    "pkg:pypi/django-package@1.11.1.dev1",
  );
  assert.equal(pypiPurl("PyYAML", "5.3.1").value, "pkg:pypi/pyyaml@5.3.1");
  assert.equal(
    pypiPurl("zope.interface", "6.0").value,
    "pkg:pypi/zope.interface@6.0",
  );
  assert.equal(nugetPurl("a/b", "1").ok, false);
  assert.equal(pypiPurl("", "1").ok, false);
  assert.deepEqual(parsePurl("pkg:nuget/Foo@1.0.0%2Bmeta").value, {
    type: "nuget",
    namespace: [],
    name: "Foo",
    version: "1.0.0+meta",
  });
});

test("attribute versions: build metadata dropped, pre-release and FileVersion downgraded, junk refused", () => {
  const attr = (value) => ({ value, offset: 1, size: 1, sourceSha256: "a" });
  let v = versionFromAttributes({
    informationalVersion: attr("12.0.1+509643a"),
  });
  assert.deepEqual(
    [v.version, v.confidence, v.attribute, v.rawValue, v.buildMetadata],
    [
      "12.0.1",
      "medium",
      "AssemblyInformationalVersion",
      "12.0.1+509643a",
      "509643a",
    ],
  );
  v = versionFromAttributes({
    informationalVersion: attr("3.1.1-main-999d686d+abc"),
  });
  assert.deepEqual([v.version, v.confidence], ["3.1.1-main-999d686d", "low"]);
  v = versionFromAttributes({ informationalVersion: attr("5.0") });
  assert.deepEqual(
    [v.version, v.confidence, v.buildMetadata],
    ["5.0", "medium", null],
  );
  // Not a version → next candidate, with the rejected value kept
  v = versionFromAttributes({
    informationalVersion: attr("Release build 7"),
    fileVersion: attr("1.2.3.0"),
  });
  assert.deepEqual(
    [v.version, v.confidence, v.attribute],
    ["1.2.3.0", "low", "AssemblyFileVersion"],
  );
  assert.deepEqual(v.rejected, [
    { attribute: "AssemblyInformationalVersion", rawValue: "Release build 7" },
  ]);
  v = versionFromAttributes({ informationalVersion: attr("+abc") });
  assert.match(v.reason, /not a NuGet-style version/);
  v = versionFromAttributes({});
  assert.match(
    v.reason,
    /no AssemblyInformationalVersion or AssemblyFileVersion/,
  );
  // AssemblyVersion is never a candidate
  v = versionFromAttributes({ assemblyVersion: attr("2.0.0.0") });
  assert.ok(v.reason);
});

test("CLI reader: assembly identity and version attributes of the built DLLs", (t) => {
  if (!gate(t)) return;
  const read = (id, file) => readCliAssembly(join(OUT, id, file)).value;
  const newtonsoft = read("dotnet-json", "Newtonsoft.Json.dll");
  assert.equal(newtonsoft.assembly.name, "Newtonsoft.Json");
  assert.equal(newtonsoft.assembly.version, "12.0.0.0");
  assert.equal(newtonsoft.entryPoint, false);
  assert.match(
    newtonsoft.attributes.informationalVersion.value,
    /^12\.0\.1\+[0-9a-f]{40}$/,
  );
  assert.equal(newtonsoft.attributes.fileVersion.value, "12.0.1.22727");
  const serilog = read("dotnet-serilog", "Serilog.dll");
  assert.equal(serilog.assembly.version, "2.0.0.0");
  assert.match(
    serilog.attributes.informationalVersion.value,
    /^3\.1\.1-main-999d686d\+/,
  );
  const sink = read("dotnet-serilog", "Serilog.Sinks.Console.dll");
  assert.equal(
    sink.attributes.informationalVersion.value,
    "5.0.1-main-33be844",
  );
  const app = read("dotnet-serilog", "dotnet-serilog.dll");
  assert.equal(app.entryPoint, true);
  // The offset points at the attribute value inside the file.
  const bytes = readFileSync(
    join(OUT, "dotnet-serilog", "Serilog.Sinks.Console.dll"),
  );
  const { offset, size } = sink.attributes.informationalVersion;
  assert.ok(
    bytes.subarray(offset, offset + size).includes("5.0.1-main-33be844"),
  );
});

test("CLI reader: corrupt and non-managed files give typed errors, never a guess", (t) => {
  if (!gate(t)) return;
  const original = readFileSync(
    join(OUT, "dotnet-serilog", "Serilog.Sinks.Console.dll"),
  );
  const write = (name, bytes) => {
    const path = join(scratch, name);
    writeFileSync(path, bytes);
    return path;
  };
  const tag = (path) => readCliAssembly(path).error?.tag;
  assert.equal(tag(write("text.dll", "hello")), "not-pe");
  assert.equal(tag(write("empty.dll", Buffer.alloc(0))), "not-pe");
  assert.equal(
    tag(write("short.dll", original.subarray(0, 200))),
    "malformed-cli-metadata",
  );
  // "BSJB" signature destroyed
  const noSig = Buffer.from(original);
  noSig.writeUInt32LE(0, noSig.indexOf(Buffer.from("BSJB")));
  assert.equal(tag(write("nosig.dll", noSig)), "malformed-cli-metadata");
  // Metadata cut in half
  assert.equal(
    tag(write("half.dll", original.subarray(0, original.length >> 1))),
    "malformed-cli-metadata",
  );
  // A PE file without CLI header (hand-built: MZ, PE32 optional header, no data directories)
  const pe = Buffer.alloc(0x200);
  pe.write("MZ", 0);
  pe.writeUInt32LE(0x80, 0x3c);
  pe.writeUInt32LE(0x4550, 0x80);
  pe.writeUInt16LE(0xe0, 0x80 + 20);
  pe.writeUInt16LE(0x10b, 0x80 + 24);
  const native = write("native.dll", pe);
  assert.equal(tag(native), "no-cli-header");
  const scan = scanArtifact(native);
  assert.equal(scan.error.tag, "unsupported-artifact");
});

test("deps.json path: exact NuGet id and version, sha512 in the evidence, high confidence", (t) => {
  for (const fx of S3_DOTNET_FIXTURES) {
    if (!fixtureGate(t, fx)) return;
    const scan = scanArtifact(fixturePath(fx));
    assert.ok(scan.ok, JSON.stringify(scan.error));
    const m = compareToTruth("nuget", scan.value.components, readTruth(fx.id));
    assert.equal(m.strict.precision, 1, `${fx.id} extra ${m.strict.extra}`);
    assert.equal(m.strict.recall, 1, `${fx.id} missing ${m.strict.missing}`);
    assert.deepEqual(scan.value.ecosystems, ["nuget"]);
    assert.equal(scan.value.root.name, fx.id);
    assert.equal(scan.value.root.version, "1.0.0");
    assert.deepEqual(scan.value.unknowns, []);
    for (const c of scan.value.components) {
      assert.equal(c.confidence, "high");
      assert.match(c.purl, /^pkg:nuget\//);
      const ev = c.evidence[0];
      assert.match(ev.nupkgSha512, /^sha512-[A-Za-z0-9+/=]{88}$/);
      assert.equal(ev.library, `${c.name}/${c.version}`);
      assert.equal(ev.location.path, `${fx.id}.deps.json`);
      assert.match(ev.sourceSha256, /^[0-9a-f]{64}$/);
    }
  }
});

test("fallback (no deps.json) is deterministic and its result is the measured one", (t) => {
  if (!gate(t)) return;
  const json = scanArtifact(withoutDeps("dotnet-json"));
  assert.ok(json.ok);
  assert.deepEqual(summary(json.value), ["Newtonsoft.Json@12.0.1:medium"]);
  assert.equal(json.value.root.name, "dotnet-json");
  const ev = json.value.components[0].evidence[0];
  assert.equal(ev.attribute, "AssemblyInformationalVersion");
  assert.match(ev.rawValue, /^12\.0\.1\+[0-9a-f]{40}$/);
  assert.match(ev.buildMetadata, /^[0-9a-f]{40}$/);
  assert.equal(ev.assemblyVersion, "12.0.0.0");
  assert.equal(ev.nameSource, "assembly-name");
  assert.equal(
    json.value.components[0].purl,
    "pkg:nuget/Newtonsoft.Json@12.0.1",
  );
  assert.ok(json.value.limitations.some((l) => /no usable deps\.json/.test(l)));

  // Serilog ships "3.1.1-main-999d686d": read literally, rated low, and wrong against NuGet.
  const serilog = scanArtifact(withoutDeps("dotnet-serilog"));
  assert.deepEqual(summary(serilog.value), [
    "Serilog@3.1.1-main-999d686d:low",
    "Serilog.Sinks.Console@5.0.1-main-33be844:low",
  ]);
  const m = compareToTruth(
    "nuget",
    serilog.value.components,
    readTruth("dotnet-serilog"),
  );
  assert.equal(m.strict.precision, 0);
  assert.equal(m.strict.recall, 0);

  const again = scanArtifact(withoutDeps("dotnet-serilog", "second"));
  assert.deepEqual(
    JSON.stringify(again.value.components.map((c) => c.version)),
    JSON.stringify(serilog.value.components.map((c) => c.version)),
  );
});

test("isolated DLL: a library is a component, an application is the scan root", (t) => {
  if (!gate(t)) return;
  const lib = scanArtifact(join(OUT, "dotnet-json", "Newtonsoft.Json.dll"));
  assert.ok(lib.ok);
  assert.deepEqual(lib.value.ecosystems, ["nuget"]);
  assert.deepEqual(summary(lib.value), ["Newtonsoft.Json@12.0.1:medium"]);
  assert.equal(lib.value.root, null);
  const app = scanArtifact(join(OUT, "dotnet-json", "dotnet-json.dll"));
  assert.deepEqual(app.value.components, []);
  assert.equal(app.value.root.name, "dotnet-json");
  assert.equal(app.value.root.version, "1.0.0");
});

// --- deps.json on synthetic directories ---------------------------------------------------

function publishDir(name, files) {
  const dir = join(scratch, name);
  mkdirSync(dir, { recursive: true });
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(
      join(dir, path),
      typeof content === "string" ? content : JSON.stringify(content),
    );
  }
  return dir;
}

test("deps.json: only type=package is a component; project, runtimepack and odd keys are not", () => {
  const dir = publishDir("synthetic", {
    "App.deps.json": {
      libraries: {
        "App/2.0.0": { type: "project", sha512: "" },
        "Other.Project/1.0.0": { type: "project" },
        "Newtonsoft.Json/13.0.3": {
          type: "package",
          sha512: "sha512-abc",
          path: "newtonsoft.json/13.0.3",
        },
        "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.1": {
          type: "runtimepack",
        },
        "Ref.Only/1.0.0": { type: "reference" },
        "NoVersionPackage/": { type: "package" },
        Weird: { type: "package" },
        "Dotted.Name.v2/1.0.0-rc.1+build": { type: "package" },
      },
    },
  });
  const scan = scanArtifact(dir);
  assert.ok(scan.ok);
  assert.deepEqual(
    summary(scan.value),
    ["Dotted.Name.v2@1.0.0-rc.1+build:high", "Newtonsoft.Json@13.0.3:high"],
    "version taken from the key verbatim, build metadata included",
  );
  assert.equal(scan.value.root.name, "App");
  assert.equal(scan.value.root.version, "2.0.0");
  assert.deepEqual(scan.value.unknowns.map((u) => u.name).sort(), [
    "NoVersionPackage/",
    "Weird",
  ]);
  assert.deepEqual(scan.value.exclusions.map((x) => x.name).sort(), [
    "Other.Project",
    "Ref.Only",
    "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64",
  ]);
  const nj = scan.value.components.find((c) => c.name === "Newtonsoft.Json");
  assert.equal(nj.evidence[0].nupkgSha512, "sha512-abc");
});

test("deps.json: same package in several files merges case-insensitively; broken files fall back", () => {
  const dir = publishDir("multi", {
    "a.deps.json": {
      libraries: {
        "Serilog/3.1.1": { type: "package", sha512: "sha512-x" },
        "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.1": {
          type: "runtimepack",
        },
      },
    },
    "plugins/b.deps.json": {
      libraries: {
        "serilog/3.1.1": { type: "package", sha512: "sha512-x" },
        "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.1": {
          type: "runtimepack",
        },
      },
    },
    "plugins/c.deps.json": {
      libraries: { "Serilog/2.0.0": { type: "package" } },
    },
  });
  const scan = scanArtifact(dir);
  assert.deepEqual(summary(scan.value), [
    "Serilog@2.0.0:high",
    "Serilog@3.1.1:high",
  ]);
  const merged = scan.value.components.find((c) => c.version === "3.1.1");
  assert.equal(merged.evidence.length, 2, "two locations, one component");
  assert.equal(
    scan.value.exclusions.length,
    1,
    "identical exclusions are listed once",
  );

  const broken = publishDir("broken", {
    "x.deps.json": "{ not json",
    "y.deps.json": "[]",
  });
  const result = scanArtifact(broken);
  assert.ok(result.ok);
  assert.deepEqual(result.value.components, []);
  assert.ok(
    result.value.limitations.some((l) => /x\.deps\.json: invalid JSON/.test(l)),
  );
  assert.ok(
    result.value.limitations.some((l) =>
      /y\.deps\.json: not a JSON object/.test(l),
    ),
  );
  assert.ok(
    result.value.limitations.some((l) => /no usable deps\.json/.test(l)),
  );
});

test("directory with both node_modules and a deps.json reports both ecosystems", () => {
  const dir = publishDir("both", {
    "App.deps.json": { libraries: { "Serilog/3.1.1": { type: "package" } } },
    "node_modules/left-pad/package.json": {
      name: "left-pad",
      version: "1.3.0",
    },
  });
  const scan = scanArtifact(dir);
  assert.deepEqual(scan.value.ecosystems, ["nuget", "npm"]);
  assert.deepEqual(scan.value.components.map((c) => c.ecosystem).sort(), [
    "npm",
    "nuget",
  ]);
});

// --- Export ------------------------------------------------------------------------------

test("CycloneDX: schema-valid, byte-identical across runs, confidence and technique mapped", (t) => {
  if (!gate(t)) return;
  const render = (path) =>
    serializeBom(
      toCycloneDx(scanArtifact(path).value, {
        timestamp: "2026-01-01T00:00:00Z",
      }),
    );
  for (const path of [
    fixturePath(S3_DOTNET_FIXTURES[1]),
    withoutDeps("dotnet-serilog", "export-nodeps"),
    join(OUT, "dotnet-json", "Newtonsoft.Json.dll"),
  ]) {
    const first = render(path);
    assert.equal(first, render(path), `${path}: two runs differ`);
    const bom = JSON.parse(first);
    assert.deepEqual(schemaErrors(bom), [], path);
  }
  const bom = JSON.parse(render(fixturePath(S3_DOTNET_FIXTURES[1])));
  const serilog = bom.components.find((c) => c.name === "Serilog");
  assert.equal(serilog.purl, "pkg:nuget/Serilog@3.1.1");
  assert.equal(
    serilog.evidence.identity[0].methods[0].technique,
    "manifest-analysis",
  );
  assert.equal(serilog.evidence.identity[0].confidence, 1);
  assert.ok(
    serilog.properties.some(
      (p) => p.name === "rea-sbom:confidence" && p.value === "high",
    ),
  );
  const fallback = JSON.parse(
    render(withoutDeps("dotnet-serilog", "export-nodeps")),
  );
  const low = fallback.components.find((c) => c.name === "Serilog");
  assert.equal(
    low.evidence.identity[0].methods[0].technique,
    "binary-analysis",
  );
  assert.equal(low.evidence.identity[0].confidence, 0.3);
});
