// PyInstaller adapter: marshal reader, bytecode bindings, archive reader and the PyPI adapter,
// on CPython-compiled snippets, synthetic archives (test/support/make_pyinstaller.py) and the
// built py-* fixtures.
import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { scanPyInstaller } from "../lib/adapters/pyinstaller.mjs";
import { moduleBindings } from "../lib/readers/pybytecode.mjs";
import { MarshalError, readMarshal } from "../lib/readers/marshal.mjs";
import { openPyInstaller, openPyz } from "../lib/readers/pyinstaller.mjs";
import { scanArtifact } from "../lib/scan.mjs";
import {
  S3_PYTHON_FIXTURES,
  compareToTruth,
  fixtureGate,
  fixturePath,
  readTruth,
} from "./support.mjs";
import { buildPyInstaller, python, requirePython313 } from "./support/py.mjs";

const scratch = mkdtempSync(join(tmpdir(), "sbom-pyi-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

/** marshal.dumps(<python expression>) as a Buffer, using the system python3. */
function marshalOf(expression) {
  const res = python([
    "-c",
    `import marshal,sys;sys.stdout.buffer.write(marshal.dumps(${expression}))`,
  ]);
  assert.equal(res.status, 0, res.stderr.toString());
  return res.stdout;
}

test("marshal: scalars, containers, references and big integers match CPython", (t) => {
  if (!requirePython313(t)) return;
  const read = (expression) => readMarshal(marshalOf(expression)).value;
  assert.equal(read("None"), null);
  assert.equal(read("True"), true);
  assert.equal(read("-5"), -5);
  assert.equal(read("2**40"), 2 ** 40);
  assert.equal(read("2**70"), 2n ** 70n);
  assert.equal(read("-(2**70)"), -(2n ** 70n));
  assert.equal(read("1.5"), 1.5);
  assert.equal(read("'héllo'"), "héllo");
  assert.equal(read("'ascii'"), "ascii");
  assert.deepEqual([...read("b'xy'")], [0x78, 0x79]);
  assert.deepEqual(read("(1, ('a', 'b'), [2, 3])"), [1, ["a", "b"], [2, 3]]);
  assert.deepEqual(read("tuple(range(300))").length, 300);
  assert.deepEqual(
    [...read("{'k': 'v', 1: (2,)}").entries()],
    [
      ["k", "v"],
      [1, [2]],
    ],
  );
  assert.deepEqual([...read("frozenset({7})")], [7]);
  // The same string object twice becomes a FLAG_REF + TYPE_REF pair.
  const shared = read("(lambda s: (s, s, s))('x' * 3 + 'yz')");
  assert.deepEqual(shared, ["xxxyz", "xxxyz", "xxxyz"]);
  // A tuple referenced twice (container refs are reserved before their children).
  const tuple = read("(lambda t: ([t, t], t))((1, (2, 3)))");
  assert.deepEqual(tuple, [
    [
      [1, [2, 3]],
      [1, [2, 3]],
    ],
    [1, [2, 3]],
  ]);
});

test("marshal: code objects expose consts, names and the instruction bytes", (t) => {
  if (!requirePython313(t)) return;
  const code = readMarshal(
    marshalOf(`compile("__version__ = '1.2.3'\\nx = 2", "m", "exec")`),
  ).value;
  assert.equal(code.kind, "code");
  assert.deepEqual(code.names, ["__version__", "x"]);
  assert.ok(code.consts.includes("1.2.3"));
  assert.ok(Buffer.isBuffer(code.code));
});

test("marshal: truncated, unknown and hostile inputs fail with MarshalError", () => {
  const cases = {
    truncated: Buffer.from("(\x02\x00\x00\x00i\x01\x00\x00\x00", "latin1"),
    "unknown type": Buffer.from("Q", "latin1"),
    "count beyond data": Buffer.from("(\xff\xff\xff\x7f", "latin1"),
    "dangling reference": Buffer.from("r\x05\x00\x00\x00", "latin1"),
    "NULL object": Buffer.from("0", "latin1"),
    empty: Buffer.alloc(0),
  };
  for (const [name, bytes] of Object.entries(cases))
    assert.throws(() => readMarshal(bytes), MarshalError, name);
  const nested = Buffer.from("(\x01\x00\x00\x00".repeat(600) + "N", "latin1");
  assert.throws(() => readMarshal(nested), /nesting too deep/);
});

function bindingsOf(source) {
  const code = readMarshal(
    marshalOf(
      `compile(${JSON.stringify(source)}, "m", "exec", dont_inherit=True)`,
    ),
  ).value;
  return moduleBindings(code);
}

test("bytecode bindings: constants, chains, imports, self-assignment, EXTENDED_ARG", (t) => {
  if (!requirePython313(t)) return;
  let b = bindingsOf("__version__ = '1.0'");
  assert.deepEqual(b.get("__version__"), [{ kind: "const", value: "1.0" }]);

  b = bindingsOf("__version__ = version = VERSION = '2.0'");
  for (const name of ["__version__", "version", "VERSION"])
    assert.deepEqual(b.get(name), [{ kind: "const", value: "2.0" }], name);

  b = bindingsOf("a = b = c = 7");
  for (const name of "abc")
    assert.deepEqual(b.get(name), [{ kind: "const", value: 7 }], name);

  b = bindingsOf("from ._version import __version__, other as renamed");
  assert.deepEqual(b.get("__version__"), [
    {
      kind: "import-from",
      level: 1,
      module: "_version",
      imported: "__version__",
    },
  ]);
  assert.deepEqual(b.get("renamed"), [
    { kind: "import-from", level: 1, module: "_version", imported: "other" },
  ]);

  b = bindingsOf("from x import y\nfrom ..up import z");
  assert.equal(b.get("y")[0].level, 0);
  assert.deepEqual(b.get("z")[0], {
    kind: "import-from",
    level: 2,
    module: "up",
    imported: "z",
  });

  // urllib3: the second statement rebinds the value the name already has; it is no binding.
  b = bindingsOf(
    "from ._version import __version__\n__version__ = __version__",
  );
  assert.equal(b.get("__version__").length, 1);

  b = bindingsOf("__version__ = compute()");
  assert.deepEqual(b.get("__version__"), [{ kind: "other" }]);
  b = bindingsOf("a, b = 1, 2");
  assert.deepEqual(b.get("b"), [{ kind: "other" }]);
  b = bindingsOf("import foo as __version__");
  assert.deepEqual(b.get("__version__"), [{ kind: "other" }]);
  b = bindingsOf(
    "def f():\n    __version__ = '9'\nclass C:\n    version = '8'",
  );
  assert.equal(
    b.has("__version__"),
    false,
    "nested code objects are not entered",
  );
  assert.equal(b.has("version"), false);

  const many = Array.from({ length: 300 }, (_, i) => `_c${i} = 'x${i}'`);
  b = bindingsOf([...many, "__version__ = '3.4.5'"].join("\n"));
  assert.deepEqual(b.get("__version__"), [{ kind: "const", value: "3.4.5" }]);
});

// --- Synthetic archives -------------------------------------------------------------------

const PKG = (source) => ({ source, ispkg: true });
const MODULES = {
  // Direct constant in the root module
  yaml: PKG("__version__ = '6.0.1'"),
  // from .sub import name chain (requests / idna / urllib3 shapes)
  requests: PKG("from .__version__ import __title__, __version__"),
  "requests.__version__": {
    source: "__title__ = 'requests'\n__version__ = '2.31.0'",
  },
  idna: PKG("from .package_data import __version__"),
  "idna.package_data": { source: "__version__ = '3.4'" },
  urllib3: PKG("from ._version import __version__\n__version__ = __version__"),
  "urllib3._version": { source: "__version__ = '1.26.17'" },
  // chain through a dotted submodule
  numpy: PKG("from .core.ver import __version__"),
  "numpy.core": PKG("pass"),
  "numpy.core.ver": { source: "__version__ = '1.26.4'" },
  // chained assignment
  jinja2: PKG("__version__ = version = '3.1.2'"),
  // try/except fallback: two bindings, one of them computed
  certifi: PKG(
    "try:\n    from importlib.metadata import version as _v\n    __version__ = _v('certifi')\nexcept Exception:\n    __version__ = '0.0.0'",
  ),
  // `version` is importlib's function: outside the package, ignored; __version__ is a constant
  click: PKG("from importlib.metadata import version\n__version__ = '8.1.7'"),
  // conflicting constants
  six: PKG("version = '1.0'\n__version__ = '1.1'"),
  // not PEP 440
  flask: PKG("__version__ = 'unknown'"),
  // placeholder left by a version script (setuptools: "0.dev0+unknown")
  markupsafe: PKG("__version__ = '0.dev0+unknown'"),
  // non-string constant
  pandas: PKG("__version__ = (1, 2)"),
  // relative import escaping the package
  scipy: PKG("from ..other import __version__"),
  // not in the module table: reported as a module, never with a distribution name
  mystery: PKG("__version__ = '9.9.9'"),
  // stdlib and runtime modules
  json: PKG("__version__ = '2.0.9'"),
  pyimod01_archive: { source: "x = 1" },
  // no version at all
  attr: PKG("x = 1"),
};

function syntheticSpec(output, overrides = {}) {
  return {
    output,
    entries: [],
    modules: Object.entries(MODULES).map(([name, m]) => ({
      name,
      source: m.source,
      ispkg: m.ispkg === true,
    })),
    ...overrides,
  };
}

function scanSynthetic(name, overrides) {
  const output = join(scratch, name);
  buildPyInstaller(syntheticSpec(output, overrides));
  const artifact = {
    path: output,
    sha256: "0".repeat(64),
    bytes: statSync(output).size,
  };
  return scanPyInstaller(artifact);
}

const byName = (list) => new Map(list.map((x) => [x.name, x]));

test("bytecode path: versions only from a single literal constant, reasons otherwise", (t) => {
  if (!requirePython313(t)) return;
  const res = scanSynthetic("bytecode.bin");
  assert.ok(res.ok, JSON.stringify(res.error));
  const components = byName(res.value.components);
  const unknowns = byName(res.value.unknowns);
  const versions = Object.fromEntries(
    [...components.values()].map((c) => [c.name, c.version]),
  );
  assert.deepEqual(versions, {
    Jinja2: "3.1.2",
    PyYAML: "6.0.1",
    click: "8.1.7",
    idna: "3.4",
    numpy: "1.26.4",
    requests: "2.31.0",
    urllib3: "1.26.17",
  });
  for (const c of components.values()) {
    assert.equal(c.confidence, "low", c.name);
    assert.equal(c.evidence[0].distributionNameSource, "static-table");
  }
  const chain = components.get("requests").evidence[0];
  assert.equal(chain.constant, "__version__");
  assert.deepEqual(chain.resolvedThrough, [
    "requests:__version__",
    "requests.__version__:__version__",
  ]);
  assert.equal(chain.location.path, "requests.__version__");

  // Everything else is an unknown with a reason, and no version is emitted for it.
  assert.match(unknowns.get("certifi").reason, /2 bindings/);
  assert.match(unknowns.get("six").reason, /conflicting constants/);
  assert.match(unknowns.get("pandas").reason, /non-string constant/);
  assert.match(unknowns.get("scipy").reason, /outside the package/);
  assert.match(unknowns.get("attrs").reason, /not bound/);
  // The module table has no entry for "mystery": the name stays the module name.
  const mystery = unknowns.get("mystery");
  assert.match(mystery.reason, /not in the module table/);
  assert.equal(mystery.evidence[0].distributionNameSource, "none");
  assert.deepEqual(mystery.evidence[0].observedLiteral, {
    module: "mystery",
    constant: "__version__",
    value: "9.9.9",
  });
  // stdlib (json) is silently out; the PyInstaller runtime module is an exclusion.
  assert.equal(components.has("json") || unknowns.has("json"), false);
  assert.deepEqual(
    res.value.exclusions.map((x) => x.name),
    ["pyimod01_archive"],
  );
  assert.equal(
    [...components.values()].some((c) => c.version === "0.0.0"),
    false,
  );
});

test("flask: a non-PEP-440 constant is an unknown that keeps the observed literal as evidence only", (t) => {
  if (!requirePython313(t)) return;
  const res = scanSynthetic("pep440.bin");
  const flask = byName(res.value.unknowns).get("Flask");
  assert.ok(flask, "mapped module keeps its distribution name");
  assert.match(flask.reason, /not a PEP 440 version/);
  assert.equal(flask.evidence[0].observedLiteral.value, "unknown");
  assert.equal(byName(res.value.components).has("Flask"), false);
});

test("placeholder constants are refused, and a dist-info of the mapped distribution covers its module", (t) => {
  if (!requirePython313(t)) return;
  const res = scanSynthetic("placeholder.bin", {
    entries: [
      // `attr` maps to "attrs"; the dist-info has no top_level.txt and its name differs from the module's
      {
        name: "attrs-23.1.0.dist-info/METADATA",
        type: "x",
        text: "Name: attrs\nVersion: 23.1.0\n",
      },
    ],
  });
  const markupsafe = byName(res.value.unknowns).get("MarkupSafe");
  assert.match(markupsafe.reason, /placeholder/);
  assert.equal(markupsafe.evidence[0].observedLiteral.value, "0.dev0+unknown");
  assert.equal(byName(res.value.components).has("MarkupSafe"), false);
  assert.equal(byName(res.value.components).get("attrs").confidence, "high");
  assert.equal(
    byName(res.value.unknowns).has("attrs"),
    false,
    "no duplicate unknown for attrs",
  );
});

test("dist-info path: Name and Version from METADATA, high confidence, covers its modules", (t) => {
  if (!requirePython313(t)) return;
  const res = scanSynthetic("distinfo.bin", {
    entries: [
      {
        name: "Foo_Bar-1.0.dist-info/METADATA",
        type: "x",
        text: "Metadata-Version: 2.1\nName: Foo_Bar\nVersion: 1.0\nSummary: x\n\nVersion: 99\n",
        compress: true,
      },
      {
        name: "Foo_Bar-1.0.dist-info/top_level.txt",
        type: "x",
        text: "mystery\n",
        compress: false,
      },
      {
        name: "broken-2.0.dist-info/METADATA",
        type: "x",
        text: "Name: broken\n\n",
      },
      // not METADATA of a dist-info at the archive root: ignored
      {
        name: "pkg/x.dist-info/METADATA",
        type: "x",
        text: "Name: no\nVersion: 1\n",
      },
    ],
  });
  assert.ok(res.ok);
  const foo = res.value.components.find((c) => c.name === "Foo_Bar");
  assert.equal(foo.version, "1.0");
  assert.equal(foo.purl, "pkg:pypi/foo-bar@1.0");
  assert.equal(foo.confidence, "high");
  assert.equal(foo.evidence[0].distInfo, "Foo_Bar-1.0.dist-info");
  assert.match(foo.evidence[0].sourceSha256, /^[0-9a-f]{64}$/);
  const broken = res.value.unknowns.find((u) => u.name === "broken");
  assert.match(broken.reason, /no Version header/);
  assert.equal(
    res.value.components.some((c) => c.name === "no"),
    false,
  );
  // top_level.txt lists "mystery": the module no longer produces an unknown.
  assert.equal(
    res.value.unknowns.some((u) => u.name === "mystery"),
    false,
  );
});

test("unsupported bytecode: a .pyc magic that is not 3.13 is reported, dist-info still read", (t) => {
  if (!requirePython313(t)) return;
  const res = scanSynthetic("magic.bin", {
    pyc_magic: "cb0d0d0a", // 3531: Python 3.12
    entries: [
      {
        name: "a-1.dist-info/METADATA",
        type: "x",
        text: "Name: a\nVersion: 1\n",
      },
    ],
  });
  assert.ok(res.ok);
  assert.deepEqual(
    res.value.components.map((c) => c.name),
    ["a"],
  );
  assert.deepEqual(res.value.unknowns, []);
  assert.ok(
    res.value.limitations.some((l) =>
      /unsupported-python-bytecode.*3531/.test(l),
    ),
    res.value.limitations.join("\n"),
  );
  const output = join(scratch, "magic.bin");
  const archive = openPyInstaller(output, statSync(output).size).value;
  const pyz = openPyz(
    archive,
    archive.entries.find((e) => e.type === "z"),
  );
  assert.equal(pyz.error.tag, "unsupported-python-bytecode");
  assert.equal(pyz.error.details.magic, 3531);
});

test("no recorded stdlib list for the archive's Python: modules are not examined", (t) => {
  if (!requirePython313(t)) return;
  const res = scanSynthetic("py312.bin", { pyvers: 312 });
  assert.ok(res.ok);
  assert.deepEqual(res.value.components, []);
  assert.deepEqual(res.value.unknowns, []);
  assert.ok(
    res.value.limitations.some((l) =>
      /no standard-library module list recorded for Python 3\.12/.test(l),
    ),
  );
});

test("archive reader: trailing bytes after the cookie, bootloader copies of the magic, corrupt TOC", (t) => {
  if (!requirePython313(t)) return;
  const entries = [
    {
      name: "a-1.dist-info/METADATA",
      type: "x",
      text: "Name: a\nVersion: 1\n",
    },
  ];
  const trailing = Buffer.alloc(5000, 0x41).toString("base64");
  const res = scanSynthetic("trailing.bin", {
    entries,
    trailing_b64: trailing,
  });
  assert.ok(
    res.value.components.some((c) => `${c.name}@${c.version}` === "a@1"),
  );

  // Corrupt the TOC length in the cookie: no consistent cookie remains.
  const plain = join(scratch, "plain.bin");
  buildPyInstaller(syntheticSpec(plain, { entries }));
  const bytes = Buffer.from(readFileSync(plain));
  bytes.writeUInt32BE(0x7fffffff, bytes.length - 88 + 16);
  const broken = join(scratch, "broken.bin");
  writeFileSync(broken, bytes);
  const opened = openPyInstaller(broken, bytes.length);
  assert.equal(opened.error.tag, "no-pyinstaller-cookie");

  // A TOC entry pointing outside the package.
  const lies = Buffer.from(readFileSync(plain));
  const tocOffset = lies.readUInt32BE(lies.length - 88 + 12);
  const start = lies.length - lies.readUInt32BE(lies.length - 88 + 8);
  lies.writeUInt32BE(0x00ffffff, start + tocOffset + 8); // compressed length of entry 0
  writeFileSync(join(scratch, "lies.bin"), lies);
  const lied = openPyInstaller(join(scratch, "lies.bin"), lies.length);
  assert.equal(lied.error.tag, "malformed-pyinstaller-archive");
});

test("scanArtifact detects a PyInstaller file by its cookie and fails cleanly on a fake marker", (t) => {
  if (!requirePython313(t)) return;
  const output = join(scratch, "detect.bin");
  buildPyInstaller(syntheticSpec(output));
  const scan = scanArtifact(output);
  assert.ok(scan.ok);
  assert.deepEqual(scan.value.ecosystems, ["pypi"]);
  assert.ok(scan.value.components.length > 0);

  const fake = join(scratch, "fake.bin");
  writeFileSync(
    fake,
    Buffer.concat([
      Buffer.from("junk"),
      Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]),
      Buffer.alloc(200),
    ]),
  );
  const result = scanArtifact(fake);
  assert.equal(result.ok, false);
  assert.equal(result.error.tag, "no-pyinstaller-cookie");
});

// --- Built fixtures -----------------------------------------------------------------------

for (const fx of S3_PYTHON_FIXTURES) {
  test(`${fx.id}: versions are never invented; ${fx.id === "py-requests-meta" ? "100% from dist-info" : "bytecode spike"}`, (t) => {
    if (!fixtureGate(t, fx)) return;
    const path = fixturePath(fx);
    const scan = scanArtifact(path);
    assert.ok(scan.ok, JSON.stringify(scan.error));
    const truth = readTruth(fx.id);
    const m = compareToTruth("pypi", scan.value.components, truth);
    // Zero invented versions: every emitted version is the truth's, up to PEP 440 spelling.
    assert.deepEqual(
      m.equivalent.extra,
      [],
      `${fx.id}: extra ${m.equivalent.extra}`,
    );
    if (fx.id === "py-requests-meta") {
      assert.equal(m.strict.precision, 1);
      assert.equal(m.strict.recall, 1);
      for (const c of scan.value.components) assert.equal(c.confidence, "high");
      assert.deepEqual(scan.value.unknowns, []);
    } else {
      assert.equal(
        m.equivalent.recall,
        1,
        `${fx.id}: missing ${m.equivalent.missing}`,
      );
      for (const c of scan.value.components) assert.equal(c.confidence, "low");
    }
    if (fx.id === "py-requests") {
      // certifi spells its version "2023.07.22" in code; pip freeze says "2023.7.22".
      const certifi = scan.value.components.find((c) => c.name === "certifi");
      assert.equal(certifi.version, "2023.07.22");
      assert.equal(m.strict.precision, 0.8);
    }
    if (fx.id === "py-yaml") {
      assert.equal(m.strict.precision, 1);
      assert.equal(scan.value.components[0].name, "PyYAML");
    }
  });
}
