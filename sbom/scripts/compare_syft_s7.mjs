#!/usr/bin/env node
// S7 A2/A3: sbom-scan and syft (CycloneDX JSON) on the same artifacts, both against the ground
// truth already used by S1–S6:
//   corpus fixtures   truth/<id>.json (go version -m, cargo tree, lockfiles, dotnet list package,
//                     pip freeze of the source venv; TRUTH_RULES.md)
//   real Go binaries  `go version -m` (deps, replacement applied, no version-less replacement)
//   real Rust         `rust-audit-info` (packages minus the root and kind=build)
// Identity = (ecosystem, name, version), exact version string; names compared by the ecosystem's
// rule (NuGet case-insensitive, PyPI PEP 503). Runtimes are not counted for either tool
// (TRUTH_RULES): our role=language-runtime components and syft's pkg:golang/stdlib. Components
// syft emits outside the artifact's ecosystem (other purl types, no purl) are listed apart and
// are not part of the precision of that ecosystem.
// Group "variant" (informative, not the shipped artifact): .NET publish directories without their
// deps.json (assembly metadata only, as in S3), and the npm staging directory that app.asar packs
// (node_modules + package-lock.json), a form syft reads, unlike ASAR.
// syft runs offline: SYFT_CHECK_FOR_APP_UPDATE=false, no registry lookups (its defaults).
// Writes s7/compare.json; prints one line per artifact.
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  rmSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { scanArtifact } from "../lib/scan.mjs";
import { goVersionM, run } from "./real_binaries.mjs";

const SBOM = join(import.meta.dirname, "..");
const OUT = join(SBOM, "corpus/out");
const WORK = join(SBOM, ".work");
export const SYFT = process.env.SYFT ?? join(WORK, "s7/tools/syft");
export const SYFT_ENV = {
  ...process.env,
  SYFT_CHECK_FOR_APP_UPDATE: "false",
};

const corpus = (id, ecosystem, artifact) => ({
  id,
  ecosystem,
  group: "corpus",
  path: join(OUT, id, artifact),
  truth: "truth",
});
const CROSS = ["windows-amd64", "darwin-arm64", "linux-s390x"];

/** Copy of a .NET publish directory without its *.deps.json (rebuilt on every run). */
function withoutDeps(id) {
  const dir = join(WORK, "s7", `${id}-nodeps`);
  rmSync(dir, { recursive: true, force: true });
  cpSync(join(OUT, id), dir, {
    recursive: true,
    filter: (src) => !src.endsWith(".deps.json"),
  });
  return dir;
}
const variant = (id, truthId, ecosystem, path, prepare = null) => ({
  id,
  truthId,
  ecosystem,
  group: "variant",
  path,
  prepare,
  truth: "truth",
});

export const ARTIFACTS = [
  corpus("go-uuid", "golang", "go-uuid"),
  corpus("go-uuid-stripped", "golang", "go-uuid"),
  corpus("go-jwt", "golang", "go-jwt"),
  corpus("go-jwt-stripped", "golang", "go-jwt"),
  corpus("rust-small", "cargo", "rust-small"),
  corpus("rust-vuln", "cargo", "rust-vuln"),
  corpus("npm-electron", "npm", "app.asar"),
  corpus("npm-cli", "npm", "app.asar"),
  corpus("dotnet-json", "nuget", ""),
  corpus("dotnet-serilog", "nuget", ""),
  corpus("py-requests", "pypi", "py-requests"),
  corpus("py-requests-meta", "pypi", "py-requests-meta"),
  corpus("py-yaml", "pypi", "py-yaml"),
  ...["stringer", "yq", "prometheus", "terraform"].map((id) => ({
    id,
    ecosystem: "golang",
    group: "real",
    path: join(WORK, "real/go", id),
    truth: "go",
  })),
  ...[
    ["ripgrep", "rg"],
    ["fd", "fd"],
  ].map(([id, bin]) => ({
    id,
    ecosystem: "cargo",
    group: "real",
    path: join(WORK, "real/cargo/bin", bin),
    truth: "rust",
  })),
  ...["dotnet-json", "dotnet-serilog"].map((id) =>
    variant(`${id}-nodeps`, id, "nuget", join(WORK, "s7", `${id}-nodeps`), () =>
      withoutDeps(id),
    ),
  ),
  ...["npm-electron", "npm-cli"].map((id) =>
    variant(`${id}-staged`, id, "npm", join(WORK, `stage-${id}`)),
  ),
  ...CROSS.flatMap((target) =>
    ["stringer", "stringer-stripped", "yq", "prometheus"].map((tool) => ({
      id: `${tool} ${target.replace("-", "/")}`,
      ecosystem: "golang",
      group: "cross",
      path: join(
        WORK,
        "cross",
        target,
        `${tool}${target.startsWith("windows") ? ".exe" : ""}`,
      ),
      truth: "go",
    })),
  ),
];

const NAME_KEY = {
  nuget: (n) => n.toLowerCase(),
  pypi: (n) => n.toLowerCase().replace(/[-_.]+/g, "-"),
};
const key = (ecosystem, name, version) =>
  `${(NAME_KEY[ecosystem] ?? ((n) => n))(name)}@${version}`;

function truthSet(a) {
  if (a.truth === "truth") {
    const rows = JSON.parse(
      readFileSync(join(SBOM, "truth", `${a.truthId ?? a.id}.json`), "utf8"),
    );
    return new Set(
      rows
        .filter((r) => r.ecosystem === a.ecosystem)
        .map((r) => key(a.ecosystem, r.name, r.version)),
    );
  }
  if (a.truth === "go")
    return new Set(
      goVersionM(a.path)
        .dependencies.map((d) => d.replacement ?? d)
        .filter((m) => m.version !== "" && m.version !== "(devel)")
        .map((m) => key("golang", m.path, m.version)),
    );
  const rai = join(WORK, "real/cargo/bin/rust-audit-info");
  const doc = JSON.parse(run(rai, [a.path]));
  return new Set(
    doc.packages
      .filter((p) => p.root !== true && p.kind !== "build")
      .map((p) => key("cargo", p.name, p.version)),
  );
}

/**
 * Facts used to explain differences: the root component's name (main module, root crate,
 * application assembly or package) and, for Go, the modules replaced by a local directory
 * (no version in the build information).
 */
function rootFacts(a) {
  if (a.ecosystem === "golang") {
    const info = goVersionM(a.path);
    const local = info.dependencies
      .filter(
        (d) =>
          d.replacement !== null &&
          (d.replacement.version === "" || d.replacement.version === "(devel)"),
      )
      .map((d) => d.path);
    return { root: info.main?.path ?? null, local: new Set(local) };
  }
  if (a.ecosystem === "cargo") {
    const rai = join(WORK, "real/cargo/bin/rust-audit-info");
    const doc = JSON.parse(run(rai, [a.path]));
    return {
      root: doc.packages.find((p) => p.root === true)?.name ?? null,
      local: new Set(),
    };
  }
  // .NET application assembly and npm root package are named after the fixture.
  if (a.ecosystem === "nuget" || a.ecosystem === "npm")
    return { root: a.truthId ?? a.id, local: new Set() };
  return { root: null, local: new Set() };
}

const nameOf = (k) => k.slice(0, k.lastIndexOf("@"));

/** Cause of each extra / missing key (TRUTH_RULES identity), from the facts above. */
function causes(m, facts, ecosystem, unknownNames = new Set()) {
  const root = facts.root === null ? null : key(ecosystem, facts.root, "");
  const rootName = root === null ? null : nameOf(root);
  const foundNames = new Set(m.found === 0 ? [] : m.extra.map(nameOf));
  const truthNames = new Set(m.missing.map(nameOf));
  const extra = m.extra.map((k) => {
    const n = nameOf(k);
    if (n === rootName) return [k, "root component emitted"];
    if (facts.local.has(n))
      return [k, "local-directory replacement, no version"];
    if (truthNames.has(n)) return [k, "version differs from the truth"];
    return [k, "not in the truth"];
  });
  const missing = m.missing.map((k) => {
    if (unknownNames.has(nameOf(k)))
      return [k, "reported as unknown (version not trusted)"];
    if (m.found === 0) return [k, "nothing found in this ecosystem"];
    if (foundNames.has(nameOf(k))) return [k, "version differs from the truth"];
    return [k, "not found"];
  });
  return {
    extra: Object.fromEntries(extra),
    missing: Object.fromEntries(missing),
  };
}

function ours(a) {
  const scan = scanArtifact(a.path);
  if (!scan.ok) return { error: `${scan.error.tag}: ${scan.error.message}` };
  const lib = scan.value.components.filter((c) => c.role === "library");
  return {
    found: new Set(
      lib
        .filter((c) => c.ecosystem === a.ecosystem)
        .map((c) => key(a.ecosystem, c.name, c.version)),
    ),
    other: lib
      .filter((c) => c.ecosystem !== a.ecosystem)
      .map((c) => `${c.ecosystem}:${c.name}@${c.version}`),
    runtime: scan.value.components
      .filter((c) => c.role !== "library")
      .map((c) => `${c.name}@${c.version}`),
    unknowns: scan.value.unknowns.map((u) => `${u.name}: ${u.reason}`),
    unknownNames: new Set(
      scan.value.unknowns.map((u) => key(a.ecosystem, u.name, "").slice(0, -1)),
    ),
    exclusions: scan.value.exclusions.length,
  };
}

const PURL_TYPE = {
  golang: "golang",
  cargo: "cargo",
  npm: "npm",
  nuget: "nuget",
  pypi: "pypi",
};

/** pkg:type/namespace/name@version?qualifiers → {type, name, version} (name with namespace). */
export function parsePurl(purl) {
  const m = /^pkg:([^/]+)\/([^@?#]+)(?:@([^?#]*))?/.exec(purl);
  if (m === null) return null;
  const name = m[2].split("/").map(decodeURIComponent).join("/");
  return {
    type: m[1],
    name,
    version: m[3] === undefined ? null : decodeURIComponent(m[3]),
  };
}

/** syft's source argument: directories are dir:, everything else file:. */
export const syftSource = (path) =>
  `${statSync(path).isDirectory() ? "dir" : "file"}:${path}`;

function syft(a) {
  const res = spawnSync(
    SYFT,
    ["scan", syftSource(a.path), "-o", "cyclonedx-json", "-q"],
    { env: SYFT_ENV, maxBuffer: 512 << 20 },
  );
  if (res.status !== 0)
    return {
      error: `exit ${res.status}: ${res.stderr.toString().slice(-400)}`,
    };
  const bom = JSON.parse(res.stdout.toString("utf8"));
  const found = new Set();
  const other = [];
  const runtime = [];
  const raw = [];
  for (const c of bom.components ?? []) {
    if (c.type === "file") continue;
    const p = c.purl ? parsePurl(c.purl) : null;
    raw.push({
      name: c.name,
      version: c.version ?? null,
      purl: c.purl ?? null,
    });
    if (p === null || p.type !== PURL_TYPE[a.ecosystem]) {
      other.push(c.purl ?? `${c.type}:${c.name}@${c.version ?? ""}`);
      continue;
    }
    if (a.ecosystem === "golang" && p.name === "stdlib") {
      runtime.push(`${p.name}@${p.version}`);
      continue;
    }
    found.add(key(a.ecosystem, p.name, p.version ?? ""));
  }
  return { found, other, runtime, raw, specVersion: bom.specVersion };
}

function measure(found, truth) {
  const tp = [...found].filter((k) => truth.has(k));
  return {
    found: found.size,
    truth: truth.size,
    truePositives: tp.length,
    precision: found.size === 0 ? null : tp.length / found.size,
    recall: truth.size === 0 ? null : tp.length / truth.size,
    extra: [...found].filter((k) => !truth.has(k)).sort(),
    missing: [...truth].filter((k) => !found.has(k)).sort(),
  };
}

const withCauses = (m, facts, ecosystem, unknownNames) => ({
  ...m,
  causes: causes(m, facts, ecosystem, unknownNames),
});

const LABELS = {
  golang: "Go",
  cargo: "Rust (cargo-auditable)",
  npm: "npm (ASAR)",
  nuget: ".NET (publish directory)",
  pypi: "PyInstaller onefile",
};
const VARIANT_LABELS = {
  nuget: ".NET without deps.json",
  npm: "npm staging directory (not ASAR)",
};

/** Micro-averaged precision / recall per ecosystem, and syft without its root components. */
export function summarize(results) {
  const rows = new Map();
  for (const r of results) {
    if (r.status) continue;
    const label =
      r.group === "variant" ? VARIANT_LABELS[r.ecosystem] : LABELS[r.ecosystem];
    if (!rows.has(label))
      rows.set(label, {
        label,
        artifacts: 0,
        truth: 0,
        ours: { found: 0, tp: 0 },
        syft: { found: 0, tp: 0, roots: 0 },
      });
    const row = rows.get(label);
    row.artifacts += 1;
    row.truth += r.ours.truth;
    for (const tool of ["ours", "syft"]) {
      row[tool].found += r[tool].found;
      row[tool].tp += r[tool].truePositives;
    }
    row.syft.roots += Object.values(r.syft.causes.extra).filter(
      (c) => c === "root component emitted",
    ).length;
  }
  const ratio = (a, b) => (b === 0 ? null : a / b);
  return [...rows.values()].map((row) => ({
    ...row,
    ours: {
      ...row.ours,
      precision: ratio(row.ours.tp, row.ours.found),
      recall: ratio(row.ours.tp, row.truth),
    },
    syft: {
      ...row.syft,
      precision: ratio(row.syft.tp, row.syft.found),
      precisionWithoutRoots: ratio(
        row.syft.tp,
        row.syft.found - row.syft.roots,
      ),
      recall: ratio(row.syft.tp, row.truth),
    },
  }));
}

function main() {
  mkdirSync(join(SBOM, "s7"), { recursive: true });
  const version = run(SYFT, ["version", "-o", "json"]);
  const results = [];
  for (const a of ARTIFACTS) {
    if (a.prepare && existsSync(join(OUT, a.truthId))) a.prepare();
    if (!existsSync(a.path)) {
      results.push({ ...a, status: "not built" });
      console.log(`${a.id}\tnot built`);
      continue;
    }
    const truth = truthSet(a);
    const facts = rootFacts(a);
    const o = ours(a);
    const s = syft(a);
    const row = {
      id: a.id,
      ecosystem: a.ecosystem,
      group: a.group,
      path: a.path.slice(SBOM.length + 1),
      ours: o.error
        ? { error: o.error }
        : {
            ...withCauses(
              measure(o.found, truth),
              facts,
              a.ecosystem,
              o.unknownNames,
            ),
            other: o.other,
            runtime: o.runtime,
            unknowns: o.unknowns,
            exclusions: o.exclusions,
          },
      syft: s.error
        ? { error: s.error }
        : {
            ...withCauses(measure(s.found, truth), facts, a.ecosystem),
            other: s.other,
            runtime: s.runtime,
            components: s.raw.length,
          },
    };
    results.push(row);
    const fmt = (r) =>
      r.error
        ? `ERROR ${r.error.slice(0, 80)}`
        : `${r.truePositives}/${r.found} found, ${r.truePositives}/${r.truth} truth, other ${r.other.length}`;
    console.log(`${a.id}\tours ${fmt(row.ours)}\tsyft ${fmt(row.syft)}`);
  }
  writeFileSync(
    join(SBOM, "s7/compare.json"),
    `${JSON.stringify({ syft: JSON.parse(version), summary: summarize(results), results }, null, 2)}\n`,
  );
}

if (import.meta.main) main();
