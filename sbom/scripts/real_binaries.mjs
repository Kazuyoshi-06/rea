#!/usr/bin/env node
// S5 B6: in-house readers on real, pinned public tools, compared with independent oracles:
//   Go    `go version -m <binary>` (the Go toolchain's own reader)
//   Rust  `rust-audit-info <binary>` (reference reader of the cargo-auditable project)
// Binaries are built by scripts/build_real_binaries.sh into .work/real/ (gitignored).
// Two levels are compared:
//   reader  every fact (Go: version, main, each dep and its replacement; Rust: each package with
//           version, source, kind, dependencies, root) must be identical;
//   SBOM    components emitted by sbom-scan vs the oracle's shipped set (Go: deps with their
//           replacement applied, local-directory replacements excluded since they have no
//           version; Rust: packages minus kind=build and the root) → precision / recall.
// Writes s5/real-binaries.json.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readCargoAuditable } from "../lib/readers/cargoauditable.mjs";
import { readGoBuildInfo } from "../lib/readers/gobuildinfo.mjs";
import { scanArtifact } from "../lib/scan.mjs";

const SBOM = join(import.meta.dirname, "..");
const REAL = process.env.SBOM_REAL_DIR ?? join(SBOM, ".work/real");
export const BINARIES = [
  {
    id: "stringer",
    ecosystem: "golang",
    path: "go/stringer",
    pin: "golang.org/x/tools/cmd/stringer@v0.26.0 (go install)",
  },
  {
    id: "yq",
    ecosystem: "golang",
    path: "go/yq",
    pin: "github.com/mikefarah/yq/v4@v4.44.3 (go install)",
  },
  {
    id: "prometheus",
    ecosystem: "golang",
    path: "go/prometheus",
    pin: "github.com/prometheus/prometheus@v0.54.1 ./cmd/prometheus (go build; replace k8s.io/klog → klog-gokit)",
  },
  {
    id: "terraform",
    ecosystem: "golang",
    path: "go/terraform",
    pin: "github.com/hashicorp/terraform@v1.9.8 (go build; 9 replace → local directories)",
  },
  {
    id: "ripgrep",
    ecosystem: "cargo",
    path: "cargo/bin/rg",
    pin: "ripgrep@14.1.1 (cargo auditable install --locked)",
  },
  {
    id: "fd",
    ecosystem: "cargo",
    path: "cargo/bin/fd",
    pin: "fd-find@10.2.0 (cargo auditable install --locked)",
  },
];

export function run(cmd, args) {
  const res = spawnSync(cmd, args, { maxBuffer: 256 << 20 });
  if (res.status !== 0)
    throw new Error(
      `${cmd} ${args.join(" ")}: ${res.stderr?.toString() ?? res.error}`,
    );
  return res.stdout.toString("utf8");
}

/** `go version -m` output → {goVersion, main, dependencies[{path, version, replacement}], settings}. */
export function goVersionM(path) {
  const lines = run("go", ["version", "-m", path]).split("\n");
  const out = {
    goVersion: lines[0].split(": ")[1],
    main: null,
    dependencies: [],
    settings: [],
  };
  let last = null;
  for (const line of lines.slice(1)) {
    const f = line.replace(/^\t/, "").split("\t");
    const mod = { path: f[1], version: f[2] ?? "", replacement: null };
    if (f[0] === "mod") last = out.main = mod;
    else if (f[0] === "dep") out.dependencies.push((last = mod));
    else if (f[0] === "=>")
      last.replacement = { path: f[1], version: f[2] ?? "" };
    else if (f[0] === "build") {
      const eq = f[1].indexOf("=");
      out.settings.push({ key: f[1].slice(0, eq), value: f[1].slice(eq + 1) });
    }
  }
  return out;
}

const RAI = join(REAL, "cargo/bin/rust-audit-info");

function rustAuditInfo(path) {
  const doc = JSON.parse(run(RAI, [path]));
  return {
    formatVersion: doc.format ?? 0,
    packages: doc.packages.map((p) => ({
      name: p.name,
      version: p.version,
      source: p.source,
      kind: p.kind ?? null,
      dependencies: p.dependencies ?? [],
      root: p.root === true,
    })),
  };
}

const key = (name, version) => `${name}@${version}`;

export function precisionRecall(found, truth) {
  const tp = [...found].filter((k) => truth.has(k));
  return {
    found: found.size,
    oracle: truth.size,
    common: tp.length,
    precision: found.size === 0 ? null : tp.length / found.size,
    recall: truth.size === 0 ? null : tp.length / truth.size,
    extra: [...found].filter((k) => !truth.has(k)).sort(),
    missing: [...truth].filter((k) => !found.has(k)).sort(),
  };
}

export function compareGo(bin, path) {
  const oracle = goVersionM(path);
  const ours = readGoBuildInfo(path);
  if (!ours.ok) return { reader: { error: ours.error } };
  const fieldDiffs = [];
  if (ours.value.goVersion !== oracle.goVersion)
    fieldDiffs.push(["goVersion", ours.value.goVersion, oracle.goVersion]);
  if (JSON.stringify(ours.value.main) !== JSON.stringify(oracle.main))
    fieldDiffs.push(["main", ours.value.main, oracle.main]);
  const a = ours.value.dependencies.map((d) => JSON.stringify(d));
  const b = oracle.dependencies.map((d) => JSON.stringify(d));
  const bs = new Set(b);
  const as = new Set(a);
  for (const d of a.filter((x) => !bs.has(x)))
    fieldDiffs.push(["dependency only ours", JSON.parse(d)]);
  for (const d of b.filter((x) => !as.has(x)))
    fieldDiffs.push(["dependency only oracle", JSON.parse(d)]);
  // Build settings (S6): GOOS / GOARCH drive the platform filter of the Go alerts.
  if (JSON.stringify(ours.value.settings) !== JSON.stringify(oracle.settings))
    fieldDiffs.push(["settings", ours.value.settings, oracle.settings]);
  const shipped = new Set(
    oracle.dependencies
      .map((d) => d.replacement ?? d)
      .filter((m) => m.version !== "" && m.version !== "(devel)")
      .map((m) => key(m.path, m.version)),
  );
  const reader = {
    identical: fieldDiffs.length === 0,
    deps: oracle.dependencies.length,
    replacements: oracle.dependencies.filter((d) => d.replacement).length,
    diffs: fieldDiffs,
  };
  const scan = scanArtifact(path);
  if (!scan.ok) return { reader, sbom: { error: scan.error } };
  const found = new Set(
    scan.value.components
      .filter((c) => c.role === "library")
      .map((c) => key(c.name, c.version)),
  );
  const stdlib = scan.value.components.find(
    (c) => c.role === "language-runtime",
  );
  return {
    reader,
    sbom: {
      ...precisionRecall(found, shipped),
      stdlib: stdlib?.version ?? null,
      stdlibMatchesOracle: `go${stdlib?.version}` === oracle.goVersion,
      unknowns: scan.value.unknowns.map((u) => `${u.name}: ${u.reason}`),
    },
  };
}

export function compareRust(bin, path) {
  const oracle = rustAuditInfo(path);
  const ours = readCargoAuditable(path);
  if (!ours.ok) return { reader: { error: ours.error } };
  const diffs = [];
  if (ours.value.section.formatVersion !== oracle.formatVersion)
    diffs.push([
      "formatVersion",
      ours.value.section.formatVersion,
      oracle.formatVersion,
    ]);
  const n = Math.max(ours.value.packages.length, oracle.packages.length);
  for (let i = 0; i < n; i += 1)
    if (
      JSON.stringify(ours.value.packages[i]) !==
      JSON.stringify(oracle.packages[i])
    )
      diffs.push(["package", i, ours.value.packages[i], oracle.packages[i]]);
  const shipped = new Set(
    oracle.packages
      .filter((p) => !p.root && p.kind !== "build")
      .map((p) => key(p.name, p.version)),
  );
  const scan = scanArtifact(path);
  const found = new Set(
    scan.value.components.map((c) => key(c.name, c.version)),
  );
  return {
    reader: {
      identical: diffs.length === 0,
      packages: oracle.packages.length,
      build: oracle.packages.filter((p) => p.kind === "build").length,
      diffs,
    },
    sbom: precisionRecall(found, shipped),
  };
}

function main() {
  const results = [];
  for (const bin of BINARIES) {
    const path = join(REAL, bin.path);
    if (!existsSync(path)) {
      results.push({ ...bin, status: "not built" });
      continue;
    }
    const bytes = Number(run("stat", ["-c", "%s", path]).trim());
    const cmp =
      bin.ecosystem === "golang"
        ? compareGo(bin, path)
        : compareRust(bin, path);
    results.push({ ...bin, bytes, ...cmp });
  }
  mkdirSync(join(SBOM, "s5"), { recursive: true });
  writeFileSync(
    join(SBOM, "s5/real-binaries.json"),
    `${JSON.stringify(results, null, 2)}\n`,
  );
  const pct = (x) =>
    x === null || x === undefined ? "—" : `${(x * 100).toFixed(1)} %`;
  for (const r of results)
    console.log(
      r.status ??
        `${r.id}\t${r.bytes} B\treader identical: ${r.reader.identical} (${r.reader.diffs?.length ?? "error"} diffs)\tSBOM P ${pct(r.sbom?.precision)} R ${pct(r.sbom?.recall)} (${r.sbom?.found}/${r.sbom?.oracle})`,
    );
}

if (import.meta.main) main();
