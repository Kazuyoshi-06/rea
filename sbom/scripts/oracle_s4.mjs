#!/usr/bin/env node
// S4 / B5: compare `sbom-scan --vulns` alerts with independent tools, per fixture.
//   osv-scanner  (go install github.com/google/osv-scanner/v2/cmd/osv-scanner) — online API,
//                on the artifact itself when it has a plugin for it (Go binary, cargo-auditable
//                binary, deps.json), otherwise on the fixture's lockfile in corpus/src
//   npm audit    --package-lock-only --omit=dev on corpus/src/<npm fixture>/package-lock.json
//   pip-audit    -r requirements.txt --no-deps --disable-pip (PyPI JSON API vulnerability data)
//   dotnet list package --vulnerable --include-transitive on corpus/src/<dotnet fixture>
// Tools are found through OSV_SCANNER / PIP_AUDIT / NPM / DOTNET (default: PATH). A tool that is
// missing or fails is recorded as "not executed" with its error; nothing is retried.
// Identifiers are compared through alias closure: two findings on the same package are the same
// vulnerability when their {id} ∪ aliases sets intersect. Writes s4/oracle.json and prints a table.
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { identityName } from "../lib/model.mjs";

const SBOM = join(import.meta.dirname, "..");
const OUT = join(SBOM, "corpus/out");
const SRC = join(SBOM, "corpus/src");
const TOOLS = {
  osv: process.env.OSV_SCANNER ?? "osv-scanner",
  pipAudit: process.env.PIP_AUDIT ?? "pip-audit",
  npm: process.env.NPM ?? "npm",
  dotnet: process.env.DOTNET ?? "dotnet",
};

// fixture → artifact, model ecosystem, oracle inputs
const FIXTURES = [
  {
    id: "go-jwt",
    artifact: "go-jwt/go-jwt",
    ecosystem: "golang",
    osv: { plugin: "go/binary", path: "go-jwt/go-jwt" },
  },
  {
    id: "go-uuid",
    artifact: "go-uuid/go-uuid",
    ecosystem: "golang",
    osv: { plugin: "go/binary", path: "go-uuid/go-uuid" },
  },
  {
    id: "rust-vuln",
    artifact: "rust-vuln/rust-vuln",
    ecosystem: "cargo",
    osv: { plugin: "rust/cargoauditable", path: "rust-vuln/rust-vuln" },
  },
  {
    id: "rust-small",
    artifact: "rust-small/rust-small",
    ecosystem: "cargo",
    osv: { plugin: "rust/cargoauditable", path: "rust-small/rust-small" },
  },
  {
    id: "npm-cli",
    artifact: "npm-cli/app.asar",
    ecosystem: "npm",
    osv: { lockfile: "npm-cli/package-lock.json" },
    npm: "npm-cli",
  },
  {
    id: "npm-electron",
    artifact: "npm-electron/app.asar",
    ecosystem: "npm",
    osv: { lockfile: "npm-electron/package-lock.json" },
    npm: "npm-electron",
  },
  {
    id: "dotnet-json",
    artifact: "dotnet-json",
    ecosystem: "nuget",
    osv: {
      plugin: "dotnet/depsjson",
      path: "dotnet-json/dotnet-json.deps.json",
    },
    dotnet: "dotnet-json",
  },
  {
    id: "dotnet-serilog",
    artifact: "dotnet-serilog",
    ecosystem: "nuget",
    osv: {
      plugin: "dotnet/depsjson",
      path: "dotnet-serilog/dotnet-serilog.deps.json",
    },
    dotnet: "dotnet-serilog",
  },
  {
    id: "py-requests",
    artifact: "py-requests/py-requests",
    ecosystem: "pypi",
    osv: { lockfile: "py-requests/requirements.txt" },
    pip: "py-requests",
  },
  {
    id: "py-requests-meta",
    artifact: "py-requests-meta/py-requests-meta",
    ecosystem: "pypi",
    osv: { lockfile: "py-requests-meta/requirements.txt" },
    pip: "py-requests-meta",
  },
  {
    id: "py-yaml",
    artifact: "py-yaml/py-yaml",
    ecosystem: "pypi",
    osv: { lockfile: "py-yaml/requirements.txt" },
    pip: "py-yaml",
  },
];

// Vulnerabilities the S1 corpus was built around, written from memory in corpus/src comments.
const EXPECTED_S1 = {
  "go-jwt": ["CVE-2020-26160", "CVE-2022-32149"],
  "rust-vuln": ["RUSTSEC-2022-0013", "CVE-2022-24713"],
  "dotnet-json": ["GHSA-5crp-9r3c-p9vr"],
  "dotnet-json-nodeps": ["GHSA-5crp-9r3c-p9vr"],
  "npm-electron": ["CVE-2021-23337"],
  "npm-cli": ["CVE-2021-44906"],
  "py-requests": ["CVE-2024-35195", "CVE-2023-45803"],
  "py-requests-meta": ["CVE-2024-35195", "CVE-2023-45803"],
  "py-yaml": ["CVE-2020-14343"],
};

// .NET variants without deps.json (fallback reader): same oracle inputs, scanned from a copy.
const scratch = mkdtempSync(join(tmpdir(), "oracle-s4-"));
for (const id of ["dotnet-json", "dotnet-serilog"]) {
  const base = FIXTURES.find((f) => f.id === id);
  const dir = join(scratch, `${id}-nodeps`);
  cpSync(join(OUT, id), dir, {
    recursive: true,
    filter: (p) => !p.endsWith(".deps.json"),
  });
  FIXTURES.push({ ...base, id: `${id}-nodeps`, artifactPath: dir });
}

function run(cmd, args, options = {}) {
  const res = spawnSync(cmd, args, { maxBuffer: 256 << 20, ...options });
  return {
    status: res.status,
    error: res.error?.message ?? null,
    stdout: res.stdout?.toString("utf8") ?? "",
    stderr: res.stderr?.toString("utf8") ?? "",
  };
}

const notExecuted = (tool, input, reason) => ({
  tool,
  input,
  executed: false,
  reason,
  findings: [],
});

function ours(fx) {
  const res = run(process.execPath, [
    join(SBOM, "bin/sbom-scan"),
    fx.artifactPath ?? join(OUT, fx.artifact),
    "--vulns",
    "--timestamp",
    "0",
  ]);
  if (res.status !== 0) throw new Error(`sbom-scan ${fx.id}: ${res.stderr}`);
  const bom = JSON.parse(res.stdout);
  const byRef = new Map(bom.components.map((c) => [c["bom-ref"], c]));
  const confidence = {};
  for (const v of bom.vulnerabilities) {
    const level = v.properties.find(
      (p) => p.name === "rea-sbom:confidence",
    ).value;
    confidence[level] = (confidence[level] ?? 0) + 1;
  }
  return {
    confidence,
    components: bom.components.map((c) => ({
      name: c.name,
      version: c.version,
    })),
    findings: bom.vulnerabilities.map((v) => {
      const c = byRef.get(v.affects[0].ref);
      return {
        package: c.name,
        version: c.version,
        ids: [v.id, ...(v.references ?? []).map((r) => r.id)],
      };
    }),
  };
}

function osvScanner(fx) {
  const input = fx.osv.plugin
    ? join(OUT, fx.osv.path)
    : join(SRC, fx.osv.lockfile);
  const args = ["scan", "source", "--format", "json"];
  if (fx.osv.plugin) args.push("--x-plugins", fx.osv.plugin, input);
  else args.push("-L", input);
  const res = run(TOOLS.osv, args);
  const label = `osv-scanner ${fx.osv.plugin ? `--x-plugins ${fx.osv.plugin}` : "-L"}`;
  if (res.error) return notExecuted(label, input, res.error);
  if (![0, 1].includes(res.status))
    return notExecuted(
      label,
      input,
      `exit ${res.status}: ${res.stderr.trim().split("\n").slice(-2).join(" | ")}`,
    );
  const json = JSON.parse(res.stdout);
  const findings = [];
  for (const r of json.results ?? [])
    for (const p of r.packages ?? [])
      for (const v of p.vulnerabilities ?? [])
        findings.push({
          package: p.package.name,
          version: p.package.version,
          ids: [v.id, ...(v.aliases ?? [])],
        });
  return {
    tool: label,
    input,
    executed: true,
    findings,
    warnings: res.stderr.includes("failed")
      ? res.stderr
          .trim()
          .split("\n")
          .filter((l) => l.includes("failed"))
      : [],
  };
}

function npmAudit(fx) {
  const cwd = join(SRC, fx.npm);
  const res = run(
    TOOLS.npm,
    ["audit", "--package-lock-only", "--omit=dev", "--json"],
    { cwd },
  );
  const label = "npm audit --package-lock-only --omit=dev";
  if (res.error) return notExecuted(label, cwd, res.error);
  let json;
  try {
    json = JSON.parse(res.stdout);
  } catch {
    return notExecuted(label, cwd, `exit ${res.status}: ${res.stderr.trim()}`);
  }
  if (json.error) return notExecuted(label, cwd, JSON.stringify(json.error));
  const findings = [];
  for (const [name, v] of Object.entries(json.vulnerabilities ?? {}))
    for (const via of v.via ?? [])
      if (typeof via === "object" && via.url)
        findings.push({
          package: name,
          version: null,
          range: via.range,
          ids: [via.url.split("/").pop()],
        });
  return { tool: label, input: cwd, executed: true, findings };
}

function pipAudit(fx) {
  const input = join(SRC, fx.pip, "requirements.txt");
  const res = run(TOOLS.pipAudit, [
    "-r",
    input,
    "--no-deps",
    "--disable-pip",
    "-f",
    "json",
    "--progress-spinner",
    "off",
  ]);
  const label = "pip-audit -r --no-deps --disable-pip (source: pypi)";
  if (res.error) return notExecuted(label, input, res.error);
  let json;
  try {
    json = JSON.parse(res.stdout);
  } catch {
    return notExecuted(
      label,
      input,
      `exit ${res.status}: ${res.stderr.trim().split("\n").slice(-2).join(" | ")}`,
    );
  }
  const findings = [];
  for (const d of json.dependencies ?? [])
    for (const v of d.vulns ?? [])
      findings.push({
        package: d.name,
        version: d.version,
        ids: [v.id, ...(v.aliases ?? [])],
      });
  return { tool: label, input, executed: true, findings };
}

function dotnetList(fx) {
  // Restored in a scratch copy: corpus/src stays free of obj/ directories.
  const source = join(SRC, fx.dotnet);
  const cwd = mkdtempSync(join(tmpdir(), `oracle-${fx.dotnet}-`));
  cpSync(source, cwd, { recursive: true });
  const label = "dotnet list package --vulnerable --include-transitive";
  const restore = run(TOOLS.dotnet, ["restore"], { cwd });
  if (restore.error || restore.status !== 0) {
    rmSync(cwd, { recursive: true, force: true });
    return notExecuted(
      label,
      source,
      `dotnet restore: ${restore.error ?? restore.stdout.trim().split("\n").slice(-2).join(" | ")}`,
    );
  }
  const res = run(
    TOOLS.dotnet,
    [
      "list",
      "package",
      "--vulnerable",
      "--include-transitive",
      "--format",
      "json",
    ],
    { cwd },
  );
  rmSync(cwd, { recursive: true, force: true });
  if (res.error) return notExecuted(label, source, res.error);
  let json;
  try {
    json = JSON.parse(res.stdout);
  } catch {
    return notExecuted(
      label,
      cwd,
      `exit ${res.status}: ${(res.stdout + res.stderr).trim().split("\n").slice(-3).join(" | ")}`,
    );
  }
  const errors = (json.problems ?? []).filter((p) => p.level === "error");
  if (errors.length > 0)
    return notExecuted(label, source, errors.map((p) => p.text).join(" | "));
  const findings = [];
  for (const project of json.projects ?? [])
    for (const fw of project.frameworks ?? [])
      for (const p of [
        ...(fw.topLevelPackages ?? []),
        ...(fw.transitivePackages ?? []),
      ])
        for (const v of p.vulnerabilities ?? [])
          findings.push({
            package: p.id,
            version: p.resolvedVersion,
            ids: [v.advisoryurl.split("/").pop()],
          });
  return { tool: label, input: source, executed: true, findings };
}

/** Group findings of one side into vulnerabilities: same package + intersecting id sets. */
function group(findings, ecosystem) {
  const groups = [];
  for (const f of findings) {
    const key = identityName({
      ecosystem,
      name: f.package === "stdlib" || f.package === "go" ? "stdlib" : f.package,
    });
    const ids = new Set(f.ids);
    const hit = groups.filter(
      (g) => g.key === key && [...ids].some((i) => g.ids.has(i)),
    );
    const target = hit[0] ?? { key, ids: new Set(), raw: [] };
    for (const other of hit.slice(1)) {
      for (const i of other.ids) target.ids.add(i);
      target.raw.push(...other.raw);
      groups.splice(groups.indexOf(other), 1);
    }
    for (const i of ids) target.ids.add(i);
    target.raw.push(f.ids[0]);
    if (hit.length === 0) groups.push(target);
  }
  return groups;
}

function compare(mine, oracle, ecosystem, inScope) {
  const a = group(mine, ecosystem);
  const b = group(oracle, ecosystem).filter(
    (g) => inScope === null || inScope.has(g.key),
  );
  const same = (x, y) =>
    x.key === y.key && [...x.ids].some((i) => y.ids.has(i));
  const matchedMine = a.filter((x) => b.some((y) => same(x, y)));
  const matchedOracle = b.filter((y) => a.some((x) => same(x, y)));
  const label = (g) => `${g.key}: ${[...new Set(g.raw)].sort().join("/")}`;
  return {
    ours: a.length,
    oracle: b.length,
    common: matchedOracle.length,
    precision: a.length === 0 ? null : matchedMine.length / a.length,
    recall: b.length === 0 ? null : matchedOracle.length / b.length,
    onlyOurs: a.filter((x) => !b.some((y) => same(x, y))).map(label),
    onlyOracle: b.filter((y) => !a.some((x) => same(x, y))).map(label),
  };
}

const report = { generatedFor: "S4 B5", fixtures: [] };
for (const fx of FIXTURES) {
  const mine = ours(fx);
  const scope = new Set(
    mine.components.map((c) =>
      identityName({ ecosystem: fx.ecosystem, name: c.name }),
    ),
  );
  const oracles = [osvScanner(fx)];
  if (fx.npm) oracles.push(npmAudit(fx));
  if (fx.pip) oracles.push(pipAudit(fx));
  if (fx.dotnet) oracles.push(dotnetList(fx));
  const comparisons = oracles.map((o) => ({
    tool: o.tool,
    input: o.input,
    executed: o.executed,
    reason: o.reason,
    warnings: o.warnings,
    all: o.executed
      ? compare(mine.findings, o.findings, fx.ecosystem, null)
      : null,
    inScope: o.executed
      ? compare(mine.findings, o.findings, fx.ecosystem, scope)
      : null,
  }));
  const ourIds = new Set(mine.findings.flatMap((f) => f.ids));
  const expected = (EXPECTED_S1[fx.id] ?? []).map((id) => ({
    id,
    confirmed: ourIds.has(id),
  }));
  report.fixtures.push({
    id: fx.id,
    ecosystem: fx.ecosystem,
    ours: mine.findings.length,
    oursByConfidence: mine.confidence,
    expectedS1: expected,
    comparisons,
  });
}
rmSync(scratch, { recursive: true, force: true });

mkdirSync(join(SBOM, "s4"), { recursive: true });
writeFileSync(
  join(SBOM, "s4/oracle.json"),
  `${JSON.stringify(report, null, 2)}\n`,
);
const pct = (x) => (x === null ? "n/a" : `${Math.round(x * 1000) / 10} %`);
console.log(
  "| Fixture | Oracle | Nous | Oracle | Communs | Précision | Rappel | Rappel (périmètre SBOM) |",
);
console.log("| --- | --- | --- | --- | --- | --- | --- | --- |");
for (const f of report.fixtures)
  for (const c of f.comparisons)
    console.log(
      c.executed
        ? `| ${f.id} | ${c.tool} | ${c.all.ours} | ${c.all.oracle} | ${c.all.common} | ${pct(c.all.precision)} | ${pct(c.all.recall)} | ${pct(c.inScope.recall)} |`
        : `| ${f.id} | ${c.tool} | — | non exécuté : ${c.reason} | | | | |`,
    );
console.log("\nS1 expected vulnerabilities (from memory) found in our alerts:");
for (const f of report.fixtures)
  if (f.expectedS1.length > 0)
    console.log(
      `  ${f.id}: ${f.expectedS1.map((e) => `${e.id} ${e.confirmed ? "confirmed" : "NOT FOUND"}`).join(", ")}`,
    );
