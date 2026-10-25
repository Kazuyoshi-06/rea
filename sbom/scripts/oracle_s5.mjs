#!/usr/bin/env node
// S5 part D: extra independent oracles for vulnerabilities.
// D1 Go: govulncheck (pinned, binary mode, -scan symbol) on the Go corpus binaries and the real
//    binaries of make sbom-real. It reports a finding per vulnerability at the deepest level it can
//    establish: module, package, or symbol (a vulnerable function present in the binary). We match
//    by version only. Comparison per vulnerability (alias group): every vulnerability govulncheck
//    reports at any level must be one of ours; ours minus its symbol-level set is the gap
//    attributable to reachability (symbols not linked).
// D2 Rust: cargo-audit (pinned) on the Rust binaries (cargo audit bin), if it can fetch RustSec.
// Needs `make vulndb`, network for the oracles' databases. Writes s5/oracle.json.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { OUT, SBOM, SCAN_BIN } from "../test/support.mjs";

const REAL = join(SBOM, ".work/real");
const GOVULNCHECK = join(REAL, "tools/govulncheck");
const CARGO_AUDIT = join(REAL, "cargo/bin/cargo-audit");
const GO = [
  ["go-uuid", join(OUT, "go-uuid/go-uuid")],
  ["go-uuid-stripped", join(OUT, "go-uuid-stripped/go-uuid")],
  ["go-jwt", join(OUT, "go-jwt/go-jwt")],
  ["go-jwt-stripped", join(OUT, "go-jwt-stripped/go-jwt")],
  ["real:stringer", join(REAL, "go/stringer")],
  ["real:yq", join(REAL, "go/yq")],
  ["real:prometheus", join(REAL, "go/prometheus")],
  ["real:terraform", join(REAL, "go/terraform")],
].filter(([, p]) => existsSync(p));
const RUST = [
  ["rust-small", join(OUT, "rust-small/rust-small")],
  ["rust-vuln", join(OUT, "rust-vuln/rust-vuln")],
  ["real:ripgrep", join(REAL, "cargo/bin/rg")],
  ["real:fd", join(REAL, "cargo/bin/fd")],
].filter(([, p]) => existsSync(p));

function run(cmd, args, okStatus = [0]) {
  const res = spawnSync(cmd, args, { maxBuffer: 512 << 20 });
  if (!okStatus.includes(res.status))
    throw new Error(
      `${cmd} ${args.join(" ")} → ${res.status}: ${res.stderr?.toString().slice(-500)}`,
    );
  return res.stdout.toString("utf8");
}

/** Concatenated JSON objects (govulncheck -format json). */
function jsonStream(text) {
  const out = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") i += 1;
      else if (ch === '"') inString = false;
    } else if (ch === '"') inString = true;
    else if (ch === "{") {
      if (depth === 0) start = i;
      depth += 1;
    } else if (ch === "}") {
      depth -= 1;
      if (depth === 0) out.push(JSON.parse(text.slice(start, i + 1)));
    }
  }
  return out;
}

/** Our vulnerabilities: [{id, ids:Set, scope, components:[name@version]}]. */
function ours(path) {
  const bom = JSON.parse(
    run(process.execPath, [SCAN_BIN, path, "--vulns", "--timestamp", "0"]),
  );
  const refs = new Map(bom.components.map((c) => [c["bom-ref"], c]));
  return bom.vulnerabilities.map((v) => ({
    id: v.id,
    ids: new Set([v.id, ...(v.references ?? []).map((r) => r.id)]),
    runtime: v.properties.some((p) => p.name === "rea-sbom:scope"),
    components: v.affects.map(
      (a) => `${refs.get(a.ref).name}@${refs.get(a.ref).version}`,
    ),
  }));
}

function govulncheck(path) {
  const findings = jsonStream(
    run(GOVULNCHECK, [
      "-mode",
      "binary",
      "-scan",
      "symbol",
      "-format",
      "json",
      path,
    ]),
  )
    .filter((o) => o.finding)
    .map((o) => o.finding);
  const level = new Map(); // osv → deepest level
  const rank = { module: 0, package: 1, symbol: 2 };
  for (const f of findings) {
    const t = f.trace?.[0] ?? {};
    const l = t.function ? "symbol" : t.package ? "package" : "module";
    if (!level.has(f.osv) || rank[l] > rank[level.get(f.osv)])
      level.set(f.osv, l);
  }
  return level;
}

function compareGo(id, path) {
  const mine = ours(path);
  const level = govulncheck(path);
  const groupOf = (osv) => mine.find((g) => g.ids.has(osv));
  const missing = [...level.keys()].filter((osv) => !groupOf(osv)).sort();
  const symbolGroups = new Set(
    [...level]
      .filter(([, l]) => l === "symbol")
      .map(([osv]) => groupOf(osv))
      .filter(Boolean),
  );
  const anyGroups = new Set([...level.keys()].map(groupOf).filter(Boolean));
  const notReported = mine.filter((g) => !anyGroups.has(g));
  const levels = { module: 0, package: 0, symbol: 0 };
  for (const l of level.values()) levels[l] += 1;
  return {
    id,
    ours: mine.length,
    oursRuntime: mine.filter((g) => g.runtime).length,
    govulncheck: level.size,
    govulncheckLevels: levels,
    govulncheckMissingFromOurs: missing,
    oursAlsoGovulncheckAnyLevel: anyGroups.size,
    oursAtSymbolLevel: symbolGroups.size,
    gapReachability: mine.length - symbolGroups.size,
    gapReachabilityRuntime: mine.filter(
      (g) => g.runtime && !symbolGroups.has(g),
    ).length,
    oursNotReportedByGovulncheck: notReported.map(
      (g) => `${g.id} (${g.components.join(", ")})`,
    ),
  };
}

function cargoAudit(id, path) {
  if (!existsSync(CARGO_AUDIT))
    return { id, status: "non exécuté", reason: "cargo-audit not installed" };
  const res = spawnSync(CARGO_AUDIT, ["audit", "--json", "bin", path], {
    maxBuffer: 64 << 20,
  });
  const stdout = res.stdout.toString();
  if (!stdout.trim().startsWith("{"))
    return {
      id,
      status: "non exécuté",
      reason: `exit ${res.status}: ${res.stderr.toString().trim().split("\n").slice(-3).join(" | ")}`,
    };
  const report = JSON.parse(stdout);
  const theirs = report.vulnerabilities.list.map((v) => ({
    id: v.advisory.id,
    aliases: v.advisory.aliases ?? [],
    package: `${v.package.name}@${v.package.version}`,
  }));
  const mine = ours(path);
  const missing = theirs.filter(
    (t) =>
      !mine.some((g) => g.ids.has(t.id) || t.aliases.some((a) => g.ids.has(a))),
  );
  const extra = mine.filter(
    (g) =>
      !theirs.some(
        (t) => g.ids.has(t.id) || t.aliases.some((a) => g.ids.has(a)),
      ),
  );
  const warnings = Object.entries(report.warnings ?? {}).map(
    ([k, list]) => `${k}: ${list.length}`,
  );
  return {
    id,
    status: "exécuté",
    ours: mine.length,
    cargoAudit: theirs.length,
    common: theirs.length - missing.length,
    missingFromOurs: missing.map((t) => `${t.id} ${t.package}`),
    oursNotInCargoAudit: extra.map(
      (g) => `${g.id} (${g.components.join(", ")})`,
    ),
    warnings,
  };
}

const result = {
  tools: {
    govulncheck: existsSync(GOVULNCHECK)
      ? run(GOVULNCHECK, ["-version"]).trim().split("\n")
      : null,
    cargoAudit: existsSync(CARGO_AUDIT)
      ? run(CARGO_AUDIT, ["--version"]).trim()
      : null,
  },
  go: existsSync(GOVULNCHECK)
    ? GO.map(([id, p]) => compareGo(id, p))
    : "govulncheck not installed",
  rust: RUST.map(([id, p]) => cargoAudit(id, p)),
};
mkdirSync(join(SBOM, "s5"), { recursive: true });
writeFileSync(
  join(SBOM, "s5/oracle.json"),
  `${JSON.stringify(result, null, 2)}\n`,
);
for (const g of Array.isArray(result.go) ? result.go : [])
  console.log(
    `${g.id}\tours ${g.ours} (runtime ${g.oursRuntime})\tgovulncheck ${g.govulncheck} ${JSON.stringify(g.govulncheckLevels)}\tmissing ${g.govulncheckMissingFromOurs.length}\tsymbol-level ${g.oursAtSymbolLevel}\tgap ${g.gapReachability}`,
  );
for (const r of result.rust)
  console.log(
    `${r.id}\t${r.status}\t${r.reason ?? `ours ${r.ours} cargo-audit ${r.cargoAudit} common ${r.common}`}`,
  );
