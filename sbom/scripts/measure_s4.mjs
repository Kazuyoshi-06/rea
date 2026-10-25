#!/usr/bin/env node
// S4 measurements: cost of --vulns. For every corpus fixture, RUNS runs (default 5) of
// `sbom-scan --format cyclonedx` without and with --vulns under GNU `/usr/bin/time -v` (wall,
// CPU, peak RSS), the index load and match times reported by --timings, the number of alerts and
// whether two outputs are byte-identical. Plus the in-process load time of each ecosystem's index
// directory. First run = "cold" (page cache not controlled), median of the others = "warm".
// Needs `make vulndb`. Writes s4/measurements.json and prints Markdown tables.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { OUT, SBOM, SCAN_BIN } from "../test/support.mjs";

const RUNS = Number(process.env.RUNS ?? 5);
const TIME = "/usr/bin/time";
if (!existsSync(TIME)) throw new Error("GNU time (/usr/bin/time) is required");
const DB = process.env.SBOM_VULNDB ?? join(SBOM, "vulndb");
if (!existsSync(join(DB, "SNAPSHOT.json")))
  throw new Error(`no index in ${DB} (run make vulndb)`);

const TARGETS = [
  ["go-uuid", "go-uuid/go-uuid"],
  ["go-jwt", "go-jwt/go-jwt"],
  ["rust-small", "rust-small/rust-small"],
  ["rust-vuln", "rust-vuln/rust-vuln"],
  ["npm-cli", "npm-cli/app.asar"],
  ["npm-electron", "npm-electron/app.asar"],
  ["dotnet-json", "dotnet-json"],
  ["dotnet-serilog", "dotnet-serilog"],
  ["py-requests-meta", "py-requests-meta/py-requests-meta"],
  ["py-requests", "py-requests/py-requests"],
  ["py-yaml", "py-yaml/py-yaml"],
];

function timed(args) {
  const res = spawnSync(TIME, ["-v", process.execPath, ...args], {
    maxBuffer: 64 << 20,
  });
  const log = res.stderr.toString("utf8");
  const field = (label) => {
    const line = log.split("\n").find((l) => l.includes(label));
    if (line === undefined) throw new Error(`no "${label}" in time -v output`);
    return line.slice(line.lastIndexOf(": ") + 2).trim();
  };
  const exit = Number(field("Exit status"));
  if (exit !== 0) throw new Error(`${args.join(" ")}: exit ${exit}\n${log}`);
  const timing = (name) => {
    const m = new RegExp(`sbom-scan: ${name} (\\d+) ms`).exec(log);
    return m ? Number(m[1]) : null;
  };
  return {
    elapsed_s: +field("Elapsed (wall clock)")
      .split(":")
      .reduce((acc, part) => acc * 60 + Number(part), 0)
      .toFixed(2),
    cpu_s: +(Number(field("User time")) + Number(field("System time"))).toFixed(
      2,
    ),
    peak_rss_mib: +(Number(field("Maximum resident set size")) / 1024).toFixed(
      1,
    ),
    vulndb_load_ms: timing("vulndb-load"),
    vuln_match_ms: timing("vuln-match \\(incl\\. load\\)"),
    stdout: res.stdout,
  };
}

const median = (values) =>
  [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
const summarize = (runs) => {
  const warm = runs.slice(1);
  const pick = (k) =>
    warm.length === 0 ? null : median(warm.map((r) => r[k]));
  const strip = ({ stdout: _s, ...rest }) => rest;
  return {
    cold: strip(runs[0]),
    warm_median:
      warm.length === 0
        ? null
        : Object.fromEntries(
            [
              "elapsed_s",
              "cpu_s",
              "peak_rss_mib",
              "vulndb_load_ms",
              "vuln_match_ms",
            ].map((k) => [k, pick(k)]),
          ),
  };
};

const results = [];
for (const [name, rel] of TARGETS) {
  const path = join(OUT, rel);
  if (!existsSync(path)) {
    console.error(`SKIP ${name}: not built`);
    continue;
  }
  const base = [
    SCAN_BIN,
    path,
    "--format",
    "cyclonedx",
    "--timestamp",
    "0",
    "--timings",
  ];
  const plain = Array.from({ length: RUNS }, () => timed(base));
  const vulns = Array.from({ length: RUNS }, () =>
    timed([...base, "--vulns", "--db", DB]),
  );
  const bom = JSON.parse(vulns[0].stdout.toString("utf8"));
  results.push({
    target: name,
    components: bom.components.length,
    alerts: bom.vulnerabilities.length,
    output_bytes: vulns[0].stdout.length,
    identical_bytes_across_runs: vulns.every((r) =>
      r.stdout.equals(vulns[0].stdout),
    ),
    without_vulns: summarize(plain),
    with_vulns: summarize(vulns),
  });
}

// In-process load of each ecosystem's directory (read of <eco>.dir + one binary-search lookup).
const loadScript = `
import { openVulnDb } from ${JSON.stringify(join(SBOM, "lib/vulns/db.mjs"))};
const out = {};
for (const eco of ["golang", "cargo", "npm", "nuget", "pypi"]) {
  const db = openVulnDb(${JSON.stringify(DB)}).value;
  const t = process.hrtime.bigint();
  const r = db.lookup(eco, "x-not-a-package");
  if (!r.ok) throw new Error(r.error.message);
  out[eco] = Number(process.hrtime.bigint() - t) / 1e6;
}
console.log(JSON.stringify(out));`;
const loads = Array.from({ length: RUNS }, () => {
  const res = spawnSync(process.execPath, [
    "--input-type=module",
    "-e",
    loadScript,
  ]);
  return JSON.parse(res.stdout.toString("utf8"));
});
const indexLoad = Object.fromEntries(
  Object.keys(loads[0]).map((eco) => [
    eco,
    {
      cold_ms: +loads[0][eco].toFixed(1),
      warm_median_ms: +median(loads.slice(1).map((l) => l[eco])).toFixed(1),
    },
  ]),
);

mkdirSync(join(SBOM, "s4"), { recursive: true });
writeFileSync(
  join(SBOM, "s4/measurements.json"),
  `${JSON.stringify({ runs: RUNS, node: process.version, index_load: indexLoad, scans: results }, null, 2)}\n`,
);

console.log("| Index | Froid | Chaud (médiane) |\n| --- | --- | --- |");
for (const [eco, v] of Object.entries(indexLoad))
  console.log(`| ${eco} | ${v.cold_ms} ms | ${v.warm_median_ms} ms |`);
const cell = (s) => `${s.elapsed_s} s / ${s.cpu_s} s / ${s.peak_rss_mib} Mio`;
console.log(
  "\n| Cible | Composants | Alertes | Sans --vulns, chaud | Avec --vulns, froid | Avec --vulns, chaud | Chargement index / appariement (chaud) | Octets identiques |\n| --- | --- | --- | --- | --- | --- | --- | --- |",
);
for (const r of results)
  console.log(
    `| ${r.target} | ${r.components} | ${r.alerts} | ${cell(r.without_vulns.warm_median)} | ${cell(r.with_vulns.cold)} | ${cell(r.with_vulns.warm_median)} | ${r.with_vulns.warm_median.vulndb_load_ms} ms / ${r.with_vulns.warm_median.vuln_match_ms} ms | ${r.identical_bytes_across_runs ? "oui" : "NON"} |`,
  );
