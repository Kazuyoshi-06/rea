#!/usr/bin/env node
// S3 measurements: precision / recall of sbom-scan against sbom/truth/, and wall time, CPU and
// peak RSS from GNU `/usr/bin/time -v`, for the .NET and PyInstaller fixtures plus the .NET
// variants whose deps.json is removed. No REA call; the raw-REA columns come from the committed
// baseline/summary.json.
//
// RUNS runs per target (default 4): the first is "cold" (page cache not controlled, so it only
// means first in this sequence), the median of the others is "warm". Writes s3/measurements.json
// and prints a Markdown table.
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  OUT,
  SBOM,
  SCAN_BIN,
  compareToTruth,
  readTruth,
} from "../test/support.mjs";

const RUNS = Number(process.env.RUNS ?? 4);
const TIME = "/usr/bin/time";
if (!existsSync(TIME)) throw new Error("GNU time (/usr/bin/time) is required");
const WORK = join(SBOM, ".work/s3");
const TIMESTAMP = "2026-01-01T00:00:00Z";

const baseline = new Map(
  JSON.parse(readFileSync(join(SBOM, "baseline/summary.json"), "utf8")).map(
    (row) => [row.fixture, row],
  ),
);

function withoutDeps(id) {
  const dir = join(WORK, `${id}-nodeps`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dirname(dir), { recursive: true });
  cpSync(join(OUT, id), dir, {
    recursive: true,
    filter: (src) => !src.endsWith(".deps.json"),
  });
  return dir;
}

const TARGETS = [
  ...["dotnet-json", "dotnet-serilog"].flatMap((id) => [
    {
      name: id,
      truth: id,
      ecosystem: "nuget",
      source: "deps.json",
      path: join(OUT, id),
      baseline: id,
    },
    {
      name: `${id}-nodeps`,
      truth: id,
      ecosystem: "nuget",
      source: "assembly attributes (deps.json removed)",
      path: () => withoutDeps(id),
      baseline: id,
    },
  ]),
  ...["py-requests-meta", "py-requests", "py-yaml"].map((id) => ({
    name: id,
    truth: id,
    ecosystem: "pypi",
    source: id === "py-requests-meta" ? "dist-info METADATA" : "PYZ bytecode",
    path: join(OUT, id, id),
    baseline: id,
  })),
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
  const wall = field("Elapsed (wall clock)")
    .split(":")
    .reduce((acc, part) => acc * 60 + Number(part), 0);
  const exit = Number(field("Exit status"));
  if (exit !== 0) throw new Error(`${args.join(" ")}: exit ${exit}\n${log}`);
  return {
    elapsed_s: +wall.toFixed(2),
    cpu_s: +(Number(field("User time")) + Number(field("System time"))).toFixed(
      2,
    ),
    peak_rss_mib: +(Number(field("Maximum resident set size")) / 1024).toFixed(
      1,
    ),
    stdout: res.stdout,
  };
}

const median = (values) =>
  [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];

const prop = (bom, name) =>
  (bom.metadata.properties ?? [])
    .filter((p) => p.name === name)
    .map((p) => p.value);

const results = [];
for (const target of TARGETS) {
  const path = typeof target.path === "function" ? target.path() : target.path;
  if (!existsSync(path)) {
    console.error(`SKIP ${target.name}: not built`);
    continue;
  }
  const args = [
    SCAN_BIN,
    path,
    "--format",
    "cyclonedx",
    "--timestamp",
    TIMESTAMP,
  ];
  const runs = Array.from({ length: RUNS }, () => timed(args));
  const outputs = new Set(runs.map((r) => r.stdout.toString("base64")));
  const bom = JSON.parse(runs[0].stdout.toString("utf8"));
  const found = bom.components.map((c) => ({
    name: c.name,
    version: c.version,
  }));
  const confidence = {};
  for (const c of bom.components) {
    const level = c.properties.find(
      (p) => p.name === "rea-sbom:confidence",
    ).value;
    confidence[level] = (confidence[level] ?? 0) + 1;
  }
  const m = compareToTruth(target.ecosystem, found, readTruth(target.truth));
  const base = baseline.get(target.baseline);
  const warm = runs.slice(1);
  results.push({
    target: target.name,
    ecosystem: target.ecosystem,
    source: target.source,
    components: found.length,
    unknowns: Number(prop(bom, "rea-sbom:unknown-count")[0]),
    confidence,
    truth: m.strict.truth,
    strict: m.strict,
    pep440_equivalent: m.equivalent,
    rea_raw: base
      ? { precision: base.precision, recall: base.recall, found: base.found }
      : null,
    identical_bytes_across_runs: outputs.size === 1,
    output_bytes: runs[0].stdout.length,
    cold: {
      elapsed_s: runs[0].elapsed_s,
      cpu_s: runs[0].cpu_s,
      peak_rss_mib: runs[0].peak_rss_mib,
    },
    warm_median: warm.length
      ? {
          elapsed_s: median(warm.map((r) => r.elapsed_s)),
          cpu_s: median(warm.map((r) => r.cpu_s)),
          peak_rss_mib: median(warm.map((r) => r.peak_rss_mib)),
        }
      : null,
    runs: runs.map(({ stdout: _stdout, ...r }) => r),
  });
}

mkdirSync(join(SBOM, "s3"), { recursive: true });
writeFileSync(
  join(SBOM, "s3/measurements.json"),
  `${JSON.stringify({ runs_per_target: RUNS, node: process.version, results }, null, 2)}\n`,
);

const pct = (x) =>
  x === null || x === undefined ? "n/a" : `${(100 * x).toFixed(0)} %`;
console.log(
  "| Cible | Source | Vrais | Trouvés | Inconnus | Précision stricte | Rappel strict | Précision PEP 440 | Rappel PEP 440 | REA brut (préc. / rappel) | Confiance | Octets identiques | Froid: durée / CPU / RSS | Chaud: durée / CPU / RSS |",
);
console.log(
  "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
);
for (const r of results) {
  const rea = r.rea_raw
    ? `${pct(r.rea_raw.precision)} / ${pct(r.rea_raw.recall)}`
    : "—";
  console.log(
    `| ${r.target} | ${r.source} | ${r.truth} | ${r.components} | ${r.unknowns} | ${pct(r.strict.precision)} | ${pct(r.strict.recall)} | ${pct(r.pep440_equivalent.precision)} | ${pct(r.pep440_equivalent.recall)} | ${rea} | ${JSON.stringify(r.confidence)} | ${r.identical_bytes_across_runs ? "oui" : "NON"} | ${r.cold.elapsed_s} s / ${r.cold.cpu_s} s / ${r.cold.peak_rss_mib} Mio | ${r.warm_median ? `${r.warm_median.elapsed_s} s / ${r.warm_median.cpu_s} s / ${r.warm_median.peak_rss_mib} Mio` : "—"} |`,
  );
}
