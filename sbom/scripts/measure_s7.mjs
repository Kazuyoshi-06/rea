#!/usr/bin/env node
// S7 A3: wall time, CPU time and peak RSS (/usr/bin/time -v) of sbom-scan and syft on the same
// artifacts, cold and warm measured separately:
//   cold  5 runs, each preceded by `sync; echo 3 > /proc/sys/vm/drop_caches` (page cache emptied;
//         needs root, the script stops if the write fails)
//   warm  1 unrecorded priming run, then 5 runs
// Both write CycloneDX JSON to /dev/null: sbom-scan --timestamp 0 --quiet --output /dev/null,
// syft scan <file:|dir:> -o cyclonedx-json=/dev/null -q (SYFT_CHECK_FOR_APP_UPDATE=false).
// No --vulns: syft has no offline matcher (grype's database download is refused here, S7_REPORT).
// Writes s7/measurements.json (median and min/max per tool, artifact, phase).
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SBOM, SCAN_BIN } from "../test/support.mjs";
import { ARTIFACTS, SYFT, SYFT_ENV, syftSource } from "./compare_syft_s7.mjs";

const RUNS = 5;
const IDS = (
  process.env.S7_MEASURE ??
  "go-uuid,rust-small,npm-cli,npm-electron,dotnet-serilog,py-requests,stringer,yq,prometheus,terraform,ripgrep,fd,prometheus windows/amd64"
).split(",");

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

function dropCaches() {
  const res = spawnSync("sh", [
    "-c",
    "sync && echo 3 > /proc/sys/vm/drop_caches",
  ]);
  if (res.status !== 0)
    throw new Error(`drop_caches failed: ${res.stderr.toString()}`);
}

function timed(cmd, args, env) {
  const res = spawnSync("/usr/bin/time", ["-v", cmd, ...args], {
    env,
    maxBuffer: 64 << 20,
  });
  const err = res.stderr.toString();
  if (res.status !== 0) throw new Error(`${cmd}: ${err.slice(-600)}`);
  const field = (re) => Number(re.exec(err)[1]);
  const [, h, m, s] =
    /Elapsed \(wall clock\) time.*: (?:(\d+):)?(?:(\d+):)?([\d.]+)$/m.exec(err);
  const parts = [h, m].filter((x) => x !== undefined).map(Number);
  const wall =
    (parts.length === 2
      ? parts[0] * 3600 + parts[1] * 60
      : (parts[0] ?? 0) * 60) + Number(s);
  return {
    wall,
    cpu:
      field(/User time \(seconds\): ([\d.]+)/) +
      field(/System time \(seconds\): ([\d.]+)/),
    rssMiB: field(/Maximum resident set size \(kbytes\): (\d+)/) / 1024,
  };
}

const TOOLS = {
  ours: (path) => [
    process.execPath,
    [SCAN_BIN, path, "--timestamp", "0", "--quiet", "--output", "/dev/null"],
    process.env,
  ],
  syft: (path) => [
    SYFT,
    ["scan", syftSource(path), "-o", "cyclonedx-json=/dev/null", "-q"],
    SYFT_ENV,
  ],
};

const summary = (runs) => {
  const pick = (k) => runs.map((r) => r[k]);
  return Object.fromEntries(
    ["wall", "cpu", "rssMiB"].map((k) => [
      k,
      {
        median: median(pick(k)),
        min: Math.min(...pick(k)),
        max: Math.max(...pick(k)),
      },
    ]),
  );
};

const rows = [];
for (const id of IDS) {
  const a = ARTIFACTS.find((x) => x.id === id);
  if (a === undefined || !existsSync(a.path)) {
    console.log(`${id}\tnot built`);
    continue;
  }
  const row = { id, ecosystem: a.ecosystem };
  for (const [tool, make] of Object.entries(TOOLS)) {
    const [cmd, args, env] = make(a.path);
    const cold = Array.from({ length: RUNS }, () => {
      dropCaches();
      return timed(cmd, args, env);
    });
    timed(cmd, args, env);
    const warm = Array.from({ length: RUNS }, () => timed(cmd, args, env));
    row[tool] = { cold: summary(cold), warm: summary(warm) };
  }
  rows.push(row);
  const f = (t, p) =>
    `${row[t][p].wall.median.toFixed(3)} s ${row[t][p].rssMiB.median.toFixed(1)} MiB`;
  console.log(
    `${id}\tours cold ${f("ours", "cold")} warm ${f("ours", "warm")}\tsyft cold ${f("syft", "cold")} warm ${f("syft", "warm")}`,
  );
}
mkdirSync(join(SBOM, "s7"), { recursive: true });
writeFileSync(
  join(SBOM, "s7/measurements.json"),
  `${JSON.stringify({ runs: RUNS, rows }, null, 2)}\n`,
);
