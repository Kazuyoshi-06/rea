#!/usr/bin/env node
// Measure wall time, CPU and peak RSS (GNU /usr/bin/time) for:
//   - each REA reader call behind lib/rea.mjs (exact same invocation), on Go and Rust fixtures
//   - each complete `sbom-scan --format cyclonedx` run, on every S2 fixture
// RUNS runs per target; the first run is reported separately as "cold" (page cache state is
// not controlled, so "cold" only means first in this process sequence).
// Writes s2/measurements.json and prints a Markdown table.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { reaInvocation } from "../oracle/rea.mjs";
import { S2_FIXTURES, SCAN_BIN, fixturePath } from "../test/support.mjs";

const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
const RUNS = Number(process.env.RUNS ?? 3);
const TIME = "/usr/bin/time";
if (!existsSync(TIME)) throw new Error("GNU time (/usr/bin/time) is required");

function timed(node, args) {
  const res = spawnSync(TIME, ["-f", "%e %U %S %M", node, ...args], {
    maxBuffer: 256 << 20,
  });
  if (res.status !== 0)
    throw new Error(`${args.join(" ")}: exit ${res.status}`);
  const [elapsed, user, sys, rssKb] = res.stderr
    .toString()
    .trim()
    .split("\n")
    .at(-1)
    .split(" ")
    .map(Number);
  return {
    elapsed_s: elapsed,
    cpu_s: +(user + sys).toFixed(2),
    peak_rss_mib: +(rssKb / 1024).toFixed(1),
    output_bytes: res.stdout.length,
  };
}

function series(node, args) {
  const runs = Array.from({ length: RUNS }, () => timed(node, args));
  const warm = runs.slice(1);
  const median = (key) => {
    const v = warm.map((r) => r[key]).sort((a, b) => a - b);
    return v.length ? v[Math.floor(v.length / 2)] : null;
  };
  return {
    cold: runs[0],
    warm_median: {
      elapsed_s: median("elapsed_s"),
      cpu_s: median("cpu_s"),
      peak_rss_mib: median("peak_rss_mib"),
    },
    runs,
  };
}

const results = [];
for (const fx of S2_FIXTURES) {
  const path = fixturePath(fx);
  if (!existsSync(path)) continue;
  if (fx.ecosystem !== "npm") {
    const command =
      fx.ecosystem === "golang" ? "inspect-go-binary" : "inspect-rust-binary";
    const { node, args } = reaInvocation(command, path);
    results.push({
      fixture: fx.id,
      what: `rea ${command}`,
      ...series(node, args),
    });
  }
  const scanArgs = [
    SCAN_BIN,
    path,
    "--format",
    "cyclonedx",
    "--timestamp",
    "2026-01-01T00:00:00Z",
  ];
  results.push({
    fixture: fx.id,
    what: "sbom-scan",
    ...series(process.execPath, scanArgs),
  });
}

mkdirSync(join(SBOM, "s2"), { recursive: true });
writeFileSync(
  join(SBOM, "s2/measurements.json"),
  `${JSON.stringify({ runs_per_target: RUNS, node: process.version, results }, null, 2)}\n`,
);
console.log(
  "| Fixture | Mesure | Froid: durée / CPU / RSS | Chaud (médiane): durée / CPU / RSS | Sortie |",
);
console.log("| --- | --- | --- | --- | --- |");
for (const r of results)
  console.log(
    `| ${r.fixture} | ${r.what} | ${r.cold.elapsed_s} s / ${r.cold.cpu_s} s / ${r.cold.peak_rss_mib} Mio | ${r.warm_median.elapsed_s} s / ${r.warm_median.cpu_s} s / ${r.warm_median.peak_rss_mib} Mio | ${r.cold.output_bytes} o |`,
  );
