#!/usr/bin/env node
// S5 measurements: Go and Rust scans with the in-house readers. RUNS runs (default 5)
// of `sbom-scan --format cyclonedx --timings` per target under GNU `/usr/bin/time -v`: wall,
// CPU (user + system), peak RSS, and the reader time reported by --timings. First run = "cold"
// (page cache not controlled), median of the others = "warm". Targets: the Go/Rust fixtures and
// the real binaries of make sbom-real when built. Writes s5/measurements.json.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { OUT, SBOM, SCAN_BIN } from "../test/support.mjs";

const RUNS = Number(process.env.RUNS ?? 5);
const TIME = "/usr/bin/time";
if (!existsSync(TIME)) throw new Error("GNU time (/usr/bin/time) is required");
const REAL = join(SBOM, ".work/real");

const TARGETS = [
  ["go-uuid", join(OUT, "go-uuid/go-uuid")],
  ["go-jwt", join(OUT, "go-jwt/go-jwt")],
  ["go-jwt-stripped", join(OUT, "go-jwt-stripped/go-jwt")],
  ["rust-small", join(OUT, "rust-small/rust-small")],
  ["rust-vuln", join(OUT, "rust-vuln/rust-vuln")],
  ["real:stringer", join(REAL, "go/stringer")],
  ["real:yq", join(REAL, "go/yq")],
  ["real:prometheus", join(REAL, "go/prometheus")],
  ["real:terraform", join(REAL, "go/terraform")],
  ["real:ripgrep", join(REAL, "cargo/bin/rg")],
  ["real:fd", join(REAL, "cargo/bin/fd")],
].filter(([, path]) => existsSync(path));

function timed(path) {
  const res = spawnSync(
    TIME,
    [
      "-v",
      process.execPath,
      SCAN_BIN,
      path,
      "--format",
      "cyclonedx",
      "--timestamp",
      "0",
      "--timings",
    ],
    { maxBuffer: 256 << 20 },
  );
  const log = res.stderr.toString("utf8");
  const field = (label) => {
    const line = log.split("\n").find((l) => l.includes(label));
    if (line === undefined) throw new Error(`no "${label}" in time -v output`);
    return line.slice(line.lastIndexOf(": ") + 2).trim();
  };
  const exit = Number(field("Exit status"));
  if (exit !== 0) throw new Error(`${path}: exit ${exit}\n${log}`);
  const reader =
    /sbom-scan: (go-buildinfo-reader|cargo-auditable-reader) (\d+) ms/.exec(
      log,
    );
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
    reader_ms: reader ? Number(reader[2]) : null,
    stdout: res.stdout,
  };
}

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const m =
    s.length % 2
      ? s[(s.length - 1) / 2]
      : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
  return m === null ? null : +m.toFixed(3);
};

const results = [];
for (const [id, path] of TARGETS) {
  const runs = Array.from({ length: RUNS }, () => timed(path));
  const warm = runs.slice(1);
  const summary = (key) => ({
    cold: runs[0][key],
    warm: median(warm.map((r) => r[key])),
  });
  results.push({
    id,
    bytes: statSync(path).size,
    runs: runs.map(({ stdout: _s, ...r }) => r),
    elapsed_s: summary("elapsed_s"),
    cpu_s: summary("cpu_s"),
    peak_rss_mib: summary("peak_rss_mib"),
    reader_ms: summary("reader_ms"),
    identicalOutputs: runs.every((r) => r.stdout.equals(runs[0].stdout)),
  });
}
mkdirSync(join(SBOM, "s5"), { recursive: true });
writeFileSync(
  join(SBOM, "s5/measurements.json"),
  `${JSON.stringify({ runs: RUNS, node: process.version, results }, null, 2)}\n`,
);
console.log(
  "| Cible | Octets | Durée froid / chaud | CPU chaud | RSS chaud | Lecteur chaud | Sorties identiques |",
);
console.log("| --- | --- | --- | --- | --- | --- | --- |");
for (const r of results)
  console.log(
    `| ${r.id} | ${r.bytes} | ${r.elapsed_s.cold} s / ${r.elapsed_s.warm} s | ${r.cpu_s.warm} s | ${r.peak_rss_mib.warm} Mio | ${r.reader_ms.warm} ms | ${r.identicalOutputs} |`,
  );
