#!/usr/bin/env node
// S6 C: cost of the end-of-scan integrity check. Runs `sbom-scan --format cyclonedx` 5 times per
// target under /usr/bin/time -v (first = cold, median of the other 4 = warm) and times sha256File
// alone in-process (median of 5). `node scripts/measure_s6.mjs <label>` writes
// s6/measurements-<label>.json; run it before and after the change to compare.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { sha256File } from "../lib/files.mjs";
import { OUT, SBOM, SCAN_BIN } from "../test/support.mjs";

const label = process.argv[2] ?? "current";
const TARGETS = [
  ["go-uuid", join(OUT, "go-uuid/go-uuid")],
  ["rust-small", join(OUT, "rust-small/rust-small")],
  ["stringer", join(SBOM, ".work/real/go/stringer")],
  ["ripgrep", join(SBOM, ".work/real/cargo/bin/rg")],
  ["prometheus", join(SBOM, ".work/real/go/prometheus")],
  ["terraform", join(SBOM, ".work/real/go/terraform")],
].filter(([, p]) => existsSync(p));

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

function timed(path) {
  const res = spawnSync(
    "/usr/bin/time",
    ["-v", process.execPath, SCAN_BIN, path, "--timestamp", "0"],
    { maxBuffer: 256 << 20 },
  );
  if (res.status !== 0) throw new Error(res.stderr.toString().slice(-400));
  const err = res.stderr.toString();
  const field = (re) => Number(re.exec(err)[1]);
  const [, m, s] = /Elapsed \(wall clock\) time.*: (?:(\d+):)?([\d.]+)/.exec(
    err,
  );
  return {
    wall: Number(m ?? 0) * 60 + Number(s),
    cpu:
      field(/User time \(seconds\): ([\d.]+)/) +
      field(/System time \(seconds\): ([\d.]+)/),
    rssMiB: field(/Maximum resident set size \(kbytes\): (\d+)/) / 1024,
  };
}

const rows = [];
for (const [id, path] of TARGETS) {
  const runs = Array.from({ length: 5 }, () => timed(path));
  const warm = runs.slice(1);
  const hashMs = Array.from({ length: 5 }, () => {
    const t = process.hrtime.bigint();
    const { bytes } = sha256File(path);
    return { ms: Number(process.hrtime.bigint() - t) / 1e6, bytes };
  });
  const row = {
    id,
    bytes: hashMs[0].bytes,
    coldWall: runs[0].wall,
    warmWall: median(warm.map((r) => r.wall)),
    warmCpu: median(warm.map((r) => r.cpu)),
    warmRssMiB: Number(median(warm.map((r) => r.rssMiB)).toFixed(1)),
    sha256FileMs: Number(median(hashMs.map((h) => h.ms)).toFixed(1)),
  };
  rows.push(row);
  console.log(Object.values(row).join("\t"));
}
mkdirSync(join(SBOM, "s6"), { recursive: true });
writeFileSync(
  join(SBOM, `s6/measurements-${label}.json`),
  `${JSON.stringify({ label, node: process.version, rows }, null, 2)}\n`,
);
