#!/usr/bin/env node
// Run the relevant REA CLI reader on each built fixture and keep the raw JSON output.
// Writes sbom/baseline/raw/<fixture>[.<target>].json.gz (raw CLI stdout, gzipped)
// plus sbom/baseline/raw/<fixture>.run.json (command, exit code, elapsed, peak RSS).
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { reaRoot } from "../oracle/rea.mjs";
import { FIXTURES } from "./fixtures.mjs";

const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = reaRoot();
const OUT = join(SBOM, "corpus/out");
const RAW = join(SBOM, "baseline/raw");
const REA = join(REPO, "scripts/rea.mjs");
const GZIP_ABOVE = 0; // always gzip: raw bytes stay untouched by repository formatters
const TIME = existsSync("/usr/bin/time") ? "/usr/bin/time" : null;

function targets(fx) {
  const dir = join(OUT, fx.id);
  if (fx.artifact !== "each-dll")
    return [{ label: null, path: join(dir, fx.artifact) }];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".dll"))
    .sort()
    .map((f) => ({ label: f, path: join(dir, f) }));
}

function runOne(fx, target) {
  const args = [REA, fx.rea, target.path, "--format", "json"];
  const started = process.hrtime.bigint();
  const res = TIME
    ? spawnSync(TIME, ["-f", "%M %U %S", process.execPath, ...args], {
        maxBuffer: 1 << 30,
        cwd: REPO,
      })
    : spawnSync(process.execPath, args, { maxBuffer: 1 << 30, cwd: REPO });
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const stderr = res.stderr.toString("utf8");
  const timeLine = TIME ? stderr.trimEnd().split("\n").at(-1) : "";
  const [rssKb, user, sys] = timeLine.split(" ").map(Number);
  const stdout = res.stdout;
  const base = target.label ? `${fx.id}.${target.label}` : fx.id;
  for (const ext of [".json", ".json.gz"])
    rmSync(join(RAW, base + ext), { force: true });
  const file = stdout.length > GZIP_ABOVE ? `${base}.json.gz` : `${base}.json`;
  writeFileSync(
    join(RAW, file),
    stdout.length > GZIP_ABOVE ? gzipSync(stdout, { level: 9 }) : stdout,
  );
  return {
    target: target.label ?? fx.artifact,
    command: `rea ${fx.rea} corpus/out/${fx.id}/${target.label ?? fx.artifact} --format json`,
    exit_code: res.status,
    output_file: file,
    output_bytes: stdout.length,
    elapsed_ms: Math.round(elapsedMs),
    cpu_ms:
      TIME && Number.isFinite(user) ? Math.round((user + sys) * 1000) : null,
    peak_rss_kb: TIME && Number.isFinite(rssKb) ? rssKb : null,
    stderr_tail: stderr
      .split("\n")
      .filter((l) => l && !l.includes("rea_progress") && l !== timeLine)
      .slice(-3),
  };
}

mkdirSync(RAW, { recursive: true });
const only = new Set(process.argv.slice(2));
for (const fx of FIXTURES) {
  if (only.size && !only.has(fx.id) && !only.has(fx.ecosystem)) continue;
  if (!existsSync(join(OUT, fx.id))) {
    console.error(`rea ${fx.id}: SKIP (artifact not built)`);
    continue;
  }
  const runs = targets(fx).map((t) => runOne(fx, t));
  writeFileSync(
    join(RAW, `${fx.id}.run.json`),
    `${JSON.stringify({ fixture: fx.id, runs }, null, 2)}\n`,
  );
  for (const r of runs)
    console.log(
      `rea ${fx.id} ${r.target}: exit=${r.exit_code} ${r.output_bytes}B ${r.elapsed_ms}ms`,
    );
}
