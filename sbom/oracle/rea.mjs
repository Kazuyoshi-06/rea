// REA as a comparison oracle only (S5): never imported by bin/ or lib/. The in-house readers
// (lib/readers/gobuildinfo.mjs, cargoauditable.mjs) replaced it; test/differential.test.mjs
// (make sbom-test-diff) checks that both give the same facts, and scripts/measure_s2.mjs reuses
// the exact REA invocation.
//
// REA is invoked through its public CLI (scripts/rea.mjs of this repository, built with
// `npm ci && npm run build:cached`). Overrides: REA_CLI (entry script), REA_NODE (Node binary).
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { err, ok } from "../lib/result.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "../..");
const MAX_REPORT_BYTES = 32 << 20; // REA bounds these reports to 8 MiB.
const TIMEOUT_MS = 120_000;

/** Exact process invocation for one REA reader call (also used by the measurement script). */
export function reaInvocation(command, artifactPath) {
  return {
    node: process.env.REA_NODE || process.execPath,
    args: [
      process.env.REA_CLI || join(REPO, "scripts/rea.mjs"),
      command,
      resolve(artifactPath),
      "--format",
      "json",
    ],
  };
}

const commandLabel = (command) => `rea ${command} <artifact> --format json`;

function runRea(command, artifactPath) {
  const { node, args } = reaInvocation(command, artifactPath);
  const started = process.hrtime.bigint();
  const res = spawnSync(node, args, {
    maxBuffer: MAX_REPORT_BYTES,
    timeout: TIMEOUT_MS,
    cwd: REPO,
  });
  const elapsedMs = Math.round(Number(process.hrtime.bigint() - started) / 1e6);
  const call = { command: commandLabel(command), elapsedMs };
  if (res.error)
    return err("rea-spawn-failed", `${call.command}: ${res.error.message}`);
  if (res.status !== 0) {
    const tail = res.stderr.toString("utf8").trim().split("\n").slice(-3);
    return err("rea-failed", `${call.command} exited ${res.status}`, { tail });
  }
  try {
    return ok({ report: JSON.parse(res.stdout.toString("utf8")), call });
  } catch (error) {
    return err("rea-bad-json", `${call.command}: ${error.message}`);
  }
}

function readerOf(report, command) {
  return {
    tool: "rea",
    command: commandLabel(command),
    provider: `${report?.provider?.id ?? "unknown"}@${report?.provider?.version ?? "unknown"}`,
  };
}

const isRange = (r) =>
  Number.isSafeInteger(r?.offset) && Number.isSafeInteger(r?.bytes);
const moduleOf = (m) =>
  m == null
    ? null
    : {
        path: m.path,
        version: m.version,
        replacement:
          m.replacement == null
            ? null
            : { path: m.replacement.path, version: m.replacement.version },
      };

/** REA `inspect-go-binary` JSON → Go build-information facts. */
export function parseGoBuildInfoReport(report) {
  const command = "inspect-go-binary";
  if (report?.operation !== "inspect_go_binary")
    return err("rea-unexpected-report", `not an ${command} report`);
  const result = report.normalized_result;
  const info = result?.build_info;
  if (info == null || info.module == null)
    return err("no-go-buildinfo", "REA found no Go build information");
  const deps = info.module.dependencies;
  if (!Array.isArray(deps))
    return err(
      "rea-unexpected-report",
      "build_info.module.dependencies missing",
    );
  return ok({
    reader: readerOf(report, command),
    artifactSha256: result.artifact?.sha256 ?? null,
    goVersion: info.go_version,
    moduleLocation: isRange(info.module_location) ? info.module_location : null,
    main: moduleOf(info.module.main),
    dependencies: deps.map(moduleOf),
    complete: info.module.complete === true,
    unparsedLines: info.module.unparsed_lines ?? [],
    unparsedBinaryLines: (info.module.unparsed_line_bytes_base64 ?? []).length,
  });
}

/** REA `inspect-rust-binary` JSON → cargo-auditable facts. */
export function parseCargoAuditableReport(report) {
  const command = "inspect-rust-binary";
  if (report?.operation !== "inspect_rust_binary")
    return err("rea-unexpected-report", `not an ${command} report`);
  const result = report.normalized_result;
  const meta = result?.auditable_metadata;
  if (meta == null || !Array.isArray(meta.packages))
    return err("no-cargo-auditable", "REA found no cargo-auditable section");
  return ok({
    reader: readerOf(report, command),
    artifactSha256: result.artifact?.sha256 ?? null,
    section: {
      name: meta.section_name,
      offset: meta.file_offset,
      bytes: meta.section_bytes,
      formatVersion: meta.format_version,
    },
    packages: meta.packages.map((p) => ({
      name: p.name,
      version: p.version,
      source: p.source,
      kind: p.kind,
      dependencies: p.dependencies ?? [],
      root: p.root === true,
    })),
  });
}

function readWith(command, parse, artifactPath) {
  const run = runRea(command, artifactPath);
  if (!run.ok) return run;
  const facts = parse(run.value.report);
  return facts.ok ? ok({ ...facts.value, call: run.value.call }) : facts;
}

export const readGoBuildInfo = (artifactPath) =>
  readWith("inspect-go-binary", parseGoBuildInfoReport, artifactPath);

export const readCargoAuditable = (artifactPath) =>
  readWith("inspect-rust-binary", parseCargoAuditableReport, artifactPath);
