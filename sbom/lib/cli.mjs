// Command-line adapter for sbom/bin/sbom-scan. Exit codes: 0 ok, 1 scan failure, 2 usage.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { serializeBom, toCycloneDx } from "./cyclonedx.mjs";
import { scanArtifact } from "./scan.mjs";
import { openVulnDb } from "./vulns/db.mjs";
import { matchComponents } from "./vulns/match.mjs";

const DEFAULT_DB = fileURLToPath(new URL("../vulndb", import.meta.url));

const USAGE =
  "usage: sbom-scan <artifact> [--format cyclonedx|model] [--vulns [--db DIR] [--no-runtime-vulns] [--all-platforms]] [--output FILE] [--timestamp ISO|EPOCH] [--timings]";

function timestampOption(value) {
  if (value !== undefined) return /^\d+$/.test(value) ? Number(value) : value;
  const epoch = process.env.SOURCE_DATE_EPOCH;
  return epoch !== undefined && /^\d+$/.test(epoch)
    ? Number(epoch)
    : new Date();
}

function render(scan, values) {
  if (values.format === "model") {
    const { calls: _calls, vulnerabilities, ...model } = scan;
    if (vulnerabilities) {
      const describe = (c) => ({
        ecosystem: c.ecosystem,
        name: c.name,
        version: c.version,
      });
      const alert = (a) => ({ ...a, component: describe(a.component) });
      const group = (g) => ({ ...g, alerts: g.alerts.map(alert) });
      model.vulnerabilities = {
        ...vulnerabilities,
        alerts: vulnerabilities.alerts.map(alert),
        groups: vulnerabilities.groups.map(group),
        platform: {
          ...vulnerabilities.platform,
          filtered: vulnerabilities.platform.filtered.map(group),
        },
        unevaluated: vulnerabilities.unevaluated.map((u) => ({
          ...u,
          component: describe(u.component),
        })),
      };
    }
    return `${JSON.stringify(model, null, 2)}\n`;
  }
  return serializeBom(
    toCycloneDx(scan, { timestamp: timestampOption(values.timestamp) }),
  );
}

export function main(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        format: { type: "string", default: "cyclonedx" },
        output: { type: "string" },
        timestamp: { type: "string" },
        timings: { type: "boolean", default: false },
        vulns: { type: "boolean", default: false },
        db: { type: "string" },
        "no-runtime-vulns": { type: "boolean", default: false },
        "all-platforms": { type: "boolean", default: false },
      },
    });
  } catch (error) {
    process.stderr.write(`${error.message}\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const { values, positionals } = parsed;
  if (
    positionals.length !== 1 ||
    !["cyclonedx", "model"].includes(values.format) ||
    ((values.db !== undefined ||
      values["no-runtime-vulns"] ||
      values["all-platforms"]) &&
      !values.vulns)
  ) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const result = scanArtifact(positionals[0]);
  if (!result.ok) {
    process.stderr.write(
      `sbom-scan: ${result.error.tag}: ${result.error.message}\n`,
    );
    process.exitCode = 1;
    return;
  }
  if (values.vulns) {
    const db = openVulnDb(values.db ?? DEFAULT_DB);
    if (!db.ok) {
      process.stderr.write(`sbom-scan: ${db.error.tag}: ${db.error.message}\n`);
      process.exitCode = 1;
      return;
    }
    const started = process.hrtime.bigint();
    const excludeRuntime = values["no-runtime-vulns"];
    const matched = matchComponents(result.value.components, db.value, {
      excludeRuntime,
      platforms: result.value.platforms,
      allPlatforms: values["all-platforms"],
    });
    result.value.vulnerabilities = {
      snapshot: {
        id: db.value.snapshot.id,
        archives: db.value.snapshot.archives,
      },
      runtimeExcluded: excludeRuntime,
      ...matched,
    };
    result.value.calls.push(
      { command: "vulndb-load", elapsedMs: Math.round(db.value.loadMs()) },
      {
        command: "vuln-match (incl. load)",
        elapsedMs: Math.round(Number(process.hrtime.bigint() - started) / 1e6),
      },
    );
  }
  let text;
  try {
    text = render(result.value, values);
  } catch (error) {
    process.stderr.write(`sbom-scan: ${error.message}\n`);
    process.exitCode = 2;
    return;
  }
  if (values.timings)
    for (const call of result.value.calls)
      process.stderr.write(`sbom-scan: ${call.command} ${call.elapsedMs} ms\n`);
  if (values.output) writeFileSync(values.output, text);
  else process.stdout.write(text);
}
