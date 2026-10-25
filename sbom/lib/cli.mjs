// Command-line adapter for sbom/bin/sbom-scan. Exit codes: 0 ok, 1 scan failure, 2 usage.
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { serializeBom, toCycloneDx } from "./cyclonedx.mjs";
import { scanArtifact } from "./scan.mjs";

const USAGE =
  "usage: sbom-scan <artifact> [--format cyclonedx|model] [--output FILE] [--timestamp ISO|EPOCH] [--timings]";

function timestampOption(value) {
  if (value !== undefined) return /^\d+$/.test(value) ? Number(value) : value;
  const epoch = process.env.SOURCE_DATE_EPOCH;
  return epoch !== undefined && /^\d+$/.test(epoch)
    ? Number(epoch)
    : new Date();
}

function render(scan, values) {
  if (values.format === "model") {
    const { calls: _calls, ...model } = scan;
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
    !["cyclonedx", "model"].includes(values.format)
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
