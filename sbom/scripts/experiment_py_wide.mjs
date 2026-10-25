#!/usr/bin/env node
// Held-out check of the PyInstaller bytecode spike: py-wide bundles 17 pinned distributions the
// module table was not tuned on, with no --copy-metadata. Build it first:
//   scripts/build_corpus.sh python_wide && node scripts/gen_truth.mjs py-wide
// Classifies every truth entry by how (and whether) the scan reported it, and lists everything
// reported that the truth does not contain. Writes s3/py-wide.json.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scanArtifact } from "../lib/scan.mjs";
import { OUT, SBOM, readTruth } from "../test/support.mjs";

const scan = scanArtifact(join(OUT, "py-wide", "py-wide"));
if (!scan.ok) throw new Error(JSON.stringify(scan.error));
const norm = (n) => n.toLowerCase().replace(/[-_.]+/g, "-");
const truth = readTruth("py-wide");
const components = scan.value.components;
const unknowns = scan.value.unknowns;
const moduleOf = (u) => u.evidence[0].module ?? u.name;

const rows = truth.map((t) => {
  const component = components.find((c) => norm(c.name) === norm(t.name));
  if (component)
    return {
      truth: `${t.name}@${t.version}`,
      outcome: component.version === t.version ? "exact" : "wrong-version",
      confidence: component.confidence,
      reported: component.version,
    };
  const unknown = unknowns.find(
    (u) => norm(u.name) === norm(t.name) || norm(moduleOf(u)) === norm(t.name),
  );
  if (unknown) {
    const observed = unknown.evidence[0].observedLiteral?.value ?? null;
    return {
      truth: `${t.name}@${t.version}`,
      outcome: "unknown",
      observedLiteral: observed,
      observedMatchesTruth: observed === null ? null : observed === t.version,
      reason: unknown.reason,
    };
  }
  return { truth: `${t.name}@${t.version}`, outcome: "absent" };
});
const truthNames = new Set(truth.map((t) => norm(t.name)));
const extra = components
  .filter((c) => !truthNames.has(norm(c.name)))
  .map((c) => ({ name: c.name, version: c.version, confidence: c.confidence }));

const count = (f) => rows.filter(f).length;
const summary = {
  truth: truth.length,
  reported_exact: count((r) => r.outcome === "exact"),
  reported_exact_high: count(
    (r) => r.outcome === "exact" && r.confidence === "high",
  ),
  reported_exact_low: count(
    (r) => r.outcome === "exact" && r.confidence === "low",
  ),
  reported_wrong: count((r) => r.outcome === "wrong-version"),
  unknown: count((r) => r.outcome === "unknown"),
  unknown_with_correct_observed_literal: count(
    (r) => r.observedMatchesTruth === true,
  ),
  absent: count((r) => r.outcome === "absent"),
  reported_not_in_truth: extra,
};
mkdirSync(join(SBOM, "s3"), { recursive: true });
writeFileSync(
  join(SBOM, "s3/py-wide.json"),
  `${JSON.stringify({ summary, rows }, null, 2)}\n`,
);
console.log(JSON.stringify(summary, null, 2));
for (const r of rows)
  console.log(
    `${r.outcome.padEnd(13)} ${r.truth.padEnd(28)} ${r.confidence ?? ""} ${r.observedLiteral ?? ""} ${r.reason ? `— ${r.reason.slice(0, 110)}` : ""}`,
  );
