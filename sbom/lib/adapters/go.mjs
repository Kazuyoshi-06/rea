// Go adapter: modules recorded by the Go linker in the binary's build information.
// Decisions (TRUTH_RULES.md: root and language runtime are not components):
// - main module  → scan root (CycloneDX metadata.component); purl only for a real version,
//                  never for "(devel)".
// - stdlib       → component with role "language-runtime", name "stdlib", version from
//                  go_version "goX.Y.Z" → "X.Y.Z" (OSV convention). Kept so vulnerability
//                  matching can see the toolchain; excluded from truth comparison.
// - replace      → the replacement module is the shipped identity, the original is evidence;
//                  a local-directory replacement has no version and becomes an unknown.
import { readRange, sha256 } from "../files.mjs";
import { makeComponent, makeUnknown } from "../model.mjs";
import { golangPurl } from "../purl.mjs";
import { err, ok } from "../result.mjs";
import { readGoBuildInfo } from "../rea.mjs";

const DEVEL = "(devel)";
const hasVersion = (v) => typeof v === "string" && v !== "" && v !== DEVEL;

function dependency(dep, evidence) {
  const target = dep.replacement ?? dep;
  const ev = dep.replacement
    ? { ...evidence, replaces: { path: dep.path, version: dep.version } }
    : evidence;
  if (!hasVersion(target.version)) {
    const reason = dep.replacement
      ? `replaced by local directory ${JSON.stringify(dep.replacement.path)}`
      : `no module version recorded (${JSON.stringify(dep.version)})`;
    return {
      unknown: makeUnknown({
        ecosystem: "golang",
        name: dep.path,
        reason,
        evidence: ev,
      }),
    };
  }
  return {
    component: makeComponent({
      ecosystem: "golang",
      name: target.path,
      version: target.version,
      source: "rea:inspect-go-binary",
      evidence: ev,
    }),
  };
}

function stdlib(goVersion, evidence) {
  const match = /^go(\d+\.\d+\.\d+)$/.exec(goVersion ?? "");
  if (match === null)
    return {
      unknown: makeUnknown({
        ecosystem: "golang",
        name: "stdlib",
        reason: `toolchain version ${JSON.stringify(goVersion)} is not goX.Y.Z`,
        evidence,
      }),
    };
  return {
    component: makeComponent({
      ecosystem: "golang",
      name: "stdlib",
      version: match[1],
      source: "rea:inspect-go-binary",
      role: "language-runtime",
      evidence: { ...evidence, goVersion },
    }),
  };
}

function limitationsOf(facts) {
  const out = [
    "golang: build information lists linked modules only; it carries no dependency graph, so none is exported.",
  ];
  if (!facts.complete)
    out.push("golang: REA reported the module metadata as incomplete.");
  const other = facts.unparsedLines.filter((l) => !/^(dep|=>)\t/.test(l));
  if (other.length > 0)
    out.push(
      `golang: ${other.length} unrecognized build-information lines ignored.`,
    );
  if (facts.unparsedBinaryLines > 0)
    out.push(
      `golang: ${facts.unparsedBinaryLines} non-UTF-8 build-information lines could not be read.`,
    );
  return out;
}

/** Pure mapping from Go build-information facts to the scan model. */
export function goScanFromFacts(facts, artifact, moduleSha256) {
  const evidence = {
    artifact: { path: artifact.path, sha256: artifact.sha256 },
    location: facts.moduleLocation
      ? {
          kind: "file-range",
          ...facts.moduleLocation,
          part: "go-buildinfo-modules",
        }
      : null,
    sourceSha256: moduleSha256,
    reader: facts.reader,
  };
  const components = [];
  const unknowns = [];
  const results = facts.dependencies.map((d) => dependency(d, evidence));
  results.push(stdlib(facts.goVersion, evidence));
  for (const line of facts.unparsedLines.filter((l) => /^(dep|=>)\t/.test(l)))
    unknowns.push(
      makeUnknown({
        ecosystem: "golang",
        name: line.split("\t")[1] ?? line,
        reason: `unparsed build-information line ${JSON.stringify(line)}`,
        evidence,
      }),
    );
  for (const r of results)
    if (r.component) components.push(r.component);
    else unknowns.push(r.unknown);
  const main = facts.main;
  return {
    root: main
      ? {
          ecosystem: "golang",
          name: main.path,
          version: hasVersion(main.version) ? main.version : null,
          rawVersion: main.version,
          purl: hasVersion(main.version)
            ? (golangPurl(main.path, main.version).value ?? null)
            : null,
          evidence,
        }
      : null,
    components,
    unknowns,
    exclusions: [],
    limitations: limitationsOf(facts),
  };
}

export function scanGo(artifact, read = readGoBuildInfo) {
  const facts = read(artifact.path);
  if (!facts.ok) return facts;
  const value = facts.value;
  if (value.artifactSha256 !== null && value.artifactSha256 !== artifact.sha256)
    return err("artifact-changed", "artifact sha256 changed during the scan");
  const loc = value.moduleLocation;
  const bytes = loc ? readRange(artifact.path, loc.offset, loc.bytes) : null;
  return ok({
    ...goScanFromFacts(value, artifact, bytes ? sha256(bytes) : null),
    calls: [value.call],
  });
}
