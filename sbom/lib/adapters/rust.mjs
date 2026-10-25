// Rust adapter: packages recorded by cargo-auditable in the .dep-v0 section.
// - kind "build" (build-dependencies, proc-macros and their dependencies) → exclusion: not
//   linked into the binary (TRUTH_RULES.md). Their count is carried in every evidence entry.
// - kind null → runtime: the cargo-auditable format omits kind for runtime packages.
// - kind "runtime" → component; any other kind → component flagged "unrecognized" (fail
//   closed: kept rather than silently dropped).
// - root package → scan root; purl only when its source is crates.io.
// - non-crates.io sources (git, local, registry) → component without purl.
import { readRange, sha256 } from "../files.mjs";
import { makeComponent, makeUnknown } from "../model.mjs";
import { cargoPurl } from "../purl.mjs";
import { err, ok } from "../result.mjs";
import { readCargoAuditable } from "../rea.mjs";

export const LIMITATIONS = [
  "cargo: cargo-auditable never records [dev-dependencies] (e.g. itoa in rust-vuln is absent); they are not linked into release binaries, so nothing is lost for the shipped artifact, but their absence is not observable evidence.",
  "cargo: build-time packages (kind=build: build-dependencies, proc-macros and their dependencies) are excluded and listed as exclusions.",
  "cargo: cargo-auditable records the resolved graph, not linker output; a crate compiled but optimized away is still reported.",
  "cargo: the dependency graph is not exported.",
];

const KNOWN_KINDS = new Set([null, "runtime"]);

function packageEntry(pkg, evidence) {
  const ev = { ...evidence, kind: pkg.kind };
  if (pkg.kind === null)
    ev.kindInterpretation = "omitted kind treated as runtime";
  else if (!KNOWN_KINDS.has(pkg.kind))
    ev.kindInterpretation = "unrecognized kind kept";
  if (typeof pkg.version !== "string" || pkg.version === "")
    return {
      unknown: makeUnknown({
        ecosystem: "cargo",
        name: String(pkg.name),
        reason: "no version recorded",
        evidence: ev,
      }),
    };
  return {
    component: makeComponent({
      ecosystem: "cargo",
      name: pkg.name,
      version: pkg.version,
      source: "rea:inspect-rust-binary",
      evidence: ev,
      noPurl:
        pkg.source === "crates.io"
          ? null
          : `source ${JSON.stringify(pkg.source)} is not crates.io`,
    }),
  };
}

/** Pure mapping from cargo-auditable facts to the scan model. */
export function rustScanFromFacts(facts, artifact, sectionSha256) {
  const build = facts.packages.filter((p) => !p.root && p.kind === "build");
  const evidence = {
    artifact: { path: artifact.path, sha256: artifact.sha256 },
    location: { kind: "file-range", ...facts.section },
    sourceSha256: sectionSha256,
    reader: facts.reader,
    packagesInSection: facts.packages.length,
    excludedBuildCount: build.length,
  };
  const components = [];
  const unknowns = [];
  let root = null;
  for (const pkg of facts.packages) {
    if (pkg.root) {
      root = {
        ecosystem: "cargo",
        name: pkg.name,
        version: pkg.version,
        source: pkg.source,
        purl:
          pkg.source === "crates.io"
            ? (cargoPurl(pkg.name, pkg.version).value ?? null)
            : null,
        evidence,
      };
      continue;
    }
    if (pkg.kind === "build") continue;
    const entry = packageEntry(pkg, evidence);
    if (entry.component) components.push(entry.component);
    else unknowns.push(entry.unknown);
  }
  const limitations = [...LIMITATIONS];
  if (
    facts.packages.some((p) => !KNOWN_KINDS.has(p.kind) && p.kind !== "build")
  )
    limitations.push(
      "cargo: some packages carry an unrecognized kind and were kept.",
    );
  return {
    root,
    components,
    unknowns,
    exclusions: build.map((p) => ({
      ecosystem: "cargo",
      name: p.name,
      version: p.version,
      reason: "kind=build (build-dependency or proc-macro, not linked)",
    })),
    limitations,
  };
}

export function scanRust(artifact, read = readCargoAuditable) {
  const facts = read(artifact.path);
  if (!facts.ok) return facts;
  const value = facts.value;
  if (value.artifactSha256 !== null && value.artifactSha256 !== artifact.sha256)
    return err("artifact-changed", "artifact sha256 changed during the scan");
  const { offset, bytes } = value.section;
  const section =
    Number.isSafeInteger(offset) && Number.isSafeInteger(bytes)
      ? readRange(artifact.path, offset, bytes)
      : null;
  return ok({
    ...rustScanFromFacts(value, artifact, section ? sha256(section) : null),
    calls: [value.call],
  });
}
