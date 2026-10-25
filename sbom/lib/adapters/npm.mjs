// npm adapter: installed packages from node_modules/**/package.json inside an ASAR archive or
// a directory. Layout followed: <root>/node_modules/<name> and <root>/node_modules/@scope/<name>,
// recursively through each package's own node_modules (npm nesting). Other directories are not
// searched. The package's identity is its package.json "name" and "version".
import { sha256 } from "../files.mjs";
import { makeComponent, makeUnknown } from "../model.mjs";

const reader = (tree) => ({
  tool: "rea-sbom",
  command:
    tree.kind === "asar" ? "asar-reader" : "node-modules-directory-reader",
});

function readManifest(tree, segments) {
  const file = tree.readFile(segments);
  if (!file.ok) return file;
  const { bytes, location } = file.value;
  let json = null;
  let parseError = null;
  try {
    json = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    parseError = error.message;
  }
  if (json === null || typeof json !== "object" || Array.isArray(json))
    parseError ??= "package.json is not a JSON object";
  return {
    ok: true,
    value: { json, parseError, location, sourceSha256: sha256(bytes) },
  };
}

const text = (value) =>
  typeof value === "string" && value.trim() !== "" ? value : null;

function visitPackage(ctx, segments, installName) {
  const installPath = segments.join("/");
  const manifest = readManifest(ctx.tree, [...segments, "package.json"]);
  if (!manifest.ok) {
    const reason =
      manifest.error.tag === "missing"
        ? "no package.json in installed package directory"
        : manifest.error.message;
    ctx.unknowns.push(
      makeUnknown({
        ecosystem: "npm",
        name: installName,
        reason,
        evidence: { ...ctx.base, installPath },
      }),
    );
    return;
  }
  const { json, parseError, location, sourceSha256 } = manifest.value;
  const evidence = { ...ctx.base, location, sourceSha256, installPath };
  if (location.asarIntegrity === "mismatch") ctx.integrityMismatches += 1;
  const declared = parseError === null ? text(json.name) : null;
  const version = parseError === null ? text(json.version) : null;
  if (declared !== null && declared !== installName)
    evidence.installedAs = installName;
  if (version === null) {
    ctx.unknowns.push(
      makeUnknown({
        ecosystem: "npm",
        name: declared ?? installName,
        reason: parseError ?? "package.json has no version",
        evidence,
      }),
    );
    return;
  }
  ctx.components.push(
    makeComponent({
      ecosystem: "npm",
      name: declared ?? installName,
      version,
      source: `${ctx.base.reader.tool}:${ctx.base.reader.command}`,
      confidence: declared === null ? "medium" : "high",
      evidence,
    }),
  );
}

function visitNodeModules(ctx, segments) {
  const entries = ctx.tree.entries(segments);
  if (entries === null) return;
  const packages = [];
  for (const entry of entries) {
    if (entry.name.startsWith(".")) continue; // .bin, .package-lock.json, .pnpm
    if (entry.type === "invalid") {
      ctx.invalidNames += 1;
      continue;
    }
    if (entry.name.startsWith("@") && entry.type === "dir") {
      for (const inner of ctx.tree.entries([...segments, entry.name]) ?? []) {
        if (inner.name.startsWith(".")) continue;
        packages.push({ ...inner, scope: entry.name });
      }
      continue;
    }
    packages.push(entry);
  }
  for (const entry of packages) {
    const installName = entry.scope
      ? `${entry.scope}/${entry.name}`
      : entry.name;
    const path = entry.scope
      ? [...segments, entry.scope, entry.name]
      : [...segments, entry.name];
    if (entry.type === "link") {
      ctx.unknowns.push(
        makeUnknown({
          ecosystem: "npm",
          name: installName,
          reason: "symbolic link not followed",
          evidence: { ...ctx.base, installPath: path.join("/") },
        }),
      );
      continue;
    }
    if (entry.type === "invalid") ctx.invalidNames += 1;
    if (entry.type !== "dir") continue;
    visitPackage(ctx, path, installName);
    visitNodeModules(ctx, [...path, "node_modules"]);
  }
}

function readRoot(ctx) {
  const manifest = readManifest(ctx.tree, ["package.json"]);
  if (!manifest.ok || manifest.value.parseError !== null) return null;
  const { json, location, sourceSha256 } = manifest.value;
  const name = text(json.name);
  if (name === null) return null;
  return {
    ecosystem: "npm",
    name,
    version: text(json.version),
    purl: null,
    evidence: { ...ctx.base, location, sourceSha256 },
  };
}

/** artifact: {path, sha256}; tree: asarTree(...) or directoryTree(...). */
export function scanNpm(artifact, tree) {
  const ctx = {
    tree,
    base: {
      artifact: { path: artifact.path, sha256: artifact.sha256 },
      reader: reader(tree),
    },
    components: [],
    unknowns: [],
    invalidNames: 0,
    integrityMismatches: 0,
  };
  visitNodeModules(ctx, ["node_modules"]);
  const limitations = [
    "npm: only <root>/node_modules and nested <package>/node_modules are read; packages elsewhere (workspaces, bundled vendor copies) are not reported.",
    "npm: identity comes from each installed package.json; it is not checked against a registry or lockfile.",
  ];
  if (ctx.invalidNames > 0)
    limitations.push(
      `npm: ${ctx.invalidNames} archive entries with unusable names (empty, '.', '..', or containing a separator) were skipped.`,
    );
  if (ctx.integrityMismatches > 0)
    limitations.push(
      `npm: ${ctx.integrityMismatches} package.json entries do not match their ASAR integrity hash (evidence asarIntegrity=mismatch).`,
    );
  return {
    root: readRoot(ctx),
    components: ctx.components,
    unknowns: ctx.unknowns,
    exclusions: [],
    limitations,
  };
}
