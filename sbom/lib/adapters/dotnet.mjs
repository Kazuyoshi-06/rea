// .NET adapter (NuGet). Two sources, strongest first; no REA involved.
//
// 1. *.deps.json (dotnet publish): "libraries" entries of type "package" carry the exact NuGet
//    id and version in their key ("Serilog/3.1.1") and the .nupkg sha512. Confidence "high".
//    Type "project" (the app itself, referenced projects) and "runtimepack" are not packages:
//    the app named after the file becomes the scan root, the others exclusions.
// 2. Fallback, only when no usable deps.json exists: AssemblyInformationalVersion (else
//    AssemblyFileVersion) of each managed assembly, read from its CLI metadata.
//      - build metadata after "+" is dropped from the version (SemVer: ignored for precedence)
//        and kept in the evidence as `buildMetadata` / `rawValue`;
//      - the package id is assumed to be the assembly name (evidence `nameSource`);
//      - "medium" for a clean informational version, "low" when it carries a pre-release label
//        (Serilog ships "3.1.1-main-999d686d" for NuGet 3.1.1) or comes from AssemblyFileVersion;
//      - AssemblyVersion is never used: it is a binding version, not the package version.
//    An assembly with an entry point is an application: scan root, not a package.
// Satellite (culture) assemblies and non-managed files are skipped.
import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";
import { sha256, walkFiles } from "../files.mjs";
import { makeComponent, makeUnknown } from "../model.mjs";
import { err, ok } from "../result.mjs";
import { readCliAssembly } from "../readers/cli-metadata.mjs";

const MAX_DEPS_JSON_BYTES = 64 << 20;
const MANAGED_EXTENSION = /\.(?:dll|exe)$/i;
// A NuGet-style version: 1 to 4 numeric parts and an optional pre-release label.
const NUGET_VERSION = /^\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$/;

const DEPS_READER = { tool: "rea-sbom", command: "deps-json-reader" };
const CLI_READER = { tool: "rea-sbom", command: "cli-metadata-reader" };

export const LIMITATIONS = [
  "nuget: deps.json lists the packages the build resolved, not what the loader will map; a package listed there with no matching assembly in the directory is still reported.",
  "nuget: type=project and type=runtimepack libraries are not NuGet packages and are listed as exclusions.",
];
export const FALLBACK_LIMITATIONS = [
  "nuget: no usable deps.json; versions come from assembly attributes, not from NuGet. The package id is assumed to equal the assembly name, and one package shipping several assemblies would appear once per assembly.",
  "nuget: a self-contained publish without deps.json would list framework assemblies as packages; not tested.",
];

/** Split "Name/1.2.3" at the last "/". Returns null when either side is empty. */
function splitLibraryKey(key) {
  const slash = key.lastIndexOf("/");
  if (slash <= 0 || slash === key.length - 1) return null;
  return { name: key.slice(0, slash), version: key.slice(slash + 1) };
}

function depsJsonPart(artifact, file, bytes, json) {
  const base = {
    artifact: { path: artifact.path, sha256: artifact.sha256 },
    location: { kind: "file", path: file.rel, size: bytes.length },
    sourceSha256: sha256(bytes),
    reader: DEPS_READER,
  };
  const stem = basename(file.rel).replace(/\.deps\.json$/i, "");
  const part = {
    root: null,
    components: [],
    unknowns: [],
    exclusions: [],
  };
  for (const [key, library] of Object.entries(json.libraries ?? {})) {
    const type = library?.type;
    const parts = splitLibraryKey(key);
    if (type === "package") {
      const evidence = {
        ...base,
        library: key,
        nupkgSha512:
          typeof library.sha512 === "string" && library.sha512 !== ""
            ? library.sha512
            : null,
        packagePath: library.path ?? null,
      };
      if (parts === null) {
        part.unknowns.push(
          makeUnknown({
            ecosystem: "nuget",
            name: key,
            reason: "library key is not <name>/<version>",
            evidence,
          }),
        );
        continue;
      }
      part.components.push(
        makeComponent({
          ecosystem: "nuget",
          name: parts.name,
          version: parts.version,
          source: "rea-sbom:deps-json-reader",
          confidence: "high",
          evidence,
        }),
      );
    } else if (parts !== null && type === "project" && parts.name === stem) {
      part.root = {
        ecosystem: "nuget",
        name: parts.name,
        version: parts.version,
        purl: null,
        evidence: { ...base, library: key },
      };
    } else {
      part.exclusions.push({
        ecosystem: "nuget",
        name: parts?.name ?? key,
        version: parts?.version ?? null,
        reason: `deps.json library type=${JSON.stringify(type ?? null)} is not a NuGet package`,
      });
    }
  }
  return part;
}

/** Parse every deps.json under the directory. Returns {parts, failures}. */
function readDepsFiles(artifact, depsFiles) {
  const parts = [];
  const failures = [];
  for (const file of depsFiles) {
    let bytes;
    try {
      if (statSync(file.abs).size > MAX_DEPS_JSON_BYTES)
        throw new Error(`larger than ${MAX_DEPS_JSON_BYTES} bytes`);
      bytes = readFileSync(file.abs);
    } catch (error) {
      failures.push(`${file.rel}: ${error.message}`);
      continue;
    }
    let json;
    try {
      json = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
      failures.push(`${file.rel}: invalid JSON (${error.message})`);
      continue;
    }
    if (json === null || typeof json !== "object" || Array.isArray(json)) {
      failures.push(`${file.rel}: not a JSON object`);
      continue;
    }
    parts.push(depsJsonPart(artifact, file, bytes, json));
  }
  return { parts, failures };
}

/**
 * Version from the assembly attributes, or the reason there is none.
 * Returns {version, confidence, attribute, rawValue, buildMetadata, rejected[]} or {reason}.
 */
export function versionFromAttributes(attributes) {
  const rejected = [];
  const candidates = [
    ["informationalVersion", "AssemblyInformationalVersion"],
    ["fileVersion", "AssemblyFileVersion"],
  ];
  for (const [key, attribute] of candidates) {
    const found = attributes[key];
    if (found === undefined) continue;
    const plus = found.value.indexOf("+");
    const core = plus === -1 ? found.value : found.value.slice(0, plus);
    if (!NUGET_VERSION.test(core)) {
      rejected.push({ attribute, rawValue: found.value });
      continue;
    }
    const confidence =
      key === "informationalVersion" && !core.includes("-") ? "medium" : "low";
    return {
      version: core,
      confidence,
      attribute,
      found,
      rawValue: found.value,
      buildMetadata: plus === -1 ? null : found.value.slice(plus + 1),
      rejected,
    };
  }
  return {
    reason:
      rejected.length === 0
        ? "no AssemblyInformationalVersion or AssemblyFileVersion attribute"
        : `attribute value is not a NuGet-style version: ${rejected.map((r) => `${r.attribute}=${JSON.stringify(r.rawValue)}`).join(", ")}`,
    rejected,
  };
}

/** One assembly file (read by readCliAssembly) → root, component or unknown. */
function assemblyEntry(artifact, rel, assembly, attributes, entryPoint) {
  const chosen = versionFromAttributes(attributes);
  const base = {
    artifact: { path: artifact.path, sha256: artifact.sha256 },
    reader: CLI_READER,
    assemblyVersion: assembly.version,
    nameSource: "assembly-name",
  };
  if (chosen.reason !== undefined) {
    const evidence = {
      ...base,
      location: { kind: "file", path: rel },
      rejected: chosen.rejected,
    };
    if (entryPoint)
      return { root: { name: assembly.name, version: null, evidence } };
    return {
      unknown: makeUnknown({
        ecosystem: "nuget",
        name: assembly.name,
        reason: chosen.reason,
        evidence,
      }),
    };
  }
  const evidence = {
    ...base,
    location: {
      kind: "cli-attribute",
      path: rel,
      offset: chosen.found.offset,
      size: chosen.found.size,
    },
    sourceSha256: chosen.found.sourceSha256,
    attribute: chosen.attribute,
    rawValue: chosen.rawValue,
    buildMetadata: chosen.buildMetadata,
  };
  if (chosen.rejected.length > 0) evidence.rejected = chosen.rejected;
  if (entryPoint)
    return { root: { name: assembly.name, version: chosen.version, evidence } };
  return {
    component: makeComponent({
      ecosystem: "nuget",
      name: assembly.name,
      version: chosen.version,
      source: "rea-sbom:cli-metadata-reader",
      confidence: chosen.confidence,
      technique: "binary-analysis",
      evidence,
    }),
  };
}

function fallbackPart(artifact, assemblies) {
  const part = {
    root: null,
    components: [],
    unknowns: [],
    exclusions: [],
  };
  let skippedSatellites = 0;
  for (const { rel, value } of assemblies) {
    if (value.assembly.culture !== "") {
      skippedSatellites += 1;
      continue;
    }
    const entry = assemblyEntry(
      artifact,
      rel,
      value.assembly,
      value.attributes,
      value.entryPoint,
    );
    if (entry.root) {
      part.root ??= {
        ecosystem: "nuget",
        name: entry.root.name,
        version: entry.root.version,
        purl: null,
        evidence: entry.root.evidence,
      };
    } else if (entry.component) part.components.push(entry.component);
    else part.unknowns.push(entry.unknown);
  }
  return { part, skippedSatellites };
}

/** Publish directory: deps.json when usable, else the assemblies' own attributes. */
export function scanDotnetDirectory(artifact) {
  const { files } = walkFiles(artifact.path);
  const depsFiles = files.filter((f) => /\.deps\.json$/i.test(f.rel));
  const limitations = [...LIMITATIONS];
  const { parts, failures } = readDepsFiles(artifact, depsFiles);
  for (const failure of failures)
    limitations.push(`nuget: deps.json ignored: ${failure}`);
  if (parts.length > 0) {
    const merged = {
      root: parts.map((p) => p.root).find(Boolean) ?? null,
      components: parts.flatMap((p) => p.components),
      unknowns: parts.flatMap((p) => p.unknowns),
      exclusions: parts.flatMap((p) => p.exclusions),
    };
    return { ...merged, limitations };
  }
  limitations.push(...FALLBACK_LIMITATIONS);
  const assemblies = [];
  let malformed = 0;
  const unknowns = [];
  for (const file of files.filter((f) => MANAGED_EXTENSION.test(f.rel))) {
    const result = readCliAssembly(file.abs);
    if (result.ok) assemblies.push({ rel: file.rel, value: result.value });
    else if (result.error.tag === "malformed-cli-metadata") {
      malformed += 1;
      unknowns.push(
        makeUnknown({
          ecosystem: "nuget",
          name: file.rel,
          reason: `unreadable CLI metadata: ${result.error.message}`,
          evidence: {
            artifact: { path: artifact.path, sha256: artifact.sha256 },
            location: { kind: "file", path: file.rel },
            reader: CLI_READER,
          },
        }),
      );
    }
  }
  const { part, skippedSatellites } = fallbackPart(artifact, assemblies);
  if (skippedSatellites > 0)
    limitations.push(
      `nuget: ${skippedSatellites} satellite (culture) assemblies were skipped.`,
    );
  if (malformed > 0)
    limitations.push(`nuget: ${malformed} assemblies had unreadable metadata.`);
  return {
    ...part,
    unknowns: [...part.unknowns, ...unknowns],
    limitations,
  };
}

/** A single managed file given directly. Result<part>. */
export function scanDotnetAssembly(artifact) {
  const result = readCliAssembly(artifact.path);
  if (!result.ok) return result;
  const { assembly, entryPoint } = result.value;
  const name = basename(artifact.path);
  if (assembly.culture !== "")
    return err(
      "unsupported-artifact",
      `${name} is a satellite assembly (culture ${JSON.stringify(assembly.culture)})`,
    );
  const { part } = fallbackPart(artifact, [{ rel: name, value: result.value }]);
  const limitations = [
    ...FALLBACK_LIMITATIONS.slice(0, 1),
    "nuget: a single assembly was given; its identity comes from its own attributes and a sibling deps.json is not consulted.",
  ];
  if (entryPoint)
    limitations.push(
      "nuget: the assembly has an entry point: it is the application (scan root), not a package.",
    );
  return ok({ ...part, limitations });
}
