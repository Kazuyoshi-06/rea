// PyInstaller adapter (PyPI), pure Node.
//
// Path 1 — distribution metadata (confidence "high"): `<name>-<version>.dist-info/METADATA`
//   entries embedded by `--copy-metadata`; Name and Version are read from the headers.
// Path 2 — bytecode spike (confidence "low"), only for modules no dist-info accounts for: the
//   root module of each third-party package is read from the PYZ and a version is reported only
//   when `__version__`, `version` or `VERSION` is bound to ONE string constant, directly or
//   through `from .sub import name` chains inside the package (see resolveBinding). The string
//   must also parse as a PEP 440 version. Anything else — computed values, several bindings,
//   other packages' names, an unsupported interpreter — is an unknown with its reason.
//
// Standard-library modules are removed with the sys.stdlib_module_names list recorded for the
// archive's Python minor version (data/); without that list the bytecode path is not attempted.
// The distribution name of a module comes from the static table in pypi-modules.mjs only.
// Versions (both paths) are emitted in their PEP 440 normal form ("2023.07.22" → "2023.7.22");
// the string as read stays in the evidence as `rawValue`. A dist-info Version that is not
// PEP 440 is kept verbatim and flagged (`pep440: "invalid"` in the evidence and a limitation).
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { makeComponent, makeUnknown } from "../model.mjs";
import { ok } from "../result.mjs";
import { moduleBindings } from "../readers/pybytecode.mjs";
import { canonicalPep440 } from "../versions/pep440.mjs";
import { openPyInstaller, openPyz } from "../readers/pyinstaller.mjs";
import { MODULE_DISTRIBUTIONS } from "./pypi-modules.mjs";

const DATA = join(dirname(fileURLToPath(import.meta.url)), "../../data");
const READER = { tool: "rea-sbom", command: "pyinstaller-reader" };
const VERSION_NAMES = ["__version__", "version", "VERSION"];
const MAX_FOLLOW = 3;
const MAX_METADATA_BYTES = 8 << 20;
// Modules the PyInstaller runtime adds to the archive itself.
const RUNTIME_MODULE = /^(?:pyimod|_pyi_rth_utils|pyi_rth_)/;

// Release segments that are all zeros ("0", "0.0.0", "0.dev0+unknown"): the placeholder a
// build-time version script leaves in the source (setuptools ships "0.dev0+unknown"), not a
// version anyone published.
const PLACEHOLDER =
  /^v?0+(?:\.0+)*(?:[-_.]?(?:dev|a|b|rc|post)[0-9]*)*(?:\+.*)?$/i;

export const LIMITATIONS = [
  "pypi: only PyInstaller onefile archives built by PyInstaller 6.x are read (checked on 6.10 / CPython 3.13); onedir builds and other layouts were not tested.",
  "pypi: dist-info entries are read from the archive's TOC (--copy-metadata); packages PyInstaller embedded without metadata are only seen through their PYZ modules.",
  "pypi: a package made only of extension modules (no Python module in the PYZ) is not seen.",
  "pypi: bytecode versions have low confidence: the constant is the one the package's own code binds, which is not guaranteed to be the version of the installed distribution.",
  "pypi: the module → distribution table is short (see pypi-modules.mjs); other modules are reported as modules.",
];

const normalizeName = (name) => name.toLowerCase().replace(/[-_.]+/g, "-");

function loadStdlib(minor) {
  const file = join(DATA, `stdlib-module-names-${minor}.json`);
  if (!existsSync(file)) return null;
  return new Set(JSON.parse(readFileSync(file, "utf8")).names);
}

/** RFC 822 style header block (core metadata): first value of each header, until a blank line. */
export function parseMetadataHeaders(text) {
  const headers = new Map();
  let last = null;
  for (const line of text.split(/\r?\n/)) {
    if (line === "") break;
    if (/^[ \t]/.test(line)) {
      continue; // folded continuation; Name and Version are never folded
    }
    const colon = line.indexOf(":");
    if (colon <= 0) {
      last = null;
      continue;
    }
    last = line.slice(0, colon).toLowerCase();
    if (!headers.has(last)) headers.set(last, line.slice(colon + 1).trim());
  }
  return headers;
}

function distInfoPhase(archive, base, part, limitations) {
  const covered = { names: new Set(), modules: new Set(), distributions: 0 };
  const entries = archive.entries.filter((e) => e.type === "x");
  const metadata = entries
    .filter((e) => /^[^/]+\.dist-info\/METADATA$/.test(e.name))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of metadata) {
    const dir = entry.name.slice(0, entry.name.indexOf("/"));
    const read = archive.readEntry(entry);
    const evidenceBase = {
      ...base,
      distInfo: dir,
    };
    if (!read.ok || read.value.data.length > MAX_METADATA_BYTES) {
      part.unknowns.push(
        makeUnknown({
          ecosystem: "pypi",
          name: dir.replace(/\.dist-info$/, ""),
          reason: read.ok ? "METADATA too large" : read.error.message,
          evidence: {
            ...evidenceBase,
            location: { kind: "pyinstaller-entry", path: entry.name },
          },
        }),
      );
      continue;
    }
    const { data, offset, size, sourceSha256 } = read.value;
    const headers = parseMetadataHeaders(data.toString("utf8"));
    const name = headers.get("name") ?? "";
    const version = headers.get("version") ?? "";
    const evidence = {
      ...evidenceBase,
      location: { kind: "pyinstaller-entry", path: entry.name, offset, size },
      sourceSha256,
    };
    if (name === "" || version === "") {
      part.unknowns.push(
        makeUnknown({
          ecosystem: "pypi",
          name: name || dir.replace(/\.dist-info$/, ""),
          reason: `METADATA has no ${name === "" ? "Name" : "Version"} header`,
          evidence,
        }),
      );
      continue;
    }
    const canonical = canonicalPep440(version);
    evidence.rawValue = version;
    if (!canonical.ok) {
      evidence.pep440 = "invalid";
      limitations.push(
        `pypi: ${dir}: Version ${JSON.stringify(version)} is not PEP 440; emitted verbatim, not normalized.`,
      );
    }
    part.components.push(
      makeComponent({
        ecosystem: "pypi",
        name,
        version: canonical.ok ? canonical.value : version,
        source: "rea-sbom:pyinstaller-reader",
        confidence: "high",
        technique: "manifest-analysis",
        evidence,
      }),
    );
    covered.distributions += 1;
    covered.names.add(normalizeName(name));
    const topLevel = entries.find((e) => e.name === `${dir}/top_level.txt`);
    const top = topLevel ? archive.readEntry(topLevel) : null;
    if (top?.ok)
      for (const line of top.value.data.toString("utf8").split(/\r?\n/))
        if (line.trim() !== "") covered.modules.add(line.trim());
  }
  return covered;
}

/**
 * Value bound to `name` in `moduleName`, following in-package `from .x import y` chains.
 * Returns {literal, module, constant, chain[], code-evidence} or {failure}.
 */
function resolveBinding(ctx, moduleName, name, depth, chain) {
  const step = `${moduleName}:${name}`;
  if (chain.includes(step)) return { failure: `import cycle at ${step}` };
  const loaded = ctx.load(moduleName);
  if (!loaded.ok)
    return { failure: `module ${moduleName}: ${loaded.error.message}` };
  const list = loaded.value.bindings.get(name) ?? [];
  if (list.length === 0)
    return { failure: `${name} is not bound in module ${moduleName}` };
  const here = [...chain, step];
  const resolved = list.map((binding) => {
    if (binding.kind === "const")
      return typeof binding.value === "string"
        ? {
            literal: binding.value,
            module: moduleName,
            constant: name,
            chain: here,
            source: loaded.value.source,
          }
        : {
            failure: `${name} in ${moduleName} is bound to a non-string constant`,
          };
    if (binding.kind !== "import-from")
      return {
        failure: `${name} in ${moduleName} is not a constant (computed or imported otherwise)`,
      };
    if (depth >= MAX_FOLLOW)
      return {
        failure: `import chain from ${moduleName} is deeper than ${MAX_FOLLOW}`,
      };
    const target = ctx.importTarget(moduleName, binding);
    if (target === null)
      return {
        failure: `${name} in ${moduleName} imports a module outside the package`,
      };
    return resolveBinding(ctx, target, binding.imported, depth + 1, here);
  });
  const literals = resolved.filter((r) => r.literal !== undefined);
  if (resolved.length > 1) {
    const distinct = new Set(literals.map((r) => r.literal));
    if (literals.length === resolved.length && distinct.size === 1)
      return literals[0];
    return {
      failure: `${name} has ${resolved.length} bindings in ${moduleName}; no single constant`,
    };
  }
  return resolved[0];
}

function versionFromModule(ctx, root) {
  const results = VERSION_NAMES.map((n) => resolveBinding(ctx, root, n, 0, []));
  const literals = results.filter((r) => r.literal !== undefined);
  const distinct = new Set(literals.map((r) => r.literal));
  if (distinct.size > 1)
    return {
      failure: `conflicting constants: ${[...distinct].map((v) => JSON.stringify(v)).join(", ")}`,
    };
  if (literals.length === 0) {
    const detail = results.map((r) => r.failure).filter(Boolean);
    const informative =
      detail.find((d) => !d.includes("is not bound in module")) ?? detail[0];
    return { failure: informative };
  }
  const found = literals[0];
  if (PLACEHOLDER.test(found.literal))
    return {
      failure: `constant ${JSON.stringify(found.literal)} (${found.constant} in ${found.module}) is a placeholder, not a release version`,
      observed: found,
    };
  if (!canonicalPep440(found.literal).ok)
    return {
      failure: `constant ${JSON.stringify(found.literal)} (${found.constant} in ${found.module}) is not a PEP 440 version`,
      observed: found,
    };
  return found;
}

/** Module loader and in-package import resolution over one PYZ, with a per-module cache. */
function moduleContext(pyz) {
  const cache = new Map();
  const load = (moduleName) => {
    if (cache.has(moduleName)) return cache.get(moduleName);
    let loaded;
    if (!pyz.has(moduleName))
      loaded = { ok: false, error: { message: "not in the PYZ" } };
    else {
      const m = pyz.module(moduleName);
      loaded = m.ok
        ? ok({
            bindings: moduleBindings(m.value.code),
            source: {
              offset: m.value.offset,
              size: m.value.size,
              sourceSha256: m.value.sourceSha256,
            },
          })
        : m;
    }
    cache.set(moduleName, loaded);
    return loaded;
  };
  /** Module a `from <dots><module> import x` in `from` refers to, inside its package only. */
  const importTarget = (from, binding) => {
    const root = from.split(".")[0];
    let target = binding.module;
    if (binding.level > 0) {
      const segments = from.split(".");
      const parent = pyz.isPackage(from) ? segments : segments.slice(0, -1);
      const kept = parent.slice(0, parent.length - (binding.level - 1));
      if (kept.length === 0) return null;
      target = [...kept, ...(binding.module ? [binding.module] : [])].join(".");
    }
    return target === root || target.startsWith(`${root}.`) ? target : null;
  };
  return { load, importTarget };
}

/** One third-party top-level module → a component, or an unknown with the reason. */
function reportModule(ctx, top, distribution, evidenceBase) {
  const found = versionFromModule(ctx, top);
  const evidence = {
    ...evidenceBase,
    module: top,
    distributionNameSource: distribution === null ? "none" : "static-table",
  };
  if (found.literal !== undefined && distribution !== null)
    return {
      component: makeComponent({
        ecosystem: "pypi",
        name: distribution,
        version: canonicalPep440(found.literal).value,
        source: "rea-sbom:pyinstaller-reader",
        confidence: "low",
        technique: "binary-analysis",
        evidence: {
          ...evidence,
          location: {
            kind: "pyz-module",
            path: found.module,
            offset: found.source.offset,
            size: found.source.size,
          },
          sourceSha256: found.source.sourceSha256,
          constant: found.constant,
          rawValue: found.literal,
          resolvedThrough: found.chain,
        },
      }),
    };
  // A literal that was found but cannot be attributed (no table entry) or accepted (not a
  // version) stays evidence of the unknown; it is never the version of a component.
  const observed = found.literal !== undefined ? found : found.observed;
  const why = found.literal !== undefined ? "" : `; ${found.failure}`;
  return {
    unknown: makeUnknown({
      ecosystem: "pypi",
      name: distribution ?? top,
      reason:
        distribution === null
          ? `module ${top} found in the PYZ; its distribution name is not in the module table${why}`
          : `module ${top}: ${found.failure}`,
      evidence: {
        ...evidence,
        location: { kind: "pyz-module", path: top },
        ...(observed
          ? {
              observedLiteral: {
                module: observed.module,
                constant: observed.constant,
                value: observed.literal,
              },
            }
          : {}),
      },
    }),
  };
}

function scanPyz(pyz, stdlib, covered, evidenceBase, part) {
  const ctx = moduleContext(pyz);
  const tops = [...new Set(pyz.names.map((n) => n.split(".")[0]))].sort();
  for (const top of tops) {
    if (stdlib.has(top)) continue;
    if (RUNTIME_MODULE.test(top)) {
      part.exclusions.push({
        ecosystem: "pypi",
        name: top,
        version: null,
        reason: "PyInstaller runtime module",
      });
      continue;
    }
    const distribution = Object.hasOwn(MODULE_DISTRIBUTIONS, top)
      ? MODULE_DISTRIBUTIONS[top]
      : null;
    const isCovered =
      covered.modules.has(top) ||
      covered.names.has(normalizeName(top)) ||
      (distribution !== null && covered.names.has(normalizeName(distribution)));
    if (isCovered) continue;
    const entry = reportModule(ctx, top, distribution, {
      ...evidenceBase,
      pythonVersion: pyz.python,
    });
    if (entry.component) part.components.push(entry.component);
    else part.unknowns.push(entry.unknown);
  }
}

function bytecodePhase(archive, evidenceBase, covered, part, limitations) {
  const pyzEntries = archive.entries.filter((e) => e.type === "z");
  if (pyzEntries.length === 0) {
    limitations.push("pypi: the archive has no PYZ entry.");
    return;
  }
  const stdlib = loadStdlib(archive.pythonVersion);
  if (stdlib === null) {
    limitations.push(
      `pypi: no standard-library module list recorded for Python ${archive.pythonVersion}; PYZ modules were not examined.`,
    );
    return;
  }
  for (const entry of pyzEntries) {
    const opened = openPyz(archive, entry);
    if (opened.ok) scanPyz(opened.value, stdlib, covered, evidenceBase, part);
    else
      limitations.push(
        `pypi: ${entry.name}: ${opened.error.tag}: ${opened.error.message}`,
      );
  }
}

export function scanPyInstaller(artifact) {
  const opened = openPyInstaller(artifact.path, artifact.bytes);
  if (!opened.ok) return opened;
  const archive = opened.value;
  const base = {
    artifact: { path: artifact.path, sha256: artifact.sha256 },
    reader: READER,
    pythonVersion: archive.pythonVersion,
  };
  const part = { root: null, components: [], unknowns: [], exclusions: [] };
  const limitations = [...LIMITATIONS];
  const covered = distInfoPhase(archive, base, part, limitations);
  bytecodePhase(archive, base, covered, part, limitations);
  return ok({ ...part, limitations });
}
