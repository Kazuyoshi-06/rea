// cargo-auditable reader, written from the format description (see NOTICE.md); no code from REA.
//
// `cargo auditable build` stores the resolved dependency graph as zlib-compressed JSON in a
// linker section: ".dep-v0" in ELF and PE, "__dep_v0" in Mach-O (any segment). JSON:
//   {"packages": [{"name", "version", "source", "kind"?, "dependencies"?: [index], "root"?}],
//    "format"?: n}
// Omitted fields take their defaults: kind "runtime" (kept null here: the adapter interprets
// it), dependencies [], root false, format 0. Section lookup uses the container structure only
// (lib/readers/executable.mjs): the section name in the bytes says nothing about where the data
// is. A fat Mach-O is read slice by slice: one result only when every slice has the section
// with the same packages (fat-slices-differ otherwise).
import { inflateSync } from "node:zlib";
import { withSource } from "../files.mjs";
import { err, ok } from "../result.mjs";
import { findSections, readExecutable } from "./executable.mjs";

// Resource guards (not format limits): real sections are a few KiB (a 400-crate workspace
// compresses to ~10 KiB); the inflated JSON is capped before it is materialized.
export const LIMITS = {
  sectionBytes: 4 << 20,
  jsonBytes: 32 << 20,
  packages: 100_000,
};

const READER = { tool: "rea-sbom", command: "cargo-auditable-reader" };
const SECTIONS = [
  { format: "elf", name: ".dep-v0" },
  { format: "pe", name: ".dep-v0" },
  { format: "macho", name: "__dep_v0" },
];

const malformed = (message) => err("malformed-cargo-auditable", message);

/** The cargo-auditable section of one image, or null. */
function locate(image) {
  for (const { format, name } of SECTIONS)
    for (const hit of findSections({ images: [image] }, name))
      if (hit.image.format === format && !hit.section.nobits) return hit;
  return null;
}

/** Inflate with an output cap. Result<Buffer>. */
export function inflateBounded(bytes, maxOutputLength) {
  try {
    return ok(inflateSync(bytes, { maxOutputLength }));
  } catch (error) {
    if (error?.code === "ERR_BUFFER_TOO_LARGE")
      return err(
        "cargo-auditable-too-large",
        `inflated JSON exceeds ${maxOutputLength} bytes`,
      );
    return malformed(`zlib: ${error.message}`);
  }
}

const isIndex = (n, count) => Number.isSafeInteger(n) && n >= 0 && n < count;

/** Validated packages of the decoded JSON. Result<{packages, formatVersion}>. */
export function parseAuditJson(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (error) {
    return malformed(`JSON: ${error.message}`);
  }
  if (doc === null || typeof doc !== "object" || !Array.isArray(doc.packages))
    return malformed("no packages array");
  const format = doc.format ?? 0;
  if (!Number.isSafeInteger(format) || format < 0)
    return malformed(`format ${JSON.stringify(doc.format)}`);
  if (doc.packages.length > LIMITS.packages)
    return malformed(
      `${doc.packages.length} packages (limit ${LIMITS.packages})`,
    );
  const count = doc.packages.length;
  const packages = [];
  for (const [i, p] of doc.packages.entries()) {
    const deps = p?.dependencies ?? [];
    if (
      typeof p?.name !== "string" ||
      typeof p.version !== "string" ||
      typeof p.source !== "string" ||
      !(p.kind === undefined || typeof p.kind === "string") ||
      !Array.isArray(deps) ||
      !deps.every((d) => isIndex(d, count)) ||
      !(p.root === undefined || typeof p.root === "boolean")
    )
      return malformed(`package ${i} does not match the format`);
    packages.push({
      name: p.name,
      version: p.version,
      source: p.source,
      kind: p.kind ?? null,
      dependencies: [...deps],
      root: p.root === true,
    });
  }
  return ok({ packages, formatVersion: format });
}

/**
 * Read the cargo-auditable section of the file at `path`.
 * Result tags: not-executable, malformed-executable, packed-executable, no-cargo-auditable,
 * cargo-auditable-too-large, malformed-cargo-auditable, fat-slices-differ.
 * Value: {reader, artifactBytes, section: {name, offset, bytes, formatVersion}, packages[], call}
 */
export function readCargoAuditable(path) {
  const started = process.hrtime.bigint();
  const result = withSource(path, (source) => {
    const executable = readExecutable(source);
    if (!executable.ok) return executable;
    if (executable.value.packer !== null)
      return err(
        "packed-executable",
        `${executable.value.packer.toUpperCase()}-packed executable: sections are compressed, not read`,
      );
    const { images } = executable.value;
    const read = images.map((image) => readSection(source, locate(image)));
    if (executable.value.format !== "fat") return read[0];
    // Fat Mach-O: every slice must carry the same packages.
    const label = (i) =>
      `slice ${i} (cputype 0x${(images[i].cpuType ?? 0).toString(16)})`;
    const failed = read.findIndex((r) => !r.ok);
    if (failed !== -1)
      return err(
        "fat-slices-differ",
        `${label(failed)}: ${read[failed].error.tag}: ${read[failed].error.message}`,
      );
    for (let i = 1; i < read.length; i += 1)
      if (
        JSON.stringify(read[i].value.packages) !==
          JSON.stringify(read[0].value.packages) ||
        read[i].value.section.formatVersion !==
          read[0].value.section.formatVersion
      )
        return err(
          "fat-slices-differ",
          `${label(0)} and ${label(i)} record different packages`,
        );
    return read[0];
  });
  if (!result.ok) return result;
  const elapsedMs = Math.round(Number(process.hrtime.bigint() - started) / 1e6);
  return ok({ ...result.value, call: { command: READER.command, elapsedMs } });
}

function readSection(source, hit) {
  if (hit === null)
    return err("no-cargo-auditable", "no .dep-v0 / __dep_v0 section");
  const { section } = hit;
  if (section.bytes > LIMITS.sectionBytes)
    return err(
      "cargo-auditable-too-large",
      `section of ${section.bytes} bytes (limit ${LIMITS.sectionBytes})`,
    );
  const bytes = source.read(section.offset, section.bytes);
  if (bytes === null)
    return malformed(
      `section (offset ${section.offset}, ${section.bytes} bytes) lies outside the file`,
    );
  const json = inflateBounded(bytes, LIMITS.jsonBytes);
  if (!json.ok) return json;
  const parsed = parseAuditJson(json.value.toString("utf8"));
  if (!parsed.ok) return parsed;
  return ok({
    reader: READER,
    artifactBytes: source.size,
    section: {
      name: section.name,
      offset: section.offset,
      bytes: section.bytes,
      formatVersion: parsed.value.formatVersion,
    },
    packages: parsed.value.packages,
  });
}
