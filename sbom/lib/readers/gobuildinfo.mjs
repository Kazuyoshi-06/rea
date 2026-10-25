// Go build information reader, written from the format description (see NOTICE.md); no code
// from REA or from the Go standard library.
//
// The Go linker (1.13+) writes a 32-byte header aligned on 16 bytes:
//   0..13   magic "\xff Go buildinf:"
//   14      pointer size (4 or 8)
//   15      flags: bit 0 big-endian (pointer format only), bit 1 strings inline (Go ≥ 1.18)
// Inline format: right after the header, two strings each prefixed by an unsigned LEB128
// length: the toolchain version ("go1.24.7") then the module information. Pointer format
// (Go < 1.18): two pointers to Go string headers in the data segment; refused with
// "go-buildinfo-pointer-format" (it needs virtual-address mapping, not implemented).
// The module information is wrapped in two 16-byte sentinels; it is used only when it is at
// least 33 bytes long and its byte before the trailing sentinel is "\n" (complete = true).
// Lines, tab-separated:
//   path\t<main package path>
//   mod\t<path>\t<version>[\t<sum>]     main module
//   dep\t<path>\t<version>[\t<sum>]     dependency
//   =>\t<path>\t<version>[\t<sum>]      replacement of the previous mod/dep line
//   build\t<key>=<value>                build setting
// Empty lines are skipped. Anything else, or a line with too few fields, is kept verbatim in
// unparsedLines; a line that is not valid UTF-8 is only counted (unparsedBinaryLines).
//
// Location: the section that holds the header (ELF ".go.buildinfo", Mach-O "__go_buildinfo",
// PE ".data") searched at 16-byte steps; when the structure gives none (no section table,
// unknown container), the whole file is searched for the magic. -s -w does not remove the
// section (it is data, not a symbol table).
import { forEachChunk, withSource } from "../files.mjs";
import { err, ok } from "../result.mjs";
import { findSections, readExecutable } from "./executable.mjs";

export const MAGIC = Buffer.from("\xff Go buildinf:", "latin1");
const HEADER_BYTES = 32;
const FLAG_INLINE = 2;
const SENTINEL_BYTES = 16;

// Resource guards (not format limits): the largest module information seen on real binaries is
// tens of KiB; the section search reads at most this much of a candidate section.
export const LIMITS = {
  versionBytes: 1024,
  moduleBytes: 8 << 20,
  sectionSearchBytes: 64 << 20,
};

const READER = { tool: "rea-sbom", command: "go-buildinfo-reader" };
const SECTION_NAMES = [
  { format: "elf", name: ".go.buildinfo" },
  { format: "macho", name: "__go_buildinfo" },
  { format: "pe", name: ".data" },
];

/** Unsigned LEB128 at `pos` (at most 9 bytes, value ≤ 2^53). Null when truncated or too long. */
export function uvarint(buffer, pos) {
  let value = 0;
  let scale = 1;
  for (let i = 0; i < 9 && pos + i < buffer.length; i += 1) {
    const byte = buffer[pos + i];
    value += (byte & 0x7f) * scale;
    if ((byte & 0x80) === 0)
      return Number.isSafeInteger(value) ? { value, bytes: i + 1 } : null;
    scale *= 128;
  }
  return null;
}

const isHeader = (bytes) =>
  bytes.length >= HEADER_BYTES && bytes.subarray(0, MAGIC.length).equals(MAGIC);

/** Header offsets inside candidate sections (16-byte steps from the section start). */
function sectionCandidates(source, executable) {
  const found = [];
  for (const { format, name } of SECTION_NAMES)
    for (const { image, section } of findSections(executable, name)) {
      if (image.format !== format || section.nobits) continue;
      const length = Math.min(section.bytes, LIMITS.sectionSearchBytes);
      const bytes = source.read(section.offset, length);
      if (bytes === null) continue;
      for (let at = 0; at + HEADER_BYTES <= bytes.length; at += 16)
        if (
          bytes[at] === 0xff &&
          isHeader(bytes.subarray(at, at + HEADER_BYTES))
        )
          found.push({
            offset: section.offset + at,
            end: section.offset + bytes.length,
            locatedBy: `section ${name}`,
          });
    }
  return found;
}

/** Fallback: every occurrence of the magic in the file, in file order. */
function markerCandidates(path) {
  const found = [];
  forEachChunk(path, MAGIC.length - 1, (chunk, start) => {
    for (
      let at = chunk.indexOf(MAGIC);
      at !== -1;
      at = chunk.indexOf(MAGIC, at + 1)
    ) {
      const offset = start + at;
      if (found.at(-1)?.offset !== offset)
        found.push({ offset, end: null, locatedBy: "marker-search" });
    }
  });
  return found;
}

/** Read one LEB128-prefixed string at `pos`; Result<{offset, bytes}>. */
function inlineString(source, pos, max, end, what) {
  const prefix = source.read(pos, Math.min(10, Math.max(0, source.size - pos)));
  const length = prefix === null ? null : uvarint(prefix, 0);
  if (length === null)
    return err("malformed-go-buildinfo", `${what}: unreadable length`);
  if (length.value > max)
    return err(
      "malformed-go-buildinfo",
      `${what}: ${length.value} bytes (limit ${max})`,
    );
  const offset = pos + length.bytes;
  if (end !== null && offset + length.value > end)
    return err("malformed-go-buildinfo", `${what}: runs past its section`);
  const bytes = source.read(offset, length.value);
  if (bytes === null)
    return err(
      "malformed-go-buildinfo",
      `${what}: runs past the end of the file`,
    );
  return ok({ offset, bytes });
}

const UTF8 = new TextDecoder("utf-8", { fatal: true });

/** Module information text → {main, dependencies, settings, unparsedLines, unparsedBinaryLines}. */
export function parseModuleInfo(raw) {
  const out = {
    path: null,
    main: null,
    dependencies: [],
    settings: [],
    unparsedLines: [],
    unparsedBinaryLines: 0,
  };
  const lines = raw.length === 0 ? [] : splitLines(raw);
  let last = null;
  for (const bytes of lines) {
    // The linker writes an empty line after each "=>" line (seen on prometheus, terraform):
    // nothing to read there.
    if (bytes.length === 0) continue;
    let line;
    try {
      line = UTF8.decode(bytes);
    } catch {
      out.unparsedBinaryLines += 1;
      continue;
    }
    const fields = line.split("\t");
    const module = () => ({
      path: fields[1],
      version: fields[2],
      replacement: null,
    });
    const moduleLine = fields.length === 3 || fields.length === 4;
    if (fields[0] === "path" && fields.length === 2) out.path = fields[1];
    else if (fields[0] === "mod" && moduleLine) {
      out.main = module();
      last = out.main;
    } else if (fields[0] === "dep" && moduleLine) {
      last = module();
      out.dependencies.push(last);
    } else if (
      fields[0] === "=>" &&
      moduleLine &&
      last !== null &&
      last.replacement === null
    )
      last.replacement = { path: fields[1], version: fields[2] };
    else if (
      fields[0] === "build" &&
      fields.length === 2 &&
      fields[1].includes("=")
    ) {
      const eq = fields[1].indexOf("=");
      out.settings.push({
        key: fields[1].slice(0, eq),
        value: fields[1].slice(eq + 1),
      });
    } else out.unparsedLines.push(line);
  }
  return out;
}

function splitLines(raw) {
  const lines = [];
  let start = 0;
  for (let nl = raw.indexOf(0x0a); nl !== -1; nl = raw.indexOf(0x0a, start)) {
    lines.push(raw.subarray(start, nl));
    start = nl + 1;
  }
  if (start < raw.length) lines.push(raw.subarray(start));
  return lines;
}

function readAt(source, candidate) {
  const header = source.read(candidate.offset, HEADER_BYTES);
  if (header === null || !isHeader(header))
    return err("malformed-go-buildinfo", "build information header truncated");
  const pointerSize = header[14];
  const flags = header[15];
  if ((flags & FLAG_INLINE) === 0)
    return err(
      "go-buildinfo-pointer-format",
      `build information uses the pre-Go 1.18 pointer format (pointer size ${pointerSize}, flags ${flags}); not supported`,
    );
  const version = inlineString(
    source,
    candidate.offset + HEADER_BYTES,
    LIMITS.versionBytes,
    candidate.end,
    "toolchain version",
  );
  if (!version.ok) return version;
  let goVersion;
  try {
    goVersion = UTF8.decode(version.value.bytes);
  } catch {
    return err("malformed-go-buildinfo", "toolchain version is not UTF-8");
  }
  const modPos = version.value.offset + version.value.bytes.length;
  const mod = inlineString(
    source,
    modPos,
    LIMITS.moduleBytes,
    candidate.end,
    "module information",
  );
  if (!mod.ok) return mod;
  const raw = mod.value.bytes;
  const complete =
    raw.length >= 2 * SENTINEL_BYTES + 1 &&
    raw[raw.length - SENTINEL_BYTES - 1] === 0x0a;
  const text = complete
    ? raw.subarray(SENTINEL_BYTES, raw.length - SENTINEL_BYTES)
    : Buffer.alloc(0);
  const parsed = parseModuleInfo(text);
  return ok({
    reader: READER,
    artifactBytes: source.size,
    headerOffset: candidate.offset,
    locatedBy: candidate.locatedBy,
    pointerSize,
    goVersion,
    moduleLocation: { offset: mod.value.offset, bytes: raw.length },
    main: parsed.main,
    dependencies: parsed.dependencies,
    settings: parsed.settings,
    complete,
    unparsedLines: parsed.unparsedLines,
    unparsedBinaryLines: parsed.unparsedBinaryLines,
  });
}

/**
 * Read the Go build information of the file at `path`.
 * Result tags: packed-executable, no-go-buildinfo, go-buildinfo-pointer-format,
 * malformed-go-buildinfo. Value: facts with the fields of the former REA adapter (goVersion,
 * moduleLocation, main, dependencies with replacements, complete, unparsedLines,
 * unparsedBinaryLines) plus headerOffset, locatedBy, settings and artifactBytes.
 */
export function readGoBuildInfo(path) {
  const started = process.hrtime.bigint();
  const result = withSource(path, (source) => {
    const executable = readExecutable(source);
    if (executable.ok && executable.value.packer !== null)
      return err(
        "packed-executable",
        `${executable.value.packer.toUpperCase()}-packed executable: build information is compressed, not read`,
      );
    let candidates = executable.ok
      ? sectionCandidates(source, executable.value)
      : [];
    if (candidates.length === 0) candidates = markerCandidates(path);
    if (candidates.length === 0)
      return err("no-go-buildinfo", "no Go build information header found");
    let first = null;
    for (const candidate of candidates) {
      const facts = readAt(source, candidate);
      if (facts.ok) return facts;
      first ??= facts;
    }
    return first;
  });
  if (!result.ok) return result;
  const elapsedMs = Math.round(Number(process.hrtime.bigint() - started) / 1e6);
  return ok({ ...result.value, call: { command: READER.command, elapsedMs } });
}
