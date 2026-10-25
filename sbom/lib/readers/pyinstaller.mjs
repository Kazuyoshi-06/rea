// PyInstaller onefile archive reader (CArchive + PYZ), pure Node.
//
// CArchive cookie, last 88 bytes of the package (big endian, PyInstaller 6.x):
//   magic "MEI\014\013\012\013\016" (8) | package length u32 | TOC offset u32 | TOC length u32
//   | python version i32 (313 = 3.13) | python library name (64)
// The package starts at (cookie end − package length); TOC and entry offsets are relative to it.
// TOC entry: length i32 (whole entry) | data offset u32 | compressed length u32 | uncompressed
//   length u32 | compression flag u8 | type code char | name (NUL padded).
// PYZ (type code "z"): "PYZ\0" | pyc magic (4) | TOC position u32 (BE), relative to the PYZ; the TOC is
//   a marshal list of (name, (is_package, offset, length)); each module is zlib(marshal(code)).
// Verified against PyInstaller 6.10 / CPython 3.13 output only (see S3_REPORT.md).
import { inflateSync } from "node:zlib";
import { readRange, sha256 } from "../files.mjs";
import { err, ok } from "../result.mjs";
import { MarshalError, readMarshal } from "./marshal.mjs";

export const COOKIE_MAGIC = Buffer.from([
  0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e,
]);
const COOKIE_SIZE = 88;
const TOC_ENTRY_HEADER = 18;
const PYZ_MAGIC = Buffer.from("PYZ\0", "latin1");
// How far from the end of the file the cookie is searched (signatures may follow the package).
const COOKIE_WINDOW = 1 << 20;

// Resource guards, not format limits.
const MAX_TOC_BYTES = 64 << 20;
const MAX_ENTRY_BYTES = 64 << 20;
const MAX_PYZ_TOC_BYTES = 16 << 20;

// .pyc magic numbers the bytecode reader has been checked against. The PYZ header carries the
// magic of the interpreter that compiled the modules.
export const PYC_MAGIC = new Map([[3571, "3.13"]]);

const bad = (message) => err("malformed-pyinstaller-archive", message);

function findCookie(path, fileSize) {
  const windowStart = Math.max(0, fileSize - COOKIE_WINDOW);
  const tail = readRange(path, windowStart, fileSize - windowStart);
  if (tail === null) return bad("file shrank while reading");
  let from = tail.length;
  for (;;) {
    const at = tail.lastIndexOf(COOKIE_MAGIC, from - 1);
    if (at === -1)
      return err(
        "no-pyinstaller-cookie",
        "no valid PyInstaller cookie near the end of the file",
      );
    from = at;
    if (at + COOKIE_SIZE > tail.length) continue;
    const c = tail.subarray(at, at + COOKIE_SIZE);
    const length = c.readUInt32BE(8);
    const tocOffset = c.readUInt32BE(12);
    const tocLength = c.readUInt32BE(16);
    const cookieEnd = windowStart + at + COOKIE_SIZE;
    const start = cookieEnd - length;
    // The bootloader embeds the magic as a constant: only a record that is consistent counts.
    if (length < COOKIE_SIZE || start < 0) continue;
    if (tocOffset + tocLength > length - COOKIE_SIZE || tocLength === 0)
      continue;
    const pyvers = c.readInt32BE(20);
    return ok({
      start,
      tocOffset,
      tocLength,
      pythonVersion: `${Math.floor(pyvers / 100)}.${pyvers % 100}`,
      pyvers,
      cookieOffset: windowStart + at,
      libraryName: c.toString("latin1", 24, 88).replace(/\0.*$/s, ""),
    });
  }
}

function parseToc(buffer, packageLength) {
  const entries = [];
  let pos = 0;
  while (pos < buffer.length) {
    if (pos + TOC_ENTRY_HEADER > buffer.length)
      return bad("TOC entry truncated");
    const entryLength = buffer.readInt32BE(pos);
    if (entryLength < TOC_ENTRY_HEADER + 1 || pos + entryLength > buffer.length)
      return bad(`TOC entry length ${entryLength} at ${pos}`);
    const offset = buffer.readUInt32BE(pos + 4);
    const compressedLength = buffer.readUInt32BE(pos + 8);
    const uncompressedLength = buffer.readUInt32BE(pos + 12);
    if (offset + compressedLength > packageLength)
      return bad(`TOC entry at ${pos} points outside the package`);
    entries.push({
      offset,
      compressedLength,
      uncompressedLength,
      compressed: buffer[pos + 16] !== 0,
      type: String.fromCharCode(buffer[pos + 17]),
      name: buffer
        .toString("utf8", pos + TOC_ENTRY_HEADER, pos + entryLength)
        .replace(/\0+$/, ""),
    });
    pos += entryLength;
  }
  return ok(entries);
}

/**
 * Open the archive. Result<{pythonVersion, entries[], readEntry(entry), ...}>.
 * Tags: no-pyinstaller-cookie, malformed-pyinstaller-archive.
 */
export function openPyInstaller(path, fileSize) {
  const cookie = findCookie(path, fileSize);
  if (!cookie.ok) return cookie;
  const c = cookie.value;
  if (c.tocLength > MAX_TOC_BYTES) return bad(`TOC of ${c.tocLength} bytes`);
  const tocBytes = readRange(path, c.start + c.tocOffset, c.tocLength);
  if (tocBytes === null) return bad("TOC lies outside the file");
  const packageLength = fileSize - c.start;
  const toc = parseToc(tocBytes, packageLength);
  if (!toc.ok) return toc;
  const entries = toc.value;

  const entryOffset = (entry) => c.start + entry.offset;
  const readFileRange = (offset, length) => readRange(path, offset, length);

  /** Raw (still compressed) bytes of an entry and where they sit in the file. */
  const readRaw = (entry) => {
    const offset = c.start + entry.offset;
    const bytes = readRange(path, offset, entry.compressedLength);
    return bytes === null ? null : { bytes, offset };
  };

  /** Inflated entry data: Result<{data, offset, size, rawSha256}>. */
  const readEntry = (entry) => {
    if (
      entry.compressedLength > MAX_ENTRY_BYTES ||
      entry.uncompressedLength > MAX_ENTRY_BYTES
    )
      return bad(`${entry.name}: entry larger than ${MAX_ENTRY_BYTES} bytes`);
    const raw = readRaw(entry);
    if (raw === null) return bad(`${entry.name}: data outside the file`);
    let data = raw.bytes;
    if (entry.compressed) {
      try {
        data = inflateSync(raw.bytes, { maxOutputLength: MAX_ENTRY_BYTES });
      } catch (error) {
        return bad(`${entry.name}: ${error.message}`);
      }
    }
    if (data.length !== entry.uncompressedLength)
      return bad(
        `${entry.name}: ${data.length} bytes after decompression, TOC says ${entry.uncompressedLength}`,
      );
    return ok({
      data,
      offset: raw.offset,
      size: entry.compressedLength,
      sourceSha256: sha256(data),
    });
  };

  return ok({
    cookie: c,
    pythonVersion: c.pythonVersion,
    entries,
    readEntry,
    entryOffset,
    readFileRange,
  });
}

/**
 * The embedded PYZ as a module index. Result<{pycMagic, python, has(name), module(name)}>.
 * Tags: malformed-pyinstaller-archive, unsupported-python-bytecode (carries the magic number).
 */
export function openPyz(archive, entry) {
  const base = archive.entryOffset(entry);
  const readPyz = (offset, length) =>
    archive.readFileRange(base + offset, length);
  const header = readPyz(0, 12);
  if (header === null || !header.subarray(0, 4).equals(PYZ_MAGIC))
    return bad(`${entry.name}: no PYZ header`);
  const magic = header.readUInt16LE(4);
  const python = PYC_MAGIC.get(magic);
  if (python === undefined || header[6] !== 0x0d || header[7] !== 0x0a)
    return err(
      "unsupported-python-bytecode",
      `.pyc magic number ${magic} (bytes ${header.subarray(4, 8).toString("hex")}) is not supported; supported: ${[...PYC_MAGIC.entries()].map(([m, v]) => `${m} (Python ${v})`).join(", ")}`,
      { magic },
    );
  const size = entry.compressedLength;
  const tocPosition = header.readUInt32BE(8);
  if (tocPosition + 4 > size || size - tocPosition > MAX_PYZ_TOC_BYTES)
    return bad(`${entry.name}: TOC position ${tocPosition} unusable`);
  const tocBytes = readPyz(tocPosition, size - tocPosition);
  if (tocBytes === null) return bad(`${entry.name}: TOC outside the file`);
  let list;
  try {
    list = readMarshal(tocBytes).value;
  } catch (error) {
    if (error instanceof MarshalError)
      return bad(`${entry.name}: TOC: ${error.message}`);
    throw error;
  }
  if (!Array.isArray(list)) return bad(`${entry.name}: TOC is not a list`);
  const toc = new Map();
  for (const item of list) {
    const wellFormed =
      Array.isArray(item) &&
      item.length === 2 &&
      typeof item[0] === "string" &&
      Array.isArray(item[1]) &&
      item[1].length === 3 &&
      item[1].every((n) => Number.isSafeInteger(n));
    if (!wellFormed) return bad(`${entry.name}: unexpected TOC item`);
    const [isPackage, position, length] = item[1];
    if (position < 0 || length < 0 || position + length > size)
      return bad(`${entry.name}: module ${item[0]} lies outside the PYZ`);
    toc.set(item[0], { isPackage: isPackage === 1, position, length });
  }
  return ok({
    python,
    pycMagic: magic,
    names: [...toc.keys()].sort(),
    isPackage: (name) => toc.get(name)?.isPackage ?? false,
    has: (name) => toc.has(name),
    /** Code object of a module: Result<{code, offset, size, sourceSha256}>. */
    module(name) {
      const item = toc.get(name);
      if (item === undefined) return err("missing-module", name);
      const compressed = readPyz(item.position, item.length);
      if (compressed === null) return bad(`${name}: data outside the file`);
      try {
        const data = inflateSync(compressed, {
          maxOutputLength: MAX_ENTRY_BYTES,
        });
        const code = readMarshal(data).value;
        if (code === null || typeof code !== "object" || code.kind !== "code")
          return bad(`${name}: not a code object`);
        return ok({
          code,
          offset: base + item.position,
          size: item.length,
          sourceSha256: sha256(compressed),
        });
      } catch (error) {
        return bad(`${name}: ${error.message}`);
      }
    },
  });
}
