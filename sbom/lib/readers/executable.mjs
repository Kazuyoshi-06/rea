// Minimal executable container reader: just enough structure to find a named section in a file
// the scanner does not trust. Written from the published format descriptions (see NOTICE.md):
//
//   ELF       32/64-bit, little/big-endian: ELF header → section header table → .shstrtab names
//             (extended numbering: section count in sh_size and string index in sh_link of
//             section 0 when e_shnum / e_shstrndx overflow)
//   PE/COFF   MZ → e_lfanew → "PE\0\0" → COFF header → optional header (data directories) →
//             section table; "/<n>" long names resolved in the COFF string table
//   Mach-O    32/64-bit, both byte orders: header → load commands → LC_SEGMENT(_64) sections
//   fat       universal Mach-O: one image per slice (offsets are absolute in the file)
//
// Every offset and length announced by a header is checked against the real file size before
// any allocation (lib/files.mjs openSource), and table sizes are capped (LIMITS). A packed file
// (UPX) is recognized and reported, never unpacked. Result tags: not-executable,
// malformed-executable.
import { err, ok } from "../result.mjs";

// Resource guards, not format limits (except PE: the Windows loader rejects more than 96).
export const LIMITS = {
  elfSections: 65535,
  peSections: 96,
  machoCommands: 4096,
  machoCommandBytes: 16 << 20,
  fatSlices: 64,
  stringTableBytes: 16 << 20,
  packerProbeBytes: 4096,
};

const malformed = (message) => err("malformed-executable", message);
const UPX = Buffer.from("UPX!");

/** Fixed-width integer views on a header buffer with the file's byte order. */
function view(buffer, littleEndian) {
  const u64 = (o) => {
    const v = littleEndian
      ? buffer.readBigUInt64LE(o)
      : buffer.readBigUInt64BE(o);
    return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : -1;
  };
  return {
    u16: (o) =>
      littleEndian ? buffer.readUInt16LE(o) : buffer.readUInt16BE(o),
    u32: (o) =>
      littleEndian ? buffer.readUInt32LE(o) : buffer.readUInt32BE(o),
    u64,
  };
}

/** NUL-terminated name inside a fixed field or a string table; null when out of range. */
function cString(buffer, start, end = buffer.length) {
  if (start < 0 || start >= end) return null;
  const stop = buffer.indexOf(0, start);
  return buffer.toString(
    "latin1",
    start,
    stop === -1 || stop > end ? end : stop,
  );
}

function readOrFail(source, offset, length, what) {
  const bytes = source.read(offset, length);
  return bytes === null
    ? malformed(
        `${what} (offset ${offset}, ${length} bytes) lies outside the file`,
      )
    : ok(bytes);
}

// --- ELF -------------------------------------------------------------------------------

function readElf(source, head) {
  const bits = head[4] === 1 ? 32 : head[4] === 2 ? 64 : null;
  const littleEndian = head[5] === 1 ? true : head[5] === 2 ? false : null;
  if (bits === null || littleEndian === null)
    return malformed(`ELF class ${head[4]} / data ${head[5]} unknown`);
  const headerSize = bits === 64 ? 64 : 52;
  const header = readOrFail(source, 0, headerSize, "ELF header");
  if (!header.ok) return header;
  const h = view(header.value, littleEndian);
  const shoff = bits === 64 ? h.u64(0x28) : h.u32(0x20);
  const entsize = h.u16(bits === 64 ? 0x3a : 0x2e);
  let count = h.u16(bits === 64 ? 0x3c : 0x30);
  let strndx = h.u16(bits === 64 ? 0x3e : 0x32);
  const image = { format: "elf", bits, littleEndian, offset: 0, sections: [] };
  if (shoff === 0) return ok(image); // no section header table (sstrip, some packers)
  if (shoff < 0) return malformed("ELF e_shoff beyond 2^53");
  const minEntry = bits === 64 ? 64 : 40;
  if (entsize < minEntry)
    return malformed(`ELF e_shentsize ${entsize} < ${minEntry}`);
  const field = (entry, at64, at32) => {
    const e = view(entry, littleEndian);
    return bits === 64 ? e.u64(at64) : e.u32(at32);
  };
  if (count === 0 || strndx === 0xffff) {
    const first = readOrFail(source, shoff, entsize, "ELF section header 0");
    if (!first.ok) return first;
    if (count === 0) count = field(first.value, 32, 20); // sh_size
    if (strndx === 0xffff)
      strndx = view(first.value, littleEndian).u32(bits === 64 ? 40 : 24); // sh_link
  }
  if (count < 0 || count > LIMITS.elfSections)
    return malformed(`${count} ELF sections (limit ${LIMITS.elfSections})`);
  const table = readOrFail(
    source,
    shoff,
    count * entsize,
    "ELF section header table",
  );
  if (!table.ok) return table;
  const raw = [];
  for (let i = 0; i < count; i += 1) {
    const entry = table.value.subarray(i * entsize, (i + 1) * entsize);
    const e = view(entry, littleEndian);
    raw.push({
      nameOffset: e.u32(0),
      type: e.u32(4),
      address: bits === 64 ? e.u64(16) : e.u32(12),
      offset: bits === 64 ? e.u64(24) : e.u32(16),
      bytes: bits === 64 ? e.u64(32) : e.u32(20),
    });
  }
  let names = null;
  if (strndx > 0 && strndx < count) {
    const s = raw[strndx];
    if (s.bytes > LIMITS.stringTableBytes)
      return malformed(
        `ELF section name table of ${s.bytes} bytes (limit ${LIMITS.stringTableBytes})`,
      );
    const strtab = readOrFail(
      source,
      s.offset,
      s.bytes,
      "ELF section name table",
    );
    if (!strtab.ok) return strtab;
    names = strtab.value;
  }
  image.sections = raw.map((s) => ({
    name: names === null ? null : cString(names, s.nameOffset),
    segment: null,
    offset: s.offset,
    bytes: s.bytes,
    address: s.address,
    nobits: s.type === 8, // SHT_NOBITS: occupies no file bytes
  }));
  return ok(image);
}

// --- PE / COFF -------------------------------------------------------------------------

function readPeImage(source) {
  const dos = readOrFail(source, 0, 64, "DOS header");
  if (!dos.ok)
    return err("not-executable", "MZ file shorter than a DOS header");
  const peOffset = dos.value.readUInt32LE(0x3c);
  const coff = source.read(peOffset, 24);
  if (coff === null || coff.readUInt32LE(0) !== 0x00004550)
    return err("not-executable", "MZ file without a PE signature");
  const count = coff.readUInt16LE(6);
  const symbolTable = coff.readUInt32LE(12);
  const symbols = coff.readUInt32LE(16);
  const optionalSize = coff.readUInt16LE(20);
  if (count > LIMITS.peSections)
    return malformed(`${count} PE sections (limit ${LIMITS.peSections})`);
  const rest = readOrFail(
    source,
    peOffset + 24,
    optionalSize + count * 40,
    "PE optional header and section table",
  );
  if (!rest.ok) return rest;
  const optional = rest.value.subarray(0, optionalSize);
  const optionalMagic = optional.length >= 2 ? optional.readUInt16LE(0) : null;
  const dirBase =
    optionalMagic === 0x10b ? 96 : optionalMagic === 0x20b ? 112 : null;
  const dataDirectories = [];
  if (dirBase !== null && optional.length >= dirBase) {
    const announced = optional.readUInt32LE(dirBase - 4);
    const fits = Math.floor((optional.length - dirBase) / 8);
    for (let i = 0; i < Math.min(announced, fits, 16); i += 1)
      dataDirectories.push({
        rva: optional.readUInt32LE(dirBase + i * 8),
        size: optional.readUInt32LE(dirBase + i * 8 + 4),
      });
  }
  const sections = [];
  for (let i = 0; i < count; i += 1) {
    const s = rest.value.subarray(
      optionalSize + i * 40,
      optionalSize + i * 40 + 40,
    );
    let name = cString(s, 0, 8) ?? "";
    const long = /^\/(\d{1,7})$/.exec(name);
    if (long !== null && symbolTable !== 0) {
      const at = symbolTable + symbols * 18 + Number(long[1]);
      const text = source.read(
        at,
        Math.min(256, Math.max(0, source.size - at)),
      );
      if (text !== null) name = cString(text, 0) ?? name;
    }
    const virtualSize = s.readUInt32LE(8);
    const rawSize = s.readUInt32LE(16);
    sections.push({
      name,
      segment: null,
      offset: s.readUInt32LE(20),
      // Bytes that belong to the section: the raw data is padded to the file alignment.
      bytes: virtualSize > 0 && virtualSize < rawSize ? virtualSize : rawSize,
      address: s.readUInt32LE(12),
      virtualSize,
      rawSize,
      nobits: rawSize === 0,
    });
  }
  return ok({
    format: "pe",
    bits: optionalMagic === 0x20b ? 64 : 32,
    littleEndian: true,
    offset: 0,
    sections,
    pe: { optionalMagic, dataDirectories },
  });
}

// --- Mach-O ----------------------------------------------------------------------------

const MACHO = {
  feedface: { bits: 32, littleEndian: false },
  cefaedfe: { bits: 32, littleEndian: true },
  feedfacf: { bits: 64, littleEndian: false },
  cffaedfe: { bits: 64, littleEndian: true },
};
const ZEROFILL = new Set([0x01, 0x0c, 0x12]); // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL

function readMachO(source, base, limit) {
  const magic = source.read(base, 4);
  const kind = magic === null ? undefined : MACHO[magic.toString("hex")];
  if (kind === undefined) return malformed(`no Mach-O magic at offset ${base}`);
  const { bits, littleEndian } = kind;
  const headerSize = bits === 64 ? 32 : 28;
  const header = readOrFail(source, base, headerSize, "Mach-O header");
  if (!header.ok) return header;
  const h = view(header.value, littleEndian);
  const ncmds = h.u32(16);
  const sizeofcmds = h.u32(20);
  if (ncmds > LIMITS.machoCommands)
    return malformed(
      `${ncmds} Mach-O load commands (limit ${LIMITS.machoCommands})`,
    );
  if (sizeofcmds > LIMITS.machoCommandBytes || headerSize + sizeofcmds > limit)
    return malformed(`Mach-O load commands of ${sizeofcmds} bytes do not fit`);
  const cmds = readOrFail(
    source,
    base + headerSize,
    sizeofcmds,
    "Mach-O load commands",
  );
  if (!cmds.ok) return cmds;
  const c = view(cmds.value, littleEndian);
  const sections = [];
  let pos = 0;
  for (let i = 0; i < ncmds; i += 1) {
    if (pos + 8 > sizeofcmds) return malformed("Mach-O load command truncated");
    const cmd = c.u32(pos);
    const size = c.u32(pos + 4);
    if (size < 8 || pos + size > sizeofcmds)
      return malformed(`Mach-O load command ${i} has size ${size}`);
    const is64 = cmd === 0x19;
    if (cmd === 0x1 || is64) {
      const segHeader = is64 ? 72 : 56;
      const secSize = is64 ? 80 : 68;
      if (size < segHeader)
        return malformed("Mach-O segment command truncated");
      const nsects = c.u32(pos + (is64 ? 64 : 48));
      if (nsects > Math.floor((size - segHeader) / secSize))
        return malformed(`Mach-O segment announces ${nsects} sections`);
      for (let k = 0; k < nsects; k += 1) {
        const at = pos + segHeader + k * secSize;
        const bytes = is64 ? c.u64(at + 40) : c.u32(at + 36);
        const offset = c.u32(at + (is64 ? 48 : 40));
        const flags = c.u32(at + (is64 ? 64 : 56));
        sections.push({
          name: cString(cmds.value, at, at + 16),
          segment: cString(cmds.value, at + 16, at + 32),
          offset: base + offset,
          bytes,
          address: is64 ? c.u64(at + 32) : c.u32(at + 32),
          nobits: ZEROFILL.has(flags & 0xff),
        });
      }
    }
    pos += size;
  }
  return ok({ format: "macho", bits, littleEndian, offset: base, sections });
}

function readFat(source, head) {
  const wide = head[3] === 0xbf; // FAT_MAGIC_64
  const count = head.readUInt32BE(4);
  if (count === 0 || count > LIMITS.fatSlices)
    return err("not-executable", `fat header announces ${count} slices`);
  const entry = wide ? 32 : 20;
  const table = readOrFail(source, 8, count * entry, "fat slice table");
  if (!table.ok) return table;
  const t = view(table.value, false);
  const images = [];
  for (let i = 0; i < count; i += 1) {
    const at = i * entry;
    const offset = wide ? t.u64(at + 8) : t.u32(at + 8);
    const size = wide ? t.u64(at + 16) : t.u32(at + 12);
    if (offset < 0 || size < 0 || offset + size > source.size)
      return malformed(
        `fat slice ${i} (offset ${offset}, ${size} bytes) lies outside the file`,
      );
    const image = readMachO(source, offset, size);
    if (!image.ok) return image;
    images.push({ ...image.value, cpuType: t.u32(at) });
  }
  return ok(images);
}

// --- entry point -----------------------------------------------------------------------

/**
 * Parse the container structure of `source` (lib/files.mjs openSource).
 * Value: {format: "elf" | "pe" | "macho" | "fat", packer: "upx" | null, images: [image]}
 * image: {format, bits, littleEndian, offset, sections: [{name, segment, offset, bytes,
 *         address, nobits}], pe?: {optionalMagic, dataDirectories}, cpuType? (fat)}
 * Section offsets are absolute file offsets; nothing beyond the headers is read.
 */
export function readExecutable(source) {
  const head = source.read(0, Math.min(source.size, LIMITS.packerProbeBytes));
  if (head === null || head.length < 8)
    return err("not-executable", "file too short for an executable header");
  let images;
  let format;
  if (head.readUInt32BE(0) === 0x7f454c46) {
    format = "elf";
    images = readElf(source, head);
  } else if (head[0] === 0x4d && head[1] === 0x5a) {
    format = "pe";
    images = readPeImage(source);
  } else if (MACHO[head.subarray(0, 4).toString("hex")] !== undefined) {
    format = "macho";
    images = readMachO(source, 0, source.size);
  } else if (
    head.readUInt32BE(0) === 0xcafebabe ||
    head.readUInt32BE(0) === 0xcafebabf
  ) {
    format = "fat";
    images = readFat(source, head);
  } else return err("not-executable", "no ELF, PE or Mach-O header");
  if (!images.ok) return images;
  const list = Array.isArray(images.value) ? images.value : [images.value];
  const upxSection = list.some((im) =>
    im.sections.some((s) => /^UPX\d$/.test(s.name ?? "")),
  );
  const packer = upxSection || head.includes(UPX) ? "upx" : null;
  return ok({ format, packer, images: list });
}

/** Sections named `name` (and, for Mach-O, optionally in segment `segment`) across images. */
export function findSections(executable, name, segment = null) {
  return executable.images.flatMap((image) =>
    image.sections
      .filter(
        (s) => s.name === name && (segment === null || s.segment === segment),
      )
      .map((section) => ({ image, section })),
  );
}
