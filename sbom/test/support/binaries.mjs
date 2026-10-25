// Synthetic executables for reader tests: ELF (32/64, LE/BE), PE32+, Mach-O (32/64, LE/BE) and
// fat Mach-O, with arbitrary named sections, plus Go build information and cargo-auditable
// payloads. Only the fields the readers look at are meaningful; nothing here is runnable.
import { deflateSync } from "node:zlib";

const align = (n, a) => Math.ceil(n / a) * a;

function writer(size, littleEndian) {
  const b = Buffer.alloc(size);
  return {
    b,
    u16: (o, v) =>
      littleEndian ? b.writeUInt16LE(v, o) : b.writeUInt16BE(v, o),
    u32: (o, v) =>
      littleEndian ? b.writeUInt32LE(v, o) : b.writeUInt32BE(v, o),
    u64: (o, v) =>
      littleEndian
        ? b.writeBigUInt64LE(BigInt(v), o)
        : b.writeBigUInt64BE(BigInt(v), o),
  };
}

/** ELF with section header table; sections: [{name, data, nobits?}]. */
export function buildElf({
  bits = 64,
  littleEndian = true,
  sections = [],
  sectionTable = true,
  tail = Buffer.alloc(0),
} = {}) {
  const ehsize = bits === 64 ? 64 : 52;
  const shentsize = bits === 64 ? 64 : 40;
  const names = [""];
  const all = [...sections, { name: ".shstrtab", data: null }];
  let strtab = Buffer.from([0]);
  const nameOffsets = all.map((s) => {
    const at = strtab.length;
    strtab = Buffer.concat([strtab, Buffer.from(`${s.name}\0`, "latin1")]);
    names.push(s.name);
    return at;
  });
  all.at(-1).data = strtab;
  let pos = ehsize;
  const placed = all.map((s) => {
    pos = align(pos, 16);
    const at = pos;
    if (!s.nobits) pos += s.data.length;
    return at;
  });
  pos = align(pos, 8);
  const shoff = sectionTable ? pos : 0;
  const count = all.length + 1;
  const size = (sectionTable ? shoff + count * shentsize : pos) + tail.length;
  const w = writer(size, littleEndian);
  w.b.writeUInt32BE(0x7f454c46, 0);
  w.b[4] = bits === 64 ? 2 : 1;
  w.b[5] = littleEndian ? 1 : 2;
  w.b[6] = 1;
  w.u16(16, 2);
  w.u16(18, bits === 64 ? 62 : 3);
  w.u32(20, 1);
  if (bits === 64) {
    w.u64(0x28, shoff);
    w.u16(0x34, ehsize);
    w.u16(0x3a, shentsize);
    w.u16(0x3c, sectionTable ? count : 0);
    w.u16(0x3e, sectionTable ? count - 1 : 0);
  } else {
    w.u32(0x20, shoff);
    w.u16(0x28, ehsize);
    w.u16(0x2e, shentsize);
    w.u16(0x30, sectionTable ? count : 0);
    w.u16(0x32, sectionTable ? count - 1 : 0);
  }
  all.forEach((s, i) => {
    if (!s.nobits) s.data.copy(w.b, placed[i]);
    if (!sectionTable) return;
    const at = shoff + (i + 1) * shentsize;
    w.u32(at, nameOffsets[i]);
    w.u32(at + 4, s.nobits ? 8 : i === all.length - 1 ? 3 : 1);
    if (bits === 64) {
      w.u64(at + 16, 0x400000 + placed[i]);
      w.u64(at + 24, placed[i]);
      w.u64(at + 32, s.data.length);
    } else {
      w.u32(at + 12, 0x400000 + placed[i]);
      w.u32(at + 16, placed[i]);
      w.u32(at + 20, s.data.length);
    }
  });
  tail.copy(w.b, size - tail.length);
  return w.b;
}

/** PE32+ image; sections: [{name, data}] (names longer than 8 bytes are not supported here). */
export function buildPe({ sections = [], numberOfSections = null } = {}) {
  const peOffset = 0x40;
  const optionalSize = 112 + 16 * 8;
  const tableAt = peOffset + 24 + optionalSize;
  let pos = align(tableAt + sections.length * 40, 0x200);
  const placed = sections.map((s) => {
    const at = pos;
    pos = align(pos + s.data.length, 0x200);
    return at;
  });
  const w = writer(pos, true);
  w.b.write("MZ", 0, "latin1");
  w.u32(0x3c, peOffset);
  w.u32(peOffset, 0x00004550);
  w.u16(peOffset + 4, 0x8664);
  w.u16(peOffset + 6, numberOfSections ?? sections.length);
  w.u16(peOffset + 20, optionalSize);
  w.u16(peOffset + 24, 0x20b);
  w.u32(peOffset + 24 + 108, 16);
  sections.forEach((s, i) => {
    const at = tableAt + i * 40;
    w.b.write(s.name, at, 8, "latin1");
    w.u32(at + 8, s.data.length);
    w.u32(at + 12, 0x1000 * (i + 1));
    w.u32(at + 16, align(s.data.length, 0x200));
    w.u32(at + 20, placed[i]);
    s.data.copy(w.b, placed[i]);
  });
  return w.b;
}

/** Mach-O with one segment; sections: [{name, segment?, data}]. */
export function buildMachO({
  bits = 64,
  littleEndian = true,
  sections = [],
} = {}) {
  const headerSize = bits === 64 ? 32 : 28;
  const segHeader = bits === 64 ? 72 : 56;
  const secSize = bits === 64 ? 80 : 68;
  const cmdSize = segHeader + sections.length * secSize;
  let pos = align(headerSize + cmdSize, 16);
  const placed = sections.map((s) => {
    const at = pos;
    pos = align(pos + s.data.length, 16);
    return at;
  });
  const w = writer(pos, littleEndian);
  w.u32(0, bits === 64 ? 0xfeedfacf : 0xfeedface);
  w.u32(4, bits === 64 ? 0x01000007 : 7);
  w.u32(12, 2);
  w.u32(16, 1);
  w.u32(20, cmdSize);
  const c = headerSize;
  w.u32(c, bits === 64 ? 0x19 : 0x1);
  w.u32(c + 4, cmdSize);
  w.b.write("__DATA", c + 8, "latin1");
  w.u32(c + (bits === 64 ? 64 : 48), sections.length);
  sections.forEach((s, i) => {
    const at = c + segHeader + i * secSize;
    w.b.write(s.name, at, 16, "latin1");
    w.b.write(s.segment ?? "__DATA", at + 16, 16, "latin1");
    if (bits === 64) {
      w.u64(at + 32, 0x100000000 + placed[i]);
      w.u64(at + 40, s.data.length);
      w.u32(at + 48, placed[i]);
    } else {
      w.u32(at + 32, 0x1000 + placed[i]);
      w.u32(at + 36, s.data.length);
      w.u32(at + 40, placed[i]);
    }
    s.data.copy(w.b, placed[i]);
  });
  return w.b;
}

/** Universal binary of Mach-O slices (aligned on 4096). */
export function buildFat(slices) {
  let pos = 4096;
  const placed = slices.map((s) => {
    const at = pos;
    pos = align(pos + s.length, 4096);
    return at;
  });
  const b = Buffer.alloc(pos);
  b.writeUInt32BE(0xcafebabe, 0);
  b.writeUInt32BE(slices.length, 4);
  slices.forEach((s, i) => {
    const at = 8 + i * 20;
    b.writeUInt32BE(i === 0 ? 0x01000007 : 0x0100000c, at);
    b.writeUInt32BE(placed[i], at + 8);
    b.writeUInt32BE(s.length, at + 12);
    b.writeUInt32BE(12, at + 16);
    s.copy(b, placed[i]);
  });
  return b;
}

const uvarint = (n) => {
  const out = [];
  do {
    let byte = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) byte |= 0x80;
    out.push(byte);
  } while (n > 0);
  return Buffer.from(out);
};

const SENTINEL = Buffer.alloc(16, 0xaa);

/** Go build information blob (header + inline strings); `text` is the module information. */
export function goBuildInfo({
  version = "go1.24.7",
  text,
  inline = true,
  sentinels = true,
  moduleLength = null,
}) {
  const header = Buffer.alloc(32);
  header.write("\xff Go buildinf:", 0, "latin1");
  header[14] = 8;
  header[15] = inline ? 2 : 0;
  if (!inline) return Buffer.concat([header, Buffer.alloc(32)]);
  const raw = Buffer.from(text, "utf8");
  const mod = sentinels ? Buffer.concat([SENTINEL, raw, SENTINEL]) : raw;
  const v = Buffer.from(version, "utf8");
  return Buffer.concat([
    header,
    uvarint(v.length),
    v,
    uvarint(moduleLength ?? mod.length),
    mod,
  ]);
}

/** cargo-auditable section content: zlib(JSON). */
export const auditSection = (doc) =>
  deflateSync(Buffer.from(typeof doc === "string" ? doc : JSON.stringify(doc)));

export const AUDIT_DOC = {
  packages: [
    {
      name: "app",
      version: "0.1.0",
      source: "local",
      dependencies: [1, 2],
      root: true,
    },
    { name: "regex", version: "1.5.4", source: "crates.io", dependencies: [2] },
    { name: "regex-syntax", version: "0.6.29", source: "crates.io" },
    { name: "autocfg", version: "1.1.0", source: "crates.io", kind: "build" },
  ],
  format: 1,
};

export const GO_TEXT = [
  "path\texample.com/app",
  "mod\texample.com/app\tv1.2.3\th1:abc=",
  "dep\tgithub.com/a/b\tv1.0.0\th1:x=",
  "dep\tgithub.com/c/d\tv0.1.0\th1:y=",
  "=>\tgithub.com/fork/d\tv0.1.1\th1:z=",
  "", // real linkers write an empty line after "=>" (prometheus, terraform)
  "dep\tgithub.com/e/f\tv2.0.0",
  "=>\t../local/f\t",
  "build\t-trimpath=true",
  "",
].join("\n");

// --- hostile inputs (S5 part C) ---------------------------------------------------------

/** PyInstaller onefile stand-in: prefix | CArchive entries | TOC | 88-byte cookie. */
export function buildCArchive(entries, { pyvers = 313 } = {}) {
  const parts = [];
  const toc = [];
  let pos = 0;
  for (const e of entries) {
    parts.push(e.data);
    const name = Buffer.from(`${e.name}\0`, "utf8");
    const length = Math.ceil((18 + name.length) / 16) * 16;
    const t = Buffer.alloc(length);
    t.writeInt32BE(length, 0);
    t.writeUInt32BE(pos, 4);
    t.writeUInt32BE(e.data.length, 8);
    t.writeUInt32BE(e.uncompressedLength ?? e.data.length, 12);
    t[16] = e.compressed ? 1 : 0;
    t[17] = e.type.charCodeAt(0);
    name.copy(t, 18);
    toc.push(t);
    pos += e.data.length;
  }
  const tocBytes = Buffer.concat(toc);
  const cookie = Buffer.alloc(88);
  Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]).copy(cookie);
  cookie.writeUInt32BE(pos + tocBytes.length + 88, 8);
  cookie.writeUInt32BE(pos, 12);
  cookie.writeUInt32BE(tocBytes.length, 16);
  cookie.writeInt32BE(pyvers, 20);
  cookie.write("libpython3.13.so", 24, "latin1");
  return Buffer.concat([
    Buffer.from("bootloader stand-in\n"),
    ...parts,
    tocBytes,
    cookie,
  ]);
}

/** PYZ with one module whose stored bytes are `moduleData` (zlib of marshalled code). */
export function buildPyz(moduleName, moduleData) {
  const header = Buffer.alloc(12);
  header.write("PYZ\0", 0, "latin1");
  header.writeUInt16LE(3571, 4); // CPython 3.13 .pyc magic
  header[6] = 0x0d;
  header[7] = 0x0a;
  const name = Buffer.from(moduleName, "latin1");
  const i32 = (n) => {
    const b = Buffer.alloc(5);
    b[0] = 0x69; // 'i'
    b.writeInt32LE(n, 1);
    return b;
  };
  // marshal: list of one tuple (name, (ispkg, position, length))
  const toc = Buffer.concat([
    Buffer.from([0x5b, 1, 0, 0, 0, 0x29, 2, 0x7a, name.length]),
    name,
    Buffer.from([0x29, 3]),
    i32(0),
    i32(12),
    i32(moduleData.length),
  ]);
  header.writeUInt32BE(12 + moduleData.length, 8);
  return Buffer.concat([header, moduleData, toc]);
}

/** ZIP with one deflated entry whose central directory declares `declaredSize`. */
export function buildZip(name, deflated, declaredSize) {
  const n = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(deflated.length, 18);
  local.writeUInt32LE(declaredSize, 22);
  local.writeUInt16LE(n.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(8, 10);
  central.writeUInt32LE(deflated.length, 20);
  central.writeUInt32LE(declaredSize, 24);
  central.writeUInt16LE(n.length, 28);
  const cdOffset = 30 + n.length + deflated.length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(46 + n.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  return Buffer.concat([local, n, deflated, central, n, eocd]);
}
