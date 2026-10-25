// Minimal ECMA-335 reader: PE header → CLI header → metadata tables, just enough to read the
// assembly identity and its version attributes. Pure Node, no REA.
//
//   PE        MZ, e_lfanew, "PE\0\0", COFF header, optional header (PE32 / PE32+), section table
//   CLI       data directory 14 (COM descriptor): metadata RVA/size, entry point token
//   metadata  "BSJB" root, stream headers (#~ #Strings #Blob ...), table rows
//   read      Assembly row (name, culture, AssemblyVersion quad) and the Assembly's custom
//             attributes AssemblyInformationalVersion / AssemblyFileVersion
//
// Attribute types are resolved through MemberRef → TypeRef (namespace + name); the constructor
// signature must be (string). Anything else is reported as absent, never guessed.
import { readRange, sha256, withSource } from "../files.mjs";
import { err, ok } from "../result.mjs";
import { readExecutable } from "./executable.mjs";

// Resource guards, not format limits.
const MAX_METADATA_BYTES = 256 << 20;

const SERIALIZED_ATTRIBUTES = {
  "System.Reflection.AssemblyInformationalVersionAttribute":
    "informationalVersion",
  "System.Reflection.AssemblyFileVersionAttribute": "fileVersion",
};

// ECMA-335 II.24.2.6 coded indexes: [tag bits, table per tag].
const CODED = {
  TypeDefOrRef: [2, [0x02, 0x01, 0x1b]],
  HasConstant: [2, [0x04, 0x08, 0x17]],
  HasCustomAttribute: [
    5,
    [
      0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11,
      0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b,
    ],
  ],
  HasFieldMarshal: [1, [0x04, 0x08]],
  HasDeclSecurity: [2, [0x02, 0x06, 0x20]],
  MemberRefParent: [3, [0x02, 0x01, 0x1a, 0x06, 0x1b]],
  HasSemantics: [1, [0x14, 0x17]],
  MethodDefOrRef: [1, [0x06, 0x0a]],
  MemberForwarded: [1, [0x04, 0x06]],
  Implementation: [2, [0x26, 0x23, 0x27]],
  CustomAttributeType: [3, [null, null, 0x06, 0x0a, null]],
  ResolutionScope: [2, [0x00, 0x1a, 0x23, 0x01]],
  TypeOrMethodDef: [1, [0x02, 0x06]],
};

const S = "S"; // #Strings index
const G = "G"; // #GUID index
const B = "B"; // #Blob index
const T = (table) => ({ table });
const C = (coded) => ({ coded });

// Column layout of every table 0x00..0x2C (ECMA-335 II.22); numbers are fixed byte widths.
const TABLES = {
  0x00: [2, S, G, G, G],
  0x01: [C("ResolutionScope"), S, S],
  0x02: [4, S, S, C("TypeDefOrRef"), T(0x04), T(0x06)],
  0x03: [T(0x04)],
  0x04: [2, S, B],
  0x05: [T(0x06)],
  0x06: [4, 2, 2, S, B, T(0x08)],
  0x07: [T(0x08)],
  0x08: [2, 2, S],
  0x09: [T(0x02), C("TypeDefOrRef")],
  0x0a: [C("MemberRefParent"), S, B],
  0x0b: [1, 1, C("HasConstant"), B],
  0x0c: [C("HasCustomAttribute"), C("CustomAttributeType"), B],
  0x0d: [C("HasFieldMarshal"), B],
  0x0e: [2, C("HasDeclSecurity"), B],
  0x0f: [2, 4, T(0x02)],
  0x10: [4, T(0x04)],
  0x11: [B],
  0x12: [T(0x02), T(0x14)],
  0x13: [T(0x14)],
  0x14: [2, S, C("TypeDefOrRef")],
  0x15: [T(0x02), T(0x17)],
  0x16: [T(0x17)],
  0x17: [2, S, B],
  0x18: [2, T(0x06), C("HasSemantics")],
  0x19: [T(0x02), C("MethodDefOrRef"), C("MethodDefOrRef")],
  0x1a: [S],
  0x1b: [B],
  0x1c: [2, C("MemberForwarded"), S, T(0x1a)],
  0x1d: [4, T(0x04)],
  0x1e: [4, 4],
  0x1f: [4],
  0x20: [4, 2, 2, 2, 2, 4, B, S, S],
  0x21: [4],
  0x22: [4, 4, 4],
  0x23: [2, 2, 2, 2, 4, B, S, S, B],
  0x24: [4, T(0x23)],
  0x25: [4, 4, 4, T(0x23)],
  0x26: [4, S, B],
  0x27: [4, 4, S, S, C("Implementation")],
  0x28: [4, 4, S, C("Implementation")],
  0x29: [T(0x02), T(0x02)],
  0x2a: [2, 2, C("TypeOrMethodDef"), S],
  0x2b: [C("MethodDefOrRef"), B],
  0x2c: [T(0x2a), C("TypeDefOrRef")],
};
const TABLE_ASSEMBLY = 0x20;
const TABLE_TYPEREF = 0x01;
const TABLE_MEMBERREF = 0x0a;
const TABLE_CUSTOMATTRIBUTE = 0x0c;

const malformed = (message) => err("malformed-cli-metadata", message);

/** Read a Result-returning range; a short read is a malformed file. */
function read(path, offset, length, what) {
  if (!Number.isSafeInteger(offset) || offset < 0)
    return malformed(`${what}: invalid offset`);
  const bytes = readRange(path, offset, length);
  return bytes === null
    ? malformed(`${what}: file is shorter than its header claims`)
    : ok(bytes);
}

function rvaToOffset(sections, rva) {
  for (const s of sections) {
    const span = Math.max(s.virtualSize, s.rawSize);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + span)
      return s.rawPointer + (rva - s.virtualAddress);
  }
  return null;
}

/**
 * PE headers → {sections, clr: {rva, size} | null}. Err "not-pe" when this is not a PE file.
 * The container structure is owned by executable.mjs; this keeps the CLI view of it.
 */
function readPe(path) {
  const exe = withSource(path, readExecutable);
  if (!exe.ok)
    return exe.error.tag === "not-executable"
      ? err("not-pe", exe.error.message)
      : malformed(exe.error.message);
  if (exe.value.format !== "pe")
    return err("not-pe", `${exe.value.format} file, not PE`);
  const image = exe.value.images[0];
  const magic = image.pe.optionalMagic;
  if (magic !== 0x10b && magic !== 0x20b)
    return malformed(`optional header magic ${magic}`);
  const sections = image.sections.map((s) => ({
    virtualSize: s.virtualSize,
    virtualAddress: s.address,
    rawSize: s.rawSize,
    rawPointer: s.offset,
  }));
  const clr = image.pe.dataDirectories[14];
  return ok({
    sections,
    clr: clr === undefined || clr.rva === 0 ? null : clr,
  });
}

function parseStreams(root) {
  if (root.length < 16 || root.readUInt32LE(0) !== 0x424a5342)
    return malformed("metadata root signature is not BSJB");
  const versionLength = root.readUInt32LE(12);
  let pos = 16 + versionLength;
  if (pos + 4 > root.length) return malformed("metadata root truncated");
  const count = root.readUInt16LE(pos + 2);
  pos += 4;
  const streams = new Map();
  for (let i = 0; i < count; i += 1) {
    if (pos + 8 > root.length) return malformed("stream headers truncated");
    const offset = root.readUInt32LE(pos);
    const size = root.readUInt32LE(pos + 4);
    let end = pos + 8;
    while (end < root.length && root[end] !== 0) end += 1;
    if (end >= root.length) return malformed("stream name unterminated");
    const name = root.toString("latin1", pos + 8, end);
    pos = (end + 1 + 3) & ~3;
    if (offset + size > root.length)
      return malformed(`stream ${name} lies outside the metadata block`);
    streams.set(name, { offset, size });
  }
  return ok(streams);
}

/** Table geometry from the "#~" header: row counts, widths and byte offsets of every table. */
function layoutTables(stream) {
  if (stream.length < 24) return malformed("#~ stream truncated");
  const heapSizes = stream[6];
  const valid = stream.readBigUInt64LE(8);
  let pos = 24;
  const rows = Array.from({ length: 0x40 }, () => 0);
  for (let id = 0; id < 64; id += 1) {
    if ((valid >> BigInt(id)) & 1n) {
      if (id > 0x2c)
        return malformed(`unknown metadata table 0x${id.toString(16)}`);
      if (pos + 4 > stream.length) return malformed("#~ row counts truncated");
      rows[id] = stream.readUInt32LE(pos);
      pos += 4;
    }
  }
  if (heapSizes & 0x40) pos += 4; // extra data, not interpreted
  const wide = {
    S: Boolean(heapSizes & 1),
    G: Boolean(heapSizes & 2),
    B: Boolean(heapSizes & 4),
  };
  const indexWidth = (table) => (rows[table] < 0x10000 ? 2 : 4);
  const codedWidth = (name) => {
    const [bits, tables] = CODED[name];
    const max = Math.max(...tables.map((t) => (t === null ? 0 : rows[t])));
    return max < 1 << (16 - bits) ? 2 : 4;
  };
  const widthOf = (col) =>
    typeof col === "number"
      ? col
      : col === S || col === G || col === B
        ? wide[col]
          ? 4
          : 2
        : col.table !== undefined
          ? indexWidth(col.table)
          : codedWidth(col.coded);
  const layout = Array.from({ length: 0x2d }, () => null);
  for (let id = 0; id <= 0x2c; id += 1) {
    const columns = TABLES[id].map(widthOf);
    const rowSize = columns.reduce((a, b) => a + b, 0);
    if (rows[id] > 0 && pos + rows[id] * rowSize > stream.length)
      return malformed(`table 0x${id.toString(16)} exceeds the #~ stream`);
    layout[id] = { rows: rows[id], rowSize, columns, offset: pos };
    pos += rows[id] * rowSize;
  }
  return ok(layout);
}

const uint = (buf, offset, width) =>
  width === 2 ? buf.readUInt16LE(offset) : buf.readUInt32LE(offset);

/** Row accessor: row(table, index1).<column values> as plain numbers (heap indexes, codes). */
function rowReader(stream, layout) {
  return (table, index) => {
    const t = layout[table];
    if (index < 1 || index > t.rows) return null;
    let pos = t.offset + (index - 1) * t.rowSize;
    return t.columns.map((width) => {
      const value = uint(stream, pos, width);
      pos += width;
      return value;
    });
  };
}

function stringAt(heap, index) {
  if (heap === null || index >= heap.length) return null;
  let end = index;
  while (end < heap.length && heap[end] !== 0) end += 1;
  return heap.toString("utf8", index, end);
}

/** Blob heap entry → {bytes, offset (in heap), headerLength}. */
function blobAt(heap, index) {
  if (heap === null || index >= heap.length) return null;
  const first = heap[index];
  let length;
  let header;
  if ((first & 0x80) === 0) {
    length = first;
    header = 1;
  } else if ((first & 0xc0) === 0x80) {
    if (index + 2 > heap.length) return null;
    length = ((first & 0x3f) << 8) | heap[index + 1];
    header = 2;
  } else if ((first & 0xe0) === 0xc0) {
    if (index + 4 > heap.length) return null;
    length =
      ((first & 0x1f) << 24) |
      (heap[index + 1] << 16) |
      (heap[index + 2] << 8) |
      heap[index + 3];
    header = 4;
  } else return null;
  if (index + header + length > heap.length) return null;
  return {
    bytes: heap.subarray(index + header, index + header + length),
    offset: index + header,
  };
}

/** SerString at the start of a custom-attribute value: prolog 0x0001, then the string. */
function attributeString(blob) {
  if (blob.length < 4 || blob.readUInt16LE(0) !== 1) return null;
  let pos = 2;
  const first = blob[pos];
  if (first === 0xff) return { value: null, bytes: blob };
  let length;
  if ((first & 0x80) === 0) {
    length = first;
    pos += 1;
  } else if ((first & 0xc0) === 0x80) {
    length = ((first & 0x3f) << 8) | blob[pos + 1];
    pos += 2;
  } else if ((first & 0xe0) === 0xc0) {
    length =
      ((first & 0x1f) << 24) |
      (blob[pos + 1] << 16) |
      (blob[pos + 2] << 8) |
      blob[pos + 3];
    pos += 4;
  } else return null;
  if (pos + length + 2 > blob.length) return null; // string + NumNamed (u16)
  return { value: blob.toString("utf8", pos, pos + length), bytes: blob };
}

// MemberRef signature of an instance constructor taking one string: HASTHIS, 1 param, void, string.
const CTOR_STRING = Buffer.from([0x20, 0x01, 0x01, 0x0e]);

/** Cheap check: a PE file with a CLI header (a managed assembly). Reads headers only. */
export function isManagedPe(path) {
  const pe = readPe(path);
  return pe.ok && pe.value.clr !== null;
}

/**
 * Read the identity and version attributes of the assembly in `path`.
 * Result tags: not-pe, no-cli-header, malformed-cli-metadata (all with a message).
 * Value: {
 *   assembly: {name, culture, version: "a.b.c.d"},
 *   entryPoint: boolean,                    // CLI header names an entry point (an application)
 *   attributes: {informationalVersion?, fileVersion?},  // {value, offset, size, sourceSha256}
 * }
 */
export function readCliAssembly(path) {
  const pe = readPe(path);
  if (!pe.ok) return pe;
  const { sections, clr } = pe.value;
  if (clr === null)
    return err("no-cli-header", "no CLI header in this PE file");
  const clrOffset = rvaToOffset(sections, clr.rva);
  if (clrOffset === null)
    return malformed("CLI header RVA is outside every section");
  const header = read(path, clrOffset, 72, "CLI header");
  if (!header.ok) return header;
  const cli = header.value;
  if (cli.readUInt32LE(0) < 72) return malformed("CLI header too small");
  const metaRva = cli.readUInt32LE(8);
  const metaSize = cli.readUInt32LE(12);
  const entryPoint = cli.readUInt32LE(20) !== 0;
  const metaOffset = rvaToOffset(sections, metaRva);
  if (metaOffset === null || metaSize === 0 || metaSize > MAX_METADATA_BYTES)
    return malformed(`metadata block rva=${metaRva} size=${metaSize} unusable`);
  const block = read(path, metaOffset, metaSize, "metadata block");
  if (!block.ok) return block;
  const meta = block.value;
  const streams = parseStreams(meta);
  if (!streams.ok) return streams;
  const slice = (name) => {
    const s = streams.value.get(name);
    return s === undefined ? null : meta.subarray(s.offset, s.offset + s.size);
  };
  if (streams.value.has("#-"))
    return malformed("uncompressed (#-) metadata stream is not supported");
  const tables = slice("#~");
  if (tables === null) return malformed("no #~ metadata stream");
  const strings = slice("#Strings");
  const blobs = slice("#Blob");
  const layout = layoutTables(tables);
  if (!layout.ok) return layout;
  const row = rowReader(tables, layout.value);

  const assemblyRow = row(TABLE_ASSEMBLY, 1);
  if (assemblyRow === null) return malformed("no Assembly table row");
  // Assembly: HashAlgId, Major, Minor, Build, Revision, Flags, PublicKey, Name, Culture
  const name = stringAt(strings, assemblyRow[7]);
  if (name === null || name === "") return malformed("assembly has no name");
  const assembly = {
    name,
    culture: stringAt(strings, assemblyRow[8]) ?? "",
    version: assemblyRow.slice(1, 5).join("."),
  };

  const blobHeapFileOffset = metaOffset + streams.value.get("#Blob")?.offset;
  const attributes = {};
  const parent = (1 << CODED.HasCustomAttribute[0]) | 14; // Assembly, row 1
  const attributeRows = layout.value[TABLE_CUSTOMATTRIBUTE].rows;
  for (let i = 1; i <= attributeRows; i += 1) {
    const [owner, type, value] = row(TABLE_CUSTOMATTRIBUTE, i);
    if (owner !== parent) continue;
    if ((type & 7) !== 3) continue; // CustomAttributeType: only MemberRef constructors
    const member = row(TABLE_MEMBERREF, type >> 3);
    if (member === null || (member[0] & 7) !== 1) continue; // MemberRefParent: TypeRef
    const typeRef = row(TABLE_TYPEREF, member[0] >> 3);
    if (typeRef === null) continue;
    const typeName = `${stringAt(strings, typeRef[2]) ?? ""}.${stringAt(strings, typeRef[1]) ?? ""}`;
    const key = SERIALIZED_ATTRIBUTES[typeName];
    if (key === undefined || key in attributes) continue;
    const signature = blobAt(blobs, member[2]);
    if (signature === null || !signature.bytes.equals(CTOR_STRING)) continue;
    const blob = blobAt(blobs, value);
    const text = blob === null ? null : attributeString(blob.bytes);
    if (text === null || text.value === null) continue;
    attributes[key] = {
      value: text.value,
      offset: blobHeapFileOffset + blob.offset,
      size: blob.bytes.length,
      sourceSha256: sha256(blob.bytes),
    };
  }
  return ok({ assembly, entryPoint, attributes });
}
