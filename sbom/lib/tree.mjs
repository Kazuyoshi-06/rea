// Read-only file trees for the npm adapter: an ASAR archive or a directory on disk.
// Both expose entries(segments) and readFile(segments); neither follows symbolic links.
//
// ASAR layout (Chromium Pickle, as written by @electron/asar):
//   u32le 4 | u32le headerPickleSize | u32le headerPayloadSize | u32le jsonLength | JSON header
//   file data starts at 8 + headerPickleSize; a file's "offset" (decimal string) is relative
//   to that point. Entries: {files:{...}} directory, {size, offset, integrity?, unpacked?} file,
//   {link} symbolic link. Unpacked files live in "<archive>.unpacked/<path>".
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
} from "node:fs";
import { join } from "node:path";
import { readRange, sha256 } from "./files.mjs";
import { err, ok } from "./result.mjs";

// Resource guards, not format limits: an ASAR header is a uint32-sized pickle.
export const MAX_ASAR_HEADER_BYTES = 64 << 20;
export const MAX_MANIFEST_BYTES = 8 << 20;

const validSegment = (name) =>
  typeof name === "string" &&
  name !== "" &&
  name !== "." &&
  name !== ".." &&
  !/[/\\\0]/.test(name);

function readPrefix(path, length) {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    const buffer = Buffer.alloc(Math.min(length, size));
    readSync(fd, buffer, 0, buffer.length, 0);
    return { buffer, size };
  } finally {
    closeSync(fd);
  }
}

/** Cheap ASAR sniff on the 16-byte pickle prefix (no header parse). */
export function looksLikeAsar(prefix, fileSize) {
  if (prefix.length < 17) return false;
  const pickleSize = prefix.readUInt32LE(4);
  const payload = prefix.readUInt32LE(8);
  const jsonLength = prefix.readUInt32LE(12);
  return (
    prefix.readUInt32LE(0) === 4 &&
    payload <= pickleSize - 4 &&
    jsonLength <= payload - 4 &&
    8 + pickleSize <= fileSize &&
    prefix[16] === 0x7b // "{"
  );
}

/** Parse the ASAR header. Returns Result<{header, dataOffset, headerBytes, fileSize}>. */
export function readAsarHeader(path) {
  const { buffer: prefix, size } = readPrefix(path, 17);
  if (!looksLikeAsar(prefix, size))
    return err(
      "asar-bad-header",
      "not an ASAR archive (pickle prefix mismatch)",
    );
  const jsonLength = prefix.readUInt32LE(12);
  if (jsonLength > MAX_ASAR_HEADER_BYTES)
    return err(
      "asar-header-too-large",
      `ASAR header is ${jsonLength} bytes (guard ${MAX_ASAR_HEADER_BYTES})`,
    );
  const bytes = readRange(path, 16, jsonLength);
  if (bytes === null) return err("asar-truncated", "ASAR header is truncated");
  let header;
  try {
    header = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    return err("asar-bad-header", `ASAR header is not JSON: ${error.message}`);
  }
  if (header === null || typeof header.files !== "object")
    return err("asar-bad-header", "ASAR header has no root directory");
  return ok({
    header,
    dataOffset: 8 + prefix.readUInt32LE(4),
    headerBytes: jsonLength,
    fileSize: size,
  });
}

const entryType = (node) =>
  node === null || typeof node !== "object"
    ? "other"
    : typeof node.files === "object" && node.files !== null
      ? "dir"
      : typeof node.link === "string"
        ? "link"
        : "file";

function asarNode(header, segments) {
  let node = header;
  for (const name of segments) {
    if (entryType(node) !== "dir" || !Object.hasOwn(node.files, name))
      return null;
    node = node.files[name];
  }
  return node;
}

function asarFileLocation(archive, node, internal) {
  if (!Number.isSafeInteger(node.size) || node.size < 0)
    return err("asar-bad-entry", `${internal}: invalid size`);
  if (node.size > MAX_MANIFEST_BYTES)
    return err("manifest-too-large", `${internal}: ${node.size} bytes`);
  if (node.unpacked === true)
    return ok({ kind: "asar-unpacked", path: internal, size: node.size });
  if (typeof node.offset !== "string" || !/^\d+$/.test(node.offset))
    return err("asar-bad-entry", `${internal}: invalid offset`);
  const offset = archive.dataOffset + Number(node.offset);
  if (!Number.isSafeInteger(offset) || offset + node.size > archive.fileSize)
    return err("asar-bad-entry", `${internal}: data outside the archive`);
  return ok({ kind: "asar-entry", path: internal, offset, size: node.size });
}

function integrityOf(node, bytes) {
  const integrity = node.integrity;
  if (integrity?.algorithm !== "SHA256" || typeof integrity.hash !== "string")
    return "absent";
  return integrity.hash === sha256(bytes) ? "verified" : "mismatch";
}

export function asarTree(path) {
  const parsed = readAsarHeader(path);
  if (!parsed.ok) return parsed;
  const archive = parsed.value;
  return ok({
    kind: "asar",
    headerBytes: archive.headerBytes,
    entries(segments) {
      const node = asarNode(archive.header, segments);
      if (entryType(node) !== "dir") return null;
      return Object.keys(node.files).map((name) => ({
        name,
        type: validSegment(name) ? entryType(node.files[name]) : "invalid",
      }));
    },
    readFile(segments) {
      const node = asarNode(archive.header, segments);
      const internal = segments.join("/");
      if (entryType(node) !== "file")
        return err("missing", `${internal}: no such file`);
      const location = asarFileLocation(archive, node, internal);
      if (!location.ok) return location;
      const loc = location.value;
      const bytes =
        loc.kind === "asar-unpacked"
          ? readUnpacked(`${path}.unpacked`, segments, loc.size)
          : readRange(path, loc.offset, loc.size);
      if (bytes === null)
        return err("asar-truncated", `${internal}: data unreadable`);
      return ok({
        bytes,
        location: { ...loc, asarIntegrity: integrityOf(node, bytes) },
      });
    },
  });
}

function readUnpacked(root, segments, size) {
  try {
    const bytes = readFileSync(join(root, ...segments));
    return bytes.length === size ? bytes : null;
  } catch {
    return null;
  }
}

const direntType = (d) =>
  d.isDirectory()
    ? "dir"
    : d.isFile()
      ? "file"
      : d.isSymbolicLink()
        ? "link"
        : "other";

/** Directory tree; symbolic links are reported as "link" and never followed. */
export function directoryTree(root) {
  return {
    kind: "directory",
    entries(segments) {
      try {
        return readdirSync(join(root, ...segments), {
          withFileTypes: true,
        }).map((d) => ({ name: d.name, type: direntType(d) }));
      } catch {
        return null;
      }
    },
    readFile(segments) {
      const internal = segments.join("/");
      const file = join(root, ...segments);
      let stat;
      try {
        stat = lstatSync(file);
      } catch {
        return err("missing", `${internal}: no such file`);
      }
      if (!stat.isFile())
        return err("missing", `${internal}: not a regular file`);
      if (stat.size > MAX_MANIFEST_BYTES)
        return err("manifest-too-large", `${internal}: ${stat.size} bytes`);
      const bytes = readFileSync(file);
      return ok({
        bytes,
        location: { kind: "file", path: internal, size: bytes.length },
      });
    },
  };
}
