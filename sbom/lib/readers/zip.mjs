// Minimal ZIP reader (central directory, ZIP64, stored and deflated entries), plain Node.
// Used by the vulnerability-database builder to read the OSV `all.zip` exports, whose npm
// archive has more than 65 535 entries (ZIP64 end-of-central-directory).
// The whole archive is held in memory: the largest export (npm) is ~220 MB.
import { readFileSync } from "node:fs";
import { inflateRawSync } from "node:zlib";
import { err, ok } from "../result.mjs";

const EOCD = 0x06054b50;
const ZIP64_LOCATOR = 0x07064b50;
const ZIP64_EOCD = 0x06064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const MAX_U32 = 0xffffffff;

function findEocd(buf) {
  const stop = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= stop; i -= 1)
    if (buf.readUInt32LE(i) === EOCD) return i;
  return -1;
}

function num(big) {
  if (big > BigInt(Number.MAX_SAFE_INTEGER))
    throw new RangeError("ZIP64 value too large");
  return Number(big);
}

/** Directory of the archive: Result<{entries: [{name, method, compressedSize, size, localOffset}]}>. */
function centralDirectory(buf) {
  const eocd = findEocd(buf);
  if (eocd < 0) return err("zip-invalid", "no end-of-central-directory record");
  let count = buf.readUInt16LE(eocd + 10);
  let size = buf.readUInt32LE(eocd + 12);
  let offset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || size === MAX_U32 || offset === MAX_U32) {
    const loc = eocd - 20;
    if (loc < 0 || buf.readUInt32LE(loc) !== ZIP64_LOCATOR)
      return err("zip-invalid", "ZIP64 locator missing");
    const rec = num(buf.readBigUInt64LE(loc + 8));
    if (rec + 56 > buf.length || buf.readUInt32LE(rec) !== ZIP64_EOCD)
      return err("zip-invalid", "ZIP64 end-of-central-directory missing");
    count = num(buf.readBigUInt64LE(rec + 32));
    size = num(buf.readBigUInt64LE(rec + 40));
    offset = num(buf.readBigUInt64LE(rec + 48));
  }
  if (offset + size > buf.length)
    return err("zip-invalid", "central directory outside the file");
  const entries = [];
  let p = offset;
  for (let i = 0; i < count; i += 1) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CENTRAL)
      return err("zip-invalid", `central directory entry ${i} is malformed`);
    const method = buf.readUInt16LE(p + 10);
    let compressedSize = buf.readUInt32LE(p + 20);
    let uncompressed = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    // ZIP64 extended information: only the fields whose 32-bit value is saturated, in order.
    let x = p + 46 + nameLen;
    const extraEnd = x + extraLen;
    while (x + 4 <= extraEnd) {
      const id = buf.readUInt16LE(x);
      const len = buf.readUInt16LE(x + 2);
      if (id === 0x0001) {
        let q = x + 4;
        if (uncompressed === MAX_U32) {
          uncompressed = num(buf.readBigUInt64LE(q));
          q += 8;
        }
        if (compressedSize === MAX_U32) {
          compressedSize = num(buf.readBigUInt64LE(q));
          q += 8;
        }
        if (localOffset === MAX_U32) localOffset = num(buf.readBigUInt64LE(q));
      }
      x += 4 + len;
    }
    entries.push({
      name,
      method,
      compressedSize,
      size: uncompressed,
      localOffset,
    });
    p = extraEnd + commentLen;
  }
  return ok({ entries });
}

/** Open a ZIP file. Result<{entries, read(entry) → Result<Buffer>}>. */
export function openZip(path) {
  const buf = readFileSync(path);
  let dir;
  try {
    dir = centralDirectory(buf);
  } catch (error) {
    return err("zip-invalid", error.message);
  }
  if (!dir.ok) return dir;
  const read = (entry) => {
    const p = entry.localOffset;
    if (p + 30 > buf.length || buf.readUInt32LE(p) !== LOCAL)
      return err("zip-invalid", `${entry.name}: bad local header`);
    const start = p + 30 + buf.readUInt16LE(p + 26) + buf.readUInt16LE(p + 28);
    const data = buf.subarray(start, start + entry.compressedSize);
    if (data.length !== entry.compressedSize)
      return err("zip-invalid", `${entry.name}: truncated`);
    if (entry.method === 0) return ok(data);
    if (entry.method !== 8)
      return err(
        "zip-unsupported",
        `${entry.name}: compression method ${entry.method}`,
      );
    try {
      return ok(inflateRawSync(data));
    } catch (error) {
      return err("zip-invalid", `${entry.name}: ${error.message}`);
    }
  };
  return ok({ entries: dir.value.entries, read });
}
