// File reads shared by detection, adapters and evidence: bounded, positional, no whole-file loads.
import { createHash } from "node:crypto";
import { closeSync, openSync, readSync } from "node:fs";

const CHUNK = 1 << 20;

/** Call visit(chunk, chunkStartOffset) over the file in fixed-size chunks with `overlap` bytes. */
export function forEachChunk(path, overlap, visit) {
  const fd = openSync(path, "r");
  try {
    const buffer = Buffer.alloc(CHUNK + overlap);
    let carried = 0;
    let position = 0;
    for (;;) {
      const read = readSync(fd, buffer, carried, CHUNK, position);
      if (read === 0) return;
      const view = buffer.subarray(0, carried + read);
      if (visit(view, position - carried) === false) return;
      carried = Math.min(overlap, view.length);
      view.copyWithin(0, view.length - carried);
      position += read;
    }
  } finally {
    closeSync(fd);
  }
}

export function sha256File(path) {
  const hash = createHash("sha256");
  let bytes = 0;
  forEachChunk(path, 0, (chunk) => {
    hash.update(chunk);
    bytes += chunk.length;
  });
  return { sha256: hash.digest("hex"), bytes };
}

/** Read exactly `length` bytes at `offset`; returns null when the file is shorter. */
export function readRange(path, offset, length) {
  const fd = openSync(path, "r");
  try {
    const buffer = Buffer.alloc(length);
    let done = 0;
    while (done < length) {
      const read = readSync(fd, buffer, done, length - done, offset + done);
      if (read === 0) return null;
      done += read;
    }
    return buffer;
  } finally {
    closeSync(fd);
  }
}

export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
