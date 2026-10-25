// File reads shared by detection, adapters and evidence: bounded, positional, no whole-file loads.
import { createHash } from "node:crypto";
import { closeSync, openSync, readdirSync, readSync } from "node:fs";
import { join } from "node:path";

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

/**
 * Regular files under `root`, depth-first, names sorted by code unit order (deterministic).
 * Symbolic links are neither followed nor listed; `links` counts them. Paths use "/".
 */
export function walkFiles(root) {
  const files = [];
  let links = 0;
  const visit = (segments) => {
    let entries;
    try {
      entries = readdirSync(join(root, ...segments), { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const next = [...segments, entry.name];
      if (entry.isSymbolicLink()) links += 1;
      else if (entry.isDirectory()) visit(next);
      else if (entry.isFile())
        files.push({ rel: next.join("/"), abs: join(root, ...next) });
    }
  };
  visit([]);
  return { files, links };
}
