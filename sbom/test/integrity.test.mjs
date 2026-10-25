// S6 C: the sha256 of the fingerprint pass is an integrity check. A file modified between
// detection and the adapters' reads (content or size) fails the scan with artifact-changed.
// The modification is injected by the afterFingerprint hook of scanArtifact (simulated scan).
import assert from "node:assert/strict";
import {
  appendFileSync,
  copyFileSync,
  mkdtempSync,
  openSync,
  closeSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { scanArtifact } from "../lib/scan.mjs";
import { S2_FIXTURES, fixtureGate, fixturePath } from "./support.mjs";

const scratch = mkdtempSync(join(tmpdir(), "sbom-integrity-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));
let n = 0;

/** Copy of the fixture, so the corpus itself is never modified. */
function copyOf(fx) {
  const path = join(scratch, `${fx.id}-${(n += 1)}`);
  copyFileSync(fixturePath(fx), path);
  return path;
}

/** Overwrite one byte at the end of the file, same size (outside the build information). */
function flipLastByte(path) {
  const size = statSync(path).size;
  const fd = openSync(path, "r+");
  try {
    const byte = Buffer.alloc(1);
    writeSync(fd, byte.fill(0x5a), 0, 1, size - 1);
  } finally {
    closeSync(fd);
  }
}

for (const id of ["go-uuid", "rust-small", "npm-cli"])
  test(`C1 ${id}: modified between detection and the adapters → artifact-changed`, (t) => {
    const fx = S2_FIXTURES.find((f) => f.id === id);
    if (!fixtureGate(t, fx)) return;
    const unchanged = scanArtifact(copyOf(fx), { afterFingerprint: () => {} });
    assert.equal(unchanged.ok, true, JSON.stringify(unchanged.error));

    const content = copyOf(fx);
    const before = statSync(content).size;
    const sameSize = scanArtifact(content, {
      afterFingerprint: () => flipLastByte(content),
    });
    assert.equal(statSync(content).size, before);
    assert.equal(sameSize.ok, false);
    assert.equal(sameSize.error.tag, "artifact-changed");
    assert.match(sameSize.error.message, /content changed .*sha256/);

    const grown = copyOf(fx);
    const larger = scanArtifact(grown, {
      afterFingerprint: () => appendFileSync(grown, Buffer.alloc(16)),
    });
    assert.equal(larger.error?.tag, "artifact-changed");
    assert.match(larger.error.message, /size changed .*→ \d+ bytes/);

    const removed = copyOf(fx);
    const gone = scanArtifact(removed, {
      afterFingerprint: () => rmSync(removed),
    });
    assert.equal(gone.ok, false, "a file removed mid-scan never yields a BOM");
    assert.equal(gone.error.tag, "artifact-changed");
    assert.match(gone.error.message, /ENOENT/);
  });
