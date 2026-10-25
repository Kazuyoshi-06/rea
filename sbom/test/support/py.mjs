// Helpers for tests that need CPython 3.13: compile snippets, marshal values, build synthetic
// PyInstaller files. Missing python3: skipped, or failed under SBOM_REQUIRE_FIXTURES=1.
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const MAKE_PYINSTALLER = join(HERE, "make_pyinstaller.py");

export function python(args, input) {
  return spawnSync("python3", ["-I", ...args], {
    input,
    maxBuffer: 64 << 20,
  });
}

let version = null;
export function pythonVersion() {
  if (version === null) {
    const res = python([
      "-c",
      "import sys;print('%d.%d'%sys.version_info[:2])",
    ]);
    version = res.status === 0 ? res.stdout.toString().trim() : "";
  }
  return version;
}

/** True when python3 is 3.13 (the bytecode format the reader supports). */
export function requirePython313(t) {
  if (pythonVersion() === "3.13") return true;
  const why = `python3 3.13 required (found ${pythonVersion() || "none"})`;
  if (process.env.SBOM_REQUIRE_FIXTURES === "1") throw new Error(why);
  t.skip(why);
  return false;
}

/** Build a synthetic PyInstaller file from a spec (see make_pyinstaller.py). */
export function buildPyInstaller(spec) {
  const res = python([MAKE_PYINSTALLER], JSON.stringify(spec));
  if (res.status !== 0)
    throw new Error(`make_pyinstaller.py failed: ${res.stderr.toString()}`);
}
