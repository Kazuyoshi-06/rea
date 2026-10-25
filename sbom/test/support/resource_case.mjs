// One hostile-input case in its own process, so /usr/bin/time -v measures exactly it.
// usage: node resource_case.mjs <case> <file>   → prints {"tag": ..., "message": ...}
import { readFileSync } from "node:fs";
import { withSource } from "../../lib/files.mjs";
import { readCargoAuditable } from "../../lib/readers/cargoauditable.mjs";
import { readExecutable } from "../../lib/readers/executable.mjs";
import { readGoBuildInfo } from "../../lib/readers/gobuildinfo.mjs";
import { MarshalError, readMarshal } from "../../lib/readers/marshal.mjs";
import { openPyInstaller, openPyz } from "../../lib/readers/pyinstaller.mjs";
import { openZip } from "../../lib/readers/zip.mjs";
import { statSync } from "node:fs";

const [kind, path] = process.argv.slice(2);
const outcome = (result) => (result.ok ? { tag: "ok" } : result.error);

function run() {
  switch (kind) {
    case "pyz": {
      const archive = openPyInstaller(path, statSync(path).size);
      if (!archive.ok) return archive.error;
      const pyz = openPyz(
        archive.value,
        archive.value.entries.find((e) => e.type === "z"),
      );
      if (!pyz.ok) return pyz.error;
      return outcome(pyz.value.module(pyz.value.names[0]));
    }
    case "carchive": {
      const archive = openPyInstaller(path, statSync(path).size);
      if (!archive.ok) return archive.error;
      return outcome(archive.value.readEntry(archive.value.entries[0]));
    }
    case "marshal":
      try {
        readMarshal(readFileSync(path));
        return { tag: "ok" };
      } catch (error) {
        if (error instanceof MarshalError)
          return { tag: "MarshalError", message: error.message };
        throw error;
      }
    case "executable":
      return outcome(withSource(path, readExecutable));
    case "go":
      return outcome(readGoBuildInfo(path));
    case "cargo":
      return outcome(readCargoAuditable(path));
    case "zip": {
      const zip = openZip(path);
      if (!zip.ok) return zip.error;
      return outcome(zip.value.read(zip.value.entries[0]));
    }
    default:
      throw new Error(`unknown case ${kind}`);
  }
}
const { tag, message } = run();
process.stdout.write(`${JSON.stringify({ tag, message })}\n`);
