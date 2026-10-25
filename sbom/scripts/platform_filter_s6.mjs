#!/usr/bin/env node
// S6 B3: Go alerts before (--all-platforms) and after the platform filter, per binary, against
// govulncheck (pinned v1.1.4, binary mode; it filters by the binary's GOOS / GOARCH itself).
// A false negative attributable to the filter = a vulnerability govulncheck reports (any level)
// that is in our alerts before the filter and not after. Binaries: Go corpus fixtures, the
// linux/amd64 real binaries of make sbom-real, the cross builds of scripts/build_cross.sh and the
// fat files of scripts/make_fat.mjs, when present. Needs make vulndb. Writes s6/platform-filter.json.
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { OUT, SBOM } from "../test/support.mjs";
import { govulncheck, ours } from "./oracle_s5.mjs";

const WORK = join(SBOM, ".work");
const binaries = [
  ["corpus", "go-uuid", join(OUT, "go-uuid/go-uuid")],
  ["corpus", "go-jwt", join(OUT, "go-jwt/go-jwt")],
  ...["stringer", "yq", "prometheus", "terraform"].map((t) => [
    "linux-amd64",
    t,
    join(WORK, "real/go", t),
  ]),
];
const CROSS = join(WORK, "cross");
for (const target of existsSync(CROSS) ? readdirSync(CROSS).sort() : [])
  for (const name of readdirSync(join(CROSS, target)).sort())
    if (!name.endsWith(".log"))
      binaries.push([
        target,
        name.replace(/\.exe$/, ""),
        join(CROSS, target, name),
      ]);
const FAT = join(WORK, "fat");
for (const name of existsSync(FAT) ? readdirSync(FAT).sort() : [])
  if (!name.startsWith("mismatch-"))
    binaries.push(["darwin-fat", name, join(FAT, name)]);

const rows = [];
for (const [target, tool, path] of binaries.filter(([, , p]) =>
  existsSync(p),
)) {
  const before = ours(path, ["--all-platforms"]);
  const after = ours(path);
  const afterIds = new Set(after.map((g) => g.id));
  const filtered = before.filter((g) => !afterIds.has(g.id));
  const row = {
    target,
    tool,
    before: before.length,
    after: after.length,
    filtered: filtered.map((g) => `${g.id} (${g.components.join(", ")})`),
  };
  try {
    const level = govulncheck(path);
    const inGroups = (groups, osv) => groups.some((g) => g.ids.has(osv));
    row.govulncheck = level.size;
    row.govulncheckMissingAfter = [...level.keys()]
      .filter((osv) => !inGroups(after, osv))
      .sort();
    row.falseNegativesFromFilter = row.govulncheckMissingAfter.filter((osv) =>
      inGroups(before, osv),
    );
    // Our remaining alerts that govulncheck does not report at any level, by cause.
    const reported = (g) => [...level.keys()].some((osv) => g.ids.has(osv));
    row.oursNotInGovulncheck = after
      .filter((g) => !reported(g))
      .map((g) => `${g.id} (${g.components.join(", ")})`);
  } catch (error) {
    row.govulncheckError = error.message.split("\n").slice(0, 3).join(" | ");
  }
  rows.push(row);
  console.log(
    [
      target,
      tool,
      `before ${row.before} after ${row.after}`,
      row.govulncheckError
        ? `govulncheck error: ${row.govulncheckError.slice(0, 160)}`
        : `govulncheck ${row.govulncheck} missing ${row.govulncheckMissingAfter.length} FN-filter ${row.falseNegativesFromFilter.length} extra ${row.oursNotInGovulncheck.length}`,
    ].join("\t"),
  );
}
mkdirSync(join(SBOM, "s6"), { recursive: true });
writeFileSync(
  join(SBOM, "s6/platform-filter.json"),
  `${JSON.stringify(rows, null, 2)}\n`,
);
