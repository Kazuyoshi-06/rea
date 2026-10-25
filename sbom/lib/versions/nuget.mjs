// NuGet versions, parse and precedence (NuGet.Versioning rules), in plain Node.
// 1 to 4 numeric parts (missing parts are 0: "1.0" = "1.0.0" = "1.0.0.0"), an optional
// pre-release label compared like SemVer 2 but case-insensitively, build metadata after "+"
// ignored. A version without a label sorts after the same version with one.
import { err, ok } from "../result.mjs";
import { compareDigits, stripZeros } from "./numeric.mjs";
import { comparePrerelease } from "./semver.mjs";

const PATTERN =
  /^(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

/** Result<{parts: [4 digit strings], pre: string[], build: string|null}>. */
export function parseNuget(text) {
  if (typeof text !== "string")
    return err("nuget-invalid", "version is not a string");
  const m = PATTERN.exec(text.trim());
  if (m === null)
    return err("nuget-invalid", `not a NuGet version: ${JSON.stringify(text)}`);
  const parts = m[1].split(".").map(stripZeros);
  while (parts.length < 4) parts.push("0");
  return ok({
    parts,
    pre: m[2] === undefined ? [] : m[2].split("."),
    build: m[3] ?? null,
  });
}

/** Precedence of two parsed NuGet versions. Returns -1, 0 or 1. */
export function compareNugetParsed(a, b) {
  for (let i = 0; i < 4; i += 1) {
    const c = compareDigits(a.parts[i], b.parts[i]);
    if (c !== 0) return c;
  }
  return comparePrerelease(a.pre, b.pre, { caseInsensitive: true });
}
