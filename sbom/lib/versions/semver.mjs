// SemVer 2.0.0 versions (npm, crates.io, Go modules), parse and precedence, in plain Node.
// Go module versions carry a "v" prefix ("v1.2.3", pseudo-versions
// "v0.0.0-20210101000000-abcdef123456", "v2.0.0+incompatible"); `parseSemver(text, {v: true})`
// requires and strips it. Pseudo-versions are ordinary pre-releases and "+incompatible" is build
// metadata, so plain SemVer precedence orders them as the go command does.
// Leniency: numeric parts with leading zeros are accepted and compared numerically (SemVer
// forbids them; a few advisories carry them). Anything else that is not MAJOR.MINOR.PATCH is
// refused ("1.2", "1.2.3.4", "latest").
import { err, ok } from "../result.mjs";
import { compareDigits, stripZeros } from "./numeric.mjs";

const PATTERN =
  /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

/** Result<{core: [major, minor, patch], pre: string[], build: string|null}>. */
export function parseSemver(text, { v = false } = {}) {
  if (typeof text !== "string")
    return err("semver-invalid", "version is not a string");
  let body = text;
  if (v) {
    if (!body.startsWith("v"))
      return err(
        "semver-invalid",
        `Go version without "v": ${JSON.stringify(text)}`,
      );
    body = body.slice(1);
  }
  const m = PATTERN.exec(body);
  if (m === null)
    return err(
      "semver-invalid",
      `not a SemVer version: ${JSON.stringify(text)}`,
    );
  return ok({
    core: [stripZeros(m[1]), stripZeros(m[2]), stripZeros(m[3])],
    pre: m[4] === undefined ? [] : m[4].split("."),
    build: m[5] ?? null,
  });
}

const NUMERIC = /^\d+$/;

/** SemVer identifier precedence: numeric < alphanumeric, numerics by value, others ASCII. */
export function compareIdentifier(a, b, { caseInsensitive = false } = {}) {
  const an = NUMERIC.test(a);
  const bn = NUMERIC.test(b);
  if (an && bn) return compareDigits(a, b);
  if (an !== bn) return an ? -1 : 1;
  const x = caseInsensitive ? a.toLowerCase() : a;
  const y = caseInsensitive ? b.toLowerCase() : b;
  return x < y ? -1 : x > y ? 1 : 0;
}

/** Pre-release precedence: none > any; then identifier by identifier, shorter first on ties. */
export function comparePrerelease(a, b, options) {
  if (a.length === 0 || b.length === 0)
    return a.length === b.length ? 0 : a.length === 0 ? 1 : -1;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const c = compareIdentifier(a[i], b[i], options);
    if (c !== 0) return c;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/** Precedence of two parsed versions (build metadata ignored). Returns -1, 0 or 1. */
export function compareSemverParsed(a, b) {
  for (let i = 0; i < 3; i += 1) {
    const c = compareDigits(a.core[i], b.core[i]);
    if (c !== 0) return c;
  }
  return comparePrerelease(a.pre, b.pre);
}
