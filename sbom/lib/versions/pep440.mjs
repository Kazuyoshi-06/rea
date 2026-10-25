// PEP 440 versions (PyPI): parse, normal form and ordering, in plain Node.
// Grammar: PEP 440 Appendix B (case-insensitive, optional leading "v", "-", "_", "." separators,
// alternate spellings alpha/beta/c/pre/preview/rev/r and implicit numbers). The normal form is
// the one packaging's `str(Version(s))` prints: "2023.07.22" → "2023.7.22", "1.0RC1" → "1.0rc1",
// "1.0-1" → "1.0.post1". Trailing ".0" release segments are kept ("1.0.0" stays "1.0.0").
// Ordering follows packaging's _cmpkey: trailing zeros of the release are ignored, a dev release
// without pre/post sorts before every pre-release of the same release, local versions sort after
// the public version and compare segment-wise (numeric segments above alphanumeric ones).
import { err, ok } from "../result.mjs";
import { compareArrays, compareDigits, stripZeros } from "./numeric.mjs";

const PATTERN = new RegExp(
  "^\\s*v?" +
    "(?:(?<epoch>[0-9]+)!)?" +
    "(?<release>[0-9]+(?:\\.[0-9]+)*)" +
    "(?<pre>[-_.]?(?<preL>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?<preN>[0-9]+)?)?" +
    "(?<post>-(?<postN1>[0-9]+)|[-_.]?(?<postL>post|rev|r)[-_.]?(?<postN2>[0-9]+)?)?" +
    "(?<dev>[-_.]?dev[-_.]?(?<devN>[0-9]+)?)?" +
    "(?:\\+(?<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\\s*$",
  "i",
);

const PRE_LABEL = {
  alpha: "a",
  a: "a",
  beta: "b",
  b: "b",
  c: "rc",
  pre: "rc",
  preview: "rc",
  rc: "rc",
};
const PRE_RANK = { a: 0, b: 1, rc: 2 };

/**
 * Parse a PEP 440 version. Returns Result<{epoch, release[], pre, post, dev, local[]}> where
 * numbers are digit strings without leading zeros; pre is [label, n] or null.
 */
export function parsePep440(text) {
  if (typeof text !== "string")
    return err("pep440-invalid", "version is not a string");
  const m = PATTERN.exec(text);
  if (m === null)
    return err(
      "pep440-invalid",
      `not a PEP 440 version: ${JSON.stringify(text)}`,
    );
  const g = m.groups;
  return ok({
    epoch: stripZeros(g.epoch ?? "0"),
    release: g.release.split(".").map(stripZeros),
    pre: g.pre
      ? [PRE_LABEL[g.preL.toLowerCase()], stripZeros(g.preN ?? "0")]
      : null,
    post: g.post ? stripZeros(g.postN1 ?? g.postN2 ?? "0") : null,
    dev: g.dev ? stripZeros(g.devN ?? "0") : null,
    local: g.local
      ? g.local
          .toLowerCase()
          .split(/[-_.]/)
          .map((s) => (/^[0-9]+$/.test(s) ? stripZeros(s) : s))
      : [],
  });
}

/** Normal form of a parsed version (packaging's str(Version)). */
export function formatPep440(v) {
  let out = v.epoch === "0" ? "" : `${v.epoch}!`;
  out += v.release.join(".");
  if (v.pre) out += `${v.pre[0]}${v.pre[1]}`;
  if (v.post !== null) out += `.post${v.post}`;
  if (v.dev !== null) out += `.dev${v.dev}`;
  if (v.local.length > 0) out += `+${v.local.join(".")}`;
  return out;
}

/** Result<string>: the PEP 440 normal form of `text`. */
export function canonicalPep440(text) {
  const parsed = parsePep440(text);
  return parsed.ok ? ok(formatPep440(parsed.value)) : parsed;
}

// Sentinels for the optional parts of the comparison key.
const NEG = -1;
const POS = 1;

function trimRelease(release) {
  let end = release.length;
  while (end > 1 && release[end - 1] === "0") end -= 1;
  return release.slice(0, end);
}

// Optional key part: a sentinel (NEG / POS) or a value compared with `cmp`.
function compareOptional(a, b, cmp) {
  if (typeof a === "number" || typeof b === "number") {
    const x = typeof a === "number" ? a : 0;
    const y = typeof b === "number" ? b : 0;
    return x === y ? (typeof a === "number" ? 0 : cmp(a, b)) : x < y ? -1 : 1;
  }
  return cmp(a, b);
}

function compareLocalSegment(a, b) {
  const an = /^[0-9]+$/.test(a);
  const bn = /^[0-9]+$/.test(b);
  if (an && bn) return compareDigits(a, b);
  if (an !== bn) return an ? 1 : -1;
  return a < b ? -1 : a > b ? 1 : 0;
}

function sortKey(v) {
  let pre;
  if (v.pre === null && v.post === null && v.dev !== null) pre = NEG;
  else if (v.pre === null) pre = POS;
  else pre = v.pre;
  return {
    epoch: v.epoch,
    release: trimRelease(v.release),
    pre,
    post: v.post === null ? NEG : v.post,
    dev: v.dev === null ? POS : v.dev,
    local: v.local,
  };
}

/** Compare two parsed versions. Returns -1, 0 or 1. */
export function comparePep440Parsed(a, b) {
  const x = sortKey(a);
  const y = sortKey(b);
  return (
    compareDigits(x.epoch, y.epoch) ||
    compareArrays(x.release, y.release, compareDigits, "0") ||
    compareOptional(
      x.pre,
      y.pre,
      (p, q) =>
        Math.sign(PRE_RANK[p[0]] - PRE_RANK[q[0]]) || compareDigits(p[1], q[1]),
    ) ||
    compareOptional(x.post, y.post, compareDigits) ||
    compareOptional(x.dev, y.dev, compareDigits) ||
    compareLocal(x.local, y.local)
  );
}

function compareLocal(a, b) {
  // No local segment sorts before any local segment; then segment-wise, shorter first on ties.
  if (a.length === 0 || b.length === 0)
    return a.length === b.length ? 0 : a.length === 0 ? -1 : 1;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const c = compareLocalSegment(a[i], b[i]);
    if (c !== 0) return c;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}
