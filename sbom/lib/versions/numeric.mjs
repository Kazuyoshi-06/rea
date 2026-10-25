// Arbitrary-length non-negative decimal integers kept as digit strings, so that a release
// segment such as "20230722123456789012" never loses precision through Number.

/** Digit string without leading zeros ("007" → "7", "000" → "0"). */
export const stripZeros = (digits) => digits.replace(/^0+(?=\d)/, "");

/** Compare two digit strings numerically. Returns -1, 0 or 1. */
export function compareDigits(a, b) {
  const x = stripZeros(a);
  const y = stripZeros(b);
  if (x.length !== y.length) return x.length < y.length ? -1 : 1;
  return x < y ? -1 : x > y ? 1 : 0;
}

/** Compare two arrays element by element with `cmp`; a missing element sorts with `fill`. */
export function compareArrays(a, b, cmp, fill) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const c = cmp(a[i] ?? fill, b[i] ?? fill);
    if (c !== 0) return c;
  }
  return 0;
}
