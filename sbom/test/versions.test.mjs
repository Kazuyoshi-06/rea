// Version parsing and ordering in plain Node: PEP 440 (PyPI), SemVer (npm, crates.io, Go), NuGet.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canonicalPep440,
  comparePep440Parsed,
  parsePep440,
} from "../lib/versions/pep440.mjs";
import { compareNugetParsed, parseNuget } from "../lib/versions/nuget.mjs";
import { compareSemverParsed, parseSemver } from "../lib/versions/semver.mjs";

const canon = (v) => {
  const r = canonicalPep440(v);
  return r.ok ? r.value : null;
};

test("pep440: normal form of alternate spellings", () => {
  const cases = {
    "2023.07.22": "2023.7.22",
    "1.0.0": "1.0.0",
    "v1.0": "1.0",
    " 1.0 ": "1.0",
    "1.0RC1": "1.0rc1",
    "1.0-rc.1": "1.0rc1",
    "1.0c1": "1.0rc1",
    "1.0pre": "1.0rc0",
    "1.0preview2": "1.0rc2",
    "1.0alpha1": "1.0a1",
    "1.0.beta": "1.0b0",
    "1.0-1": "1.0.post1",
    "1.0r": "1.0.post0",
    "1.0rev3": "1.0.post3",
    "1.0-post_2": "1.0.post2",
    "1.0dev": "1.0.dev0",
    "1.0-dev-3": "1.0.dev3",
    "1!2.0": "1!2.0",
    "0!2.0": "2.0",
    "1.0+Ubuntu-1": "1.0+ubuntu.1",
    "1.0+0010": "1.0+10",
    "1.0a1.post2.dev3+abc": "1.0a1.post2.dev3+abc",
  };
  for (const [input, expected] of Object.entries(cases))
    assert.equal(canon(input), expected, input);
  for (const bad of ["", "1.0.final", "unknown", "1..0", "1.0+", "1.0-", "a1"])
    assert.equal(canon(bad), null, bad);
});

// Strictly increasing sequence (adapted from packaging's ordering tests).
const ORDERED = [
  "1.0.dev456",
  "1.0a1",
  "1.0a2.dev456",
  "1.0a12.dev456",
  "1.0a12",
  "1.0b1.dev456",
  "1.0b2",
  "1.0b2.post345.dev456",
  "1.0b2.post345",
  "1.0rc1.dev456",
  "1.0rc1",
  "1.0",
  "1.0+abc.5",
  "1.0+abc.7",
  "1.0+5",
  "1.0.post456.dev34",
  "1.0.post456",
  "1.0.15",
  "1.1.dev1",
  "1.2+123abc",
  "1.2+123abc456",
  "1.2+abc",
  "1.2+abc123",
  "1.2+abc123def",
  "1.2+1234.abc",
  "1.2+123456",
  "2023.7.22",
  "20230722123456789012345",
  "1!0.1",
];

test("pep440: ordering matches the packaging reference sequence", () => {
  const parsed = ORDERED.map((v) => parsePep440(v).value);
  for (let i = 0; i < parsed.length; i += 1)
    for (let j = 0; j < parsed.length; j += 1)
      assert.equal(
        comparePep440Parsed(parsed[i], parsed[j]),
        Math.sign(i - j),
        `${ORDERED[i]} vs ${ORDERED[j]}`,
      );
});

test("pep440: equal versions under different spellings and trailing zeros", () => {
  const eq = (a, b) =>
    comparePep440Parsed(parsePep440(a).value, parsePep440(b).value);
  assert.equal(eq("1.0", "1.0.0"), 0);
  assert.equal(eq("1", "1.0.0.0"), 0);
  assert.equal(eq("2023.07.22", "2023.7.22"), 0);
  assert.equal(eq("1.0RC1", "1.0rc1"), 0);
  assert.equal(eq("1.0-1", "1.0.post1"), 0);
  assert.equal(eq("1.0+1", "1.0"), 1);
});

// --- SemVer (npm, crates.io, Go) and NuGet ----------------------------------------------

const ascending = (parse, compare, list, label) => {
  const parsed = list.map((v) => {
    const r = parse(v);
    assert.ok(r.ok, `${label}: ${v} does not parse`);
    return r.value;
  });
  for (let i = 0; i < parsed.length; i += 1)
    for (let j = 0; j < parsed.length; j += 1)
      assert.equal(
        compare(parsed[i], parsed[j]),
        Math.sign(i - j),
        `${label}: ${list[i]} vs ${list[j]}`,
      );
};

test("semver: SemVer 2.0.0 precedence example, numeric identifiers, build ignored", () => {
  ascending(
    (v) => parseSemver(v),
    compareSemverParsed,
    [
      "0.0.0-0",
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
      "1.0.1",
      "1.2.0",
      "1.10.0",
      "2.0.0",
      "99999999999999999999.0.0",
    ],
    "semver",
  );
  const eq = (a, b) =>
    compareSemverParsed(parseSemver(a).value, parseSemver(b).value);
  assert.equal(eq("1.0.0+build.1", "1.0.0+other"), 0);
  assert.equal(eq("1.0.0+build", "1.0.0"), 0);
  assert.equal(eq("01.2.3", "1.2.3"), 0, "leading zeros tolerated");
  for (const bad of [
    "1.2",
    "1.2.3.4",
    "v1.2.3",
    "1.2.3-",
    "latest",
    "1.2.x",
    "",
  ])
    assert.equal(parseSemver(bad).ok, false, bad);
});

test("semver (Go): v prefix, pseudo-versions and +incompatible", () => {
  assert.equal(parseSemver("1.2.3", { v: true }).ok, false);
  ascending(
    (v) => parseSemver(v, { v: true }),
    compareSemverParsed,
    [
      "v0.0.0-20210101000000-abcdefabcdef",
      "v0.0.0-20220715151400-c0bba94af5f8",
      "v0.1.0",
      "v1.2.4-0.20200101000000-abcdefabcdef",
      "v1.2.4",
      "v3.2.0+incompatible",
      "v3.2.1-0.20200101000000-abcdefabcdef+incompatible",
      "v3.2.1+incompatible",
    ],
    "go",
  );
});

test("nuget: up to four parts, missing parts are zero, labels case-insensitive", () => {
  ascending(
    parseNuget,
    compareNugetParsed,
    [
      "0.9",
      "1.0.0-alpha",
      "1.0.0-Beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc1",
      "1.0.0",
      "1.0.0.1",
      "1.0.1",
      "12.0.1",
      "12.0.2",
      "13.0.1",
    ],
    "nuget",
  );
  const eq = (a, b) =>
    compareNugetParsed(parseNuget(a).value, parseNuget(b).value);
  assert.equal(eq("1.0", "1.0.0.0"), 0);
  assert.equal(eq("1.0.0-BETA", "1.0.0-beta"), 0);
  assert.equal(eq("12.0.1+509643a", "12.0.1"), 0);
  for (const bad of ["1.2.3.4.5", "1.0-", "a.b", ""])
    assert.equal(parseNuget(bad).ok, false, bad);
});
