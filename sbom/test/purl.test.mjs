import assert from "node:assert/strict";
import { test } from "node:test";
import {
  cargoPurl,
  formatPurl,
  golangPurl,
  npmPurl,
  parsePurl,
  percentEncode,
} from "../lib/purl.mjs";

const value = (result) => {
  assert.equal(result.ok, true, JSON.stringify(result.error));
  return result.value;
};
const failure = (result) => {
  assert.equal(result.ok, false, `expected failure, got ${result.value}`);
  return result.error.tag;
};

test("percent-encoding keeps unreserved characters and ':' only", () => {
  assert.equal(percentEncode("a-Z_0.9~:"), "a-Z_0.9~:");
  assert.equal(percentEncode("@?#%+ /"), "%40%3F%23%25%2B%20%2F");
  assert.equal(percentEncode("café"), "caf%C3%A9");
});

test("golang: module path splits into namespace and name", () => {
  const cases = [
    [
      "github.com/google/uuid",
      "v1.6.0",
      "pkg:golang/github.com/google/uuid@v1.6.0",
    ],
    // +incompatible build metadata is percent-encoded
    [
      "github.com/dgrijalva/jwt-go",
      "v3.2.0+incompatible",
      "pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0%2Bincompatible",
    ],
    // major-version suffix stays part of the path; the last segment is the name
    [
      "github.com/go-chi/chi/v5",
      "v5.0.12",
      "pkg:golang/github.com/go-chi/chi/v5@v5.0.12",
    ],
    [
      "golang.org/x/sys",
      "v0.0.0-20220715151400-c0bba94af5f8",
      "pkg:golang/golang.org/x/sys@v0.0.0-20220715151400-c0bba94af5f8",
    ],
    ["gopkg.in/yaml.v3", "v3.0.1", "pkg:golang/gopkg.in/yaml.v3@v3.0.1"],
    // case is preserved (Go module paths are case-sensitive)
    [
      "github.com/Masterminds/semver/v3",
      "v3.2.1",
      "pkg:golang/github.com/Masterminds/semver/v3@v3.2.1",
    ],
    ["example", null, "pkg:golang/example"],
    ["golang.org/x/text", null, "pkg:golang/golang.org/x/text"],
    ["stdlib", "1.24.7", "pkg:golang/stdlib@1.24.7"],
  ];
  for (const [path, version, expected] of cases)
    assert.equal(value(golangPurl(path, version)), expected);
});

test("golang: malformed module paths are rejected", () => {
  for (const path of ["", "github.com//x", "a/../b", "a/./b", "trailing/"])
    assert.equal(
      failure(golangPurl(path, "v1.0.0")).startsWith("purl-invalid"),
      true,
      path,
    );
  assert.equal(failure(golangPurl("a/b", "")), "purl-invalid-version");
});

test("cargo: name kept as published, semver build metadata encoded", () => {
  assert.equal(value(cargoPurl("serde", "1.0.210")), "pkg:cargo/serde@1.0.210");
  assert.equal(
    value(cargoPurl("regex-syntax", "0.6.29")),
    "pkg:cargo/regex-syntax@0.6.29",
  );
  assert.equal(
    value(cargoPurl("wasi", "0.11.0+wasi-snapshot-preview1")),
    "pkg:cargo/wasi@0.11.0%2Bwasi-snapshot-preview1",
  );
  assert.equal(
    value(cargoPurl("Inflector", "0.11.4")),
    "pkg:cargo/Inflector@0.11.4",
  );
  assert.equal(failure(cargoPurl("a/b", "1.0.0")), "purl-invalid-name");
});

test("npm: scope is the namespace, '@' encoded, lowercased", () => {
  assert.equal(value(npmPurl("lodash", "4.17.20")), "pkg:npm/lodash@4.17.20");
  assert.equal(
    value(npmPurl("@babel/core", "7.24.0")),
    "pkg:npm/%40babel/core@7.24.0",
  );
  assert.equal(
    value(npmPurl("@Scope/Pkg", "1.0.0")),
    "pkg:npm/%40scope/pkg@1.0.0",
  );
  assert.equal(
    value(npmPurl("JSONStream", "1.3.5")),
    "pkg:npm/jsonstream@1.3.5",
  );
  assert.equal(
    value(npmPurl("left-pad", "1.0.0-beta.1")),
    "pkg:npm/left-pad@1.0.0-beta.1",
  );
  assert.equal(
    value(npmPurl("x", "1.0.0+build.5")),
    "pkg:npm/x@1.0.0%2Bbuild.5",
  );
  assert.equal(value(npmPurl("ms")), "pkg:npm/ms");
});

test("npm: malformed names are rejected", () => {
  for (const name of ["@scope", "@/x", "@scope/a/b", "a/b", "", "..", 42])
    assert.equal(
      failure(npmPurl(name, "1.0.0")).startsWith("purl-invalid"),
      true,
      String(name),
    );
});

test("formatPurl validates type", () => {
  assert.equal(
    failure(formatPurl({ type: "NPM", name: "x" })),
    "purl-invalid-type",
  );
});

test("parsePurl decodes what the builders encode", () => {
  for (const purl of [
    value(npmPurl("@babel/core", "7.24.0")),
    value(golangPurl("github.com/dgrijalva/jwt-go", "v3.2.0+incompatible")),
    value(cargoPurl("wasi", "0.11.0+wasi-snapshot-preview1")),
    value(npmPurl("café", "1.0.0")),
  ]) {
    const parsed = value(parsePurl(purl));
    assert.equal(value(formatPurl(parsed)), purl);
  }
  assert.deepEqual(value(parsePurl("pkg:npm/%40babel/core@7.24.0")), {
    type: "npm",
    namespace: ["@babel"],
    name: "core",
    version: "7.24.0",
  });
  assert.equal(failure(parsePurl("pkg:npm/x@1?a=b")), "purl-unparseable");
  assert.equal(failure(parsePurl("pkg:npm/%E0%A4%A")), "purl-unparseable");
});
