// Package URL (purl) builder for the S2 ecosystems: golang, cargo, npm.
// Spec: https://github.com/package-url/purl-spec (PURL-SPECIFICATION.rst, PURL-TYPES.rst).
// Encoding choice: every UTF-8 byte outside [A-Za-z0-9.-_~] and ':' is percent-encoded in
// namespace segments, name and version, so a semver "+build" suffix is written "%2B".
// Qualifiers and subpaths are not produced by any S2 adapter and are not supported.
import { err, ok } from "./result.mjs";

const UNENCODED = /[A-Za-z0-9.\-_~:]/;

export function percentEncode(value) {
  let out = "";
  for (const char of value) {
    if (UNENCODED.test(char)) {
      out += char;
      continue;
    }
    for (const byte of Buffer.from(char, "utf8"))
      out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

const badSegment = (segment) =>
  segment === "" || segment === "." || segment === "..";

/**
 * Serialize already-split purl components. Returns Result<string>.
 * namespace: array of segments (may be empty); version: string or null.
 */
export function formatPurl({ type, namespace = [], name, version = null }) {
  if (!/^[a-z][a-z0-9.+-]*$/.test(type))
    return err(
      "purl-invalid-type",
      `invalid purl type: ${JSON.stringify(type)}`,
    );
  if (typeof name !== "string" || badSegment(name) || name.includes("/"))
    return err(
      "purl-invalid-name",
      `invalid purl name: ${JSON.stringify(name)}`,
    );
  if (namespace.some((s) => typeof s !== "string" || badSegment(s)))
    return err(
      "purl-invalid-namespace",
      `invalid purl namespace: ${JSON.stringify(namespace)}`,
    );
  if (version !== null && (typeof version !== "string" || version === ""))
    return err(
      "purl-invalid-version",
      `invalid purl version: ${JSON.stringify(version)}`,
    );
  const path = [...namespace, name].map(percentEncode).join("/");
  return ok(
    `pkg:${type}/${path}${version === null ? "" : `@${percentEncode(version)}`}`,
  );
}

/**
 * Go module: the module path is split on "/"; the last segment is the name. Go module paths
 * are case-sensitive and kept as is (PURL-TYPES asks for lowercase, pending purl-spec#196;
 * packageurl-js does not lowercase either).
 */
export function golangPurl(modulePath, version = null) {
  if (typeof modulePath !== "string" || modulePath.length === 0)
    return err("purl-invalid-name", "empty Go module path");
  const segments = modulePath.split("/");
  return formatPurl({
    type: "golang",
    namespace: segments.slice(0, -1),
    name: segments.at(-1),
    version,
  });
}

/** crates.io package: no namespace, name kept as published. */
export function cargoPurl(name, version = null) {
  return formatPurl({ type: "cargo", name, version });
}

/** npm package: "@scope/name" becomes namespace "@scope" (encoded %40); both lowercased. */
export function npmPurl(packageName, version = null) {
  if (typeof packageName !== "string")
    return err("purl-invalid-name", "npm package name is not a string");
  const lower = packageName.toLowerCase();
  if (lower.startsWith("@")) {
    const parts = lower.split("/");
    if (parts.length !== 2 || parts[0].length < 2)
      return err(
        "purl-invalid-name",
        `invalid scoped npm name: ${JSON.stringify(packageName)}`,
      );
    return formatPurl({
      type: "npm",
      namespace: [parts[0]],
      name: parts[1],
      version,
    });
  }
  return formatPurl({ type: "npm", name: lower, version });
}

/** Parse the subset produced above (no qualifiers or subpath). Returns Result. */
export function parsePurl(purl) {
  const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#@]+)(?:@([^?#]+))?$/.exec(purl);
  if (!match) return err("purl-unparseable", `unsupported purl: ${purl}`);
  try {
    const segments = match[2].split("/").map(decodeURIComponent);
    return ok({
      type: match[1],
      namespace: segments.slice(0, -1),
      name: segments.at(-1),
      version: match[3] === undefined ? null : decodeURIComponent(match[3]),
    });
  } catch {
    return err("purl-unparseable", `invalid percent-encoding: ${purl}`);
  }
}
