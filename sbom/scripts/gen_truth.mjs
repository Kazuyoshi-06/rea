#!/usr/bin/env node
// Generate sbom/truth/<fixture>.json from each ecosystem's native tool.
// Rules are documented in sbom/TRUTH_RULES.md. No external dependencies.
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { EXPERIMENT_FIXTURES, FIXTURES } from "./fixtures.mjs";

const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(SBOM, "corpus/src");
const OUT = join(SBOM, "corpus/out");
const WORK = join(SBOM, ".work");
const TRUTH = join(SBOM, "truth");

const run = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, { encoding: "utf8", maxBuffer: 64 << 20, ...opts });

const sortComponents = (list) =>
  [
    ...new Map(
      list.map((c) => [`${c.ecosystem}|${c.name}|${c.version}`, c]),
    ).values(),
  ].sort(
    (a, b) =>
      a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
  );

// `go version -m` on the built binary. `dep` lines, with `=>` replacements taking the replacement.
function goTruth(fx) {
  const text = run("go", ["version", "-m", join(OUT, fx.id, fx.artifact)]);
  const out = [];
  const lines = text.split("\n").map((l) => l.trim().split("\t"));
  for (let i = 0; i < lines.length; i++) {
    const [kind, path, version] = lines[i];
    if (kind !== "dep") continue;
    const next = lines[i + 1];
    if (next?.[0] === "=>")
      out.push({ ecosystem: "golang", name: next[1], version: next[2] });
    else out.push({ ecosystem: "golang", name: path, version });
  }
  return out;
}

// `cargo tree`: normal edges only, no proc-macro subtrees, host target, root excluded.
function rustTruth(fx) {
  const text = run(
    "cargo",
    [
      "tree",
      "--locked",
      "-e",
      "normal,no-proc-macro",
      "--prefix",
      "none",
      "--target",
      "x86_64-unknown-linux-gnu",
      "-f",
      "{p}",
    ],
    { cwd: join(SRC, fx.source) },
  );
  const out = [];
  for (const line of text.split("\n")) {
    const m = /^(\S+) v(\S+)(.*)$/.exec(line.trim());
    if (!m || m[3].includes("(proc-macro)")) continue;
    if (m[3].includes(`(${join(SRC, fx.source)})`)) continue; // root package
    out.push({ ecosystem: "cargo", name: m[1], version: m[2] });
  }
  return out;
}

// `dotnet list package --include-transitive --format json` on a restored copy of the project.
function dotnetTruth(fx) {
  const dir = join(WORK, `truth-${fx.id}`);
  rmSync(dir, { recursive: true, force: true });
  cpSync(join(SRC, fx.source), dir, { recursive: true });
  const env = {
    ...process.env,
    DOTNET_CLI_TELEMETRY_OPTOUT: "1",
    DOTNET_NOLOGO: "1",
  };
  run("dotnet", ["restore", "--locked-mode", "-v", "q"], { cwd: dir, env });
  const report = JSON.parse(
    run(
      "dotnet",
      ["list", "package", "--include-transitive", "--format", "json"],
      { cwd: dir, env },
    ),
  );
  const out = [];
  for (const project of report.projects ?? [])
    for (const framework of project.frameworks ?? [])
      for (const p of [
        ...(framework.topLevelPackages ?? []),
        ...(framework.transitivePackages ?? []),
      ])
        out.push({
          ecosystem: "nuget",
          name: p.id,
          version: p.resolvedVersion,
        });
  return out;
}

// package-lock.json v3: installed non-dev packages under node_modules/.
function npmTruth(fx) {
  const lock = JSON.parse(
    readFileSync(join(SRC, fx.source, "package-lock.json"), "utf8"),
  );
  const out = [];
  for (const [key, pkg] of Object.entries(lock.packages ?? {})) {
    if (!key.startsWith("node_modules/") && !key.includes("/node_modules/"))
      continue;
    if (pkg.dev) continue;
    const name =
      pkg.name ??
      key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
    out.push({ ecosystem: "npm", name, version: pkg.version });
  }
  return out;
}

// `pip freeze` of a clean venv holding only the fixture requirements (no PyInstaller toolchain).
function pythonTruth(fx) {
  const venv = join(WORK, `venv-truth-${fx.id}`);
  if (!existsSync(join(venv, "bin/pip"))) {
    run("python3", ["-m", "venv", venv]);
    run(join(venv, "bin/pip"), [
      "install",
      "-q",
      "--disable-pip-version-check",
      "-r",
      join(SRC, fx.source, "requirements.txt"),
    ]);
  }
  const out = [];
  for (const line of run(join(venv, "bin/pip"), [
    "freeze",
    "--disable-pip-version-check",
  ]).split("\n")) {
    const m = /^([A-Za-z0-9._-]+)==(\S+)$/.exec(line.trim());
    if (m) out.push({ ecosystem: "pypi", name: m[1], version: m[2] });
  }
  return out;
}

const READERS = {
  golang: goTruth,
  cargo: rustTruth,
  nuget: dotnetTruth,
  npm: npmTruth,
  pypi: pythonTruth,
};

mkdirSync(TRUTH, { recursive: true });
const only = new Set(process.argv.slice(2));
for (const fx of [...FIXTURES, ...EXPERIMENT_FIXTURES]) {
  if (only.size && !only.has(fx.id) && !only.has(fx.ecosystem)) continue;
  try {
    const components = sortComponents(READERS[fx.ecosystem](fx));
    writeFileSync(
      join(TRUTH, `${fx.id}.json`),
      `${JSON.stringify(components, null, 2)}\n`,
    );
    console.log(`truth ${fx.id}: ${components.length} components`);
  } catch (error) {
    console.error(
      `truth ${fx.id}: FAILED ${String(error.message).split("\n")[0]}`,
    );
    process.exitCode = 1;
  }
}
