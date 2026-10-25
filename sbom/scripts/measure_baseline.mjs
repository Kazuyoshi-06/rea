#!/usr/bin/env node
// Compare raw REA outputs (sbom/baseline/raw/) with ground truth (sbom/truth/) and write
// sbom/BASELINE.md and sbom/baseline/summary.json. Node built-ins only.
//
// Matching is strict on (ecosystem, normalized name, exact version string). Name normalization
// is per ecosystem identity rules (TRUTH_RULES.md); versions are never normalized.
// A "found" component is only what REA states as a package/module/assembly identity with a
// version field. File paths and module names are reported separately as name-only signals.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { FIXTURES } from "./fixtures.mjs";

const SBOM = join(dirname(fileURLToPath(import.meta.url)), "..");
const RAW = join(SBOM, "baseline/raw");
const TRUTH = join(SBOM, "truth");

const normName = {
  golang: (n) => n,
  cargo: (n) => n,
  npm: (n) => n,
  nuget: (n) => n.toLowerCase(),
  pypi: (n) => n.toLowerCase().replace(/[-_.]+/g, "-"),
};

function readRaw(file) {
  const path = join(RAW, file);
  const bytes = readFileSync(path);
  return (file.endsWith(".gz") ? gunzipSync(bytes) : bytes).toString("utf8");
}

// Each extractor returns { found: [{name, version, note?}], signals: string[], fieldNotes: string[] }
// from the parsed raw outputs. fieldNotes record fixture-level observations used as reasons.
const EXTRACT = {
  golang([{ json }]) {
    const bi = json?.normalized_result?.build_info;
    if (!bi?.module)
      return {
        found: [],
        signals: [],
        fieldNotes: ["champ absent: normalized_result.build_info.module"],
      };
    const found = (bi.module.dependencies ?? []).map((d) => ({
      name: d.replacement?.path ?? d.path,
      version: d.replacement?.version ?? d.version,
    }));
    return { found, signals: [], fieldNotes: [] };
  },
  cargo([{ json }]) {
    const meta = json?.normalized_result?.auditable_metadata;
    if (!meta)
      return {
        found: [],
        signals: [],
        fieldNotes: ["champ absent: normalized_result.auditable_metadata"],
      };
    const found = (meta.packages ?? [])
      .filter((p) => !p.root)
      .map((p) => ({
        name: p.name,
        version: p.version,
        note: `kind=${p.kind ?? "null"}`,
      }));
    return { found, signals: [], fieldNotes: [] };
  },
  nuget(runs, fx) {
    const found = [];
    const signals = [];
    for (const { json, target } of runs) {
      const asm = json?.normalized_result?.assembly;
      if (!asm) continue;
      if (target === `${fx.source}.dll`) {
        for (const r of json.normalized_result.references ?? [])
          signals.push(`AssemblyRef ${r.name} ${r.version}`);
        continue; // the application's own assembly is the root, not a component
      }
      found.push({
        name: asm.name,
        version: asm.version,
        note: "assembly.version (AssemblyVersion)",
      });
    }
    return { found, signals, fieldNotes: [] };
  },
  npm([{ json }]) {
    const nodes = json?.normalized_result?.graph?.nodes;
    if (!nodes)
      return {
        found: [],
        signals: [],
        fieldNotes: ["champ absent: normalized_result.graph.nodes"],
      };
    const found = [];
    for (const n of nodes) {
      if (n.kind !== "package") continue;
      for (const o of n.observations ?? []) {
        const p = o.properties ?? {};
        if (p.path === "package.json") continue; // application root
        found.push({ name: p.name, version: p.version, note: p.path });
      }
    }
    return { found, signals: [], fieldNotes: [] };
  },
  pypi([{ json }]) {
    const found = [];
    const modules = new Set();
    for (const step of json?.normalized_result?.substeps ?? []) {
      for (const occ of step.evidence?.normalized_result?.occurrences ?? []) {
        const path = occ.logical_path ?? "";
        const dist =
          /(?:^|\/)([^/]+?)-([^/-]+)\.(?:dist-info|egg-info)(?:\/|$)/.exec(
            path,
          );
        if (dist)
          found.push({
            name: dist[1],
            version: dist[2],
            note: path.replace(/\/[^/]*$/, ""),
          });
        const mod = /^PYZ-00\.pyz\/([^/]+?)(?:\/|\.pyc$)/.exec(path);
        if (mod) modules.add(mod[1]);
      }
    }
    const fieldNotes = found.length
      ? []
      : [
          "aucun répertoire *.dist-info dans l'inventaire: pas de métadonnée de distribution (nom+version)",
        ];
    return {
      found,
      signals: [...modules].sort().map((m) => `module ${m}`),
      fieldNotes,
    };
  },
};

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// Version token search: "5.0.1" must not match inside "5.0.1.0".
const hasVersionToken = (text, v) =>
  new RegExp(`(?<![\\w.+-])${escapeRe(v)}(?![\\w.+-])`).test(text);
const pct = (n, d) => (d === 0 ? "n/a" : `${((100 * n) / d).toFixed(0)}%`);
const key = (eco, c) => `${normName[eco](c.name)}@${c.version}`;

const results = [];
for (const fx of FIXTURES) {
  const runMetaPath = join(RAW, `${fx.id}.run.json`);
  const truthPath = join(TRUTH, `${fx.id}.json`);
  if (!existsSync(runMetaPath) || !existsSync(truthPath)) {
    results.push({
      fixture: fx.id,
      ecosystem: fx.ecosystem,
      skipped: !existsSync(truthPath) ? "truth missing" : "REA not run",
    });
    continue;
  }
  const truth = JSON.parse(readFileSync(truthPath, "utf8"));
  const meta = JSON.parse(readFileSync(runMetaPath, "utf8"));
  const runs = meta.runs.map((r) => {
    const text = readRaw(r.output_file);
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* recorded below as unparsable */
    }
    return { ...r, text, json };
  });
  const failed = runs.filter(
    (r) => r.exit_code !== 0 || !r.json || r.json.error,
  );
  const { found, signals, fieldNotes } = EXTRACT[fx.ecosystem](runs, fx);
  const allText = runs.map((r) => r.text).join("\n");

  const foundKeys = new Map(found.map((c) => [key(fx.ecosystem, c), c]));
  const truthKeys = new Map(truth.map((c) => [key(fx.ecosystem, c), c]));
  const foundByName = new Map(
    found.map((c) => [normName[fx.ecosystem](c.name), c]),
  );
  const truthByName = new Set(truth.map((c) => normName[fx.ecosystem](c.name)));

  const tp = [...truthKeys.keys()].filter((k) => foundKeys.has(k));
  const missing = truth
    .filter((c) => !foundKeys.has(key(fx.ecosystem, c)))
    .map((c) => {
      let reason;
      const sameName = foundByName.get(normName[fx.ecosystem](c.name));
      if (failed.length)
        reason = `REA en échec (${failed.map((r) => r.target).join(", ")})`;
      else if (sameName)
        reason =
          `version différente: REA=${sameName.version} (${sameName.note ?? "champ version"}); ` +
          (hasVersionToken(allText, c.version)
            ? `"${c.version}" figure ailleurs dans la sortie brute`
            : `"${c.version}" absent de la sortie brute`);
      else if (fieldNotes.length) reason = fieldNotes.join("; ");
      else if (allText.includes(c.name))
        reason =
          "nom présent dans la sortie brute mais pas comme composant versionné";
      else reason = "absent de la sortie brute";
      return { ...c, reason };
    });
  const extra = found
    .filter((c) => !truthKeys.has(key(fx.ecosystem, c)))
    .map((c) => ({
      name: c.name,
      version: c.version,
      reason: truthByName.has(normName[fx.ecosystem](c.name))
        ? `nom attendu, version différente (${c.note ?? ""})`
        : `hors vérité terrain (${c.note ?? "pas de détail"})`,
    }));
  const nameRecall = truth.filter((c) =>
    foundByName.has(normName[fx.ecosystem](c.name)),
  ).length;
  results.push({
    fixture: fx.id,
    ecosystem: fx.ecosystem,
    command: `rea ${fx.rea}`,
    truth: truth.length,
    found: foundKeys.size,
    tp: tp.length,
    precision: foundKeys.size ? tp.length / foundKeys.size : null,
    recall: truth.length ? tp.length / truth.length : null,
    name_recall: truth.length ? nameRecall / truth.length : null,
    missing,
    extra,
    signals,
    output_bytes: runs.reduce((s, r) => s + r.output_bytes, 0),
    elapsed_ms: runs.reduce((s, r) => s + r.elapsed_ms, 0),
    cpu_ms: runs.every((r) => r.cpu_ms != null)
      ? runs.reduce((s, r) => s + r.cpu_ms, 0)
      : null,
    peak_rss_kb: runs.every((r) => r.peak_rss_kb != null)
      ? Math.max(...runs.map((r) => r.peak_rss_kb))
      : null,
    exit_codes: runs.map((r) => r.exit_code),
  });
}

// Per-ecosystem micro-average.
const byEco = new Map();
for (const r of results.filter((x) => !x.skipped)) {
  const a = byEco.get(r.ecosystem) ?? {
    fixtures: 0,
    truth: 0,
    found: 0,
    tp: 0,
  };
  a.fixtures++;
  a.truth += r.truth;
  a.found += r.found;
  a.tp += r.tp;
  byEco.set(r.ecosystem, a);
}

const fmtBytes = (b) =>
  b > 1 << 20
    ? `${(b / (1 << 20)).toFixed(1)} MiB`
    : `${(b / 1024).toFixed(1)} KiB`;
const md = [];
md.push("# BASELINE — ce que REA (brut) sort réellement", "");
md.push(
  "Généré par `sbom/scripts/measure_baseline.mjs` (`make baseline`). Ne pas éditer à la main.",
  "",
);
md.push(
  "Correspondance stricte sur (nom normalisé, version exacte). « Trouvé » = identité de composant",
  "avec un champ version dans la sortie REA ; chemins de fichiers et noms de modules ne comptent pas",
  "(voir *signaux nom seul*). Rappel nom seul = part des composants vrais dont le nom apparaît comme",
  "composant REA, quelle que soit la version.",
  "",
);
md.push("## Par écosystème (micro-moyenne)", "");
md.push(
  "| Écosystème | Fixtures | Vrais | Trouvés | VP | Précision | Rappel |",
  "|---|---|---|---|---|---|---|",
);
for (const [eco, a] of byEco)
  md.push(
    `| ${eco} | ${a.fixtures} | ${a.truth} | ${a.found} | ${a.tp} | ${pct(a.tp, a.found)} | ${pct(a.tp, a.truth)} |`,
  );
md.push("", "## Par fixture", "");
md.push(
  "| Fixture | Commande REA | Vrais | Trouvés | VP | Manquants | En trop | Précision | Rappel | Rappel nom seul | Sortie | Durée | CPU | RSS max |",
  "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
);
for (const r of results) {
  if (r.skipped) {
    md.push(`| ${r.fixture} | SKIP: ${r.skipped} |||||||||||||`);
    continue;
  }
  md.push(
    `| ${r.fixture} | \`${r.command}\` | ${r.truth} | ${r.found} | ${r.tp} | ${r.missing.length} | ${r.extra.length} | ` +
      `${pct(r.tp, r.found)} | ${pct(r.tp, r.truth)} | ${r.name_recall == null ? "n/a" : pct(r.name_recall * r.truth, r.truth)} | ` +
      `${fmtBytes(r.output_bytes)} | ${(r.elapsed_ms / 1000).toFixed(1)} s | ` +
      `${r.cpu_ms == null ? "non mesuré" : `${(r.cpu_ms / 1000).toFixed(1)} s`} | ` +
      `${r.peak_rss_kb == null ? "non mesuré" : `${Math.round(r.peak_rss_kb / 1024)} MiB`} |`,
  );
}
md.push(
  "",
  "Durée = temps mur du processus CLI (démarrage Node inclus), un seul run par cible, sans répétition ni séparation froid/chaud ;",
  "CPU = user+sys et RSS max via `/usr/bin/time` (processus principal + enfants attendus, pic du plus gros). Pour .NET : somme/max sur toutes les DLL.",
  "",
);
md.push("## Détail", "");
for (const r of results.filter((x) => !x.skipped)) {
  md.push(`### ${r.fixture}`, "");
  md.push(`- Codes de sortie REA : ${r.exit_codes.join(", ")}`);
  if (!r.missing.length) md.push("- Manquants : aucun");
  else {
    md.push("- Manquants :");
    for (const m of r.missing)
      md.push(`  - \`${m.name}@${m.version}\` — ${m.reason}`);
  }
  if (!r.extra.length) md.push("- En trop : aucun");
  else {
    md.push("- En trop :");
    for (const e of r.extra)
      md.push(`  - \`${e.name}@${e.version}\` — ${e.reason}`);
  }
  if (r.ecosystem === "pypi" && r.signals.length) {
    const truthNames = new Set(
      JSON.parse(readFileSync(join(TRUTH, `${r.fixture}.json`), "utf8")).map(
        (c) => normName.pypi(c.name),
      ),
    );
    const hits = r.signals
      .map((s) => s.slice("module ".length))
      .filter((m) => truthNames.has(normName.pypi(m)));
    md.push(
      `- Signaux nom seul (non comptés) : ${r.signals.length} modules de premier niveau dans PYZ-00.pyz, stdlib comprise ; ` +
        `nom normalisé identique à une distribution vraie : ${hits.length ? hits.map((m) => `\`${m}\``).join(", ") : "aucun"}`,
    );
  } else if (r.signals.length)
    md.push(
      `- Signaux nom seul (non comptés) : ${r.signals.map((s) => `\`${s}\``).join(", ")}`,
    );
  md.push("");
}
writeFileSync(join(SBOM, "BASELINE.md"), `${md.join("\n")}\n`);
writeFileSync(
  join(SBOM, "baseline/summary.json"),
  `${JSON.stringify(results, null, 2)}\n`,
);
console.log(`BASELINE.md written (${results.length} fixtures)`);
