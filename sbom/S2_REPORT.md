# S2_REPORT — cœur SBOM : modèle, purl, CycloneDX 1.6, adaptateurs Go / Rust / npm

Session S2, 2026-10-25, conteneur Linux x64 (Ubuntu 24.04), Node 24.22.1, go1.24.7, cargo-auditable 0.7.7.
Chaque affirmation est marquée **[constaté]** (sortie de commande dans cette session) ou
**[supposé]** (raisonnement non vérifié). Hors périmètre : .NET et PyInstaller (S3).

## Ce qui marche

| Livrable                              | Où                                                      | État                                                                                  |
| ------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Modèle composant / unknown / evidence | `lib/model.mjs`                                         | composants dédupliqués (une identité, N preuves), tri stable                          |
| purl golang / cargo / npm             | `lib/purl.mjs`, `test/purl.test.mjs`                    | 8 tests, cas limites ci-dessous [constaté]                                            |
| Interface REA mince                   | `lib/rea.mjs` (`readGoBuildInfo`, `readCargoAuditable`) | seul module qui connaît REA ; renvoie des faits indépendants de REA                   |
| Adaptateur Go                         | `lib/adapters/go.mjs`                                   | 4/4 fixtures : précision 100 %, rappel 100 % [constaté]                               |
| Adaptateur Rust                       | `lib/adapters/rust.mjs`                                 | 2/2 fixtures : précision 100 %, rappel 100 % (REA brut : 54 %) [constaté]             |
| Lecteur ASAR + node_modules           | `lib/tree.mjs`, `lib/adapters/npm.mjs`                  | 2/2 fixtures : 100 % / 100 %, sans REA [constaté]                                     |
| Export CycloneDX 1.6                  | `lib/cyclonedx.mjs`                                     | valide au schéma officiel épinglé, octets identiques entre deux exécutions [constaté] |
| CLI                                   | `bin/sbom-scan <artefact> --format cyclonedx`           | détection auto Go / Rust / ASAR / répertoire ; codes 0 / 1 (échec) / 2 (usage)        |
| Tests                                 | `make sbom-test` (dans `sbom/`)                         | 39 tests node:test, 0 échec [constaté], voir « Depuis un clone propre »               |

### Commandes

```sh
cd sbom
make sbom-test                       # construit fixtures Go/Rust/npm + REA si absents, npm ci (deps de test), tests
make sbom-measure                    # temps / CPU / RSS par appel REA et par scan → s2/measurements.json
bin/sbom-scan corpus/out/go-jwt/go-jwt --format cyclonedx [--output f.json] [--timestamp ISO|EPOCH]
bin/sbom-scan <dossier contenant node_modules> --format model   # modèle interne (JSON)
```

Prérequis de `make sbom-test` : Go, Rust + `cargo-auditable`, Node 24 (le Makefile prend
`/opt/nvm/versions/node/v24.22.1` s'il existe), accès registre npm (deps de test et build de REA).
`sbom-scan` lui-même n'a aucune dépendance hors Node standard ; il a aussi tourné sous Node 22.22.0
(go-jwt, npm-cli) [constaté]. REA est appelé avec le même binaire Node (`REA_NODE`, `REA_CLI` pour
surcharger).

## Décisions

### Modèle

- Composant `{purl, name, version, ecosystem, source, confidence, role, evidence[]}` ; `role` vaut
  `library` ou `language-runtime` (stdlib Go). `confidence` : `observed` (lu tel quel) ou `inferred`
  (ex. nom npm pris du répertoire d'installation faute de `name`).
- `unknowns` `{ecosystem, name, reason, evidence[]}` : détecté sans version (package.json sans
  version ou illisible, `replace` Go vers un répertoire local, version `(devel)`, toolchain Go non
  `goX.Y.Z`, lien symbolique non suivi). Jamais de version inventée.
- `exclusions` `{ecosystem, name, version, reason}` : présent dans les métadonnées, volontairement non
  composant (Rust `kind=build`).
- Evidence : `artifact {path tel que donné par l'appelant, sha256}`, `location` (`file-range`
  offset/taille pour Go/Rust ; `asar-entry` chemin interne + offset absolu + taille ; `asar-unpacked` ;
  `file` en mode répertoire), `sourceSha256` (sha256 des octets qui portent l'info : bloc modules
  du buildinfo Go, section `.dep-v0`, `package.json`), `reader` (`rea inspect-go-binary <artifact>
  --format json` + provider REA, ou `asar-reader`). Les durées ne sont pas dans l'evidence (elles
  casseraient le déterminisme) ; `--timings` les écrit sur stderr.

### purl

- Encodage : tout octet UTF-8 hors `[A-Za-z0-9.-_~]` et `:` est encodé. Donc
  `v3.2.0+incompatible` → `v3.2.0%2Bincompatible`, `@babel` → `%40babel`.
  **Écart connu** : `packageurl-js` 2.0.1 laisse `+` non encodé dans la version [constaté en lisant son
  `encode.js`]. Les deux formes décodent à l'identique ; un consommateur qui compare des purl en chaîne
  brute verra une différence [supposé].
- golang : chemin de module découpé sur `/`, dernier segment = nom ; casse conservée (la règle
  « lowercase » de PURL-TYPES est en suspens, purl-spec#196 ; packageurl-js ne met pas en minuscules
  [constaté]). Suffixe `/vN` conservé dans le chemin.
- npm : `@scope/nom` → namespace `%40scope`, nom en minuscules (règle du type npm).
- cargo : nom tel que publié.
- Cas testés : `+incompatible`, pseudo-versions, `/v5`, `gopkg.in/yaml.v3`, casse Go, module à un seul
  segment, `0.11.0+wasi-snapshot-preview1`, scope en majuscules, `JSONStream`, non-ASCII, chemins
  vides / `.` / `..`, `@scope` sans nom, `@scope/a/b`, aller-retour `parsePurl`/`formatPurl`.

### Go : module principal et stdlib (point 8, cohérent avec TRUTH_RULES.md)

- **Module principal → `metadata.component`**, pas `components` (TRUTH_RULES : la racine n'est pas un
  composant). Version `(devel)` → pas de `version` ni de purl ; la valeur brute est gardée en propriété
  `rea-sbom:root-raw-version`. Une vraie version (binaire `go install mod@vX`) donnerait un purl.
- **stdlib → `components`** avec `rea-sbom:role=language-runtime`, nom `stdlib`, version `goX.Y.Z` →
  `X.Y.Z`, purl `pkg:golang/stdlib@1.24.7`. Raison : c'est la seule façon pour un scanner de voir les
  CVE de la bibliothèque standard Go, fréquentes [supposé : convention OSV/syft/grype, non vérifiée
  contre ces outils]. Conformément à TRUTH_RULES (runtimes hors comparaison), **la stdlib est exclue du
  calcul précision/rappel** ; les tests vérifient séparément sa présence. Toolchain non `goX.Y.Z`
  (`devel …`, `go1.21rc2`, `X:boringcrypto`) → unknown avec la valeur brute.
- `replace` : le module de remplacement est l'identité livrée, l'original est dans l'evidence
  (`replaces`) ; remplacement local → unknown. Testé sur faits synthétiques uniquement (aucun `replace`
  dans le corpus).

### Rust (point 9)

- `kind=build` exclu ; `kind` null traité comme runtime (`kindInterpretation` dans l'evidence) ;
  `kind` inconnu (ex. futur `dev`) **gardé** et signalé (fail-closed : on ne jette pas un composant).
- Chaque evidence porte `excludedBuildCount` (5 pour rust-small, 1 pour rust-vuln [constaté]) et
  `packagesInSection` ; la liste nominative est dans `metadata.properties` (`rea-sbom:excluded-component`).
- **Limite connue de cargo-auditable** (notée dans chaque BOM Rust, `rea-sbom:limitation`) : les
  `[dev-dependencies]` ne sont jamais enregistrées (`itoa` de rust-vuln absent [constaté en S1]).
  Pour un binaire release c'est correct, mais leur absence n'est pas une preuve observable.
- Racine (`root: true`) → `metadata.component` ; purl seulement si source `crates.io`. Sources non
  crates.io (git, local, registre tiers) → composant sans purl (`rea-sbom:purl-status`).

### CycloneDX 1.6

- Déterminisme : tableaux triés par le modèle, clés dans un ordre fixe, `serialNumber` = UUIDv5
  (namespace URL RFC 4122) du sha256 du BOM sérialisé sans `serialNumber` **mais avec** le timestamp
  (même contenu + même instant = même numéro ; un autre instant donne un autre numéro, ce que demande la
  spec). Timestamp : `--timestamp`, sinon `SOURCE_DATE_EPOCH`, sinon l'heure courante.
- Composants sans version : **pas dans `components`**, dans `metadata.properties` sous
  `rea-sbom:unknown-component` (valeur JSON : écosystème, nom, raison, emplacements) + compteur
  `rea-sbom:unknown-count`. Raison : un composant sans version peut être apparié à toutes les versions
  par un scanner [supposé].
- Evidence CycloneDX : `evidence.identity` (technique `binary-analysis` ou `manifest-analysis`,
  confiance 1 ou 0,5) et `evidence.occurrences` (emplacement, `offset`, evidence complète en JSON dans
  `additionalContext`).
- Pas de `dependencies` : Go n'enregistre pas de graphe, le graphe Rust et npm n'est pas exporté en S2.
  Absence = inconnu, pas « aucune dépendance ».
- Schéma : `@cyclonedx/cyclonedx-library@10.3.0` (npm, **1re tentative**), fichiers épinglés gzippés
  dans `schemas/` avec sha256 et provenance (`schemas/README.md`). Validation Ajv 8 + `ajv-formats` +
  `ajv-formats-draft2019`, comme la bibliothèque. Le validateur rejette bien un BOM corrompu
  (`serialNumber` invalide, `type` inconnu) [constaté]. Égalité octet à octet avec le
  `bom-1.6.schema.json` du dépôt de spécification CycloneDX : **non vérifiée** (GitHub brut non utilisé).

### Lecteur ASAR (npm)

- Lit le préfixe Pickle (16 octets), l'en-tête JSON (garde 64 Mio), puis uniquement les
  `package.json` (garde 8 Mio chacun) par lecture positionnelle : jamais l'archive entière.
- Parcours : `node_modules/<nom>`, `node_modules/@scope/<nom>`, récursivement via
  `<paquet>/node_modules`. Entrées `.` ignorées (`.bin`, `.package-lock.json`, `.pnpm`). Un
  `package.json` interne à un paquet (`lib/esm/package.json`) n'est pas un paquet.
- Vérifie le hash d'intégrité ASAR de chaque `package.json` (`asarIntegrity: verified|mismatch|absent`) ;
  fichiers `unpacked` lus dans `app.asar.unpacked/`. Données hors archive, JSON invalide, offset non
  décimal → unknown ou échec, jamais un composant.
- Même code sur un répertoire contenant `node_modules` (liens symboliques signalés, non suivis).
- Tests sur arbres synthétiques empaquetés par le vrai `@electron/asar` 3.2.17 (dépendance de test) :
  scopes, imbrication, deux versions du même paquet, même paquet à deux endroits (1 composant,
  2 preuves), alias npm, sans nom, sans version, JSON invalide, sans package.json, lien, unpacked,
  falsification détectée par l'intégrité, en-têtes malformés, données hors archive.

## Mesures

Toutes **[constaté]**, `/usr/bin/time` (GNU), 4 exécutions par cible (`RUNS=4 make sbom-measure`,
données brutes dans `s2/measurements.json`). « Froid » = 1re exécution de la série, cache disque non
contrôlé ; « chaud » = médiane des 3 suivantes. RSS = pic du plus gros processus de l'arbre (REA est un
enfant de `sbom-scan`). Tokens d'agent : non mesurés.

### Coût par appel REA (derrière `lib/rea.mjs`)

| Fixture          | Appel                     | Durée froid / chaud | CPU chaud | RSS chaud | JSON REA |
| ---------------- | ------------------------- | ------------------- | --------- | --------- | -------- |
| go-uuid          | `rea inspect-go-binary`   | 1,35 s / 1,39 s     | 1,99 s    | 355 Mio   | 4 448 o  |
| go-uuid-stripped | `rea inspect-go-binary`   | 1,48 s / 1,38 s     | 1,86 s    | 356 Mio   | 4 484 o  |
| go-jwt           | `rea inspect-go-binary`   | 1,47 s / 1,42 s     | 1,90 s    | 358 Mio   | 4 067 o  |
| go-jwt-stripped  | `rea inspect-go-binary`   | 1,37 s / 1,39 s     | 1,83 s    | 357 Mio   | 4 103 o  |
| rust-small       | `rea inspect-rust-binary` | 1,47 s / 1,40 s     | 1,85 s    | 360 Mio   | 5 143 o  |
| rust-vuln        | `rea inspect-rust-binary` | 1,43 s / 1,36 s     | 1,85 s    | 355 Mio   | 3 903 o  |

Plage sur les 24 exécutions : 1,29–2,05 s, 330–366 Mio. Cohérent avec la mesure S1 (~1,7–2,0 s,
338–364 Mio), un peu plus rapide ici [constaté] ; cause non isolée (machine, cache) [supposé].
L'appel REA représente ~95 % du temps d'un scan Go/Rust.

### Scan complet `sbom-scan --format cyclonedx`

| Fixture          | Durée chaud | RSS chaud  | CycloneDX | REA brut S1 (sortie / durée / RSS) |
| ---------------- | ----------- | ---------- | --------- | ---------------------------------- |
| go-uuid          | 1,42 s      | 357 Mio    | 7 677 o   | 4,3 Kio / 1,8 s / 358 Mio          |
| go-jwt           | 1,45 s      | 359 Mio    | 6 234 o   | 4,0 Kio / 1,7 s / 338 Mio          |
| rust-small       | 1,52 s      | 361 Mio    | 11 181 o  | 5,0 Kio / 1,8 s / 361 Mio          |
| rust-vuln        | 1,49 s      | 356 Mio    | 5 800 o   | 3,8 Kio / 2,0 s / 364 Mio          |
| **npm-electron** | **0,06 s**  | **55 Mio** | 4 706 o   | 92,8 Mio / 215,5 s / 892 Mio       |
| npm-cli          | 0,05 s      | 54 Mio     | 11 577 o  | 14,0 Mio / 11,3 s / 489 Mio        |

Critère npm-electron (< 10 s, < 300 Mio) avec `/usr/bin/time -v bin/sbom-scan
corpus/out/npm-electron/app.asar --format cyclonedx` : `Elapsed 0:00.06`, `Maximum resident set size
55628 kbytes`, `Exit status 0`, sortie 4 686 octets [constaté]. Facteur ~3 500× en temps et ~16× en
RSS par rapport à `analyze-javascript-application`, pour le même résultat (2/2 paquets). Les 55 Mio
sont essentiellement le coût fixe de Node [supposé : non profilé].

La taille CycloneDX dépend du chemin de l'artefact donné par l'appelant (conservé dans l'evidence).

## Depuis un clone propre

`git clone --branch sbom-s2-core` du dépôt local dans un répertoire temporaire, puis
`cd sbom && make sbom-test` [constaté] :

- fixtures Go / Rust / npm construites, **8/8 identiques à `corpus/DIGESTS.txt`** ;
- REA construit (`npm ci && npm run build:cached` à la racine du clone, fichiers ignorés uniquement) ;
- `npm ci` dans `sbom/` (Ajv, formats, `@electron/asar`) ;
- **39 tests, 39 réussis, 0 échec, 0 sauté** (avec `SBOM_REQUIRE_FIXTURES=1` : une fixture absente
  fait échouer au lieu de sauter) ; durée totale 61,6 s ;
- `git status` du clone vide après coup : aucun fichier suivi modifié.

Réserve : caches Go (`~/go/pkg/mod`), cargo (`~/.cargo/registry`) et npm déjà chauds dans ce conteneur ;
un premier build sur une machine vierge sera plus long [supposé].

## Limites constatées

- Corpus étroit : les cas scopes npm, `node_modules` imbriqués, `replace` Go, sources Rust non
  crates.io, kind inconnu ne sont couverts que par des tests synthétiques ; aucune fixture réelle.
- `sbom-scan` lit `app.asar`, pas une application Electron complète (binaire + `resources/app.asar`) :
  un exécutable Electron est refusé (`unsupported-artifact`) [supposé : aucun marqueur Go/Rust/ASAR
  dans le binaire ; non testé, pas de runtime Electron dans le corpus].
- npm : seuls `node_modules` racine et imbriqués sous les paquets ; workspaces, copies vendored,
  bundles (webpack/esbuild) qui n'embarquent pas les `package.json` : invisibles. pnpm (liens
  symboliques) en mode répertoire : les paquets sortent en unknowns, non suivis.
- Pas de graphe de dépendances exporté.
- Un scan Go/Rust coûte ~1,4 s et ~356 Mio pour lire < 1 Kio de métadonnées : coût fixe du CLI REA.
- Le BOM contient le chemin de l'artefact tel que donné : deux chemins différents → deux BOM
  différents (et deux `serialNumber`) pour le même binaire.

## Les trois choses les plus fragiles

1. **Le contrat JSON du CLI REA.** `lib/rea.mjs` dépend de `normalized_result.build_info.module.*` et
   `auditable_metadata.packages[*]` (format non versionné côté consommateur) et d'un dépôt REA construit
   (`dist/`). Un changement de forme échoue proprement (`rea-unexpected-report`) mais casse tout scan
   Go/Rust. C'est aussi 95 % du coût. Remplacer par un lecteur maison du buildinfo Go et de la section
   `.dep-v0` (zlib + JSON) ne touche que `lib/rea.mjs` ; à faire en priorité si REA n'apporte rien
   d'autre ici.
2. **La détection par marqueurs d'octets.** `\xff Go buildinf:` et `.dep-v0`/`__dep_v0` n'importe où
   dans le fichier choisissent le lecteur ; une chaîne littérale dans un binaire qui n'est ni l'un ni
   l'autre déclenche un appel REA (qui échoue proprement). Un binaire Rust sans cargo-auditable, un PE
   / Mach-O, un binaire Rust strippé de sa section, n'ont pas été testés. `__dep_v0` (Mach-O) est
   [supposé] d'après le nommage de cargo-auditable, non vérifié.
3. **Les conventions non standard de l'export.** Unknowns et exclusions en `metadata.properties` à
   valeur JSON, stdlib Go en `pkg:golang/stdlib@X.Y.Z`, `+` encodé `%2B` dans les purl : valides au
   schéma, mais aucun consommateur réel (grype, Dependency-Track, OSV-Scanner) n'a été essayé. Le
   gain attendu (CVE stdlib, pas de faux positifs sur les versions inconnues) reste [supposé].

## Hors S2

.NET et PyInstaller (S3), graphe de dépendances, consommation par un scanner de vulnérabilités, mesure
en tokens d'agent.
