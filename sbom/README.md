# sbom/ — S1 : corpus de vérité terrain et mesure brute de REA

Dossier isolé, aucun code produit SBOM. Il mesure ce que les lecteurs existants de REA sortent sur
des binaires dont on connaît exactement les dépendances.

| Fichier                 | Rôle                                                                                                                    |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `PROBE.md`              | Outils et réseau disponibles, faisabilité par écosystème                                                                |
| `TRUTH_RULES.md`        | Ce qui compte comme composant présent, par écosystème                                                                   |
| `BASELINE.md`           | Précision / rappel de REA brut par fixture (généré)                                                                     |
| `corpus/src/<fixture>/` | Sources des mini-programmes, dépendances et lockfiles épinglés                                                          |
| `corpus/out/`           | Artefacts construits (non commités, ~36 Mo > budget de 25 Mo)                                                           |
| `corpus/DIGESTS.txt`    | sha256 de chaque artefact construit                                                                                     |
| `corpus/REPRO.txt`      | Comparaison de deux reconstructions                                                                                     |
| `truth/<fixture>.json`  | Vérité terrain `[{ecosystem, name, version}]`                                                                           |
| `baseline/raw/`         | Sorties JSON brutes de REA, gzippées (`npm-*.json.gz` non commités, 2–18 Mo) + `*.run.json` (commande, durée, CPU, RSS) |
| `baseline/summary.json` | Résultat machine de la comparaison                                                                                      |
| `scripts/`              | `build_corpus.sh`, `gen_truth.mjs`, `run_rea.mjs`, `measure_baseline.mjs`, `check_repro.sh`, `fixtures.mjs`             |
| `tools/`                | Outils de build épinglés (`@electron/asar`, PyInstaller)                                                                |

## Utilisation

```sh
cd sbom
make baseline   # construit le corpus et REA si absents, lance REA, écrit BASELINE.md
make truth      # régénère truth/*.json avec les outils natifs
make corpus     # force la reconstruction et rafraîchit DIGESTS.txt
make repro      # deux reconstructions complètes, écrit corpus/REPRO.txt
```

Prérequis (bring-your-own) : Node 24.22.1 (`.nvmrc` ; le Makefile prend `/opt/nvm` s'il existe), Go,
Rust + `cargo-auditable`, .NET SDK 8, Python 3 + venv, GNU make ; `/usr/bin/time` optionnel (CPU/RSS).
Un écosystème dont la toolchain manque est sauté avec un message `SKIP`.

`make baseline` dure ~5 min, dont ~3,5 min pour `npm-electron` (voir BASELINE.md).

## Corpus

| Fixture                    | Écosystème  | Dépendances directes épinglées                                      | Vulnérabilité publique connue                       |
| -------------------------- | ----------- | ------------------------------------------------------------------- | --------------------------------------------------- |
| go-uuid / go-uuid-stripped | Go          | google/uuid v1.6.0, sirupsen/logrus v1.9.3                          | —                                                   |
| go-jwt / go-jwt-stripped   | Go          | dgrijalva/jwt-go v3.2.0+incompatible, golang.org/x/text v0.3.7      | CVE-2020-26160 (jwt-go), CVE-2022-32149 (x/text)    |
| rust-small                 | Rust        | serde =1.0.210 (derive), serde_json =1.0.128                        | —                                                   |
| rust-vuln                  | Rust        | regex =1.5.4 (+ build-dep autocfg, dev-dep itoa)                    | CVE-2022-24713 / RUSTSEC-2022-0013                  |
| dotnet-json                | .NET        | Newtonsoft.Json [12.0.1]                                            | GHSA-5crp-9r3c-p9vr                                 |
| dotnet-serilog             | .NET        | Serilog [3.1.1], Serilog.Sinks.Console [5.0.1]                      | —                                                   |
| npm-electron               | npm (ASAR)  | lodash 4.17.20, ms 2.1.3 (dev: electron 33.2.1)                     | CVE-2021-23337 (lodash)                             |
| npm-cli                    | npm (ASAR)  | minimist 1.2.5, chalk 4.1.2                                         | CVE-2021-44906 (minimist)                           |
| py-requests                | PyInstaller | requests 2.31.0, urllib3 1.26.17, certifi, idna, charset-normalizer | CVE-2024-35195 (requests), CVE-2023-45803 (urllib3) |
| py-requests-meta           | PyInstaller | idem py-requests, avec `--copy-metadata` (dist-info embarqués) (S3) | idem py-requests                                    |
| py-yaml                    | PyInstaller | PyYAML 5.3.1                                                        | CVE-2020-14343                                      |

Les identifiants de vulnérabilité viennent de la connaissance publique des avis (et, pour Newtonsoft,
de l'avertissement `NU1903` émis par `dotnet restore`, constaté) ; ils ne sont pas vérifiés par un
scanner dans S1.

## Choix de build (déterminisme)

- Go : `CGO_ENABLED=0 -trimpath -buildvcs=false`. Sans `-buildvcs=false`, le binaire embarque
  `vcs.revision`, `vcs.time`, `vcs.modified` du dépôt REA (constaté) : il change à chaque commit.
- Rust : `cargo auditable build --release --locked`, `--remap-path-prefix` sur la source et `$HOME`.
- .NET : `dotnet publish -c Release -p:RestoreLockedMode=true -p:DebugType=none -p:PathMap=<sbom>=/sbom`,
  `<Deterministic>`. Sans `PathMap`, la DLL de l'application change avec le chemin du clone (constaté :
  clone dans `/tmp` ≠ dépôt original) ; les DLL NuGet, copiées telles quelles, ne changent pas.
- npm : `npm ci --omit=dev --ignore-scripts` dans un répertoire de staging, suppression des répertoires
  vides, puis `asar pack`. Sans la suppression, un build depuis un clone propre contenait des
  répertoires de scope vides (`@electron`, `@types`, `@sindresorhus`, `@szmarczak`, restes des
  devDependencies omises) absents d'un autre build (constaté ; cause côté npm non isolée). Les paquets
  eux-mêmes étaient identiques et REA donnait le même résultat.
- PyInstaller : `--onefile --clean`, `SOURCE_DATE_EPOCH=0`. `py-requests-meta` ajoute
  `--copy-metadata` pour chaque distribution listée dans `corpus/src/py-requests-meta/copy-metadata.txt`. **Non déterministe malgré cela** (constaté) :
  les builds successifs alternent entre deux sorties (A, B, A…) pour `py-yaml` comme pour `py-requests`.
  `pyi-archive_viewer` montre une seule différence de TOC : l'entrée libpython s'appelle
  `libpython3.13.so.1.0` dans un build et `libpython3.13.so` dans l'autre (même taille, même offset),
  soit 8 octets différents dans le fichier. Le contenu Python embarqué est le même. Cause dans PyInstaller
  non investiguée. Conséquence : `DIGESTS.txt` des fixtures PyInstaller dépend du build, et le champ
  REA `format_metadata.python_library` aussi.

Résultat de `make repro` (3 builds, même chemin) : voir `corpus/REPRO.txt`. Un `make repro` à 2 builds
avait conclu « 21/21 identiques » : il est tombé sur deux builds du même état. Hors PyInstaller,
les artefacts sont identiques entre le dépôt et un clone propre dans un autre chemin (constaté après
les correctifs `PathMap` et répertoires vides).

## S2 — cœur SBOM (Go, Rust, npm)

`bin/sbom-scan <artefact> --format cyclonedx` produit un CycloneDX 1.6 JSON déterministe pour un
binaire Go, un binaire Rust construit avec `cargo auditable`, une archive `app.asar` ou un répertoire
contenant `node_modules`. Détails, décisions et mesures : [`S2_REPORT.md`](S2_REPORT.md).

| Fichier                       | Rôle                                                                      |
| ----------------------------- | ------------------------------------------------------------------------- |
| `lib/model.mjs`               | Composants, unknowns, exclusions, evidence ; fusion et tri                |
| `lib/purl.mjs`                | purl `pkg:golang`, `pkg:cargo`, `pkg:npm`                                 |
| `oracle/rea.mjs`              | REA comme oracle de comparaison uniquement (S5 : plus importé par `lib/`) |
| `lib/tree.mjs`                | Lecteur ASAR minimal et arborescence répertoire                           |
| `lib/adapters/*.mjs`          | Go, Rust, npm → modèle                                                    |
| `lib/cyclonedx.mjs`           | Export CycloneDX 1.6                                                      |
| `lib/scan.mjs`, `lib/cli.mjs` | Détection automatique, CLI                                                |
| `schemas/`                    | Schéma CycloneDX 1.6 épinglé (gzip, sha256, provenance)                   |
| `test/`                       | Tests node:test ; `make sbom-test` construit ce qu'il faut et les lance   |
| `s2/measurements.json`        | Sortie de `make sbom-measure` (temps, CPU, RSS par appel REA et par scan) |

## S3 — cas difficiles : .NET et PyInstaller

`bin/sbom-scan` lit aussi un répertoire de publication .NET (ou une DLL isolée) et un exécutable
PyInstaller `--onefile`, en Node pur (aucun appel à REA). Détails, mesures, limites :
[`S3_REPORT.md`](S3_REPORT.md).

| Fichier                              | Rôle                                                                                    |
| ------------------------------------ | --------------------------------------------------------------------------------------- |
| `lib/readers/cli-metadata.mjs`       | PE → en-tête CLI → tables de métadonnées ECMA-335 (assembly, attributs de version)      |
| `lib/adapters/dotnet.mjs`            | `*.deps.json` (confiance high) ; repli sur les attributs de la DLL (medium, ou unknown) |
| `lib/readers/marshal.mjs`            | Lecteur `marshal` (CPython 3.13) : TOC du PYZ et objets code                            |
| `lib/readers/pybytecode.mjs`         | Liaisons de noms au niveau module d'un objet code 3.13                                  |
| `lib/readers/pyinstaller.mjs`        | Cookie MEI, CArchive (TOC), PYZ                                                         |
| `lib/adapters/pyinstaller.mjs`       | dist-info METADATA (high) ; spike bytecode (low) ; stdlib retirée                       |
| `lib/adapters/pypi-modules.mjs`      | Table statique module → distribution (courte, documentée)                               |
| `data/stdlib-module-names-3.13.json` | `sys.stdlib_module_names` de Python 3.13.17 (donnée de référence)                       |
| `scripts/measure_s3.mjs`             | Précision / rappel + `/usr/bin/time -v` → `s3/measurements.json`                        |
| `scripts/experiment_py_wide.mjs`     | Test hors corpus du spike bytecode (`corpus/src/py-wide`, jamais dans `make sbom-test`) |

```sh
make sbom-test          # construit Go/Rust/npm/.NET/PyInstaller + REA, lance tous les tests
make sbom-measure-s3    # précision / rappel / temps / RSS .NET et PyInstaller → s3/measurements.json
make stdlib-names       # régénère data/stdlib-module-names-<X.Y>.json avec python3
```

Prérequis supplémentaires : SDK .NET 8 (`apt install dotnet-sdk-8.0` quand dot.net est bloqué),
Python 3.13 avec `venv` et accès PyPI. Les tests qui compilent des extraits Python exigent Python 3.13
(bytecode et numéros d'opcode propres à cette version).

### Décisions appliquées en S4 (partie A)

- **Confiance** : une seule échelle `high` / `medium` / `low` pour tous les écosystèmes (propriété
  `rea-sbom:confidence`, CycloneDX 1 / 0,6 / 0,3). Go, Rust, npm : `observed` → `high`,
  `inferred` → `medium`.
- **PyPI** : `version` et purl = forme normale PEP 440 de la chaîne lue (`2023.07.22` → `2023.7.22`) ;
  la chaîne lue reste dans l'evidence (`rawValue`). Une version de dist-info non PEP 440 est émise
  telle quelle, marquée `pep440: "invalid"` et signalée en limitation. Bytecode : toujours `low`.
- **.NET, repli sans deps.json** : seule une `AssemblyInformationalVersion` sans étiquette de
  pré-version donne un composant (`medium`) ; une pré-version ou une `AssemblyFileVersion` donne un
  unknown, la valeur candidate restant dans l'evidence (`candidate`).
- **Chemin de l'artefact** : le BOM ne contient plus le chemin donné en argument, seulement le nom de
  base (`rea-sbom:artifact-name`) et le sha256 ; le même fichier scanné depuis deux répertoires donne
  les mêmes octets (`test/path-independence.test.mjs`).

## S4 — appariement aux vulnérabilités connues, hors ligne

`bin/sbom-scan <artefact> --format cyclonedx --vulns [--db sbom/vulndb]` ajoute la section
`vulnerabilities` de CycloneDX 1.6, à partir d'un index local construit depuis les exports OSV.
Aucun appel réseau au moment du scan. Détails, mesures, oracles indépendants, limites :
[`S4_REPORT.md`](S4_REPORT.md) ; joignabilité des sources : [`PROBE_S4.md`](PROBE_S4.md).

| Fichier                                           | Rôle                                                                                 |
| ------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `lib/versions/{semver,nuget,pep440}.mjs`          | Comparaison de versions en Node pur (SemVer/Go, NuGet, PEP 440)                      |
| `lib/vulns/osv.mjs`                               | Évaluation des plages OSV (SEMVER, ECOSYSTEM, listes `versions` ; GIT ignoré)        |
| `lib/vulns/db.mjs`                                | Index par paquet (`vulndb/index/`), écriture et lecture par recherche dichotomique   |
| `lib/vulns/match.mjs`                             | Appariement des composants (jamais des unknowns), confiance héritée                  |
| `lib/readers/zip.mjs`                             | Lecteur ZIP minimal (ZIP64) pour les exports OSV                                     |
| `scripts/vulndb.mjs`                              | `make vulndb` : téléchargement, index, `vulndb/SNAPSHOT.json` (seul fichier commité) |
| `scripts/oracle_s4.mjs`, `scripts/measure_s4.mjs` | Comparaison aux oracles → `s4/oracle.json` ; mesures → `s4/measurements.json`        |
| `test/data/osv-mini/`                             | Mini corpus au format OSV pour les tests hors ligne                                  |

```sh
make vulndb             # ~275 Mo d'archives OSV dans vulndb/ (gitignoré) + index ; VULNDB_FLAGS=--no-download pour réindexer
make sbom-test          # inclut les tests hors ligne ; les tests de bornes sur la vraie snapshot tournent si l'index existe
make sbom-measure-s4    # temps / CPU / RSS avec et sans --vulns → s4/measurements.json
make sbom-oracle        # osv-scanner, npm audit, pip-audit, dotnet list package --vulnerable → s4/oracle.json
```

## S5 — décisions de format (partie A) et indépendance vis-à-vis de REA

Détails, mesures et limites : [`S5_REPORT.md`](S5_REPORT.md).

### Alertes (`--vulns`)

- **Une entrée `vulnerabilities[]` par vulnérabilité**, pas par enregistrement OSV : les
  enregistrements liés par leurs `aliases` (GO-/GHSA-/CVE-/PYSEC-/RUSTSEC-…, transitivement ;
  `related` ne lie pas) forment un groupe. Identifiant principal déterministe : le premier CVE par
  ordre alphabétique, sinon le premier GHSA, sinon le premier identifiant. Tous les autres
  identifiants vont dans `references` ; les enregistrements OSV effectivement appariés sont listés
  en `rea-sbom:osv-record` ; tous les composants concernés sont dans `affects`.
  `rea-sbom:vuln-count` = nombre de groupes, `rea-sbom:vuln-record-count` = nombre de couples
  (enregistrement OSV, composant).
- **Stdlib Go** : ses alertes portent `rea-sbom:scope=language-runtime`. `--no-runtime-vulns` (avec
  `--vulns`) les exclut ; leur nombre reste visible (`rea-sbom:vuln-runtime-excluded-count`).
- **Pas d'analyse d'atteignabilité** : une version dans la plage d'un avis donne une alerte, que les
  symboles vulnérables soient liés et appelés ou non (govulncheck filtre par symboles, pas nous).
  La stdlib Go à elle seule donne des dizaines d'alertes sur un binaire minuscule.
- **Confiance** : `rea-sbom:confidence` d'une alerte = la plus basse des composants touchés ; une
  alerte sur un composant `low` (version lue dans le bytecode PyInstaller) porte
  `analysis.state = in_triage` (valeur acceptée par le schéma CycloneDX 1.6 épinglé) avec une
  explication dans `analysis.detail`.

### Limites connues

- **Plages non évaluées** : une plage GIT sans liste `versions` ou un événement que le comparateur
  de l'écosystème ne sait pas lire (`"0.8"` en Go, `"2.9.0-NA"` en PyPI…) n'est jamais transformé en
  alerte ni en absence d'alerte. Il reste visible : `rea-sbom:vuln-unevaluated-count` et une
  propriété `rea-sbom:vuln-unevaluated` par couple (avis, composant). Ordre de grandeur sur la
  snapshot S4 : ~120 entrées `affected` concernées sur ~270 000 avis (voir S4_REPORT.md).
- **Garde-fou de format OSV** : `make vulndb` échoue (index non écrit) si un écosystème indexe
  moins d'avis que le seuil de `test/data/osv-guard.json` (80 % de la snapshot de référence) ou si
  un avis connu (≥ 3 par écosystème) n'est plus indexé sous son paquet. Ce garde-fou détecte un
  changement grossier du format, pas un changement de sens d'un champ.

### Lecteurs maison (partie B) : plus de dépendance runtime à REA

`bin/sbom-scan` n'appelle plus REA. Les faits Go et Rust viennent de lecteurs écrits depuis la
description des formats (sources lues : [`NOTICE.md`](NOTICE.md)) :

| Fichier                              | Rôle                                                                                                  |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| `lib/readers/executable.mjs`         | Tables de sections ELF (32/64, LE/BE), PE/COFF, Mach-O (32/64) et fat ; détection UPX                 |
| `lib/readers/gobuildinfo.mjs`        | Buildinfo Go à chaînes inline (Go ≥ 1.18) ; format par pointeurs (< 1.18) refusé avec une raison      |
| `lib/readers/cargoauditable.mjs`     | Section `.dep-v0` / `__dep_v0`, zlib borné, JSON validé                                               |
| `oracle/rea.mjs`                     | REA via sa CLI, seulement pour `make sbom-test-diff` et les scripts de mesure S1/S2                   |
| `test/differential/readers.test.mjs` | Lecteurs maison = REA champ par champ (fixtures Go/Rust, strippées comprises, + `SBOM_DIFF_BINARIES`) |

```sh
make sbom-test        # n'a plus besoin de REA
make sbom-test-diff   # construit REA si absent, compare les lecteurs maison à REA
make sbom-real        # outils Go/Rust réels épinglés vs go version -m / rust-audit-info → s5/real-binaries.json
make sbom-oracle-s5   # govulncheck, cargo-audit, plages risquées vs api.osv.dev → s5/oracle.json
```

Lecteurs de fichiers non fiables : chaque décompression a un plafond de sortie, chaque table un
plafond d'entrées, et toute taille annoncée par un en-tête est comparée à la taille réelle du
fichier avant allocation (liste des plafonds et mesures : S5_REPORT.md, partie C ;
`test/resources.test.mjs`).

La détection (`lib/scan.mjs`) lit d'abord la structure : un ELF ou Mach-O avec table de sections
est Go seulement s'il a `.go.buildinfo` / `__go_buildinfo`, et Rust seulement s'il a `.dep-v0` /
`__dep_v0` (le binaire `go` contient la chaîne magique en constante, `rust-audit-info` le nom de
section). Sans table de sections, les marqueurs d'octets décident. Un exécutable UPX est
`unsupported-artifact` avec la raison.

### Format du BOM (`rea-sbom:format-version`)

`metadata.properties` porte `rea-sbom:format-version` (entier), incrémenté à chaque changement
cassant pour un consommateur. Historique :

| Version | Session | Changements cassants                                                                                                                                                                                                                                                |
| ------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1       | S2 / S3 | Format initial (propriété non émise à l'époque) : `rea-sbom:artifact-path`, confiance `observed` / `inferred` (Go, Rust, npm) et `high` / `medium` / `low` (NuGet, PyPI)                                                                                            |
| 2       | S4      | `rea-sbom:artifact-path` remplacé par `rea-sbom:artifact-name` (nom de base) ; une seule échelle de confiance `high` / `medium` / `low` ; version PyPI = forme normale PEP 440 ; section `vulnerabilities` (un enregistrement OSV par entrée) (propriété non émise) |
| 3       | S5      | `vulnerabilities[]` regroupées par alias (id = CVE / GHSA / premier) ; `rea-sbom:vuln-count` compte les groupes ; `analysis.state = in_triage` sur confiance `low` ; `rea-sbom:scope`, `rea-sbom:osv-record` ; lecteurs Go/Rust maison (`rea-sbom:reader` change)   |

## S6 — validation sur binaires réels multi-plateformes, filtre de plateforme, intégrité

Détails, mesures et limites : [`S6_REPORT.md`](S6_REPORT.md).

### Matrice de support

« Vérifié sur binaire réel » = un binaire produit par la vraie chaîne d'outils (Go 1.24.7,
cargo-auditable 0.7.7) a été lu et comparé à l'oracle (`go version -m`, `rust-audit-info`) :
faits identiques, précision et rappel 100 %. « Vérifié sur fichier fabriqué » = seulement des
conteneurs construits par `test/support/binaries.mjs` ou par un script de ce dépôt, donc à partir
de ma propre lecture du format. Rien d'autre n'est revendiqué.

| Écosystème       | Disposition                                                    | Statut                                                                                            |
| ---------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Go (≥ 1.18)      | ELF64 LE (linux/amd64, linux/arm64)                            | vérifié sur binaire réel                                                                          |
| Go (≥ 1.18)      | ELF32 LE (linux/386)                                           | vérifié sur binaire réel                                                                          |
| Go (≥ 1.18)      | ELF64 BE (linux/s390x, linux/ppc64)                            | vérifié sur binaire réel                                                                          |
| Go (≥ 1.18)      | ELF32 BE                                                       | vérifié sur fichier fabriqué                                                                      |
| Go (≥ 1.18)      | PE32+ (windows/amd64, windows/arm64)                           | vérifié sur binaire réel                                                                          |
| Go (≥ 1.18)      | PE32 (windows/386, windows/arm)                                | non vérifié (ni réel ni fabriqué)                                                                 |
| Go (≥ 1.18)      | Mach-O 64 LE (darwin/amd64, darwin/arm64)                      | vérifié sur binaire réel                                                                          |
| Go (≥ 1.18)      | Mach-O 32 BE                                                   | vérifié sur fichier fabriqué                                                                      |
| Go (≥ 1.18)      | fat Mach-O (darwin/amd64 + darwin/arm64)                       | tranches réelles, **conteneur fabriqué** (`scripts/make_fat.mjs`, pas `lipo`)                     |
| Go (≥ 1.18)      | strippé `-ldflags="-s -w"` (toutes les cibles ci-dessus)       | vérifié sur binaire réel                                                                          |
| Go (≥ 1.18)      | sans table de sections (recherche du marqueur)                 | vérifié sur fichier fabriqué                                                                      |
| Go (1.13–1.17)   | format par pointeurs                                           | **non supporté** : refus typé `go-buildinfo-pointer-format`, testé sur en-tête fabriqué seulement |
| Go, Rust         | exécutable UPX                                                 | **non supporté** : refus typé (`unsupported-artifact`) vérifié sur binaire réel (S5)              |
| Rust (auditable) | ELF64 LE (x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu) | vérifié sur binaire réel                                                                          |
| Rust (auditable) | PE32+ (x86_64-pc-windows-gnu, linker mingw-w64)                | vérifié sur binaire réel                                                                          |
| Rust (auditable) | PE MSVC, Mach-O, fat                                           | vérifié sur fichier fabriqué (Mach-O réel non réalisable ici : pas de linker ni de SDK Apple)     |
| .NET             | répertoire de publication, DLL PE (corpus linux)               | vérifié sur binaire réel (S3)                                                                     |
| npm              | `app.asar`, répertoire `node_modules`                          | vérifié sur artefact réel (S2)                                                                    |
| PyInstaller      | `--onefile` ELF linux/amd64, CPython 3.13                      | vérifié sur binaire réel (S3) ; autres plateformes et versions de CPython non vérifiées           |

Un fat Mach-O donne un seul résultat quand toutes ses tranches portent les mêmes modules
(Go) ou paquets (Rust) ; sinon erreur `fat-slices-differ` qui nomme la tranche et le fait qui
diffère. `go version -m` ne lit que la première tranche d'un fat (constaté sur un fat
stringer + yq) : il ne voit pas ce désaccord.

```sh
scripts/build_cross.sh        # cross-compilations Go épinglées → .work/cross/
scripts/build_rust_cross.sh   # cargo auditable windows-gnu / aarch64 → .work/rust-cross/
node scripts/make_fat.mjs .work/fat/stringer .work/cross/darwin-{amd64,arm64}/stringer
node scripts/cross_binaries.mjs   # → s6/cross-binaries.json, s6/fat-binaries.json, s6/rust-cross-binaries.json
```
