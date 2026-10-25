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
| `lib/rea.mjs`                 | Seul point de contact avec REA (`readGoBuildInfo`, `readCargoAuditable`)  |
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
