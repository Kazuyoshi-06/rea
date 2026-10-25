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
- PyInstaller : `--onefile --clean`, `SOURCE_DATE_EPOCH=0`. **Non déterministe malgré cela** (constaté) :
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
