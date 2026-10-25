# &lt;NOM-DU-PROJET&gt; — SBOM hors ligne d'artefacts construits

`sbom-scan` lit un **artefact déjà construit** (binaire Go, binaire Rust `cargo auditable`, archive
Electron `app.asar`, répertoire `node_modules`, répertoire de publication .NET, exécutable
PyInstaller `--onefile`) et écrit un SBOM **CycloneDX 1.6 JSON** déterministe : composants avec
leur provenance dans l'artefact, unknowns explicites (jamais de version inventée), et, sur demande,
les vulnérabilités connues appariées **hors ligne** à un index local construit depuis les exports
OSV.

Aucune dépendance à l'exécution hors de Node.js (≥ 24). Le nom du projet, sa licence et son
dépôt ne sont pas décidés : voir [`DECISIONS_PROPRIETAIRE.md`](DECISIONS_PROPRIETAIRE.md).

## Usage

```sh
bin/sbom-scan <artefact> [--format cyclonedx|model] [--output FICHIER] [--timestamp ISO|EPOCH]
              [--vulns [--db DIR] [--no-runtime-vulns] [--all-platforms]] [--timings] [--quiet]
```

| Option               | Effet                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `--format`           | `cyclonedx` (défaut) ou `model` (modèle interne JSON, pour le débogage)                            |
| `--timestamp`        | Horodatage du BOM ; défaut `SOURCE_DATE_EPOCH`, sinon l'heure courante. Même entrée → mêmes octets |
| `--vulns`            | Ajoute `vulnerabilities[]` depuis l'index local (`vulndb/` par défaut, `--db` pour un autre)       |
| `--no-runtime-vulns` | Retire les alertes sur la stdlib Go (comptées dans `rea-sbom:vuln-runtime-excluded-count`)         |
| `--all-platforms`    | Désactive le filtre de plateforme des alertes Go                                                   |
| `--timings`          | Durée de chaque lecteur sur stderr                                                                 |
| `--quiet`            | Supprime les lignes de résumé sur stderr (alertes filtrées, composants exclus, unknowns)           |

Codes de sortie : `0` succès, `1` échec du scan (erreur typée `tag: message` sur stderr), `2` usage.
La sortie standard (ou `--output`) ne contient que le BOM ; les lignes de résumé vont sur stderr et
ne répètent que des faits déjà présents dans le BOM :

```text
sbom-scan: platform filter removed 2 alerts whose vulnerable imports only exist on platforms other than linux/amd64 (listed as rea-sbom:platform-filtered; --all-platforms keeps them)
sbom-scan: 9 components detected without a version, reported as unknowns (rea-sbom:unknown-component), not matched against vulnerabilities
```

## Installation

```sh
# Node 24.22.1 (.nvmrc ; le Makefile prend /opt/nvm s'il existe)
make vulndb      # optionnel, pour --vulns : ~275 Mo d'exports OSV dans vulndb/ + index (réseau)
make sbom-test   # construit le corpus de test (Go, Rust, npm, .NET, Python, réseau) puis lance les tests
```

Le scanner lui-même n'a besoin que de `bin/`, `lib/`, `data/` et `package.json`. Les tests ont des
dépendances de développement épinglées (`package-lock.json` : Ajv et `@electron/asar`). Le corpus
de test se construit avec les chaînes d'outils de chaque écosystème (bring-your-own : Go,
Rust + `cargo-auditable`, SDK .NET 8, Python 3.13 + venv) ; un écosystème sans chaîne d'outils
est sauté avec un message `SKIP`.

## Matrice de support

« Vérifié sur binaire réel » : un artefact produit par la vraie chaîne d'outils a été lu et
comparé à un oracle (`go version -m`, `rust-audit-info`, lockfile, `pip freeze`, `dotnet list
package`) avec des faits identiques. « Vérifié sur fichier fabriqué » : seulement sur des
conteneurs construits par les tests ou par un script de ce dépôt, donc à partir de ma propre
lecture du format.

| Écosystème       | Disposition                                                   | Statut                                                                                   |
| ---------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Go (≥ 1.18)      | ELF64 LE (linux/amd64, linux/arm64)                           | vérifié sur binaire réel                                                                 |
| Go (≥ 1.18)      | ELF32 LE (linux/386)                                          | vérifié sur binaire réel                                                                 |
| Go (≥ 1.18)      | ELF64 BE (linux/s390x, linux/ppc64)                           | vérifié sur binaire réel                                                                 |
| Go (≥ 1.18)      | ELF32 BE, Mach-O 32 BE, sans table de sections                | vérifié sur fichier fabriqué                                                             |
| Go (≥ 1.18)      | PE32+ (windows/amd64, windows/arm64)                          | vérifié sur binaire réel                                                                 |
| Go (≥ 1.18)      | PE32 (windows/386, windows/arm)                               | non vérifié (ni réel ni fabriqué)                                                        |
| Go (≥ 1.18)      | Mach-O 64 LE (darwin/amd64, darwin/arm64)                     | vérifié sur binaire réel                                                                 |
| Go (≥ 1.18)      | fat Mach-O                                                    | tranches réelles, **conteneur fabriqué** (`scripts/make_fat.mjs`, pas `lipo`)            |
| Go (≥ 1.18)      | strippé `-ldflags="-s -w"`                                    | vérifié sur binaire réel                                                                 |
| Go (1.13–1.17)   | format par pointeurs                                          | **non supporté** : refus typé `go-buildinfo-pointer-format` (en-tête fabriqué seulement) |
| Go, Rust         | exécutable UPX                                                | **non supporté** : refus typé `unsupported-artifact` (vérifié sur binaire réel)          |
| Rust (auditable) | ELF64 LE (x86_64 et aarch64 linux-gnu)                        | vérifié sur binaire réel                                                                 |
| Rust (auditable) | PE32+ (x86_64-pc-windows-gnu)                                 | vérifié sur binaire réel                                                                 |
| Rust (auditable) | PE MSVC, Mach-O, fat                                          | vérifié sur fichier fabriqué                                                             |
| Rust             | binaire sans `cargo auditable`                                | **non supporté** : refus `unsupported-artifact` (constaté sur `rust-audit-info`, S7)     |
| .NET             | répertoire de publication avec `*.deps.json`, DLL isolée      | vérifié sur artefact réel (Linux, `net8.0`)                                              |
| .NET             | sans `*.deps.json` (attributs d'assembly seulement)           | vérifié sur artefact réel ; versions à étiquette pre-release → unknown (voir limites)    |
| npm              | `app.asar`, répertoire avec `node_modules`                    | vérifié sur artefact réel                                                                |
| PyInstaller      | `--onefile` ELF linux/amd64, CPython 3.13, PyInstaller 6.10   | vérifié sur binaire réel ; autres plateformes, CPython et PyInstaller non vérifiés       |
| Autres           | images de conteneurs, paquets OS (deb, rpm, apk), Java, Ruby… | **non supporté**                                                                         |

Un répertoire sans `node_modules` ni assembly .NET est lu comme une racine npm vide : le BOM
n'a alors aucun composant, sans erreur (constaté sur un répertoire `var/lib/dpkg` en S7).

## Format de sortie

CycloneDX 1.6 JSON, validé dans les tests contre le schéma épinglé (`schemas/`). Correspondance :

| Fait du scan                       | CycloneDX                                                                                                         |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Artefact scanné                    | `metadata.component` (sha256 dans `hashes`) ; seul le nom de base est émis (`rea-sbom:artifact-name`)             |
| Composant                          | `components[]` (`type: library`, purl), `evidence.identity` (technique) et `evidence.occurrences` (voir plus bas) |
| Runtime (stdlib Go)                | composant avec `rea-sbom:role = language-runtime`                                                                 |
| Unknown (détecté, version non lue) | `metadata.properties` `rea-sbom:unknown-component` (JSON : nom, raison, evidence) — jamais un composant           |
| Exclusion (présent, non livré)     | `metadata.properties` `rea-sbom:excluded-component` (ex. Rust `kind=build`, modules runtime PyInstaller)          |
| Limites du lecteur                 | `metadata.properties` `rea-sbom:limitation`                                                                       |
| Vulnérabilité (`--vulns`)          | `vulnerabilities[]`, une entrée par groupe d'alias OSV (id CVE, sinon GHSA, sinon premier)                        |
| Graphe de dépendances              | **non émis** : l'absence de `dependencies` veut dire « inconnu », pas « aucune »                                  |

`evidence.occurrences[]` donne, par composant, l'emplacement lu dans l'artefact : `location`
(nom de base ou chemin interne), `offset` (octet de début de la plage lue, quand c'est une plage)
et `additionalContext` (JSON : type et taille de la plage, `sourceSha256` = sha256 des octets lus,
lecteur, faits propres à l'écosystème).

### Propriétés `rea-sbom:*`

Le préfixe vient de l'origine du projet ; son renommage est une décision du propriétaire
(changement cassant). Il apparaît aussi hors des noms de propriétés : `bom-ref`
`rea-sbom:subject` de l'artefact, valeurs `rea-sbom:*-reader` de `rea-sbom:source`, outil
`rea-sbom` des lecteurs, format d'index `rea-sbom-osv-index/2`. Composants : `rea-sbom:ecosystem`, `rea-sbom:source`, `rea-sbom:confidence`
(`high` / `medium` / `low`, une seule échelle), `rea-sbom:role`, `rea-sbom:purl-status` (pas de
purl, avec la raison). Métadonnées : `rea-sbom:format-version`, `rea-sbom:artifact-name`,
`rea-sbom:artifact-bytes`, `rea-sbom:artifact-kind`, `rea-sbom:detected-ecosystem`,
`rea-sbom:reader`, `rea-sbom:root-*`, `rea-sbom:unknown-count`, `rea-sbom:unknown-component`,
`rea-sbom:excluded-count`, `rea-sbom:excluded-component`, `rea-sbom:limitation`,
`rea-sbom:target-platform` (Go, `GOOS/GOARCH`, une par tranche d'un fat). Avec `--vulns` :
`rea-sbom:vulndb-snapshot`, `rea-sbom:vulndb-archive`, `rea-sbom:vuln-count` (groupes),
`rea-sbom:vuln-record-count`, `rea-sbom:vuln-runtime-excluded-count`,
`rea-sbom:vuln-unevaluated-count`, `rea-sbom:vuln-unevaluated`, `rea-sbom:vuln-failure`,
`rea-sbom:platform-filter` (`applied` / `disabled` / `no-platform`),
`rea-sbom:platform-filtered-count`, `rea-sbom:platform-filtered` ; sur chaque vulnérabilité :
`rea-sbom:confidence`, `rea-sbom:osv-record`, `rea-sbom:scope`, `rea-sbom:matched-by`.

### Format du BOM (`rea-sbom:format-version`)

Entier incrémenté à chaque changement cassant pour un consommateur. Version actuelle : **4**.

| Version | Changements cassants                                                                                                                                                       |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1       | Format initial (propriété non émise)                                                                                                                                       |
| 2       | `rea-sbom:artifact-name` (nom de base) remplace le chemin ; une seule échelle de confiance ; version PyPI = forme normale PEP 440 ; section `vulnerabilities`              |
| 3       | Vulnérabilités regroupées par alias ; `rea-sbom:vuln-count` compte les groupes ; `in_triage` sur confiance `low` ; lecteurs Go/Rust maison                                 |
| 4       | Index `rea-sbom-osv-index/2` (à reconstruire) ; alertes Go filtrées par plateforme par défaut ; propriétés `rea-sbom:target-platform` / `platform-*` ; `fat-slices-differ` |

Le résumé sur stderr (S7) ne change pas le BOM : pas d'incrément.

## Vulnérabilités (`--vulns`)

- Index local construit par `make vulndb` depuis les exports OSV par écosystème (Go, crates.io,
  npm, NuGet, PyPI) ; `vulndb/SNAPSHOT.json` enregistre la date et le sha256 de chaque archive.
  **Aucun appel réseau pendant le scan.**
- Seuls les composants versionnés sont appariés ; les unknowns ne le sont jamais.
- Une plage que le comparateur ne sait pas évaluer (GIT sans `versions`, version illisible) est
  `rea-sbom:vuln-unevaluated`, jamais une alerte ni une absence d'alerte.
- **Pas d'analyse d'atteignabilité** : une version dans la plage donne une alerte, symboles
  appelés ou non. La stdlib Go seule donne des dizaines d'alertes sur un petit binaire.
- Filtre de plateforme Go : une alerte est retirée seulement si tous ses enregistrements OSV
  restreignent leurs imports à des `goos` / `goarch` qui excluent la plateforme du binaire ;
  chaque alerte retirée reste listée (`rea-sbom:platform-filtered`), `--all-platforms` la garde.

## Comparaison avec syft (S7)

Mesures de [`S7_REPORT.md`](S7_REPORT.md) : syft v1.42.0 (`go install`, CycloneDX JSON, hors
ligne), mêmes artefacts, même vérité terrain ([`TRUTH_RULES.md`](TRUTH_RULES.md) : racine et
runtimes non comptés, version exacte). Corpus de test, 6 binaires réels publics et 12 binaires
Go cross-compilés (windows/amd64, darwin/arm64, linux/s390x). Données : `s7/compare.json`.

| Écosystème (artefacts)                    | Vrais | Nous : VP / émis | Nous : précision | Nous : rappel | syft : VP / émis | syft : précision | syft : précision hors racine | syft : rappel |
| ----------------------------------------- | ----- | ---------------- | ---------------- | ------------- | ---------------- | ---------------- | ---------------------------- | ------------- |
| Go (20)                                   | 1012  | 1012 / 1012      | 100,0 %          | 100,0 %       | 1012 / 1041      | 97,2 %           | 99,1 %                       | 100,0 %       |
| Rust cargo-auditable (4)                  | 93    | 93 / 93          | 100,0 %          | 100,0 %       | 93 / 97          | 95,9 %           | 100,0 %                      | 100,0 %       |
| npm ASAR (2)                              | 9     | 9 / 9            | 100,0 %          | 100,0 %       | 0 / 0            | —                | —                            | 0,0 %         |
| .NET, répertoire de publication (2)       | 3     | 3 / 3            | 100,0 %          | 100,0 %       | 3 / 5            | 60,0 %           | 100,0 %                      | 100,0 %       |
| PyInstaller onefile (3)                   | 11    | 11 / 11          | 100,0 %          | 100,0 %       | 0 / 0            | —                | —                            | 0,0 %         |
| .NET sans deps.json (2, variante)         | 3     | 1 / 1            | 100,0 %          | 33,3 %        | 0 / 5            | 0,0 %            | 0,0 %                        | 0,0 %         |
| npm, répertoire décompressé (2, variante) | 9     | 9 / 9            | 100,0 %          | 100,0 %       | 9 / 11           | 81,8 %           | 100,0 %                      | 100,0 %       |

Causes des écarts (constatées sur les sorties) : syft émet le composant racine (module principal,
crate racine, assembly, paquet) comme composant (30 cas) ; 9 modules terraform remplacés par un
répertoire local, émis par syft avec la version `UNKNOWN` (nous : 9 unknowns) ; syft ne lit ni
ASAR ni PyInstaller ; sans deps.json, syft émet le `FileVersion` Win32
(`serilog@3.1.1.0`) et le `ProductName` (`json.net@12.0.1.22727`), nous émettons
`newtonsoft.json@12.0.1` et déclarons les 2 paquets Serilog unknowns (étiquette pre-release).

Temps et RSS (médiane de 5 exécutions, `/usr/bin/time -v`, une machine, CycloneDX vers
`/dev/null`, sans `--vulns`) :

| Artefact                 | Octets      | Nous froid : durée / CPU / RSS | Nous chaud               | syft froid                | syft chaud                |
| ------------------------ | ----------- | ------------------------------ | ------------------------ | ------------------------- | ------------------------- |
| go-uuid                  | 3 088 475   | 0,17 s / 0,15 s / 57 Mio       | 0,14 s / 0,14 s / 57 Mio | 2,39 s / 2,74 s / 173 Mio | 2,03 s / 2,53 s / 175 Mio |
| rust-small               | 4 480 648   | 0,20 s / 0,18 s / 57 Mio       | 0,14 s / 0,14 s / 57 Mio | 2,38 s / 2,78 s / 176 Mio | 2,27 s / 2,85 s / 177 Mio |
| npm-electron (ASAR)      | 1 713 085   | 0,16 s / 0,15 s / 58 Mio       | 0,13 s / 0,13 s / 57 Mio | 2,11 s / 2,52 s / 164 Mio | 1,98 s / 2,39 s / 172 Mio |
| dotnet-serilog           | 262 028     | 0,14 s / 0,13 s / 54 Mio       | 0,11 s / 0,11 s / 54 Mio | 2,30 s / 2,68 s / 172 Mio | 2,10 s / 2,65 s / 177 Mio |
| py-requests              | 8 510 328   | 0,25 s / 0,25 s / 58 Mio       | 0,19 s / 0,21 s / 58 Mio | 2,26 s / 2,65 s / 175 Mio | 1,99 s / 2,46 s / 174 Mio |
| prometheus               | 136 617 940 | 1,17 s / 1,13 s / 58 Mio       | 1,33 s / 1,33 s / 58 Mio | 4,74 s / 6,19 s / 225 Mio | 4,54 s / 5,89 s / 236 Mio |
| prometheus windows/amd64 | 136 190 976 | 1,20 s / 1,21 s / 65 Mio       | 1,11 s / 1,12 s / 65 Mio | 4,81 s / 6,70 s / 693 Mio | 4,60 s / 6,60 s / 705 Mio |

Tableau complet (13 artefacts) dans `S7_REPORT.md`. Les temps de syft et les nôtres sur npm-electron
et py-requests portent sur des artefacts où syft ne trouve aucun composant.

Ce que syft fait et que ce scanner ne fait pas (vérifié sur sortie réelle, voir S7_REPORT.md) :
66 catalogueurs (paquets OS, Java, Ruby, PHP, lockfiles…), images de conteneurs (non exécuté ici),
SPDX et autres formats de sortie, graphe `dependencies` (Rust), CPE, lecture de toutes les tranches
d'un fat Mach-O y compris quand elles diffèrent. Ce que ce scanner fait et que syft ne fait pas :
ASAR, PyInstaller, versions .NET sans deps.json au format NuGet, unknowns et exclusions explicites
avec raison, evidence par composant avec offset et sha256 des octets lus, appariement OSV hors
ligne intégré avec filtre de plateforme, refus typés (`fat-slices-differ`, `go-buildinfo-pointer-format`).

## Limites connues

- Pas de graphe de dépendances, pas de licences, pas de CPE.
- Go < 1.18 (format par pointeurs) refusé ; PE32 non vérifié ; fat Mach-O vérifié seulement sur
  un conteneur fabriqué ; Mach-O Rust jamais vu sur un binaire réel.
- PyInstaller : seule la combinaison PyInstaller 6.10 / CPython 3.13 / ELF linux est vérifiée ;
  sans dist-info embarqués, les versions viennent d'un spike bytecode (confiance `low`).
- .NET sans deps.json : une version d'assembly à étiquette pre-release n'est pas prise pour la
  version NuGet (unknown) ; le nom NuGet est supposé égal au nom d'assembly (`medium`).
- Un répertoire non reconnu donne un BOM vide sans erreur.
- Vulnérabilités : pas d'atteignabilité ; le filtre de plateforme ne lit que `goos` / `goarch`
  des imports OSV (36 entrées sur 15 126 en S6) ; union des enregistrements GO- et GHSA d'un même
  export, même quand ils divergent.
- Intégrité : le fichier est haché deux fois (avant et après lecture) ; coût ≈ un sha256 complet
  supplémentaire ; une modification défaite entre les deux (A → B → A) n'est pas vue.

## Sécurité

Les lecteurs traitent des fichiers potentiellement hostiles : chaque table a un plafond d'entrées,
chaque décompression un plafond de sortie, et toute taille annoncée est comparée à la taille réelle
avant allocation (`test/resources.test.mjs`, `test/robustness.test.mjs`). **Il n'y a aucun bac à
sable** : le scanner tourne avec les droits de l'utilisateur, dans le processus Node. Ne
l'exposez pas à des fichiers non fiables (service en ligne, pipeline recevant des artefacts
tiers) sans isolation (conteneur, utilisateur dédié, limites de ressources). Aucun code de
l'artefact n'est exécuté. Politique de signalement : non décidée (voir
`DECISIONS_PROPRIETAIRE.md`).

## Provenance

Ce répertoire est issu d'un fork de REA (outil local de rétro-ingénierie, licence MIT). Le
scanner n'utilise plus REA : les lecteurs Go et Rust ont été écrits pour ce projet (sources lues :
[`NOTICE.md`](NOTICE.md)). REA ne sert plus que d'**oracle de test optionnel**
(`oracle/rea.mjs`, `oracle/rea.mk`, `make sbom-test-diff`, `SBOM_REA_ROOT`) ; `make sbom-test`
ne l'utilise pas. `scripts/extract.sh <répertoire> <nom>` produit une copie autonome sans
historique git.

Historique des sessions : [`HISTORY.md`](HISTORY.md) (ancien README, S1–S6), `S2_REPORT.md` à
`S7_REPORT.md`, `BASELINE.md` (mesure de REA brut, S1), `TRUTH_RULES.md`, `PROBE.md`.

## Commandes de développement

```sh
make sbom-test            # tests (node:test) ; construit le corpus si besoin
make sbom-test-diff       # lecteurs maison = REA champ par champ (oracle optionnel)
make vulndb               # index OSV local
make sbom-real            # binaires publics épinglés vs go version -m / rust-audit-info
make sbom-compare-syft    # comparaison avec syft → s7/
make extract DEST=<dir> NAME=<nom-npm>
```
