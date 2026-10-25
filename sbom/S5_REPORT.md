# S5_REPORT — indépendance vis-à-vis de REA, décisions de format, durcissement, oracles

Session S5, 2026-10-25, conteneur Linux x64 (Ubuntu 24.04), Node 24.22.1, go1.24.7, cargo 1.97.0,
cargo-auditable 0.7.7, SDK .NET 8.0.132, Python 3.13.17, upx 4.2.2, govulncheck 1.1.4, cargo-audit
0.22.2, rust-audit-info 0.5.4. Chaque affirmation est marquée **[constaté]** (sortie de commande
dans cette session) ou **[supposé]** (raisonnement non vérifié). Branche `sbom-s5-independent`,
4 commits de fonctionnalité (A, B1–B5, B6–B7, C, D) + ce rapport.

## Critères de réussite

| Critère                                            | Résultat                                                                                                                                  |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `make sbom-test` vert sans REA construit           | **144 tests, 144 réussis, 0 échec, 0 sauté**, 8,1 s ; la cible ne dépend plus de `dist/cli-runtime` [constaté]                            |
| `make sbom-test-diff` vert (lecteurs maison = REA) | **13/13** : 6 fixtures Go/Rust (dont 2 strippées) + 7 binaires réels via `SBOM_DIFF_BINARIES` [constaté]                                  |
| B7 : `sbom/` copié seul passe `make sbom-test`     | `git archive HEAD sbom` dans `/tmp/claude-0/b7*`, sans dépôt parent ni REA : corpus reconstruit, **0 échec** (détail plus bas) [constaté] |
| Scan Go et Rust : durée, RSS (5 exécutions)        | **~0,08 s et ~57,5 Mio** sur les fixtures, contre ~1,42 s et ~357 Mio en S2 [constaté] ; tableau « Mesures »                              |
| Précision / rappel sur binaires réels (B6)         | **100 % / 100 %** sur 6 outils (4 Go, 2 Rust), faits du lecteur identiques à l'oracle champ par champ [constaté]                          |
| Partie C : tests de ressources verts, mesurés      | **15/15**, chaque cas < 0,14 s et ≤ 125 Mio de RSS (`/usr/bin/time -v`) [constaté]                                                        |
| Aucune modification hors `sbom/`                   | `git diff --name-only origin/main... \| grep -v '^sbom/' \| wc -l` → `0` [constaté]                                                       |

## Partie A — décisions (commit `feat(sbom)!: group alerts by alias…`, tests verts : 110/110)

- **A1** : une entrée `vulnerabilities[]` par groupe d'enregistrements OSV liés par `aliases`
  (union transitive ; `related` ne lie pas). Identifiant principal : premier CVE (ordre
  alphabétique), sinon premier GHSA, sinon premier identifiant. Autres identifiants en
  `references`, enregistrements appariés en `rea-sbom:osv-record`, composants dans `affects`
  (`lib/vulns/match.mjs` `groupAlerts`, `lib/cyclonedx.mjs`). Sur le mini-corpus : go-jwt passe de 5
  entrées à 3 (`CVE-2020-26160`, `CVE-2022-32149`, `CVE-2025-61725`), py-requests de 2 enregistrements
  à 2 CVE [constaté].
- **A2** : `rea-sbom:scope=language-runtime` quand **tous** les composants du groupe sont des
  runtimes ; `--no-runtime-vulns` (exige `--vulns`) retire les alertes stdlib et les compte
  (`rea-sbom:vuln-runtime-excluded-count`). README : pas d'analyse d'atteignabilité. Constat : sur
  yq/prometheus/terraform, 7 groupes mêlent stdlib et `golang.org/x/net` (même CVE) et ne portent
  donc pas la portée runtime (52 groupes « runtime » au lieu de 59) [constaté].
- **A3** : confiance d'un groupe = la plus basse de ses composants ; `low` → `analysis.state =
  in_triage` + `analysis.detail`. `in_triage` est dans l'énumération `impactAnalysisState` du
  schéma 1.6 épinglé [constaté] ; validé sur py-requests (toutes ses alertes, bytecode `low`).
- **A4** : README, « Limites connues » : les plages non évaluées restent visibles
  (`rea-sbom:vuln-unevaluated-count` / `-unevaluated`).
- **A5** : `lib/vulns/guard.mjs` + `test/data/osv-guard.json` (seuil = 80 % des avis indexés de la
  snapshot `osv-3fe57c98aea6919b`, 3 ou 4 avis connus par écosystème, vérifiés présents). `make
  vulndb` avec un garde-fou piégé (seuil crates.io 99 999, id PyPI inexistant) : message explicite
  listant les deux échecs, index **non écrit**, `make` → code 2, SNAPSHOT.json inchangé [constaté].
- **A6** : `rea-sbom:format-version` = `3` dans `metadata.properties` ; README « Format du BOM »
  liste les changements cassants des versions 1 (S2/S3), 2 (S4), 3 (S5).
- `vulndb/SNAPSHOT.json` rafraîchi (l'export npm avait changé depuis S4 : 230 779 avis).

## Partie B — lecteurs maison

### Ce qui marche

| Fichier                              | Rôle                                                                                                                                                       |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib/readers/executable.mjs`         | ELF 32/64 LE/BE (numérotation étendue), PE/COFF (noms longs `/n`), Mach-O 32/64 (deux ordres d'octets), fat ; détection UPX ; `cli-metadata.mjs` l'utilise |
| `lib/readers/gobuildinfo.mjs`        | En-tête 32 octets, chaînes inline (flag 2, Go ≥ 1.18), sentinelles, lignes `path`/`mod`/`dep`/`=>`/`build` ; section puis repli sur le marqueur            |
| `lib/readers/cargoauditable.mjs`     | `.dep-v0` / `__dep_v0` (ELF, PE, Mach-O, fat), zlib borné, JSON validé (`format` absent = 0)                                                               |
| `oracle/rea.mjs`                     | ex-`lib/rea.mjs`, plus importé par `bin/` ni `lib/` (`grep` vide) [constaté]                                                                               |
| `test/readers.test.mjs`              | 18 tests sur conteneurs synthétiques de chaque disposition (`test/support/binaries.mjs`)                                                                   |
| `test/differential/readers.test.mjs` | `make sbom-test-diff`, hors `make sbom-test`                                                                                                               |

- **B1** : format par pointeurs (Go < 1.18) **refusé** proprement (`go-buildinfo-pointer-format`) :
  il faut traduire des adresses virtuelles, non fait. Aucun binaire Go < 1.18 n'a été construit pour
  l'essayer (seul un en-tête synthétique est testé). Strip `-s -w` : sans effet, la section
  `.go.buildinfo` reste (fixtures strippées lues par la section) [constaté].
- **B2** : décompression `inflateSync({maxOutputLength})`, champs `name`, `version`, `source`, `kind`,
  `dependencies`, `root` + `formatVersion`. Mêmes champs que l'ancien adaptateur REA ;
  `dependencies` ajouté des deux côtés (oracle compris).
- **B3** : adaptateurs Go/Rust branchés sur les lecteurs ; la vérification « artefact modifié pendant
  le scan » compare désormais la **taille** (REA rendait un sha256) : plus faible, voir fragilités.
  `rea-sbom:source` devient `go-buildinfo` / `cargo-auditable`.
- **B4** : un ELF ou Mach-O avec table de sections n'est Go que s'il a `.go.buildinfo` /
  `__go_buildinfo`, Rust que s'il a `.dep-v0` / `__dep_v0` ; PE : Rust par la section, Go par le
  marqueur (l'en-tête est dans `.data`). Sans table de sections : marqueurs. Constats : le binaire
  `go` lui-même (qui contient la chaîne magique en constante) est lu par sa section ;
  `rust-audit-info` (qui contient `.dep-v0` dans son code, non construit avec auditable) n'est plus
  pris pour un binaire Rust → `unsupported-artifact` ; un binaire UPX (go-uuid et rust-small
  compressés par upx 4.2.2) → `unsupported-artifact: UPX-packed elf executable: …` [constaté].
- **B5** : comparaison champ par champ (`goVersion`, `moduleLocation`, `main`, `dependencies`,
  `complete`, `unparsedLines`, `unparsedBinaryLines` ; `section`, `packages`) : 6/6 fixtures dès
  le premier essai [constaté].
- **B7** : deux corrections nécessaires pour la copie isolée, trouvées en la faisant : le Makefile
  lisait `../.nvmrc` (repli sur `sbom/.nvmrc`), et **5 tests de bornes échouaient** car ils
  testaient la présence de `SNAPSHOT.json` (commité) au lieu de l'index. Cause racine corrigée dans
  `openVulnDb` : un répertoire qui n'a que `SNAPSHOT.json` (clone propre) est `vulndb-missing`,
  alors qu'avant `--vulns` y aurait produit un BOM avec des `vuln-failure` au lieu d'une erreur.
  Résultat après correction, copie de l'état B : 128 tests, 123 réussis, 5 sautés (bornes OSV sans
  index), 0 échec, 100 s dont la reconstruction du corpus [constaté]. Copie de l'état final : voir
  « B7 final » en fin de rapport.

### B6 — binaires réels (`make sbom-real` → `s5/real-binaries.json`)

Oracles : `go version -m` (lecteur de la chaîne d'outils Go) et `rust-audit-info` 0.5.4 (lecteur de
référence du projet cargo-auditable). « Lecteur » = tous les faits identiques ; « SBOM » =
composants émis contre l'ensemble livré de l'oracle (remplacements appliqués, remplacements vers
un répertoire local exclus faute de version ; Rust : sans `kind=build` ni racine) [constaté] :

| Outil (épinglé)                                               | Construction                       | Octets      | Faits            | Remplacements / build                | SBOM : trouvés / oracle | Précision | Rappel |
| ------------------------------------------------------------- | ---------------------------------- | ----------- | ---------------- | ------------------------------------ | ----------------------- | --------- | ------ |
| `golang.org/x/tools/cmd/stringer@v0.26.0`                     | `go install`                       | 7 400 333   | identiques (2)   | 0                                    | 2 / 2                   | 100 %     | 100 %  |
| `github.com/mikefarah/yq/v4@v4.44.3`                          | `go install`                       | 16 257 348  | identiques (21)  | 0                                    | 21 / 21                 | 100 %     | 100 %  |
| `github.com/prometheus/prometheus@v0.54.1` (`cmd/prometheus`) | `go build` depuis le zip de module | 136 617 940 | identiques (176) | 2 (module → module)                  | 176 / 176               | 100 %     | 100 %  |
| `github.com/hashicorp/terraform@v1.9.8`                       | `go build` depuis le tag git       | 124 452 395 | identiques (217) | 9 (→ répertoires locaux, 9 unknowns) | 208 / 208               | 100 %     | 100 %  |
| `ripgrep@14.1.1`                                              | `cargo auditable install --locked` | 29 448 808  | identiques (33)  | 0 build                              | 32 / 32                 | 100 %     | 100 %  |
| `fd-find@10.2.0`                                              | `cargo auditable install --locked` | 3 979 488   | identiques (66)  | 11 build exclus                      | 54 / 54                 | 100 %     | 100 %  |

**Écarts, un par un** : aucun au niveau SBOM. Un écart au niveau lecteur, **trouvé par le
différentiel REA sur prometheus et terraform, corrigé** : le linker Go écrit une ligne vide après
chaque ligne `=>` (visible aussi dans `go version -m`) ; mon lecteur la gardait en
`unparsedLines` (2 sur prometheus, 9 sur terraform), ce qui aurait ajouté une limitation « lignes non
reconnues » au BOM. Les lignes vides sont désormais ignorées, et le cas est dans les données de test.
Les fixtures du corpus n'avaient aucun `replace` et ne pouvaient pas le révéler.

Construction : terraform depuis le zip de module a **échoué** (« replacement directory
./internal/backend/remote-state/azure does not exist » : les zips de module excluent les sous-modules
imbriqués) ; 2e tentative par `git clone --branch v1.9.8` réussie [constaté]. Pas de binaire vendoré
construit (lazygit était un candidat, non essayé faute de temps).

## Mesures (`scripts/measure_s5.mjs` → `s5/measurements.json`)

5 exécutions de `sbom-scan --format cyclonedx` sous `/usr/bin/time -v` ; 1re = « froid » (cache disque
non contrôlé), médiane des 4 autres = « chaud ». Sorties identiques entre les 5 exécutions partout.
Tokens d'agent : non mesurés [constaté] :

| Cible             | Octets      | Durée froid / chaud | CPU chaud | RSS chaud | Lecteur (`--timings`) |
| ----------------- | ----------- | ------------------- | --------- | --------- | --------------------- |
| go-uuid           | 3 088 475   | 0,08 / 0,095 s      | 0,095 s   | 57,7 Mio  | 1 ms                  |
| go-jwt            | 4 606 705   | 0,09 / 0,095 s      | 0,095 s   | 57,6 Mio  | 1 ms                  |
| go-jwt-stripped   | 3 068 088   | 0,08 / 0,08 s       | 0,08 s    | 57,5 Mio  | 1 ms                  |
| rust-small        | 4 480 648   | 0,12 / 0,085 s      | 0,08 s    | 57,8 Mio  | 1,5 ms                |
| rust-vuln         | 667 376     | 0,09 / 0,07 s       | 0,07 s    | 57,3 Mio  | 1 ms                  |
| stringer (réel)   | 7 400 333   | 0,11 / 0,11 s       | 0,115 s   | 57,5 Mio  | 1 ms                  |
| yq (réel)         | 16 257 348  | 0,17 / 0,14 s       | 0,14 s    | 57,8 Mio  | 1,5 ms                |
| prometheus (réel) | 136 617 940 | 0,70 / 0,66 s       | 0,655 s   | 59,0 Mio  | 2 ms                  |
| terraform (réel)  | 124 452 395 | 0,59 / 0,59 s       | 0,59 s    | 60,1 Mio  | 2 ms                  |
| ripgrep (réel)    | 29 448 808  | 0,21 / 0,225 s      | 0,22 s    | 58,1 Mio  | 2 ms                  |
| fd (réel)         | 3 979 488   | 0,10 / 0,09 s       | 0,09 s    | 58,3 Mio  | 1 ms                  |

S2 (même machine type, `s2/measurements.json`) : go-uuid 1,42 s, 1,89 s CPU, 357 Mio (sbom-scan,
dont ~1,38 s et ~355 Mio pour l'appel REA). Soit **~15× plus rapide et ~6× moins de mémoire** ; le
lecteur lui-même prend 1–2 ms. Le reste du temps sur les gros binaires est le sha256 du fichier
entier (prometheus : 137 Mo) [supposé : non profilé séparément, mais le lecteur mesure 2 ms].
`make sbom-test` : 8,1 s contre 23,9 s en S4 (plus d'appel REA dans les tests) [constaté].

## Partie C — durcissement (commit `fix(sbom): bound decompression…`)

### Plafonds (nouveaux en **gras**, existants rappelés)

| Lecteur              | Plafond                                                                                                                                 | Valeur                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `files.mjs`          | **`readRange` / `openSource` : plage comparée à la taille réelle (`fstat`) avant toute allocation** (tous les lecteurs qui l'utilisent) | taille du fichier                        |
| `executable.mjs`     | **sections ELF** (dont numérotation étendue)                                                                                            | **65 535**                               |
|                      | **sections PE** (limite du chargeur Windows)                                                                                            | **96**                                   |
|                      | **commandes de chargement Mach-O / octets de commandes**                                                                                | **4 096 / 16 Mio**                       |
|                      | **tranches fat**                                                                                                                        | **64**                                   |
|                      | **table de noms de sections ELF**                                                                                                       | **16 Mio**                               |
| `gobuildinfo.mjs`    | **version de la chaîne d'outils / bloc modules / recherche dans une section**                                                           | **1 Kio / 8 Mio / 64 Mio**               |
| `cargoauditable.mjs` | **section / JSON décompressé (`maxOutputLength`) / paquets**                                                                            | **4 Mio / 32 Mio / 100 000**             |
| `zip.mjs`            | **sortie = taille déclarée par le répertoire central (`maxOutputLength`), entrée refusée au-delà de** / **nombre d'entrées**            | **taille déclarée ≤ 64 Mio / 4 000 000** |
| `pyinstaller.mjs`    | **entrée CArchive : sortie = taille déclarée par la TOC** (avant : 64 Mio pour toutes)                                                  | **taille déclarée ≤ 64 Mio**             |
|                      | module PYZ (message désormais explicite « inflated data exceeds ») ; TOC ; TOC PYZ                                                      | 64 Mio ; 64 Mio ; 16 Mio                 |
| `marshal.mjs`        | profondeur ; comptes ≤ octets restants (existant, vérifié)                                                                              | 512 ; reste du tampon                    |
| `cli-metadata.mjs`   | bloc de métadonnées ; tables ≤ flux `#~` (existant) ; sections PE via `executable.mjs`                                                  | 256 Mio ; taille du flux ; 96            |

### Tests (`test/resources.test.mjs`, un processus par cas sous `/usr/bin/time -v`)

Budget par cas : < 5 s et < 256 Mio. Mesures [constaté] (`s5/resources.json`) :

| Cas                                                    | Erreur typée                    | Octets    | Durée   | RSS max   |
| ------------------------------------------------------ | ------------------------------- | --------- | ------- | --------- |
| PYZ : module zlib qui se gonfle à 128 Mio              | `malformed-pyinstaller-archive` | 130 648   | 0,137 s | 125,1 Mio |
| CArchive : TOC annonce 1 Kio, zlib gonfle à 128 Mio    | `malformed-pyinstaller-archive` | 130 606   | 0,097 s | 53,7 Mio  |
| CArchive : offset d'entrée hors du fichier             | `malformed-pyinstaller-archive` | 143       | 0,087 s | 53,1 Mio  |
| marshal : liste de 2³¹−1 éléments annoncés             | `MarshalError`                  | 6         | 0,090 s | 53,3 Mio  |
| marshal : chaîne de 4 Gio annoncée                     | `MarshalError`                  | 6         | 0,081 s | 53,0 Mio  |
| marshal : 200 000 listes imbriquées                    | `MarshalError` (profondeur)     | 1 000 000 | 0,076 s | 54,8 Mio  |
| ELF : `e_shoff` à 1 Tio                                | `malformed-executable`          | 208       | 0,068 s | 53,2 Mio  |
| ELF : 65 535 sections annoncées, table hors du fichier | `malformed-executable`          | 208       | 0,065 s | 53,1 Mio  |
| ELF : numérotation étendue à 2³²−1 sections            | `malformed-executable`          | 288       | 0,063 s | 53,2 Mio  |
| PE : 65 535 sections annoncées                         | `malformed-executable`          | 512       | 0,066 s | 53,2 Mio  |
| PE : données de `.dep-v0` à 2 Gio                      | `malformed-cargo-auditable`     | 1 024     | 0,076 s | 53,1 Mio  |
| cargo-auditable : 64 Kio de zlib → 128 Mio             | `cargo-auditable-too-large`     | 130 760   | 0,092 s | 93,0 Mio  |
| buildinfo Go : bloc modules de 2⁴⁰ octets annoncé      | `malformed-go-buildinfo`        | 368       | 0,064 s | 53,3 Mio  |
| ZIP : entrée déclarée 1 Kio, gonfle à 128 Mio          | `zip-too-large`                 | 130 570   | 0,065 s | 53,6 Mio  |
| ZIP : entrée déclarée 4 Gio                            | `zip-too-large`                 | 130 570   | 0,081 s | 53,1 Mio  |

Contre-épreuve (correctifs ZIP et PyInstaller retirés temporairement, `s5/resources-before-fix.json`)
[constaté] : la bombe ZIP était **acceptée** (128 Mio gonflés, 317,5 Mio de RSS, aucune erreur) ;
l'entrée CArchive montait à 125 Mio avant d'échouer sur le plafond global. Le module PYZ reste à
~125 Mio : son plafond (64 Mio) est atteint avant l'erreur, la TOC du PYZ ne déclare pas de taille
décompressée. `make vulndb --no-download` avec le plafond ZIP : 0 enregistrement illisible sur les
5 archives réelles [constaté].

## Partie D — oracles supplémentaires (`make sbom-oracle-s5` → `s5/oracle.json`)

### D1 — govulncheck 1.1.4, mode binaire (base vuln.go.dev du 2026-10-21)

Comparaison par vulnérabilité (groupe d'alias). « Tous niveaux » = govulncheck la signale (module,
paquet ou symbole) ; « symbole » = une fonction vulnérable est présente dans le binaire [constaté] :

| Binaire    | Nous | govulncheck (tous niveaux) | dont absents chez nous | Niveau symbole | Écart attribuable à l'atteignabilité | Autres écarts |
| ---------- | ---- | -------------------------- | ---------------------- | -------------- | ------------------------------------ | ------------- |
| go-uuid    | 60   | 58                         | **0**                  | 0              | 58 (97 %)                            | 2             |
| go-jwt     | 63   | 62                         | **0**                  | 0              | 62 (98 %)                            | 1             |
| stringer   | 61   | 60                         | **0**                  | 0              | 60 (98 %)                            | 1             |
| yq         | 73   | 71                         | **0**                  | 11             | 60 (82 %)                            | 2             |
| prometheus | 120  | 117                        | **0**                  | 67             | 50 (42 %)                            | 3             |
| terraform  | 121  | 118                        | **0**                  | 87             | 31 (26 %)                            | 3             |

- **Toutes** les vulnérabilités vues par govulncheck sont dans nos alertes (inclusion vérifiée) [constaté].
- **Binaires strippés** : govulncheck classe tout au niveau symbole (go-uuid-stripped : 58/58 ;
  « Use '-show traces' to see the other 4027 found symbols » pour un seul avis) : sans table de
  symboles, il suppose présents tous les symboles. Ses chiffres « symbole » sur un strippé ne
  mesurent donc pas l'atteignabilité ; exclus du tableau [constaté].
- **Autres écarts (nos alertes absentes de govulncheck)**, causes vérifiées sur les avis :
  `GO-2026-5024` (x/sys) et `GO-2026-6604` (stdlib) ne visent que `goos: windows` : govulncheck
  filtre par plateforme, nous non (le GOOS est pourtant dans le buildinfo : amélioration possible,
  non faite). `CVE-2025-54410` (docker v27.0.3+incompatible) et `CVE-2026-63209` (klauspost/compress
  v1.15.11) : l'enregistrement GO- dit « non affecté » mais le **GHSA** du même export Go a une plage
  plus large (`introduced 26.0.0-rc1, fixed 28.0.0` ; `introduced 0, fixed 1.18.7`) ; nous prenons
  l'union des enregistrements, govulncheck ne lit que les GO-.

### D2 — cargo-audit (base RustSec du 2026-10-24)

1re tentative : cargo-audit **0.21.2** construit, base téléchargée, puis **échec** :
`error loading advisory database: … RUSTSEC-2026-0207.md: … unsupported CVSS version: 4.0`.
2e tentative : cargo-audit **0.22.2** (dernière publiée) : exécuté [constaté].

| Binaire    | Nous | cargo-audit (vulnérabilités) | Communs | Absents chez nous | En plus chez nous                                                   |
| ---------- | ---- | ---------------------------- | ------- | ----------------- | ------------------------------------------------------------------- |
| rust-small | 0    | 0                            | 0       | 0                 | —                                                                   |
| rust-vuln  | 1    | 1                            | 1       | 0                 | —                                                                   |
| ripgrep    | 3    | 1                            | 1       | 0                 | RUSTSEC-2026-0186 (memmap2), RUSTSEC-2026-0190 (anyhow) : `unsound` |
| fd         | 3    | 2                            | 2       | 0                 | RUSTSEC-2026-0190 (anyhow) : `unsound`                              |

Les 3 « en plus » sont exactement les avertissements `unsound` de cargo-audit (avis informatifs
qu'il ne compte pas comme vulnérabilités ; l'export OSV ne les distingue pas dans nos données
indexées) [constaté].

### D3 — plages risquées (`scripts/risky_ranges.mjs`, `test/data/risky-ranges.json`)

30 paquets réels (6 par écosystème) pris dans la snapshot, dont la plage utilise des pré-versions
(24) ou `last_affected` (6) ; 188 versions sondées autour de chaque borne (la borne, sa version
de base, une pré-version de la base, le correctif suivant), dont 71 pré-versions. Oracle :
**api.osv.dev** `/v1/querybatch` (évaluation des plages par OSV.dev, implémentation indépendante ;
mêmes données amont). Résultat : **0 désaccord sur 188** ; `modified` identique entre notre snapshot
et l'API pour tous les avis touchés [constaté]. Rejoué hors ligne par `test/risky-ranges.test.mjs`.

- 1re exécution : 18 « désaccords », tous NuGet, l'oracle disant toujours « non affecté ». Cause :
  **mon script** interrogeait avec la clé d'index en minuscules ; l'API est sensible à la casse
  (`akka` → `{}`, `Akka` → l'avis) [constaté]. Corrigé en prenant le nom exact de l'avis
  (`/v1/vulns/{id}`) ; ce n'était pas un défaut de l'évaluateur.
- **Aucun événement `limit`** dans toute la snapshot (0 sur les 5 index) [constaté] : `limit` n'est
  couvert que par le test synthétique de S4.

## Limites

- Format buildinfo Go < 1.18 refusé ; non essayé sur un vrai binaire ancien.
- PE et Mach-O (Go et Rust) **testés uniquement sur des conteneurs synthétiques** : aucun binaire
  Windows ou macOS réel construit ni lu dans cette session.
- Détection : un PE Go est sélectionné par le marqueur, pas par la structure.
- `artifact-changed` : contrôle de taille seulement (REA fournissait un sha256 de sa propre lecture).
- Pas de filtre de plateforme (GOOS/GOARCH) des avis Go, pas d'atteignabilité (voir D1).
- Les avis RustSec `unsound` / informatifs sont des alertes comme les autres (voir D2).
- Le garde-fou A5 détecte un effondrement grossier de l'export, pas un changement de sens.
- Mesures : une seule machine, cache disque non contrôlé ; tokens d'agent non mesurés.

## Non résolu

- Lecture du format par pointeurs (Go 1.13–1.17).
- Filtre GOOS des avis Go à partir des réglages `build` déjà lus (`GOOS=linux`).
- Politique pour les avis informatifs RustSec et pour les désaccords GO-/GHSA d'un même export.
- Un binaire vendoré (lazygit) n'a pas été essayé.

## Les trois choses les plus fragiles

1. **La couverture réelle des lecteurs se limite à ELF linux/amd64.** Les dispositions PE, Mach-O,
   fat, ELF 32 bits et gros-boutien ne sont vérifiées que contre des fichiers que j'ai fabriqués
   moi-même à partir de la même compréhension du format : une erreur de lecture de la spécification
   serait reproduite des deux côtés. La connaissance du buildinfo Go vient de mémoire (NOTICE.md).
2. **La sémantique des alertes reste « par version », sans plateforme ni atteignabilité.** Sur un
   petit binaire Go, 97 % des alertes concernent du code non lié (govulncheck) et certaines visent
   Windows sur un binaire Linux ; le regroupement par alias mêle parfois stdlib et bibliothèque, ce
   qui rend `rea-sbom:scope` et `--no-runtime-vulns` subtils. Un consommateur pressé lira un bruit
   important comme un risque.
3. **Les oracles partagent les données amont.** OSV.dev, govulncheck (vuln.go.dev) et cargo-audit
   (RustSec) dérivent des mêmes sources que notre snapshot : l'accord prouve que l'évaluation des
   plages et l'appariement sont justes, pas que les plages elles-mêmes le sont ; et les écarts de
   date de base (vuln.go.dev au 21/10, export au 24/10) peuvent masquer ou créer des différences.

## B7 final et `git diff --stat`

```text
$ git archive HEAD sbom | tar -x -C /tmp/claude-0/b7final && cd /tmp/claude-0/b7final/sbom && make sbom-test
ℹ tests 144
ℹ pass 139
ℹ fail 0
ℹ skipped 5        (tests de bornes sur la vraie snapshot : pas d'index dans une copie fraîche)
77.80 s elapsed    (corpus reconstruit : Go, Rust, npm, .NET, PyInstaller)
```

```text
$ git diff --name-only origin/main... | grep -v '^sbom/' | wc -l
0
$ git diff --stat sbom-s4-vulns... | tail -1
 48 files changed, 8201 insertions(+), 156 deletions(-) (avec ce rapport)
```
