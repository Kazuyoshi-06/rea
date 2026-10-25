# S7_REPORT — comparaison avec syft, résumé sur stderr, extractabilité

Session S7, 2026-10-25, conteneur Linux x64 neuf (Ubuntu 24.04, 4 CPU, Intel Xeon @ 2,80 GHz),
Node 24.22.1 (nvm), go1.24.7, cargo-auditable 0.7.7 et rust-audit-info 0.5.4 (réinstallés),
SDK .NET 8 et mingw-w64 (apt), snapshot OSV `osv-eef787903cdb54a4` (re-téléchargée, plus récente
que celle de S6). Chaque affirmation est marquée **[constaté]** (sortie de commande dans cette
session) ou **[supposé]**. Branche `sbom-s7-compare` depuis `sbom-s6-field`.

## Critères de réussite

| Critère                                        | Résultat                                                                                                                                                               |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make sbom-test` vert sans REA                 | **163 tests, 163 réussis, 0 échec, 0 sauté**, 12,2 s (index vulndb présent) [constaté]                                                                                 |
| `make sbom-test-diff` vert                     | **6 / 6** [constaté]                                                                                                                                                   |
| Tableau scanner / syft par écosystème          | Partie A : précision, rappel, causes, temps, RSS [constaté]                                                                                                            |
| B : stdout identique avec et sans `--quiet`    | `test/cli-summary.test.mjs` **6 / 6** ; vérifié aussi sur la vraie snapshot (4 binaires, `cmp` identique) [constaté]                                                   |
| C : copie extraite passe `make sbom-test`      | **163 tests, 158 réussis, 5 sautés (pas d'index vulndb dans la copie), 0 échec**, 111 s corpus compris [constaté]                                                      |
| C : aucune référence REA hors oracle optionnel | `extract.sh` : « no REA reference outside the oracle » ; 67 lignes dans 8 fichiers d'oracle ; reste le préfixe de format `rea-sbom` (décision propriétaire) [constaté] |
| Aucune modification hors `sbom/`               | `git diff --name-only origin/main... \| grep -v '^sbom/' \| wc -l` → `0` (fin de session) [constaté]                                                                   |

## Partie A — comparaison avec syft

### A1 — installation

| Outil | Version  | Choix de version                                                                                                        | Commande                                                                   | Tentatives | Build (mur / RSS max) |
| ----- | -------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ---------- | --------------------- |
| syft  | v1.42.0  | Dernière version dont `go.mod` accepte go1.24.7 (`go 1.24.6`) ; v1.42.1 exige `go 1.25`, v1.55.0 (dernière) `go 1.26.8` | `GOTOOLCHAIN=local go install github.com/anchore/syft/cmd/syft@v1.42.0`    | 1          | 4 min 14 s / 1,29 Gio |
| grype | v0.104.0 | Idem (`go 1.24.1`) ; v0.105.0 exige `go 1.24.9`                                                                         | `GOTOOLCHAIN=local go install github.com/anchore/grype/cmd/grype@v0.104.0` | 1          | 4 min 41 s / 1,41 Gio |

[constaté] Les exigences `go` viennent des `go.mod` téléchargés par `go mod download -json`.
`GOTOOLCHAIN=local` empêche le téléchargement d'une autre chaîne Go. Une première commande a
échoué **avant** `go install` (`/usr/bin/time: No such file or directory`, conteneur neuf) ;
`time` installé par apt, puis l'installation a réussi du premier coup. `syft version` affiche
`Version: [not provided]` (pas de `-ldflags` avec `go install`) : la version **v1.42.0 est lue
dans le buildinfo** (`go version -m` : `mod github.com/anchore/syft v1.42.0`) [constaté].

### A2 — exécution

`syft scan file:<chemin>` (ou `dir:` pour un répertoire) `-o cyclonedx-json -q`, avec
`SYFT_CHECK_FOR_APP_UPDATE=false`, catalogueurs par défaut (aucun enrichissement réseau activé
par défaut). Sortie : CycloneDX `specVersion 1.6` [constaté]. Aucun échec d'exécution de syft
sur les 35 artefacts [constaté].

Artefacts (`scripts/compare_syft_s7.mjs` → `s7/compare.json`) : 13 fixtures du corpus ; 6 binaires
réels de S5 (stringer, yq, prometheus, terraform, ripgrep, fd ; reconstruits, mêmes épingles) ;
12 binaires Go cross-compilés (stringer, stringer `-s -w`, yq, prometheus × windows/amd64,
darwin/arm64, linux/s390x ; `scripts/build_cross.sh` accepte maintenant une liste de cibles) ;
4 variantes informatives : 2 répertoires .NET sans `*.deps.json`, 2 répertoires de staging npm
(ce que `app.asar` empaquette : `node_modules` + `package-lock.json`, forme que syft sait lire).

### A3 — précision, rappel, causes

Vérité : `truth/*.json` (corpus), `go version -m` (deps, remplacement appliqué, remplacements
sans version exclus), `rust-audit-info` (paquets hors racine et hors `kind=build`). Identité
(écosystème, nom, version exacte) ; nom NuGet insensible à la casse, PyPI PEP 503. Les runtimes
ne sont comptés pour aucun outil (notre `role=language-runtime`, `pkg:golang/stdlib` de syft) ;
les deux émettent `stdlib@1.24.7` sur chaque binaire Go [constaté]. « Précision hors racine » :
syft sans le composant racine qu'il émet ; ce chiffre n'est donné que pour syft parce que nous
n'émettons jamais la racine en composant. Micro-moyennes [constaté] :

| Écosystème (artefacts)                   | Vrais | Nous : VP / émis | Nous : précision | Nous : rappel | syft : VP / émis | syft : précision | syft : précision hors racine | syft : rappel |
| ---------------------------------------- | ----- | ---------------- | ---------------- | ------------- | ---------------- | ---------------- | ---------------------------- | ------------- |
| Go (20)                                  | 1012  | 1012 / 1012      | 100,0 %          | 100,0 %       | 1012 / 1041      | 97,2 %           | 99,1 %                       | 100,0 %       |
| Rust cargo-auditable (4)                 | 93    | 93 / 93          | 100,0 %          | 100,0 %       | 93 / 97          | 95,9 %           | 100,0 %                      | 100,0 %       |
| npm ASAR (2)                             | 9     | 9 / 9            | 100,0 %          | 100,0 %       | 0 / 0            | —                | —                            | 0,0 %         |
| .NET, répertoire de publication (2)      | 3     | 3 / 3            | 100,0 %          | 100,0 %       | 3 / 5            | 60,0 %           | 100,0 %                      | 100,0 %       |
| PyInstaller onefile (3)                  | 11    | 11 / 11          | 100,0 %          | 100,0 %       | 0 / 0            | —                | —                            | 0,0 %         |
| .NET sans deps.json (2, variante)        | 3     | 1 / 1            | 100,0 %          | 33,3 %        | 0 / 5            | 0,0 %            | 0,0 %                        | 0,0 %         |
| npm, répertoire de staging (2, variante) | 9     | 9 / 9            | 100,0 %          | 100,0 %       | 9 / 11           | 81,8 %           | 100,0 %                      | 100,0 %       |

Causes, par catégorie (classées automatiquement par le script, puis relues) [constaté] :

| Outil | Écart              | Nombre | Cause                                                                                                                                                                                                                      |
| ----- | ------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| syft  | en trop            | 30     | Composant racine émis dans `components[]` : module principal Go (20), crate racine (4), assembly de l'application (4), paquet racine npm (2). Choix de conception, pas une erreur de lecture                               |
| syft  | en trop            | 9      | terraform : modules remplacés par un répertoire local (`=> ./internal/… (devel)`), émis avec `version: "UNKNOWN"` et un purl sans version ; nous : 9 unknowns avec raison                                                  |
| syft  | manquant           | 9      | npm ASAR : aucun composant (syft ne lit pas ASAR)                                                                                                                                                                          |
| syft  | manquant           | 11     | PyInstaller : aucun composant (syft ne lit pas l'archive PyInstaller)                                                                                                                                                      |
| syft  | en trop + manquant | 2 + 2  | .NET sans deps.json : `serilog@3.1.1.0`, `serilog.sinks.console@5.0.1.0` = `FileVersion` de la ressource de version Win32 (relevé dans `Serilog.dll` : `3.1.1.0`) au lieu de `3.1.1`, `5.0.1`                              |
| syft  | en trop + manquant | 1 + 1  | .NET sans deps.json : `json.net@12.0.1.22727` = `ProductName` (`Json.NET`) et `FileVersion` (`12.0.1.22727`) de la ressource Win32, relevés dans la DLL, au lieu de `newtonsoft.json@12.0.1`                               |
| syft  | hors écosystème    | 4      | PE Go (windows/amd64) : composant `application` `<nom de fichier>@UNKNOWN` du `pe-binary-package-cataloger` (nom tiré du nom de fichier : `stringer-stripped`)                                                             |
| nous  | manquant           | 2      | .NET sans deps.json : Serilog et Serilog.Sinks.Console déclarés unknowns (`AssemblyInformationalVersion` `3.1.1-main-999d686d+…`, `5.0.1-main-33be844` : étiquette pre-release, non prise pour la version NuGet, règle S4) |

Sur tous les autres artefacts, les ensembles de composants des deux outils sont identiques à la
vérité, à la racine de syft près (tableau par artefact ci-dessous) [constaté]. Les deux outils
sont donc **à égalité de rappel sur Go, Rust et .NET avec deps.json** sur ce corpus ; l'écart de
précision de syft vient de la racine et des 9 versions `UNKNOWN`.

<details><summary>Tableau par artefact (35 lignes)</summary>

| Artefact                        | Groupe  | Vrais | Nous VP / émis | Nous : unknowns / exclusions | syft VP / émis | syft hors écosystème | Écarts syft (cause)                                                                                           |
| ------------------------------- | ------- | ----- | -------------- | ---------------------------- | -------------- | -------------------- | ------------------------------------------------------------------------------------------------------------- |
| go-uuid                         | corpus  | 3     | 3 / 3          | 0 / 0                        | 3 / 4          | 0                    | 1 × root component emitted                                                                                    |
| go-uuid-stripped                | corpus  | 3     | 3 / 3          | 0 / 0                        | 3 / 4          | 0                    | 1 × root component emitted                                                                                    |
| go-jwt                          | corpus  | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| go-jwt-stripped                 | corpus  | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| rust-small                      | corpus  | 5     | 5 / 5          | 0 / 5                        | 5 / 6          | 0                    | 1 × root component emitted                                                                                    |
| rust-vuln                       | corpus  | 2     | 2 / 2          | 0 / 1                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| npm-electron                    | corpus  | 2     | 2 / 2          | 0 / 0                        | 0 / 0          | 0                    | 2 × manquant : nothing found in this ecosystem                                                                |
| npm-cli                         | corpus  | 7     | 7 / 7          | 0 / 0                        | 0 / 0          | 0                    | 7 × manquant : nothing found in this ecosystem                                                                |
| dotnet-json                     | corpus  | 1     | 1 / 1          | 0 / 0                        | 1 / 2          | 0                    | 1 × root component emitted                                                                                    |
| dotnet-serilog                  | corpus  | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| py-requests                     | corpus  | 5     | 5 / 5          | 0 / 0                        | 0 / 0          | 0                    | 5 × manquant : nothing found in this ecosystem                                                                |
| py-requests-meta                | corpus  | 5     | 5 / 5          | 0 / 0                        | 0 / 0          | 0                    | 5 × manquant : nothing found in this ecosystem                                                                |
| py-yaml                         | corpus  | 1     | 1 / 1          | 0 / 0                        | 0 / 0          | 0                    | 1 × manquant : nothing found in this ecosystem                                                                |
| stringer                        | real    | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| yq                              | real    | 21    | 21 / 21        | 0 / 0                        | 21 / 22        | 0                    | 1 × root component emitted                                                                                    |
| prometheus                      | real    | 176   | 176 / 176      | 0 / 0                        | 176 / 177      | 0                    | 1 × root component emitted                                                                                    |
| terraform                       | real    | 208   | 208 / 208      | 9 / 0                        | 208 / 218      | 0                    | 9 × local-directory replacement, no version; 1 × root component emitted                                       |
| ripgrep                         | real    | 32    | 32 / 32        | 0 / 0                        | 32 / 33        | 0                    | 1 × root component emitted                                                                                    |
| fd                              | real    | 54    | 54 / 54        | 0 / 11                       | 54 / 55        | 0                    | 1 × root component emitted                                                                                    |
| dotnet-json-nodeps              | variant | 1     | 1 / 1          | 0 / 0                        | 0 / 2          | 0                    | 1 × manquant : not found; 1 × not in the truth; 1 × root component emitted                                    |
| dotnet-serilog-nodeps           | variant | 2     | 0 / 0          | 2 / 0                        | 0 / 3          | 0                    | 2 × manquant : version differs from the truth; 1 × root component emitted; 2 × version differs from the truth |
| npm-electron-staged             | variant | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| npm-cli-staged                  | variant | 7     | 7 / 7          | 0 / 0                        | 7 / 8          | 0                    | 1 × root component emitted                                                                                    |
| stringer windows/amd64          | cross   | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 1                    | 1 × root component emitted                                                                                    |
| stringer-stripped windows/amd64 | cross   | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 1                    | 1 × root component emitted                                                                                    |
| yq windows/amd64                | cross   | 22    | 22 / 22        | 0 / 0                        | 22 / 23        | 1                    | 1 × root component emitted                                                                                    |
| prometheus windows/amd64        | cross   | 171   | 171 / 171      | 0 / 0                        | 171 / 172      | 1                    | 1 × root component emitted                                                                                    |
| stringer darwin/arm64           | cross   | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| stringer-stripped darwin/arm64  | cross   | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| yq darwin/arm64                 | cross   | 21    | 21 / 21        | 0 / 0                        | 21 / 22        | 0                    | 1 × root component emitted                                                                                    |
| prometheus darwin/arm64         | cross   | 172   | 172 / 172      | 0 / 0                        | 172 / 173      | 0                    | 1 × root component emitted                                                                                    |
| stringer linux/s390x            | cross   | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| stringer-stripped linux/s390x   | cross   | 2     | 2 / 2          | 0 / 0                        | 2 / 3          | 0                    | 1 × root component emitted                                                                                    |
| yq linux/s390x                  | cross   | 21    | 21 / 21        | 0 / 0                        | 21 / 22        | 0                    | 1 × root component emitted                                                                                    |
| prometheus linux/s390x          | cross   | 176   | 176 / 176      | 0 / 0                        | 176 / 177      | 0                    | 1 × root component emitted                                                                                    |

</details>

### A3 — temps et RSS

`scripts/measure_s7.mjs` → `s7/measurements.json`. 5 exécutions **froides** (chacune précédée de
`sync; echo 3 > /proc/sys/vm/drop_caches`, effet constaté : buff/cache 556 → 303 Mio) et, après
une exécution d'amorçage non comptée, 5 **chaudes**. Médianes ; `/usr/bin/time -v` ; sortie
CycloneDX vers `/dev/null` ; sans `--vulns` (syft n'a pas d'appariement hors ligne). Nous :
`node bin/sbom-scan <a> --timestamp 0 --quiet --output /dev/null` ; RSS = processus Node seul.
syft : `syft scan … -o cyclonedx-json=/dev/null -q` [constaté] :

| Artefact                 | Octets      | Nous froid : durée / CPU / RSS | Nous chaud               | syft froid                | syft chaud                |
| ------------------------ | ----------- | ------------------------------ | ------------------------ | ------------------------- | ------------------------- |
| go-uuid                  | 3 088 475   | 0,17 s / 0,15 s / 57 Mio       | 0,14 s / 0,14 s / 57 Mio | 2,39 s / 2,74 s / 173 Mio | 2,03 s / 2,53 s / 175 Mio |
| rust-small               | 4 480 648   | 0,20 s / 0,18 s / 57 Mio       | 0,14 s / 0,14 s / 57 Mio | 2,38 s / 2,78 s / 176 Mio | 2,27 s / 2,85 s / 177 Mio |
| npm-cli                  | 150 893     | 0,13 s / 0,12 s / 55 Mio       | 0,11 s / 0,11 s / 55 Mio | 2,20 s / 2,65 s / 170 Mio | 2,04 s / 2,55 s / 175 Mio |
| npm-electron             | 1 713 085   | 0,16 s / 0,15 s / 58 Mio       | 0,13 s / 0,13 s / 57 Mio | 2,11 s / 2,52 s / 164 Mio | 1,98 s / 2,39 s / 172 Mio |
| dotnet-serilog           | 262 028     | 0,14 s / 0,13 s / 54 Mio       | 0,11 s / 0,11 s / 54 Mio | 2,30 s / 2,68 s / 172 Mio | 2,10 s / 2,65 s / 177 Mio |
| py-requests              | 8 510 328   | 0,25 s / 0,25 s / 58 Mio       | 0,19 s / 0,21 s / 58 Mio | 2,26 s / 2,65 s / 175 Mio | 1,99 s / 2,46 s / 174 Mio |
| stringer                 | 7 400 333   | 0,21 s / 0,19 s / 57 Mio       | 0,18 s / 0,18 s / 57 Mio | 2,53 s / 2,96 s / 176 Mio | 2,34 s / 2,86 s / 172 Mio |
| yq                       | 16 257 348  | 0,36 s / 0,34 s / 57 Mio       | 0,28 s / 0,28 s / 57 Mio | 2,60 s / 3,12 s / 176 Mio | 2,43 s / 3,06 s / 176 Mio |
| prometheus               | 136 617 940 | 1,17 s / 1,13 s / 58 Mio       | 1,33 s / 1,33 s / 58 Mio | 4,74 s / 6,19 s / 225 Mio | 4,54 s / 5,89 s / 236 Mio |
| terraform                | 124 452 395 | 1,31 s / 1,28 s / 59 Mio       | 1,12 s / 1,13 s / 59 Mio | 4,40 s / 5,51 s / 203 Mio | 4,01 s / 5,28 s / 207 Mio |
| ripgrep                  | 29 448 808  | 0,35 s / 0,34 s / 57 Mio       | 0,39 s / 0,40 s / 57 Mio | 2,59 s / 3,15 s / 179 Mio | 2,30 s / 2,89 s / 173 Mio |
| fd                       | 3 979 488   | 0,21 s / 0,20 s / 58 Mio       | 0,14 s / 0,15 s / 58 Mio | 2,15 s / 2,52 s / 177 Mio | 1,97 s / 2,46 s / 175 Mio |
| prometheus windows/amd64 | 136 190 976 | 1,20 s / 1,21 s / 65 Mio       | 1,11 s / 1,12 s / 65 Mio | 4,81 s / 6,70 s / 693 Mio | 4,60 s / 6,60 s / 705 Mio |

- Les écarts min–max sont dans `s7/measurements.json` ; pour nous, « chaud » > « froid » sur
  prometheus (1,33 / 1,17 s) et ripgrep (0,39 / 0,35 s), avec des plages qui se recouvrent
  (prometheus chaud 1,12–1,42 s, froid 1,10–1,28 s) [constaté] ; bruit de la VM [supposé].
- **Machine différente de S6** : sha256 seul de prometheus en Node = 360 ms ici contre 124 ms en
  S6 ; notre scan de prometheus est à 1,1 s ici contre 0,55 s en S6, pour les mêmes octets
  (136 617 940). Les temps ne se comparent qu'à l'intérieur de S7 [constaté]. Notre temps est
  dominé par les deux passes de hachage (empreinte + intégrité) ; le lecteur Go seul : 3 ms
  (`--timings`) [constaté].
- syft ≈ 2 s même sur un fichier de 150 Ko (npm-cli, où il ne trouve rien) ; cause non analysée
  [supposé : initialisation des catalogueurs et catalogage des fichiers].
- syft monte à 693–705 Mio de RSS sur prometheus PE contre 225–236 Mio sur le même outil en ELF ;
  cause non analysée [supposé : `pe-binary-package-cataloger`].
- Non mesuré : tokens d'agent (aucun), mémoire de la famille de processus de syft (un seul
  processus observé par `time -v`).

### A4 — hors périmètre

Ce que syft fait et pas nous, vérifié sur une sortie réelle de syft v1.42.0 [constaté] :

| Capacité                                   | Vérification                                                                                                                                                                                                                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 66 catalogueurs                            | `syft cataloger list -o json` : alpm, apk, dpkg, rpm, java (jar, pom, gradle), ruby, php, dart, elixir, erlang, haskell, swift, cocoapods, conan, nix, lua, R, homebrew, snap, wordpress, github-actions, GGUF…                                                                 |
| Paquets OS                                 | Répertoire contenant `var/lib/dpkg/status` de ce conteneur : **876 / 876** paquets deb (purl absent : pas d'`/etc/os-release` dans le répertoire). Nous : 0 composant, sans erreur (lu comme racine npm vide)                                                                   |
| Lockfiles de sources                       | Répertoire de staging npm : 8 composants (`javascript-lock-cataloger`), 7 avec licence, 5 entrées `dependencies`                                                                                                                                                                |
| Graphe de dépendances                      | rust-small : 2 entrées `dependencies` (racine → serde, serde_json ; serde_json → itoa, memchr, ryu, serde). Go (yq) : 1 entrée (racine → tout). Nous : aucun graphe                                                                                                             |
| CPE                                        | Chaque composant porte un `cpe` (ex. `cpe:2.3:a:itoa:itoa:1.0.18:…`). Nous : aucun                                                                                                                                                                                              |
| Licences                                   | Présentes quand le lockfile les donne (npm). Nous : aucune                                                                                                                                                                                                                      |
| Fat Mach-O, toutes les tranches            | Fat stringer (darwin/amd64 + arm64, fabriqué par `make_fat.mjs`) : composants par tranche, étiquetés `syft:metadata:architecture`. Fat aux tranches différentes (stringer + yq) : union des deux, étiquetée par architecture ; **nous : erreur `fat-slices-differ`**, aucun BOM |
| Images de conteneurs, SPDX, autres formats | `syft scan --help` : docker, podman, registry, docker-archive, oci-archive, oci-dir, singularity ; sorties SPDX 2.2 / 2.3, syft-json, template. **Images non exécutées ici** (ni démon, ni registre, ni archive d'image)                                                        |
| Hash de l'artefact                         | Composant `file` avec SHA-1 et SHA-256 du fichier scanné (comme notre `metadata.component.hashes`)                                                                                                                                                                              |

Où syft fait mieux, honnêtement : couverture d'écosystèmes et de formats sans commune mesure ;
graphe de dépendances, CPE, licences ; sur un fat aux tranches différentes, syft produit un
inventaire utilisable là où nous refusons ; images de conteneurs.

Ce que nous faisons et pas syft, vérifié sur les sorties des deux outils [constaté] :

| Capacité                                 | Nous                                                                                                                      | syft                                                                                      |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| ASAR (`app.asar`)                        | 9 / 9                                                                                                                     | 0 composant                                                                               |
| PyInstaller onefile                      | 11 / 11 (dist-info ou bytecode, confiance `low` pour ce dernier)                                                          | 0 composant                                                                               |
| .NET sans deps.json                      | `newtonsoft.json@12.0.1` ; pre-release → unknown                                                                          | `FileVersion` Win32 (`3.1.1.0`), `ProductName` (`json.net`)                               |
| Version absente                          | jamais émise : unknown avec raison (`rea-sbom:unknown-component`), compté (`rea-sbom:unknown-count`)                      | `version: "UNKNOWN"` (modules `(devel)`, remplacements locaux, PE)                        |
| Composants exclus                        | listés avec raison (rust-small : 5 `kind=build` ; fd : 11)                                                                | absents, sans trace dans le BOM (0 occurrence de `proc-macro2` dans la sortie rust-small) |
| Evidence par composant                   | `offset` de la plage lue, `sourceSha256` des octets lus, lecteur, faits du format                                         | `syft:location:0:path` (chemin seulement)                                                 |
| Appariement de vulnérabilités hors ligne | intégré (`--vulns`), index OSV local, filtre de plateforme Go, plages non évaluées visibles                               | aucun (grype séparé, base non téléchargeable ici, A5)                                     |
| Refus typés                              | `fat-slices-differ`, `go-buildinfo-pointer-format`, `unsupported-artifact` (UPX, Rust sans auditable), `artifact-changed` | non comparé                                                                               |
| Racine                                   | jamais en composant (`metadata.component`)                                                                                | en composant                                                                              |

### A5 — grype

**Non exécuté.** `grype db update` (une tentative, 0,57 s) :
`unable to update vulnerability database: check for vulnerability database update failed: unable
to download listing: Get "https://grype.anchore.io/databases/v6/latest.json": Forbidden`
[constaté]. Pas d'autre tentative, conformément à la consigne. Aucune comparaison d'alertes avec
grype n'est donc faite.

## Partie B — résumé sur stderr (commit `feat(sbom): summarize filtered alerts…`)

`lib/cli.mjs` : `summaryLines(scan)` (fonction pure) produit au plus trois lignes, écrites sur
stderr **après** la sortie : alertes retirées par le filtre de plateforme (nombre, plateformes
cibles, `--all-platforms`), composants exclus (nombre par raison), unknowns. Rien n'est écrit
quand il n'y a rien à dire, ni quand le filtre est désactivé. `--quiet` supprime ces lignes (pas
les erreurs ni `--timings`). Le BOM n'est pas modifié : pas d'incrément de
`rea-sbom:format-version`.

Tests (`test/cli-summary.test.mjs`, 6) [constaté] : `summaryLines` vide / complet ; go-uuid
`--vulns` sur les enregistrements de plateforme (ligne « 4 alerts », égale à
`rea-sbom:platform-filtered-count`) ; rust-vuln (`kind=build`) ; `--output` ; .NET sans deps.json
(2 unknowns). Dans chaque cas, stdout (ou le fichier) est **identique octet pour octet** avec et
sans `--quiet`, et stderr est vide avec `--quiet`.

Sur la vraie snapshot [constaté] :

```text
go-uuid          platform filter removed 2 alerts … other than linux/amd64
yq windows/amd64 platform filter removed 1 alert … other than windows/amd64
terraform        platform filter removed 2 alerts … ; 9 components detected without a version …
fd               11 components excluded from the BOM …: 11 kind=build (build-dependency or proc-macro, not linked)
```

`cmp` des BOM avec et sans `--quiet` : identiques sur les 4 ; stderr avec `--quiet` : 0 octet.

## Partie C — extractabilité (commit `feat(sbom)!: make sbom/ extractable…`)

### C1 — `scripts/extract.sh <répertoire> <nom>`

- Copie les fichiers suivis et non ignorés de ce répertoire (`git ls-files --cached --others
  --exclude-standard`, sinon `find` moins les sorties générées), sans `.git` ; refuse un
  répertoire cible non vide ou situé dans la source ; valide le nom selon les règles npm.
- `package.json` / `package-lock.json` : nom donné, `version 0.0.0`, `private: true`.
- Liste par grep les références restantes. Résultat sur la copie [constaté] :
  `REA references in the optional oracle: 67 lines in 8 files (oracle/rea.mjs oracle/rea.mk
  scripts/measure_baseline.mjs scripts/measure_s2.mjs scripts/measure_s3.mjs scripts/run_rea.mjs
  test/binary-adapters.test.mjs test/differential/readers.test.mjs)` ; `no REA reference outside
  the oracle` ; `'rea-sbom' … in lib/: 69 occurrences`.
- Contrôle insensible à la casse hors oracle [constaté] : restent le champ `rea:` (commande REA
  par fixture, configuration de l'oracle) de `scripts/fixtures.mjs`, et les mentions
  `oracle/rea.mk` du Makefile (`include`). La documentation (`*.md`, historique) parle de REA et
  n'est pas filtrée.

Changements faits pour y arriver : `oracle/rea.mjs` est le seul module qui localise REA
(`SBOM_REA_ROOT`, sinon le répertoire parent s'il contient `scripts/rea.mjs`) et expose
`reaAvailability()` avec la raison ; les cibles `rea`, `baseline`, `sbom-test-diff`,
`sbom-measure` sont dans `oracle/rea.mk` ; le Makefile ne lit plus le `.nvmrc` du parent ;
commentaires « no REA » neutralisés dans `lib/` et les tests ; enregistrements synthétiques
renommés `SYN-TEST-*` / `SYN-PLAT-*`. **Changement cassant** : `make` sans cible lance
`sbom-test` (avant : `baseline`, qui exige REA).

### C2 — copie extraite

| Contrôle                                                                            | Résultat [constaté]                                                                                                                                 |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make sbom-test` (corpus reconstruit de zéro)                                       | 163 tests, 158 réussis, 5 sautés (« no vulnerability index … (run make vulndb) »), 0 échec, 111 s                                                   |
| `node --test 'test/differential/*.test.mjs'`                                        | 6 sautés, message : « REA oracle not found: set SBOM_REA_ROOT to a REA checkout built with `npm ci && npm run build:cached` … »                     |
| `make sbom-test-diff`                                                               | échec explicite, même message, code 2                                                                                                               |
| `SBOM_REA_ROOT=<REA construit> make sbom-test-diff`                                 | 6 / 6                                                                                                                                               |
| Fichiers identiques octet pour octet à un fichier suivi de REA hors `sbom/`         | 1 sur 242 (copie finale, hors corpus construit et `node_modules`) : `.nvmrc` (6 295 empreintes distinctes de REA comparées), listé dans `NOTICE.md` |
| `LICENSE*`, `licenses/`, `.oxfmtrc*`, `.oxlintrc*`, `.editorconfig`, `.prettierrc*` | aucun                                                                                                                                               |

Ma première commande de test de l'oracle, `node --test test/differential/`, a échoué
(`Cannot find module …/test/differential`) : Node 24 n'accepte pas un répertoire ; relancée avec
le motif de fichiers, 6 sautés. Erreur d'invocation, pas du code.

### C3 — `DECISIONS_PROPRIETAIRE.md`

Nom (et espace de noms `rea-sbom:*`, changement cassant), licence (aucun `LICENSE` créé ; REA est
MIT ; renvoi à `NOTICE.md`), dépôt cible (historique, oracle, rapports), politique de sécurité
(aucun bac à sable), processus de contribution (formateur à choisir : aucune configuration
héritée). `NOTICE.md` (section S7) liste la provenance des fichiers non écrits ici.

## Partie D — README

`README.md` réécrit (produit : usage, installation, matrice de support, format et propriétés,
comparaison syft issue de A, limites, sécurité, provenance) ; l'ancien README est conservé tel
quel dans `HISTORY.md` ; les `S*_REPORT.md` ne sont pas modifiés. Le texte que les rapports S5/S6
citent comme « README.md, section S6 » se trouve désormais dans `HISTORY.md`.

## Limites

- syft : une version (v1.42.0, contrainte par go1.24.7 ; la dernière est v1.55.0), catalogueurs
  par défaut. Une version plus récente peut se comporter autrement [supposé].
- Le corpus est petit et choisi pour nos lecteurs : il favorise les formats que nous lisons (ASAR,
  PyInstaller) et ne contient aucun format que seul syft lit, hors les deux vérifications
  ponctuelles (dpkg, staging npm). Les chiffres ne mesurent pas une couverture générale.
- Vérité Go et Rust = métadonnées embarquées lues par l'outil officiel ; les deux scanners lisent
  les mêmes octets : l'accord ne valide pas la vérité elle-même (TRUTH_RULES.md).
- Temps : une machine, une VM partagée ; froid = cache de pages vidé, pas de redémarrage.
- grype non exécuté (A5) ; images de conteneurs non testées.

## Non résolu

- Comparaison des alertes avec grype (base inaccessible).
- Politique pour un fat aux tranches différentes : refuser (nous) ou inventorier par tranche
  (syft) ; aujourd'hui le refus empêche tout BOM.
- Répertoire non reconnu → BOM vide sans erreur (comportement hérité, constaté sur dpkg) ; un
  refus `unsupported-artifact` serait plus honnête, non fait (changement de comportement hors
  périmètre).
- Toutes les décisions de `DECISIONS_PROPRIETAIRE.md`.
- Cause du plancher de ≈ 2 s et du RSS PE de syft (non analysées).

## Les trois choses les plus fragiles

1. **La comparaison repose sur un corpus taillé pour nos lecteurs.** 35 artefacts, dont 20 Go
   construits par la même chaîne go1.24.7 ; sur Go, Rust et .NET avec deps.json, syft et nous
   lisons les mêmes métadonnées et obtenons le même rappel. Nos 100 % ne disent rien des formats
   que nous ne lisons pas, et syft en lit beaucoup plus.
2. **L'extraction dépend de `git ls-files` et d'un grep par motifs.** Un fichier ignoré par
   erreur, un nouveau chemin vers le parent écrit autrement (`path.resolve(…, "..")`) ou une
   mention en minuscules ne seraient pas signalés ; le seul contrôle fonctionnel est
   `make sbom-test` dans une copie placée hors de REA.
3. **L'espace de noms `rea-sbom:*` est partout dans le format.** 69 occurrences dans `lib/`, dans
   les noms de propriétés, `bom-ref`, valeurs `source` et le format d'index ; le renommer est un
   changement cassant pour tout consommateur, à faire une seule fois quand le nom sera choisi.

## `git diff --stat`

```text
$ git diff --name-only origin/main... | grep -v '^sbom/' | wc -l
0
$ git diff --stat origin/sbom-s6-field... | tail -1
 44 files changed, 4380 insertions(+), 442 deletions(-) (avant ce rapport)
```
