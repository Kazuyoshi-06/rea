# S6_REPORT — binaires réels multi-plateformes, filtre de plateforme Go, intégrité

Session S6, 2026-10-25, conteneur Linux x64 (Ubuntu 24.04, 4 CPU), Node 24.22.1, go1.24.7,
cargo 1.97.0, cargo-auditable 0.7.7, rust-audit-info 0.5.4, govulncheck 1.1.4 (base vuln.go.dev
du 2026-10-21), mingw-w64 et gcc-aarch64-linux-gnu (apt), snapshot OSV `osv-5668560afe1cbc0d`
(re-téléchargée : conteneur neuf). Chaque affirmation est marquée **[constaté]** (sortie de
commande dans cette session) ou **[supposé]**. Branche `sbom-s6-field`, 3 commits (A, B, C) + ce
rapport.

## Critères de réussite

| Critère                                       | Résultat                                                                                                                                                |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make sbom-test` vert sans REA                | **157 tests, 157 réussis, 0 échec, 0 sauté**, 7,0 s [constaté]                                                                                          |
| `make sbom-test-diff` vert                    | **6/6** (fixtures) ; étendu par `SBOM_DIFF_BINARIES` à 44 binaires réels : **41/44 + 3 fat refusés par REA** (détail en A2) [constaté]                  |
| Précision / rappel par cible (A)              | **100 % / 100 %** sur 32 binaires Go (8 cibles) et 2 Rust (2 cibles) ; faits du lecteur identiques à l'oracle champ par champ [constaté]                |
| Bug trouvé sur un vrai binaire                | **aucun dans les lecteurs** ; un écart des fixtures fabriquées (octet de drapeaux 3 en gros-boutien) ajouté aux tests ; un défaut trouvé en C (voir C1) |
| B : avant / après filtre, 0 FN vs govulncheck | **0 faux négatif attribuable au filtre sur 38 binaires** ; tableau en B3 [constaté]                                                                     |
| C : test d'intégrité vert                     | `test/integrity.test.mjs` **3/3** (contenu, taille, suppression) [constaté]                                                                             |
| `sbom/` copié seul passe `make sbom-test`     | `git archive HEAD sbom` dans un répertoire vide : **157 tests, 152 réussis, 5 sautés, 0 échec**, 78 s (corpus reconstruit) [constaté]                   |
| Aucune modification hors `sbom/`              | `git diff --name-only origin/main... \| grep -v '^sbom/' \| wc -l` → `0` [constaté]                                                                     |

Les 5 sautés de la copie isolée sont les tests de bornes sur la vraie snapshot (pas d'index dans
une copie fraîche), comme en S5.

## Partie A — binaires réels multi-plateformes (commit `feat(sbom): validate Go and Rust readers…`)

### A1 — Go, cross-compilation `CGO_ENABLED=0` (`scripts/build_cross.sh`, `scripts/cross_binaries.mjs`)

Outils épinglés comme en S5 : `golang.org/x/tools@v0.26.0` (`cmd/stringer`),
`github.com/mikefarah/yq/v4@v4.44.3`, `github.com/prometheus/prometheus@v0.54.1`
(`cmd/prometheus`, 2 `replace` module → module), construits depuis le zip de module avec
`-trimpath -buildvcs=false`. Un stringer strippé (`-ldflags="-s -w"`) par cible. Oracle :
`go version -m` ; comparaison de `goVersion`, `main`, chaque `dep` et son `=>`, **et désormais
toutes les lignes `build`** (GOOS/GOARCH servent au filtre B). Résultat `s6/cross-binaries.json`
[constaté] :

| Cible         | Conteneur vu             | Section lue      | stringer | stringer `-s -w` | yq      | prometheus | Faits identiques | Précision | Rappel |
| ------------- | ------------------------ | ---------------- | -------- | ---------------- | ------- | ---------- | ---------------- | --------- | ------ |
| windows/amd64 | PE32+                    | `.data`          | 2 / 2    | 2 / 2            | 22 / 22 | 171 / 171  | 4 / 4            | 100 %     | 100 %  |
| windows/arm64 | PE32+                    | `.data`          | 2 / 2    | 2 / 2            | 22 / 22 | 171 / 171  | 4 / 4            | 100 %     | 100 %  |
| darwin/amd64  | Mach-O 64 LE             | `__go_buildinfo` | 2 / 2    | 2 / 2            | 21 / 21 | 172 / 172  | 4 / 4            | 100 %     | 100 %  |
| darwin/arm64  | Mach-O 64 LE             | `__go_buildinfo` | 2 / 2    | 2 / 2            | 21 / 21 | 172 / 172  | 4 / 4            | 100 %     | 100 %  |
| linux/arm64   | ELF64 LE                 | `.go.buildinfo`  | 2 / 2    | 2 / 2            | 21 / 21 | 176 / 176  | 4 / 4            | 100 %     | 100 %  |
| linux/386     | ELF32 LE, pointeur 4     | `.go.buildinfo`  | 2 / 2    | 2 / 2            | 21 / 21 | 176 / 176  | 4 / 4            | 100 %     | 100 %  |
| linux/s390x   | ELF64 **BE**, drapeaux 3 | `.go.buildinfo`  | 2 / 2    | 2 / 2            | 21 / 21 | 176 / 176  | 4 / 4            | 100 %     | 100 %  |
| linux/ppc64   | ELF64 **BE**, drapeaux 3 | `.go.buildinfo`  | 2 / 2    | 2 / 2            | 21 / 21 | 176 / 176  | 4 / 4            | 100 %     | 100 %  |

« n / m » = composants émis / ensemble livré de l'oracle (remplacements appliqués). La stdlib
émise vaut `go1.24.7` de l'oracle sur les 32 binaires. Le module principal est `(devel)` (build
depuis un zip, pas `go install`) : pas de version inventée, conforme à l'oracle.

- **Échecs : aucun** sur les 32 binaires. Aucune construction n'a échoué [constaté].
- **Écart de compréhension trouvé sur les vrais binaires** : l'octet de drapeaux de l'en-tête
  buildinfo vaut **3** (bit 0 gros-boutien + bit 1 inline) sur s390x et ppc64, alors que mes
  fixtures fabriquées n'écrivaient que 2. Le lecteur ne testait que le bit 1 et lit donc
  correctement ; ce n'était pas un bug, mais une disposition jamais testée. Cas ajoutés à
  `test/readers.test.mjs` : « ELF64 BE, flags 3 » et « ELF32 LE, pointer size 4 » (dérivés des
  octets de l'en-tête réel, relevés à l'offset `headerOffset`) [constaté].
- PE : l'en-tête est trouvé dans `.data` par la structure (S5 le supposait d'après la
  disposition, sans PE réel) [constaté]. La détection d'un PE Go reste par marqueur.
- Les dépendances diffèrent selon la plateforme (prometheus : 171 sous windows, 172 sous darwin,
  176 sous linux), et le lecteur suit l'oracle sur chacune [constaté].

### A2 — fat Mach-O

Le conteneur est **fabriqué** par `scripts/make_fat.mjs` (en-tête `0xcafebabe`, `fat_arch`
gros-boutiens, tranches alignées sur 2¹⁴, cputype/cpusubtype recopiés des tranches) à partir des
tranches réelles darwin/amd64 + darwin/arm64 copiées octet pour octet. **Ce n'est pas une sortie
de `lipo`** (absent du conteneur Linux) : une disposition propre à `lipo` (alignement, ordre)
n'est pas couverte.

Décision : le lecteur Go (et Rust) lit **chaque tranche** ; un seul résultat si toutes portent
les mêmes `goVersion`, `main`, `dependencies` (et indicateurs de complétude), sinon erreur typée
`fat-slices-differ` qui nomme la tranche et le fait. Avant S6, seule la première tranche ayant un
buildinfo était lue, et une tranche sans buildinfo passait inaperçue.

| Fat (`s6/fat-binaries.json`)  | Résultat                                                                                        | = tranche amd64 seule | = tranche arm64 seule | Plateformes cibles         |
| ----------------------------- | ----------------------------------------------------------------------------------------------- | --------------------- | --------------------- | -------------------------- |
| stringer                      | 3 composants                                                                                    | oui                   | oui                   | darwin/amd64, darwin/arm64 |
| stringer `-s -w`              | 3 composants                                                                                    | oui                   | oui                   | darwin/amd64, darwin/arm64 |
| yq                            | 22 composants                                                                                   | oui                   | oui                   | darwin/amd64, darwin/arm64 |
| stringer (amd64) + yq (arm64) | `fat-slices-differ: slice 0 (cputype 0x1000007) and slice 1 (cputype 0x100000c) differ in main` | —                     | —                     | —                          |

[constaté]. Oracles sur les fat : `go version -m` ne lit **que la première tranche** (sur le fat
stringer + yq il imprime stringer sans signaler yq) ; govulncheck refuse (`unrecognized binary
format`) ; REA échoue (`rea inspect-go-binary … exited 1`), d'où les 3 échecs du différentiel
étendu. Le différentiel REA n'apporte donc rien sur les fat ; la vérification est la
comparaison tranche par tranche ci-dessus [constaté].

### A3 — Rust (`scripts/build_rust_cross.sh`)

`ripgrep@14.1.1`, `cargo auditable install --locked --target …`, oracle `rust-audit-info`
(`s6/rust-cross-binaries.json`) [constaté] :

| Cible                     | Linker                 | Conteneur | Faits                     | Composants / oracle | Précision | Rappel |
| ------------------------- | ---------------------- | --------- | ------------------------- | ------------------- | --------- | ------ |
| x86_64-pc-windows-gnu     | x86_64-w64-mingw32-gcc | PE32+     | identiques (0 différence) | 35 / 35             | 100 %     | 100 %  |
| aarch64-unknown-linux-gnu | aarch64-linux-gnu-gcc  | ELF64 LE  | identiques (0 différence) | 32 / 32             | 100 %     | 100 %  |
| x86_64-apple-darwin       | —                      | —         | **non réalisable**        | —                   | —         | —      |

Mach-O, 2 tentatives [constaté] : (1) linker par défaut `cc` (GCC) : `cc: error: unrecognized
command-line option '-arch'` / `'-mmacosx-version-min=10.12.0'` ; (2) `rust-lld` avec
`-C linker-flavor=darwin-lld` : `the linker flavor 'darwin-lld' is unstable, the '-Z
unstable-options' flag must also be passed`. Cause de fond : ni ld64 ni SDK Apple (`libSystem`)
dans le conteneur [supposé pour la suite : même avec un flavor accepté, `-lSystem` manquerait].
Aucun Mach-O Rust fabriqué pour le remplacer. Windows a 3 paquets de plus que linux (crates
spécifiques à Windows), suivis correctement.

### A4 — buildinfo Go < 1.18

**Non réalisable.** `go install golang.org/dl/go1.17.13@latest` a réussi, mais `go1.17.13
download` a échoué deux fois : `go1.17.13: download failed: Head
"https://dl.google.com/go/go1.17.13.linux-amd64.tar.gz": Forbidden` [constaté]. Le refus typé
`go-buildinfo-pointer-format` reste vérifié uniquement sur un en-tête fabriqué.

### A5 — matrice

`README.md`, section S6 « Matrice de support » : chaque disposition est « vérifié sur binaire
réel », « vérifié sur fichier fabriqué » ou « non supporté ». PE32 (windows/386) n'est vérifié ni
en réel ni en fabriqué et est écrit comme tel.

## Partie B — filtre de plateforme des alertes Go (commit `feat(sbom)!: filter Go alerts…`)

### B1 — ce que dit la snapshot, règle appliquée

Sur l'export Go (9 779 enregistrements, 15 126 entrées `affected`) : 1 208 entrées ont
`ecosystem_specific.imports`, **36** ont une restriction de plateforme, **aucune** ne mélange
imports restreints et non restreints ; clés vues : `path`, `symbols`, `goos` (40), `goarch` (7) ;
valeurs : listes positives (`["windows"]`, `["linux"]`, `["darwin"]`, `["js"]`, et des listes
d'architectures), jamais de négation [constaté]. GO-2026-5024 (x/sys) : un import
`goos: ["windows"]` ; GO-2026-6604 (stdlib) : deux imports, tous deux `goos: ["windows"]`
[constaté].

Règle (`lib/vulns/match.mjs`) : un enregistrement est exclu quand **chaque** entrée appariée a
des imports restreints et que **chaque** import exclut **toutes** les plateformes du binaire ;
une alerte (groupe d'alias) n'est retirée que si **tous** ses enregistrements sont exclus (un
jumeau GHSA sans information de plateforme garde le groupe). GOOS/GOARCH absents ou inconnus :
rien n'est retiré. Fat : une alerte reste si elle concerne une seule des tranches. L'index passe
au format `rea-sbom-osv-index/2` (champ `platforms`) ; un ancien index est refusé (`vulndb-stale`
/ format inconnu) plutôt que lu sans plateformes.

Tests (`test/platform.test.mjs`, 6) sur les deux vrais enregistrements copiés et 5 synthétiques :
GO-2026-5024 et GO-2026-6604 absents pour linux/amd64, présents pour windows/amd64 ; jumeau sans
plateforme ; `goarch` seul ; import restreint + non restreint ; `goos` et `goarch` sur un même
import ; fat ; `--all-platforms` ; plateforme inconnue [constaté].

### B2 — visibilité, réversibilité, format

`rea-sbom:target-platform` (toujours, Go), `rea-sbom:platform-filter` (`applied` / `disabled` /
`no-platform`), `rea-sbom:platform-filtered-count`, une `rea-sbom:platform-filtered` par alerte
retirée (`{id, records, affects, requires}`), `--all-platforms`. Deux exécutions identiques à
l’octet près (test B2). `rea-sbom:format-version` **4**, documenté dans le README (changement
cassant : index à reconstruire, alertes filtrées par défaut, `fat-slices-differ`).

### B3 — mesure (`scripts/platform_filter_s6.mjs` → `s6/platform-filter.json`)

« Avant » = `--all-platforms`, « après » = défaut ; govulncheck en mode binaire, tous niveaux
(module, paquet, symbole). Nombre d'alertes (groupes) [constaté] :

| Binaire                  | linux/amd64 | linux/arm64 | linux/386 | linux/s390x | linux/ppc64 | windows/amd64 | windows/arm64 | darwin/amd64 | darwin/arm64 | darwin fat |
| ------------------------ | ----------- | ----------- | --------- | ----------- | ----------- | ------------- | ------------- | ------------ | ------------ | ---------- |
| stringer (avant → après) | 61 → 60     | 61 → 60     | 61 → 60   | 61 → 60     | 61 → 60     | 61 → 60       | 61 → 60       | 61 → 59      | 61 → 59      | 61 → 59    |
| stringer `-s -w`         | —           | 61 → 60     | 61 → 60   | 61 → 60     | 61 → 60     | 61 → 60       | 61 → 60       | 61 → 59      | 61 → 59      | 61 → 59    |
| yq                       | 73 → 71     | 73 → 71     | 73 → 71   | 73 → 71     | 73 → 71     | 73 → **72**   | 73 → **72**   | 73 → 70      | 73 → 70      | 73 → 70    |
| prometheus               | 120 → 118   | 120 → 118   | 120 → 118 | 120 → 118   | 120 → 118   | 119 → 118     | 119 → 118     | 119 → 116    | 119 → 116    | —          |
| terraform                | 121 → 119   | —           | —         | —           | —           | —             | —             | —            | —            | —          |
| go-uuid (corpus)         | 60 → 58     | —           | —         | —           | —           | —             | —             | —            | —            | —          |
| go-jwt (corpus)          | 63 → 62     | —           | —         | —           | —           | —             | —             | —            | —            | —          |

Alertes retirées, par identifiant : CVE-2026-56857 (GO-2026-6604, stdlib, windows) sur toutes les
cibles non Windows ; CVE-2026-39824 (GO-2026-5024, x/sys, windows) partout où x/sys est lié, hors
Windows ; CVE-2026-32282 (GO-2026-4864, stdlib, `goos: linux`) sur Windows et darwin. Windows
contre linux du même outil : yq garde GO-2026-5024 et GO-2026-6604 sous Windows, les perd sous
linux, et inversement pour GO-2026-4864 [constaté].

Contre govulncheck (38 binaires ; les 3 fat exclus, govulncheck les refuse) [constaté] :

- **0** vulnérabilité signalée par govulncheck absente de nos alertes après filtre ; donc **0 faux
  négatif attribuable au filtre**.
- Écarts restants (nos alertes que govulncheck ne signale à aucun niveau) : **2 identifiants**,
  les mêmes qu'en S5, sans rapport avec la plateforme. `CVE-2025-54410` (docker
  `v27.0.3+incompatible`, prometheus sur 9 cibles) et `CVE-2026-63209` (klauspost/compress
  v1.15.11, terraform) : l'enregistrement GO- ne les déclare pas affectés, le GHSA du même export
  a une plage plus large ; nous prenons l'union, govulncheck ne lit que les GO-.
- Sur les 2 binaires de S5 que govulncheck séparait de nous par la plateforme (go-uuid,
  stringer), l'écart « autres » passe de 2 et 1 à 0.

## Partie C — intégrité (commit `fix(sbom): restore the integrity check…`)

Après les adaptateurs, `lib/scan.mjs` hache à nouveau le fichier entier et compare taille et
sha256 à ceux de la détection ; écart → `artifact-changed` (couvre Go, Rust, .NET, PyInstaller,
ASAR). Les contrôles de taille de S5 dans les adaptateurs Go et Rust sont supprimés (remplacés).

`test/integrity.test.mjs` (go-uuid, rust-small, npm-cli ; modification injectée entre détection
et adaptateurs par `scanArtifact(path, {afterFingerprint})`) : un octet modifié à taille égale →
`artifact-changed … content changed (sha256 … → …)` ; 16 octets ajoutés → `size changed` ;
fichier supprimé → `artifact-changed … ENOENT` [constaté].

**Défaut trouvé par ce test** : un fichier supprimé entre la détection et la lecture faisait
lever une exception `ENOENT` non typée (pile JavaScript, aucune erreur `Result`). Corrigé à la
frontière : une erreur système après la détection donne `artifact-changed`, avant elle
`unreadable-artifact` ; les autres exceptions continuent à remonter.

Surcoût (`scripts/measure_s6.mjs`, 5 exécutions, médiane chaude des 4 dernières,
`/usr/bin/time -v`) [constaté] :

| Cible      | Octets      | Avant C | Après C | Écart   | sha256 seul (en processus) | RSS avant / après |
| ---------- | ----------- | ------- | ------- | ------- | -------------------------- | ----------------- |
| go-uuid    | 3 088 475   | 0,070 s | 0,080 s | +10 ms  | 3,3 ms                     | 57,5 / 58,5 Mio   |
| rust-small | 4 480 648   | 0,085 s | 0,095 s | +10 ms  | 4,8 ms                     | 57,7 / 58,7 Mio   |
| stringer   | 7 400 333   | 0,090 s | 0,100 s | +10 ms  | 8,0 ms                     | 57,6 / 58,6 Mio   |
| ripgrep    | 29 448 808  | 0,145 s | 0,175 s | +30 ms  | 27,2 ms                    | 58,0 / 59,2 Mio   |
| terraform  | 124 452 395 | 0,380 s | 0,490 s | +110 ms | 119,5 ms                   | 60,1 / 61,3 Mio   |
| prometheus | 136 617 940 | 0,405 s | 0,550 s | +145 ms | 124,2 ms                   | 59,1 / 60,6 Mio   |

Honnêtement : **négligeable en absolu sur les petits binaires (≈ 10 ms), pas négligeable en
relatif sur les gros (+29 à +36 %)** ; le coût est ≈ 1 ms/Mo, un second hachage complet. Une
seule machine, cache disque chaud ; les mesures « avant » et « après » ont été prises à quelques
minutes d'intervalle, une variation de ±10 ms est du bruit [supposé]. Alternative non faite :
vérifier seulement les plages lues par les adaptateurs (empreintes par bloc) — moins coûteuse,
mais plus de code et une garantie plus faible ; pas de besoin mesuré pour l'instant.

## Limites

- Mach-O Rust réel et Go < 1.18 réel : non réalisables ici (A3, A4).
- Fat : conteneur fabriqué par mon script, jamais par `lipo` ; aucun oracle externe ne lit un fat
  Go en entier (`go version -m` : première tranche seulement ; REA et govulncheck : refus).
- PE32 (windows/386) ni réel ni fabriqué ; ELF32 BE et Mach-O 32 seulement fabriqués.
- Un seul compilateur Go (1.24.7) et un seul cargo-auditable (0.7.7) : un autre linker pourrait
  placer les données autrement.
- Le filtre ne s'appuie que sur `goos` / `goarch` des imports OSV ; il ne lit pas les
  contraintes de build (`//go:build`) ni les symboles ; il dépend de la complétude de ces champs
  dans l'export (36 entrées sur 15 126 en ont).
- `--all-platforms` et le filtre ne concernent que Go ; les autres écosystèmes n'ont pas de
  donnée de plateforme exploitée.
- Intégrité : un changement défait avant le second hachage (A → B → A) n'est pas vu ; le coût
  croît linéairement avec la taille.
- Mesures : une machine, tokens d'agent non mesurés.

## Non résolu

- Lecture du format par pointeurs (Go 1.13–1.17) et son test sur un vrai binaire.
- Politique pour les désaccords GO- / GHSA d'un même export (CVE-2025-54410, CVE-2026-63209).
- Vérification sur un fat produit par `lipo` et sur un Mach-O Rust réel (machine macOS requise).
- Détection d'un PE Go par la structure plutôt que par le marqueur.

## Les trois choses les plus fragiles

1. **Le filtre de plateforme repose entièrement sur des métadonnées rares de l'export OSV.** Seules
   36 entrées Go sur 15 126 portent `goos`/`goarch` ; un avis spécifique à une plateforme qui
   n'a pas ce champ reste une alerte (sûr), mais un champ erroné en amont retirerait une vraie
   alerte, et govulncheck lit les mêmes données (même source vuln.go.dev) : l'accord à 0 faux
   négatif ne protège pas contre une erreur commune.
2. **Les fat Mach-O ne sont vérifiés que contre moi-même.** Le conteneur vient de mon script et
   aucun oracle disponible ne lit toutes les tranches ; une disposition propre à `lipo`
   (alignement, `fat_arch_64`, tranches non Mach-O) n'est pas testée.
3. **La couverture « réel » dépend d'une seule version de chaque chaîne d'outils.** Go 1.24.7 et
   cargo-auditable 0.7.7 sur toutes les cibles ; le format par pointeurs et Mach-O Rust ne sont
   jamais sortis du fabriqué. Un changement de disposition dans une version future (comme
   l'octet de drapeaux 3 découvert ici, heureusement toléré) ne serait vu qu'en reconstruisant.

## `git diff --stat`

```text
$ git diff --name-only origin/main... | grep -v '^sbom/' | wc -l
0
$ git diff --stat sbom-s5-independent... | tail -1
 39 files changed, 3820 insertions(+), 156 deletions(-) (avant ce rapport)
```
