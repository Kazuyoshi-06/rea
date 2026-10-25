# S4_REPORT — appariement hors ligne aux vulnérabilités connues (OSV)

Session S4, 2026-10-25, conteneur Linux x64, Node 24.22.1, SDK .NET 8.0.132, Python 3.13.17,
osv-scanner 2.7.0, pip-audit 2.10.1, npm 11.19.1. Chaque affirmation est marquée
**[constaté]** (sortie de commande dans cette session) ou **[supposé]** (raisonnement non vérifié).

## Critères de réussite

| Critère                                                        | Résultat                                                                                                                                                  |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Partie A : `make sbom-test` vert                               | **105 tests, 105 réussis, 0 échec, 0 sauté** (dont 5 tests A5 et 5 tests de bornes sur la vraie snapshot), 23,9 s [constaté]                              |
| Test A5 (deux chemins, mêmes octets)                           | `test/path-independence.test.mjs` : Go, Rust, ASAR, .NET, PyInstaller, copiés dans deux répertoires (absolu / relatif) → mêmes octets [constaté]          |
| `PROBE_S4.md` dit ce qui est joignable                         | Oui : les 5 exports OSV, api.osv.dev, vuln.go.dev et les 3 points d'entrée du plan B répondent ; `api.deps.dev` bloqué (vu plus tard)                     |
| Précision / rappel par écosystème contre un oracle indépendant | Tableau « Oracles » : **100 % / 100 %** partout dans le périmètre du SBOM ; seul écart hors périmètre : devDependencies npm [constaté]                    |
| 0 alerte sur un composant sans version                         | Les unknowns ne sont jamais appariés (test sur les unknowns .NET contre un avis `introduced: 0`) ; chaque alerte pointe un composant versionné [constaté] |
| Tests de bornes verts                                          | ≥ 227 avis par écosystème, 4 690 vérifications, **0 échec** [constaté]                                                                                    |
| Temps de chargement de l'index, temps et RSS avec `--vulns`    | Tableau « Mesures »                                                                                                                                       |
| Aucune modification hors `sbom/`                               | `git diff --name-only origin/main... \| grep -v '^sbom/' \| wc -l` → `0` [constaté], voir fin de rapport                                                  |

## Partie A — décisions appliquées (commit séparé `refactor(sbom)!: …`)

- **A1 PyPI** : `version` et purl = forme normale PEP 440 (`lib/versions/pep440.mjs`, même sortie que
  `str(packaging.version.Version(s))` de packaging 26.3 sur les cas des tests [constaté]). La chaîne lue
  va dans `evidence.rawValue`. Version de dist-info non PEP 440 : émise telle quelle, `pep440: "invalid"`
  dans l'evidence, une limitation dans le BOM. Effet : `certifi` sort en `2023.7.22`, précision stricte de
  `py-requests` 80 % → **100 %** [constaté].
- **A2 .NET, repli sans deps.json** : pré-version ou `AssemblyFileVersion` → unknown avec la valeur
  candidate (`evidence.candidate`) ; seule une informationnelle propre reste un composant (`medium`).
  `dotnet-serilog` sans deps.json : 0 composant, 2 unknowns (`3.1.1-main-999d686d`, `5.0.1-main-33be844`)
  au lieu de 2 composants faux [constaté]. La racine (application) garde sa version lue.
- **A3** : versions bytecode toujours `low` (inchangé, vérifié par les tests S3).
- **A4** : une seule échelle `high` / `medium` / `low` (`observed` → `high`, `inferred` → `medium`),
  CycloneDX 1 / 0,6 / 0,3, propriété `rea-sbom:confidence` partout.
- **A5** : le BOM ne porte plus `rea-sbom:artifact-path` mais `rea-sbom:artifact-name` (nom de base) + le
  sha256 ; les occurrences sans emplacement propre utilisent aussi le nom de base. **Changement cassant**
  du format (signalé `!` + `BREAKING CHANGE`). Le modèle interne garde le chemin (il faut bien lire le
  fichier) ; seul l'exporteur décide de ce qui sort. Constat : REA (Go, Rust) ne fait remonter aucun chemin
  dans l'evidence, le test passe aussi pour eux.

## Partie B — ce qui marche

### B0 / B1 — snapshot et index

`make vulndb` (`scripts/vulndb.mjs`) télécharge les 5 exports (curl, 2 tentatives max, 1re réussie
partout), lit les ZIP en Node pur (`lib/readers/zip.mjs`, ZIP64 nécessaire pour npm : 230 777 entrées) et
écrit, par écosystème, `vulndb/index/<eco>.ndjson` (une ligne par paquet : id, alias, résumé, `modified`,
`withdrawn`, entrées `affected` réduites à ce paquet, versions corrigées) et `<eco>.dir` (en-tête JSON +
lignes triées `clé TAB offset TAB longueur`). `vulndb/SNAPSHOT.json` (commité) : URL, `Last-Modified`,
date de téléchargement, sha256, nombre d'avis par archive ; id de snapshot `osv-72f8333dd7306195` =
sha256 des sha256 d'archives. L'index refuse de servir s'il n'a pas été construit pour ce SNAPSHOT.json
(`vulndb-stale`).

| Archive   | Octets      | Avis    | dont withdrawn | Paquets indexés | Last-Modified (UTC) |
| --------- | ----------- | ------- | -------------- | --------------- | ------------------- |
| Go        | 12 594 328  | 9 779   | 182            | 1 662           | 2026-10-24 03:03:12 |
| crates.io | 3 654 719   | 2 969   | 124            | 1 682           | 2026-10-24 08:47:51 |
| npm       | 219 092 980 | 230 777 | 737            | 226 135         | 2026-10-25 15:32:59 |
| NuGet     | 2 676 989   | 1 965   | 41             | 1 393           | 2026-10-21 12:18:07 |
| PyPI      | 37 065 123  | 26 613  | 622            | 13 641          | 2026-10-25 11:33:01 |

[constaté] Construction de l'index : 20,7 s, 28,6 s CPU, **pic RSS 988 Mio** (l'archive npm entière en
mémoire). Index : 100 Mo sur disque, dont 58 Mo pour npm (222 805 des 230 777 avis npm sont des `MAL-`,
paquets malveillants).

### B2 — comparaison de versions (Node pur)

- `lib/versions/semver.mjs` : SemVer 2.0.0 (npm, crates.io, Go). Go : préfixe `v` exigé côté composant et
  retiré avant comparaison (les données OSV Go n'ont jamais de `v` [constaté sur l'export]) ; pseudo-versions
  = pré-versions ordinaires ; `+incompatible` = métadonnée de build, ignorée. Zéros de tête tolérés.
- `lib/versions/nuget.mjs` : 1 à 4 champs, champs manquants = 0, étiquette comparée comme SemVer 2 sans
  casse, `+…` ignoré.
- `lib/versions/pep440.mjs` : époques, pré/post/dev, local, orthographes alternatives ; ordre de
  `packaging` (séquence de référence de ses tests vérifiée contre packaging 26.3 [constaté]). Nombres en
  chaînes de chiffres (pas de perte au-delà de 2^53).
- `lib/vulns/osv.mjs` : plages SEMVER et ECOSYSTEM (événements `introduced`, `fixed`, `last_affected`,
  `limit`, triés puis rejoués), listes `versions` explicites (égalité au sens de l'écosystème), avis
  `withdrawn` ignorés. **GIT ignoré** : si l'entrée a une liste `versions` (cas PYSEC), la liste fait foi ;
  sinon la plage est rapportée comme non évaluée. Un événement ou une version non analysable rend la plage
  non évaluée (propriété `rea-sbom:vuln-unevaluated`), jamais devinée.

### B3 — appariement, et la stdlib Go

Seuls les composants sont appariés (les unknowns n'ont pas de version et ne passent même pas par le
matcher) ; un composant sans purl (crate git, etc.) est sauté et compté. Clé de recherche =
`identityName` du modèle (NuGet sans casse, PyPI PEP 503) : la même règle que la fusion des composants.

**Stdlib Go, constaté dans l'export** : 188 entrées `affected` nomment le paquet `stdlib` (purl OSV
`pkg:golang/stdlib`) et 34 `toolchain` (la commande `go`) ; versions sans `v`, bornes du type
`introduced: "1.16.0-0"`, `fixed: "1.16.1"` (le `-0` fait entrer les pré-versions de la branche). Le
composant Go `stdlib` (rôle `language-runtime`, version `1.24.7` tirée de `go1.24.7`) est donc apparié tel
quel au paquet `stdlib` ; `toolchain` n'est pas apparié (pas dans le binaire). osv-scanner fait pareil
(il nomme le composant `stdlib`, purl `pkg:golang/go@1.24.7`) [constaté]. Les symboles importés
(`ecosystem_specific.imports`) ne sont **pas** utilisés : pas d'analyse d'atteignabilité.

### B4 — sortie

`sbom-scan <artefact> --format cyclonedx --vulns [--db sbom/vulndb]` (`--db` sans `--vulns` = erreur
d'usage ; index absent ou périmé = code 1). Une entrée `vulnerabilities[]` par couple (avis OSV,
composant) : `id`, `source` OSV, alias en `references` (NVD, GitHub Advisory Database, OSV), `description`
(résumé), `recommendation` et `affects[].versions` (version du composant `affected`, versions corrigées
`unaffected`), `updated` (`modified` OSV), propriétés `rea-sbom:confidence` (héritée) et
`rea-sbom:matched-by` (`SEMVER`, `ECOSYSTEM` ou `versions`). Métadonnées : `rea-sbom:vulndb-snapshot`,
`rea-sbom:vulndb-archive` (date et sha256 par archive), `rea-sbom:vuln-count`,
`rea-sbom:vuln-unevaluated-count` / `-unevaluated`. Tri stable (id, composant). [constaté] Les 11
fixtures avec la vraie snapshot : schéma CycloneDX 1.6 épinglé valide (200 alertes au total), deux
exécutions = mêmes octets ; sous `unshare -n` (aucune interface réseau) la sortie est identique octet pour
octet pour Go, npm, PyPI et .NET.

### B5 — oracles indépendants (`make sbom-oracle` → `s4/oracle.json`)

Comparaison par **vulnérabilité** : sur un même paquet, deux constats sont la même vulnérabilité si
`{id} ∪ alias` se recoupent (les paires GO-/GHSA- et PYSEC-/GHSA- comptent une fois). « Périmètre SBOM » =
constats de l'oracle limités aux paquets présents dans notre SBOM.

| Écosystème | Oracle (entrée)                                                    | Nous | Oracle | Communs | Précision | Rappel     | Rappel (périmètre SBOM) |
| ---------- | ------------------------------------------------------------------ | ---- | ------ | ------- | --------- | ---------- | ----------------------- |
| Go         | osv-scanner `--x-plugins go/binary` sur les 2 binaires             | 123  | 123    | 123     | 100 %     | 100 %      | 100 %                   |
| crates.io  | osv-scanner `--x-plugins rust/cargoauditable` sur les 2 binaires   | 1    | 1      | 1       | 100 %     | 100 %      | 100 %                   |
| npm        | `npm audit --package-lock-only --omit=dev` (2 lockfiles)           | 6    | 6      | 6       | 100 %     | 100 %      | 100 %                   |
| npm        | osv-scanner `-L package-lock.json`                                 | 6    | 54     | 6       | 100 %     | **11,1 %** | 100 %                   |
| NuGet      | osv-scanner `--x-plugins dotnet/depsjson` (2 fixtures)             | 1    | 1      | 1       | 100 %     | 100 %      | 100 %                   |
| NuGet      | `dotnet list package --vulnerable --include-transitive` (restauré) | 1    | 1      | 1       | 100 %     | 100 %      | 100 %                   |
| NuGet      | idem, variantes **sans deps.json** (repli)                         | 1    | 1      | 1       | 100 %     | 100 %      | 100 %                   |
| PyPI       | osv-scanner `-L requirements.txt` (3 fixtures)                     | 33   | 33     | 33      | 100 %     | 100 %      | 100 %                   |
| PyPI       | pip-audit `-r --no-deps --disable-pip` (source PyPI)               | 33   | 33     | 33      | 100 %     | 100 %      | 100 %                   |

Go : 118 des 123 vulnérabilités sont de la stdlib 1.24.7 (59 par binaire) ; hors stdlib : jwt-go (1), x/text
(3), x/sys (1) [constaté]. Les 2 variantes .NET sans deps.json donnent la même chose que les fixtures
avec deps.json (Newtonsoft 12.0.1 en `medium`, Serilog en unknowns sans avis connu).

Aucun oracle n'a été « non exécuté ». Tous ont tourné avec réseau, contre la base de leur fournisseur **au
moment de l'exécution** (api.osv.dev, avis GitHub via npm, base PyPI, avis GitHub via nuget.org), donc pas
contre notre snapshot.

**Écarts, un par un** :

1. **npm-electron, osv-scanner sur le lockfile : 48 vulnérabilités de plus** (46 `electron`, 2
   `extract-zip`). Cause : périmètre. `electron` est une devDependency (et `extract-zip` une dépendance
   d'`electron`) : présentes dans `package-lock.json`, absentes de l'`app.asar` livré, donc absentes du
   SBOM. `npm audit --omit=dev` sur le même lockfile en trouve 5, les nôtres [constaté]. Pas une erreur de
   plage ni d'alias.
2. **Version de la base** : aucun écart observé. Notre snapshot date du jour (Last-Modified 2026-10-21 à
   2026-10-25) et les oracles ont interrogé leurs bases quelques minutes après. Un avis publié entre les
   deux apparaîtrait comme « seulement chez l'oracle » [supposé : non provoqué].
3. **Alias** : sans regroupement, nos comptes bruts sont plus hauts (65 entrées CycloneDX pour go-jwt
   contre 63 vulnérabilités ; 32 contre 16 pour py-requests) parce que l'export OSV contient les deux
   enregistrements d'une même vulnérabilité (GO-2020-0017 et GHSA-w73w-5m7g-f7qc, PYSEC-2023-212 et
   GHSA-g4mx-q9vg-27p4…) et que nous émettons un avis OSV par entrée. osv-scanner fait la même chose dans
   `vulnerabilities` et regroupe dans `groups` ; npm audit et `dotnet list` ne donnent que le GHSA. Le
   regroupement par alias est fait **dans la mesure**, pas dans le BOM (voir Limites).
4. **Plages** : aucun écart observé sur le corpus. Les plages des avis touchés sont simples
   (`introduced`/`fixed`, listes `versions` PyPI/NuGet).
5. **osv-scanner sur `requirements.txt`** : `api.deps.dev` étant bloqué, la résolution transitive a échoué
   (2 messages par fixture, enregistrés dans `s4/oracle.json`) ; les versions épinglées ont quand même été
   évaluées. Sans effet ici : les `requirements.txt` épinglent toute la fermeture.

**Vulnérabilités attendues du corpus S1 (écrites de mémoire dans `corpus/src`)** : toutes **confirmées
par les données** et présentes dans nos alertes [constaté] — jwt-go `CVE-2020-26160`, x/text
`CVE-2022-32149`, regex 1.5.4 `RUSTSEC-2022-0013` / `CVE-2022-24713`, Newtonsoft.Json 12.0.1
`GHSA-5crp-9r3c-p9vr` (aussi en repli sans deps.json), lodash 4.17.20 `CVE-2021-23337`, minimist 1.2.5
`CVE-2021-44906`, requests 2.31.0 `CVE-2024-35195`, urllib3 1.26.17 `CVE-2023-45803`, PyYAML 5.3.1
`CVE-2020-14343`. Les données en ajoutent beaucoup d'autres (ex. lodash : 5 avis, urllib3 : 9 vulnérabilités).

### B6 — tests

- **Hors ligne** (`test/vulns.test.mjs`, 15 tests, toujours exécutés) : plages (ordre des événements,
  plusieurs intervalles, `last_affected`, `limit`, `introduced: 0`), GIT avec et sans `versions`, versions
  non analysables, index (identité PEP 503 / NuGet, recherche dichotomique sur 5 000 clés, snapshot
  périmée refusée), matcher (confiance héritée, withdrawn, composant sans purl), CLI sur le corpus avec un
  index construit depuis `test/data/osv-mini/` (12 enregistrements OSV réels copiés + 7 synthétiques
  `REA-TEST-*`), unknowns jamais appariés. `test/versions.test.mjs` : SemVer, Go, NuGet, PEP 440.
- **Bornes sur la vraie snapshot** (`test/vulndb-bounds.test.mjs`, sautés sans `make vulndb`, vérifié avec
  un `SBOM_VULNDB` absent : 5 sautés) : avis à une seule plage `[introduced X, fixed Y]` pris dans l'index,
  300 répartis sur tout l'index par écosystème ; « juste avant Y » construit sur la chaîne (`Y-0` /
  `Y.dev0` et Y décrémenté), Y, « juste avant X ». [constaté] :

| Écosystème | Avis testés | Vérifications | dont « avant introduced » | Écartés | Échecs |
| ---------- | ----------- | ------------- | ------------------------- | ------- | ------ |
| Go         | 227         | 769           | 88                        | 73      | 0      |
| crates.io  | 289         | 983           | 116                       | 11      | 0      |
| npm        | 293         | 999           | 121                       | 7       | 0      |
| NuGet      | 299         | 983           | 86                        | 1       | 0      |
| PyPI       | 282         | 956           | 112                       | 18      | 0      |

Écartés = `fixed` qui n'est pas une version « simple » (pré-version, pseudo-version Go : 73 en Go) ou
`introduced` non analysable. Ces tests vérifient la cohérence du rejeu des plages ; la construction de
« juste avant » est indépendante du comparateur, le filtrage « ≥ introduced » ne l'est pas.

## Mesures

`make sbom-measure-s4` (`/usr/bin/time -v`, 5 exécutions, 1re = « froid » sans contrôle du cache disque,
médiane des 4 suivantes = « chaud »), brut dans `s4/measurements.json`. Tokens d'agent : non mesurés.

Chargement de l'index (lecture de `<eco>.dir` + une recherche, en processus) [constaté] : Go 0,6 ms,
crates.io 0,1 ms, **npm 12–14 ms** (fichier de 7,8 Mo), NuGet 0,3 ms, PyPI 1,7–2,4 ms. Une première
version (répertoire JSON de 8,7 Mo `JSON.parse`) coûtait **254–276 ms et +75 Mio** pour npm ; remplacée par
le fichier trié lu par dichotomie.

| Cible        | Alertes | Sans `--vulns` (chaud) : durée / CPU / RSS | Avec `--vulns` froid        | Avec `--vulns` chaud        | Index / appariement (chaud) |
| ------------ | ------- | ------------------------------------------ | --------------------------- | --------------------------- | --------------------------- |
| go-uuid      | 60      | 1,67 s / 2,21 s / 361,7 Mio                | 1,57 s / 2,10 s / 359,2 Mio | 1,63 s / 2,18 s / 361,2 Mio | 0 ms / 7 ms                 |
| go-jwt       | 65      | 1,56 s / 2,06 s / 362,2 Mio                | 1,58 s / 2,11 s / 362,3 Mio | 1,72 s / 2,21 s / 363,6 Mio | 0 ms / 7 ms                 |
| rust-vuln    | 2       | 1,78 s / 2,37 s / 359,6 Mio                | 1,66 s / 2,18 s / 356,0 Mio | 1,68 s / 2,21 s / 362,1 Mio | 0 ms / 2 ms                 |
| npm-cli      | 1       | 0,08 s / 0,07 s / 56,6 Mio                 | 0,09 s / 0,09 s / 70,0 Mio  | 0,08 s / 0,08 s / 70,2 Mio  | 13 ms / 15 ms               |
| npm-electron | 5       | 0,07 s / 0,07 s / 58,2 Mio                 | 0,09 s / 0,09 s / 70,5 Mio  | 0,09 s / 0,09 s / 70,5 Mio  | 12 ms / 14 ms               |
| dotnet-json  | 1       | 0,07 s / 0,07 s / 56,2 Mio                 | 0,07 s / 0,07 s / 56,4 Mio  | 0,09 s / 0,09 s / 56,5 Mio  | 0 ms / 2 ms                 |
| py-requests  | 32      | 0,11 s / 0,11 s / 59,8 Mio                 | 0,12 s / 0,13 s / 61,8 Mio  | 0,13 s / 0,14 s / 62,0 Mio  | 1 ms / 12 ms                |
| py-yaml      | 2       | 0,10 s / 0,10 s / 59,6 Mio                 | 0,10 s / 0,10 s / 59,0 Mio  | 0,11 s / 0,11 s / 59,1 Mio  | 1 ms / 4 ms                 |

(rust-small, dotnet-serilog, py-requests-meta : même ordre de grandeur, dans `s4/measurements.json`.)
Go et Rust sont dominés par l'appel à REA (S2), pas par `--vulns`. Coût de `--vulns` : ≤ 15 ms et +14 Mio
pour npm, ≤ 12 ms et +2 Mio pour PyPI, négligeable ailleurs [constaté].

Extraits bruts `/usr/bin/time -v` [constaté] : `sbom-scan corpus/out/py-requests/py-requests --vulns` —
User 0,12 s, System 0,03 s, Elapsed 0:00.13, Maximum resident set size 63 124 kB, Exit status 0 ;
`sbom-scan corpus/out/npm-cli/app.asar --vulns` — User 0,08 s, System 0,03 s, Elapsed 0:00.11, Maximum
resident set size 71 896 kB, Exit status 0.

## Limites constatées

- **Plages non évaluables dans la snapshot** (hors withdrawn) [constaté] : GIT sans liste `versions` :
  PyPI 7 entrées (1 528 autres GIT ont une liste et sont couvertes) ; événements non SemVer / non PEP 440 :
  Go 50 (`"0.8"`, `"1.99"` en ECOSYSTEM), crates.io 7, npm 12, PyPI 42 (`"2.9.0-NA"`,
  `"4.6.0.stable11"`), NuGet 0. Ils sortent en `rea-sbom:vuln-unevaluated` quand le paquet est présent,
  jamais en alerte. osv-scanner « coerce » probablement `"0.8"` en `0.8.0` [supposé] : écart possible sur
  ces avis.
- **Un avis par enregistrement OSV**, pas par vulnérabilité : GO-/GHSA- et PYSEC-/GHSA- apparaissent deux
  fois (les alias le montrent). Regrouper dans le BOM demanderait de choisir un identifiant « principal ».
- **Pas d'atteignabilité** : la stdlib Go donne 59 alertes pour un binaire de 2 dépendances ;
  `govulncheck` filtrerait par symboles appelés, nous non (osv-scanner non plus en mode binaire).
- **Pas de sévérité** (CVSS non recopiés), pas de `ratings`.
- Les alertes héritent des faiblesses d'identité : .NET en repli suppose « id NuGet = nom d'assembly » ;
  PyPI bytecode reste `low` et la version peut ne pas être celle de la distribution installée.
- Les avis `MAL-` (paquets malveillants) sont indexés et appariés comme les autres ; aucun n'a touché le
  corpus.
- `make vulndb` : 275 Mo téléchargés, 988 Mio de pic mémoire (archive npm lue en entier).
- La comparaison aux oracles porte sur **11 fixtures** (+2 variantes .NET) et 165 constats (vulnérabilité ×
  fixture), dont 118 de la stdlib Go : un corpus minuscule, choisi pour contenir des vulnérabilités connues.

## Non résolu

- Le regroupement par alias dans le BOM (décision de format).
- Les 118 plages à versions non standard : les ignorer (choix actuel, visible) ou les « coercer » comme
  le font d'autres outils.
- Aucune mise à jour incrémentale : `make vulndb` reconstruit tout.

## Les trois choses les plus fragiles

1. **La sémantique des plages, vérifiée surtout contre elle-même.** Les tests de bornes construisent des
   versions et rejouent les plages avec mon code ; seuls les oracles (11 fixtures) apportent un regard
   indépendant. Les cas qui divergeraient (pré-versions dans les plages npm, `last_affected` +
   pré-versions, `-0` des bornes Go, versions locales PEP 440) ne sont pas représentés dans le corpus.
2. **La dépendance au format des exports OSV.** Noms d'archives, `stdlib`/`toolchain` pour Go, Go sans
   `v`, GIT + `versions` pour PYSEC : constatés sur la snapshot du jour, pas garantis. Un changement de
   convention ferait taire des alertes sans erreur (pas d'alerte ≠ pas de vulnérabilité). L'index protège
   contre une snapshot périmée, pas contre un changement de sens.
3. **La confiance héritée est la seule défense contre une identité fausse.** Une alerte `low` (PyPI
   bytecode) ou `medium` (.NET repli) est aussi précise que le composant qu'elle vise ; un consommateur qui
   ignore `rea-sbom:confidence` traite 32 alertes `low` de py-requests comme certaines. Et un composant
   absent (devDependency, module non tabulé, unknown) ne produit aucune alerte : le rappel « 100 % » est
   mesuré dans le périmètre du SBOM.

## `git diff --stat`

```text
$ git diff --name-only origin/main... | grep -v '^sbom/' | wc -l
0
```

Le détail de `git diff --stat origin/main...` (S1 à S4) est donné dans le message de fin de session.
