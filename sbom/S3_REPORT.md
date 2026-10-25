# S3_REPORT — cas difficiles : .NET (NuGet) et PyInstaller (PyPI), en Node pur

Session S3, 2026-10-25, conteneur Linux x64 (Ubuntu 24.04), Node 24.22.1, SDK .NET 8.0.132 (apt),
Python 3.13.17, PyInstaller 6.10.0 (+ hooks-contrib 2024.8). Aucun appel à REA dans les nouveaux
adaptateurs. Chaque affirmation est marquée **[constaté]** (sortie de commande dans cette session)
ou **[supposé]** (raisonnement non vérifié).

## Critères de réussite

| Critère                                                             | Résultat                                                                                                                                                                                  |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make sbom-test` passe depuis un clone propre                       | **74 tests, 74 réussis, 0 échec, 0 sauté** ; durée totale 2 min 05 s (dont 24,2 s de tests) [constaté] (détail plus bas)                                                                  |
| .NET avec deps.json : précision = rappel = 100 % sur les 2 fixtures | **Atteint** : 1/1 et 2/2, confiance high [constaté]                                                                                                                                       |
| Variante .NET sans deps.json mesurée, résultat consigné tel quel    | `dotnet-json` 100 % / 100 % ; `dotnet-serilog` **0 % / 0 %** (repli : mauvaise version, voir plus bas) [constaté]                                                                         |
| PyInstaller : zéro version inventée                                 | **Atteint** : aucune version émise ne diffère de la vérité terrain, sur les 3 fixtures et sur le test hors corpus (0 version fausse sur 7 émises) [constaté]                              |
| PyInstaller : précision 100 % « partout »                           | **Atteint au sens PEP 440, pas au sens chaîne identique** : `py-requests` 80 % en strict (`certifi` : le code écrit `2023.07.22`, `pip freeze` donne `2023.7.22`), 100 % sinon [constaté] |
| PyInstaller : rappel 100 % sur `py-requests-meta`                   | **Atteint** : 5/5, confiance high [constaté]                                                                                                                                              |
| Rappel du spike sur `py-requests` et `py-yaml`                      | `py-requests` 4/5 strict (5/5 PEP 440), `py-yaml` 1/1 ; **hors corpus (`py-wide`) : 6/15 par bytecode seul** [constaté]                                                                   |
| Aucune modification hors `sbom/`                                    | Voir « `git diff --stat` » en fin de rapport                                                                                                                                              |
| Temps et RSS de chaque scan (`/usr/bin/time -v`) consignés          | Tableau « Mesures »                                                                                                                                                                       |

## Ce qui marche

| Livrable                                    | Où                                                                                                       | État                                                                                   |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Lecteur PE / métadonnées CLI (ECMA-335)     | `lib/readers/cli-metadata.mjs`                                                                           | écrit et validé dès la 1re tentative sur les 5 DLL du corpus [constaté]                |
| Adaptateur .NET                             | `lib/adapters/dotnet.mjs`                                                                                | deps.json (high) ; repli attributs (medium / low) ; DLL isolée ; répertoire            |
| Lecteur `marshal` (CPython 3.13)            | `lib/readers/marshal.mjs`                                                                                | comparé à `marshal.dumps` de CPython (scalaires, refs, grands entiers, code)           |
| Liaisons de noms d'un module 3.13           | `lib/readers/pybytecode.mjs`                                                                             | constante, chaîne `a = b = x`, `from .x import y`, auto-affectation, EXTENDED_ARG      |
| Lecteur PyInstaller (cookie, CArchive, PYZ) | `lib/readers/pyinstaller.mjs`                                                                            | 3 fixtures réelles + archives synthétiques                                             |
| Adaptateur PyInstaller                      | `lib/adapters/pyinstaller.mjs`, `lib/adapters/pypi-modules.mjs`                                          | dist-info (high) ; spike bytecode (low) ; stdlib retirée ; table module → distribution |
| purl `nuget`, `pypi`                        | `lib/purl.mjs`                                                                                           | règles ci-dessous                                                                      |
| Détection automatique                       | `lib/scan.mjs`                                                                                           | répertoire `.deps.json` / DLL managée / cookie MEI, en plus de Go, Rust, ASAR          |
| Données de référence                        | `data/stdlib-module-names-3.13.json`                                                                     | `sys.stdlib_module_names` de Python 3.13.17 (290 noms), `make stdlib-names`            |
| Mesures                                     | `scripts/measure_s3.mjs` → `s3/measurements.json` ; `scripts/experiment_py_wide.mjs` → `s3/py-wide.json` | `make sbom-measure-s3`                                                                 |
| Tests                                       | `test/dotnet`, `pyinstaller`, `s3-corpus`, `robustness`                                                  | 35 nouveaux tests node:test (74 au total avec S2)                                      |

### Commandes

```sh
cd sbom
make sbom-test                       # Go/Rust/npm/.NET/PyInstaller + REA (pour les tests S2) + tests
make sbom-measure-s3                 # précision / rappel / temps / RSS .NET + PyInstaller
bin/sbom-scan corpus/out/dotnet-serilog                       --format cyclonedx   # répertoire de publication
bin/sbom-scan corpus/out/dotnet-json/Newtonsoft.Json.dll      --format cyclonedx   # DLL isolée
bin/sbom-scan corpus/out/py-requests-meta/py-requests-meta    --format cyclonedx   # exécutable PyInstaller
```

`make truth` et `make baseline` couvrent la nouvelle fixture `py-requests-meta` (une ligne dans
`scripts/fixtures.mjs`) ; `make corpus` la reconstruit.

## Décisions

### Vocabulaire de confiance

Go, Rust, npm (S2) gardent `observed` / `inferred`. NuGet et PyPI utilisent `high` / `medium` / `low`,
comme demandé. Les deux échelles coexistent dans le modèle (`lib/model.mjs`) ; en CycloneDX la confiance
numérique est `observed` 1, `inferred` 0,5, `high` 1, `medium` 0,6, `low` 0,3 : **un choix de
correspondance, pas une probabilité calibrée**. La propriété `rea-sbom:confidence` garde le mot.

### purl

- `nuget` : le nom garde sa casse d'origine, aussi dans le purl. **[constaté]** La suite de tests des purl
  livrée avec `packageurl-python` 0.17.5 (`tests/data/test-suite-data.json`) contient le cas « nuget names
  are case sensitive » : `pkg:Nuget/EnterpriseLibrary.Common@6.0.1304` →
  `pkg:nuget/EnterpriseLibrary.Common@6.0.1304` (seul le type passe en minuscules). Le texte de la
  spécification elle-même n'a pas été lu (GitHub brut non utilisé). L'appariement insensible à la casse
  est fait côté consommateur ; le modèle fusionne deux observations qui ne diffèrent que par la casse
  (`identityName`).
- `pypi` : minuscules et `_` → `-` (même règle que `normalize_name` de `packageurl-python`, cas « pypi
  names have special rules »). Les autres séparateurs PEP 503 (`.`, séries de `-`) ne sont **pas**
  touchés : `zope.interface` reste `zope.interface` dans le purl.
- `+` est encodé `%2B` comme en S2 (`pkg:nuget/Foo@1.0.0%2Bmeta`).

## .NET (NuGet)

### Source principale : `*.deps.json` (confiance high)

- Entrées de `libraries` de type `package` : nom et version viennent de la clé (`Serilog/3.1.1`, coupée
  au **dernier** `/`) ; `sha512` (hash du `.nupkg`), `path` et la clé complète vont dans l'evidence
  (`nupkgSha512`, `packagePath`, `library`), avec le sha256 du fichier deps.json.
- `project` : l'application dont le nom est celui du fichier (`dotnet-serilog.deps.json` →
  `dotnet-serilog/1.0.0`) devient la racine du scan (`metadata.component`), pas un composant. Les autres
  `project`, les `runtimepack` et les types inconnus sont des **exclusions** (visibles, pas perdues).
- Plusieurs deps.json (plugins) : tous lus, composants fusionnés (même identité, plusieurs preuves).
- Clé sans `/` ou sans version → unknown avec la raison. deps.json illisible ou JSON invalide →
  limitation + repli sur les DLL.
- Un deps.json utilisable exclut l'examen des DLL qu'il ne décrit pas (limitation notée dans le BOM).

### Repli sans deps.json (lecteur CLI maison, confiance medium / low)

Le lecteur a été écrit **dès la 1re tentative** (le plan « 2 tentatives puis non résolu » n'a pas servi).
Il lit PE → en-tête CLI → métadonnées (`BSJB`, `#~`, `#Strings`, `#Blob`) → tables (disposition de
toutes les tables 0x00–0x2C, index codés) → ligne `Assembly` + attributs personnalisés de l'assembly,
résolus par `MemberRef` → `TypeRef` (espace de noms + nom) et signature de constructeur `(string)`.
Mutations déterministes : 4 000 (lecteur CLI), 3 000 (marshal) et 6 000 (archive PyInstaller) pendant le
développement, 600 par lecteur dans la suite : aucune exception, seulement des erreurs typées (`not-pe`, `no-cli-header`, `malformed-cli-metadata`) [constaté].

Règles :

- Version = `AssemblyInformationalVersion`, à défaut `AssemblyFileVersion`. **`AssemblyVersion` n'est
  jamais utilisée** (version de liaison, pas de paquet : `Serilog` 3.1.1 → `2.0.0.0` [constaté]).
- **Suffixe de métadonnée de build après `+` retiré de la version (et donc du purl), conservé dans
  l'evidence** (`rawValue`, `buildMetadata`). Raison : SemVer ignore ce suffixe pour la précédence,
  c'est ce que NuGet affiche (`12.0.1+509643a…` → paquet `12.0.1`), et `%2B…` dans un purl empêche
  tout appariement. Le suffixe de pré-version (`-main-999d686d`) est, lui, **conservé** : le retirer
  serait une dérivation, pas une lecture.
- Une valeur qui n'est pas de la forme `n(.n){0,3}(-étiquette)?` (après retrait du `+`) est refusée
  (`rejected` dans l'evidence) et on passe au candidat suivant ; sans candidat : unknown.
- Confiance : **medium** pour une version informationnelle sans étiquette de pré-version ;
  **low** si elle porte une étiquette de pré-version ou si elle vient d'`AssemblyFileVersion` (écart
  par rapport à la consigne « medium pour le repli » : plus prudent, voulu, voir « Décisions à valider »).
- L'identifiant du paquet est **supposé égal au nom de l'assembly** (`nameSource: assembly-name` dans
  l'evidence). Faux pour un paquet qui livre plusieurs assemblies ou une assembly nommée autrement.
- Assembly avec point d'entrée (`EntryPointToken` non nul) = application = racine, pas composant. Assemblies
  satellites (culture non vide) et fichiers non gérés : ignorés.
- DLL isolée : une bibliothèque donne un composant (racine = le fichier) ; une application donne la racine seule.

### Mesures de précision / rappel

`sbom-scan --format cyclonedx` contre `truth/`, REA brut = `BASELINE.md` (S1). « Strict » = chaîne de
version identique.

| Cible                              | Vrais | Trouvés | Précision | Rappel  | REA brut  | Confiance |
| ---------------------------------- | ----- | ------- | --------- | ------- | --------- | --------- |
| dotnet-json (deps.json)            | 1     | 1       | 100 %     | 100 %   | 0 % / 0 % | high      |
| dotnet-serilog (deps.json)         | 2     | 2       | 100 %     | 100 %   | 0 % / 0 % | high      |
| dotnet-json, deps.json supprimé    | 1     | 1       | 100 %     | 100 %   | 0 % / 0 % | medium    |
| dotnet-serilog, deps.json supprimé | 2     | 2       | **0 %**   | **0 %** | 0 % / 0 % | low       |

Pourquoi le repli échoue sur Serilog **[constaté]** : les DLL portent
`AssemblyInformationalVersion` = `3.1.1-main-999d686d+999d686d1830…` (Serilog) et `5.0.1-main-33be844`
(Serilog.Sinks.Console) alors que les paquets NuGet sont `3.1.1` et `5.0.1`. L'étiquette `-main-<hash>`
est ajoutée par la CI de l'éditeur ; lue littéralement elle donne une **pré-version** (`3.1.1-main-…`
< `3.1.1` en SemVer), donc une version fausse que rien dans l'artefact ne permet de corriger. Newtonsoft.Json
(`12.0.1+509643a…`) donne la bonne version. Les deux composants Serilog sortent en confiance `low`, ce qui
est la seule protection : un consommateur qui ignore la confiance ferait remonter, par exemple, des CVE
corrigées en 3.1.1 [supposé : comportement des scanners non essayé].

Autres constats [constaté] : (1) l'`AssemblyInformationalVersion` de la DLL de l'application embarque le commit
git du dépôt (`+32c75b68…` = `git rev-parse HEAD` au moment du build, via SourceLink) : la DLL
applicative change à chaque commit, ce qui explique que `corpus/DIGESTS.txt` ne la vérifie plus ; les DLL
NuGet, copiées telles quelles, sont identiques. (2) `AssemblyFileVersion` de Newtonsoft est `12.0.1.22727` : un
repli sur cet attribut émettrait une version à quatre champs qui n'est pas celle du paquet.

## PyInstaller (PyPI)

### Format lu

Cookie `MEI\014\013\012\013\016` (88 octets, fin de fichier ; cherché dans le dernier Mio, le bootloader
embarque la même constante, seul un enregistrement cohérent est retenu), TOC CArchive (entrées `!iIIIBc` +
nom), entrées zlib, PYZ (`PYZ\0`, magic .pyc, position de la TOC, TOC marshal `(nom, (ispkg, pos, len))`,
modules = `zlib(marshal(code))`). **Vérifié uniquement sur PyInstaller 6.10 / CPython 3.13, onefile, Linux
x64** [constaté]. Le magic .pyc du PYZ est comparé à la liste des versions vérifiées (3571 = 3.13) ;
un autre numéro donne `unsupported-python-bytecode` (testé avec le magic de 3.12 : les dist-info sont
quand même lus, une limitation est notée, aucun composant bytecode) [constaté].

### Cas facile : `dist-info/METADATA` (confiance high)

`<nom>-<version>.dist-info/METADATA` (entrées `x` de la TOC, décompressées) : en-têtes `Name` et
`Version` lus avant la première ligne vide. Le `top_level.txt` voisin et le nom de distribution servent
à ne pas refaire un unknown pour un module déjà couvert. `py-requests-meta` : **5/5, 100 % / 100 %,
5 composants high, 0 unknown** [constaté].

### Cas dur : spike bytecode (confiance low)

Objectif : savoir si la version se lit littéralement dans le bytecode. **Oui, dans une partie des cas**
[constaté]. Méthode : le module racine de chaque paquet tiers est lu dans le PYZ ; un lecteur `marshal`
extrait ses constantes ; les instructions du code de module (3.13, numéros d'opcode de CPython 3.13.17,
mots de cache ignorés, EXTENDED_ARG replié) donnent les liaisons de noms. Une version est émise
seulement si `__version__`, `version` ou `VERSION` est liée à **une seule** constante chaîne, directement
ou par `from .sous_module import nom` à l'intérieur du paquet (profondeur ≤ 3 ; un import hors du
paquet, p. ex. `from importlib.metadata import version`, n'est pas suivi). Refus (→ unknown avec la raison)
quand : plusieurs liaisons du même nom sans constante unique (`try/except`), valeur calculée, constante non
chaîne, constantes contradictoires entre noms, chaîne qui n'est pas une version PEP 440, valeur « marqueur »
(`0`, `0.0.0`, `0.dev0+unknown`). Evidence : module, nom de constante, chaîne d'imports suivie, offset et
sha256 des octets du module dans le PYZ.

Résultats sur le corpus [constaté] :

| Cible                        | Vrais | Trouvés | Précision stricte | Rappel strict | Précision / rappel PEP 440 | REA brut          |
| ---------------------------- | ----- | ------- | ----------------- | ------------- | -------------------------- | ----------------- |
| py-requests-meta (dist-info) | 5     | 5       | 100 %             | 100 %         | 100 % / 100 %              | 100 % / 100 % (*) |
| py-requests (bytecode)       | 5     | 5       | **80 %**          | **80 %**      | 100 % / 100 %              | n/a / 0 %         |
| py-yaml (bytecode)           | 1     | 1       | 100 %             | 100 %         | 100 % / 100 %              | n/a / 0 %         |

(*) Le 100 % de REA brut sur `py-requests-meta` vient de l'inventaire de chemins : `measure_baseline.mjs`
lit `requests-2.31.0.dist-info` dans les noms de répertoires, REA ne décode pas METADATA [constaté dans
l'extracteur]. Notre lecteur lit le contenu (Name/Version), pas le nom du répertoire.

`py-requests`, trouvés par bytecode : `requests 2.31.0` (via `requests.__version__`), `urllib3 1.26.17`
(via `urllib3._version`, après avoir ignoré l'auto-affectation `__version__ = __version__`), `idna 3.4`
(via `idna.package_data`), `charset-normalizer 3.3.0` (via `charset_normalizer.version`), `certifi`
**`2023.07.22`** (constante du module racine). `pip freeze` donne `2023.7.22` : même version PEP 440,
orthographe différente. **La version émise est la chaîne lue** ; la mesure donne donc deux chiffres (strict,
et équivalence PEP 440 sans zéros de tête, appliquée uniquement dans la mesure, jamais aux valeurs émises).
`py-yaml` : `PyYAML 5.3.1` (`yaml.__version__`).

### Test hors corpus : `py-wide` (le bytecode, pas la table)

Les 5 modules de `py-requests` sont dans la table module → distribution, et la table comme les règles ont été
écrites en connaissant le corpus : le résultat ci-dessus ne prouve rien sur des paquets inconnus. Pour
le vérifier, `corpus/src/py-wide` (hors `make sbom-test` : `scripts/build_corpus.sh python_wide`, puis
`scripts/gen_truth.mjs py-wide` et `scripts/experiment_py_wide.mjs`) empaquette 16 distributions épinglées,
sans `--copy-metadata`. **Ce test est « hors corpus » pour la lecture du bytecode, pas pour la table** : la
table, écrite avant `py-wide`, contient déjà 9 de ses 16 modules (`attr`, `bs4`, `click`, `dateutil`, `dotenv`,
`jinja2`, `jwt`, `markupsafe`, `six`) ; 7 n'y sont pas.

| Sur 16 distributions                                                 | Nombre                                                                                                                                                                                  |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Versions émises exactes                                              | 7 (6 par bytecode, low : beautifulsoup4, click, Jinja2, MarkupSafe, PyJWT, six ; 1 par dist-info, high : attrs)                                                                         |
| Versions émises fausses                                              | **0**                                                                                                                                                                                   |
| Unknown                                                              | 9                                                                                                                                                                                       |
| … dont littéral correct vu mais non émis (module absent de la table) | 3 (colorama 0.4.6, pytz 2023.3, toml 0.10.2)                                                                                                                                            |
| … dont calculé / non lié / plusieurs liaisons                        | pyparsing, soupsieve (calculés), python-dateutil, tqdm (try/except), python-dotenv (version dans `dotenv/version.py`, non importée par la racine), typing_extensions (aucune constante) |
| Émis hors vérité terrain                                             | `typeguard 4.3.0`, `wheel 0.43.0` (high)                                                                                                                                                |

Rappel par bytecode seul : **6/15 (40 %)** émis ; 9/15 (60 %) si chaque module avait une entrée dans la table
(les 3 littéraux corrects de modules non tabulés sont visibles dans l'evidence des unknowns). Avec le
dist-info : 7/16 (44 %). Précision bytecode : 6/6. Sur les 9 modules tabulés avec lecture bytecode
(attrs est couvert par son dist-info), 6 réussissent, 2 échouent (`dateutil`, `dotenv`).
Les deux composants « hors vérité » sont de vrais `dist-info` présents dans l'exécutable (copiés par un
hook PyInstaller à cause du `setuptools` du venv de build ; `attrs` a été embarqué de la même façon sans
`--copy-metadata`) [constaté] : la vérité terrain `pip freeze` d'un venv sans outils de build ne les
contient pas. Une première version de `py-wide` listait `packaging==23.2`, que `requirements-build.txt`
remplace par 24.1 dans le venv de build : l'exécutable contenait 24.1, la vérité disait 23.2 [constaté] ;
`packaging` a été retiré de `py-wide`. La vérité terrain PyPI est donc **un `pip freeze` séparé, pas une
lecture de l'artefact**, et peut diverger de ce qu'il contient.

8 des 17 unknowns de `py-wide` sont des modules qui ne viennent d'aucune distribution de l'application
(`_distutils_hack`, `_sysconfigdata__x86_64-linux-gnu`, `backports`, `jaraco`, `packaging`, `pkg_resources`,
`setuptools`, `sitecustomize`) : le bruit de `setuptools` vendorisé est visible, pas filtré.

### Correspondance module → distribution

`lib/adapters/pypi-modules.mjs` : 35 paires courantes (identités explicites comprises : `requests` est
listé, pas déduit). Un module absent de la table reste un **unknown nommé par son module**, jamais par un
nom de distribution inventé ; si un littéral de version y a été lu, il figure dans `evidence.observedLiteral`
et jamais dans une version. Une distribution déjà décrite par un dist-info (par `top_level.txt`, par nom
normalisé identique au module, ou par nom de distribution de la table) ne produit pas d'unknown en double.

### Standard library

`data/stdlib-module-names-3.13.json` : `sys.stdlib_module_names` du Python 3.13.17 qui construit les
fixtures (290 noms). Les modules dont le premier segment est dans cette liste sont écartés ; les modules du
runtime PyInstaller (`pyimod*`, `_pyi_rth_utils`, `pyi_rth_*`) sont des exclusions [supposé : préfixes
non observés dans le PYZ des fixtures, repris de la nomenclature PyInstaller]. Sans liste enregistrée
pour la version de Python de l'archive, le chemin bytecode n'est pas tenté (les dist-info restent lus).

## Intégration

- `sbom-scan` détecte : répertoire avec `*.deps.json` ou DLL/EXE managé au premier niveau (→ NuGet),
  répertoire avec `node_modules` (→ npm, les deux si les deux), fichier PE avec en-tête CLI (→ NuGet),
  cookie MEI (→ PyPI), en plus de Go, Rust, ASAR. Un PE natif est `unsupported-artifact`. Un répertoire sans
  rien de reconnu garde le comportement S2 (npm vide).
- Export CycloneDX 1.6 : même forme qu'en S2. Techniques d'evidence : deps.json et dist-info
  `manifest-analysis`, attributs d'assembly et bytecode `binary-analysis`. **Versions inconnues** :
  `rea-sbom:unknown-component` (JSON : écosystème, nom, raison, emplacements) et `rea-sbom:unknown-count`,
  jamais dans `components`. Exclusions identiques listées une fois (correctif de `finalizeScan`).
- Déterminisme : deux exécutions, mêmes octets, vérifié pour chaque fixture S3, y compris les variantes sans
  deps.json et la DLL isolée ; schéma CycloneDX 1.6 validé sur chaque sortie (Ajv, schéma épinglé en S2) [constaté].
- Tests (35 nouveaux) : lecteur CLI (identité, attributs, offset de l'attribut dans le fichier, fichiers
  corrompus, PE natif construit à la main), deps.json synthétiques (types, clés, fusion insensible à la
  casse, JSON invalide), repli, DLL isolée ; `marshal` contre CPython ; liaisons de noms sur une dizaine de formes de code ;
  archives PyInstaller synthétiques (`test/support/make_pyinstaller.py`, construites avec CPython 3.13) :
  octets après le cookie, magic du bootloader, cookie ou TOC corrompus, magic .pyc de 3.12, version de Python sans
  liste ; fixtures réelles ; CLI de bout en bout ; mutations aléatoires déterministes.
  Les tests qui compilent du Python exigent Python 3.13 (échec, pas saut, sous `SBOM_REQUIRE_FIXTURES=1`).

## Mesures

`scripts/measure_s3.mjs`, `/usr/bin/time -v` (GNU), 5 exécutions par cible, `sbom-scan --format cyclonedx`
complet. « Froid » = 1re exécution de la série (cache disque non contrôlé), « chaud » = médiane des 4
suivantes. RSS = pic du processus. Brut dans `s3/measurements.json`. Tokens d'agent : non mesurés.

| Cible                          | Sortie CycloneDX | Froid : durée / CPU / RSS  | Chaud : durée / CPU / RSS  | REA brut (S1) : durée / RSS |
| ------------------------------ | ---------------- | -------------------------- | -------------------------- | --------------------------- |
| dotnet-json (deps.json)        | 3 442 o          | 0,06 s / 0,06 s / 54,1 Mio | 0,06 s / 0,06 s / 54,3 Mio | 4,4 s / 412 Mio             |
| dotnet-json, sans deps.json    | 4 028 o          | 0,07 s / 0,07 s / 57,5 Mio | 0,07 s / 0,07 s / 57,6 Mio | idem                        |
| dotnet-serilog (deps.json)     | 4 881 o          | 0,06 s / 0,06 s / 54,3 Mio | 0,06 s / 0,06 s / 54,3 Mio | 7,0 s / 417 Mio             |
| dotnet-serilog, sans deps.json | 5 581 o          | 0,09 s / 0,10 s / 58,7 Mio | 0,07 s / 0,08 s / 58,7 Mio | idem                        |
| py-requests-meta               | 9 558 o          | 0,11 s / 0,12 s / 58,5 Mio | 0,10 s / 0,10 s / 58,5 Mio | 3,1 s / 468 Mio             |
| py-requests                    | 9 990 o          | 0,10 s / 0,11 s / 58,9 Mio | 0,11 s / 0,11 s / 59,3 Mio | 2,8 s / 464 Mio             |
| py-yaml                        | 3 988 o          | 0,09 s / 0,10 s / 57,6 Mio | 0,09 s / 0,09 s / 57,6 Mio | 3,2 s / 458 Mio             |

Extrait brut `/usr/bin/time -v` [constaté] : `dotnet-serilog` — User 0,04 s, System 0,02 s, Elapsed
0:00.06, Maximum resident set size 55 524 kB, Exit status 0 ; `py-requests` — User 0,09 s, System 0,01 s,
Elapsed 0:00.09, Maximum resident set size 60 532 kB, Exit status 0. Le REA brut cumule les DLL pour
.NET (une exécution par DLL), un seul run, sans séparation froid/chaud (BASELINE.md). Les ~55–60 Mio sont
essentiellement le coût fixe de Node [supposé : non profilé, cohérent avec les 55 Mio de S2 pour npm].
Un scan lit les en-têtes, les métadonnées de la DLL ou quelques modules du PYZ : jamais le fichier entier en
mémoire, sauf le bloc de métadonnées CLI (plafonné à 256 Mio, valeur de garde).

## Depuis un clone propre

`git clone --branch sbom-s3-hard-cases` du dépôt local dans un répertoire vide, puis `cd sbom && make
sbom-test` [constaté] : fixtures Go / Rust / npm / .NET / PyInstaller construites, **11/11 empreintes
vérifiées identiques à `corpus/DIGESTS.txt`** (8 fixtures S2 + 3 DLL NuGet ; l'exécutable PyInstaller et la
DLL applicative .NET ne sont pas vérifiés, voir plus haut), REA construit, `npm ci` dans `sbom/`,
**74 tests, 74 réussis, 0 échec, 0 sauté**, durée totale **2 min 04,7 s** (`time make sbom-test` : réel 2:04.7, user 2:19, sys 0:35 ; tests seuls 24,2 s), `git status` du clone vide ensuite (aucun fichier suivi modifié).
Réserve : caches Go, cargo, npm, NuGet et pip déjà chauds dans ce conteneur ; une machine vierge sera plus
lente [supposé]. Installation des outils dans cette session : `nvm install 24.22.1`, `apt-get install
dotnet-sdk-8.0 time`, `cargo install cargo-auditable --locked` — réussis à la 1re tentative ; aucune
installation n'a échoué. Pendant `nvm install`, le proxy a refusé une connexion vers `iojs.org` (miroir
secondaire) sans conséquence [constaté].

## Limites constatées

- **Corpus minuscule** : 2 fixtures .NET, 3 PyInstaller (+1 hors corpus) ; les « 100 % » portent sur 3 et
  11 composants. Linux x64, PyInstaller 6.10, CPython 3.13, SDK .NET 8, un seul run de build.
- .NET : self-contained, single-file, ReadyToRun, `.exe` .NET Framework, Windows/macOS : **non testés**. Un
  publish self-contained sans deps.json listerait les assemblies du framework comme paquets [supposé].
  NuGet « runtime packs » de l'ancien `Microsoft.NETCore.App` 2.x listés comme `package` : non vus [supposé].
- .NET, repli : l'identité = nom d'assembly ; la version d'attribut n'est pas la version NuGet quand l'éditeur
  met une étiquette de pré-version ou une version de fichier à quatre champs (Serilog : 0 %).
- PyInstaller : onedir, PE et Mach-O, PyInstaller autre que 6.x, Python autre que 3.13 : **non testés**
  (les autres versions de Python sont refusées proprement pour le bytecode). Un paquet fait uniquement
  d'extensions n'est pas vu. Le bytecode ne dit rien d'un paquet dont la version est dans un module non
  importé par la racine (`dotenv`), calculée (`pyparsing`, `soupsieve`) ou dans un `try/except`
  (`dateutil`, `tqdm`).
- La version lue dans le code est celle que le paquet déclare, pas forcément celle de la distribution
  installée (orthographe différente : `certifi`) ; aucune vérification croisée dist-info ↔ bytecode.
- Les liaisons sont lues **sans modéliser le flot de contrôle** : une seule liaison dans une branche
  conditionnelle est acceptée.
- Les modules de `setuptools` vendorisé apparaissent comme unknowns (bruit) ; les dist-info de `typeguard` et
  `wheel` embarqués par un hook sont des composants high que `pip freeze` ne contient pas.
- Pas de graphe de dépendances, pas de consommation par un scanner de vulnérabilités, pas de mesure en tokens.
- Le BOM contient toujours le chemin de l'artefact tel que donné (déjà vrai en S2).

## Non résolu

- Aucun sous-problème bloqué : le lecteur CLI a abouti à la 1re tentative, le spike bytecode a répondu.
- **Rappel du spike hors corpus : 40 %.** Le rendre plus haut demande soit d'élargir la table (circulaire),
  soit de suivre plus de formes de code (`try/except`, `version.py` non importé), soit de modéliser le flot de
  contrôle : non fait, décision à prendre.
- **Orthographe PEP 440 de `certifi`** : tranchée dans le sens « lire littéralement » (voir ci-dessous).
- Le non-déterminisme de l'exécutable PyInstaller (deux sorties alternées, S1) n'est pas résolu et n'est pas
  de la responsabilité du scan : le scan est déterministe pour un fichier donné.

## Les trois choses les plus fragiles

1. **Le repli .NET émet une version fausse sans le savoir.** `3.1.1-main-999d686d` pour Serilog est lu
   fidèlement et rangé en `low`, mais le purl correspondant désigne une pré-version de 3.1.1 : tout consommateur
   qui n'utilise pas la confiance en tire des conclusions de vulnérabilité fausses. Même risque pour
   `AssemblyFileVersion` (4 champs) et pour « id = nom d'assembly ». Ce repli ne devrait pas alimenter un
   appariement CVE automatique ; il faut soit le sortir de `components` (unknown) quand il y a une étiquette
   de pré-version, soit laisser le consommateur filtrer sur `rea-sbom:confidence`.
2. **Le spike bytecode est collé à CPython 3.13 et à PyInstaller 6.x.** Numéros d'opcode, disposition des champs
   de l'objet code, magic 3571, format du cookie, de la TOC et du PYZ : tout est vérifié sur 4 exécutables
   réels et des archives synthétiques de ma fabrication (qui valident ma lecture du format, pas le format).
   Une nouvelle version de Python ou de PyInstaller change des octets sans prévenir ; le garde-fou est le magic
   .pyc (refus propre) et les contrôles de cohérence du cookie / de la TOC, pas une garantie. Et la table
   module → distribution, écrite en connaissant le corpus, gonfle le résultat : 6/15 (40 %) émis hors corpus,
   alors que même `py-wide` est partiellement couvert par elle.
3. **La vérité terrain et la mesure.** `pip freeze` d'un venv séparé n'est pas le contenu de l'exécutable
   (cas `packaging` 23.2 contre 24.1, dist-info vendorisés) ; la comparaison « strict / PEP 440 » est un choix
   de mesure ; 3 composants .NET et 11 PyPI ne permettent aucune conclusion statistique ; le `100 %` de
   `py-requests-meta` tient à ce que le hook `--copy-metadata` a été demandé pour exactement ces 5 distributions.

## Décisions à valider

- **Orthographe de la version PyPI** : émettre la chaîne lue (`2023.07.22`, choix actuel, précision stricte
  80 % sur `py-requests`) ou la forme canonique PEP 440 (`2023.7.22`, précision stricte 100 %, mais une valeur
  qui n'est plus lue littéralement). Un changement tient en une fonction.
- **Repli .NET** : `low` pour une pré-version ou `AssemblyFileVersion` (choix actuel, plus prudent que la
  consigne « medium »), ou `unknown` pour ces cas.
- Les unknowns de module non tabulé gardent le littéral observé en evidence ; à retirer si une evidence qui
  contient un numéro de version est jugée trop proche d'une émission.

## `git diff --stat`

Contrôle (sortie de session, rapport exclu) :

```text
$ git diff --name-only origin/main... | grep -v '^sbom/' | wc -l
0
$ git diff --stat sbom-s2-core... | tail -1
 47 files changed, 5044 insertions(+), 49 deletions(-)
```

Les 47 fichiers sont tous sous `sbom/` (`origin/main` n'a été récupéré qu'en fin de session : il n'y a pas de
branche locale `main`). `git diff --stat origin/main...` couvre S1 + S2 + S3 ; le détail fichier par fichier
est donné dans le message de fin de session.
