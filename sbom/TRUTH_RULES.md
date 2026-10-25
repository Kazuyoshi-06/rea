# TRUTH_RULES — ce qui compte comme « composant présent dans l'artefact »

`sbom/truth/<fixture>.json` = liste `[{ecosystem, name, version}]` triée, sans doublon, générée par
`scripts/gen_truth.mjs` (`make truth`) avec l'outil natif de chaque écosystème. Règles communes :

- **Le composant racine** (module principal Go, crate racine, assembly de l'application, `package.json`
  racine, script PyInstaller) **n'est pas un composant**.
- **Les runtimes de langage ne sont pas comptés** en S1 : toolchain/stdlib Go, `std` Rust, runtime .NET,
  interpréteur CPython (`libpython3.13.so`), Electron. REA en expose certains (ex. `go_version`,
  `python_minor`, hash de commit rustc) : constatés mais hors comparaison.
- Identité = (écosystème, nom, version **exacte telle que publiée par le registre**). Aucune
  normalisation de version. Normalisation de nom uniquement selon la règle d'identité de l'écosystème :
  NuGet insensible à la casse, PyPI selon PEP 503 (`[-_.]+` → `-`, minuscules). Go, cargo, npm : exact.

## Go — `golang`

- Source : `go version -m <binaire construit>`, lignes `dep` ; si une ligne `=>` suit, la cible du
  `replace` remplace le module (aucun `replace` dans le corpus actuel).
- Compte : chaque module dont au moins un paquet est lié dans le binaire (c'est ce que l'éditeur de
  liens Go enregistre). Les modules seulement présents dans `go.sum` (ex. dépendances de tests de
  logrus : `go-spew`, `go-difflib`, `yaml.v3`, `testify`) ne comptent pas.
- Limite assumée : la vérité vient des métadonnées embarquées dans le binaire, lues par l'outil officiel ;
  ce n'est pas une vérité indépendante du binaire. Le binaire strippé `-s -w` garde ces métadonnées
  (constaté : vérité identique normal/strippé).

## Rust — `cargo`

- Source : `cargo tree --locked -e normal,no-proc-macro --target x86_64-unknown-linux-gnu --prefix none`
  sur le `Cargo.lock` épinglé.
- Compte : dépendances **normales** liées dans le binaire pour la cible.
- Ne compte pas : `[build-dependencies]` (ex. `autocfg`), `[dev-dependencies]` (ex. `itoa` de
  `rust-vuln`), crates **proc-macro** et leurs dépendances (`serde_derive`, `syn`, `quote`,
  `proc-macro2`, `unicode-ident`) : elles s'exécutent à la compilation, leur code n'est pas lié.

## .NET — `nuget`

- Source : `dotnet list package --include-transitive --format json` sur une copie restaurée en
  `--locked-mode` (`packages.lock.json` épinglé).
- Compte : paquets NuGet de premier niveau et transitifs, avec la **version du paquet NuGet**
  (`resolvedVersion`), pour `net8.0`.
- Ne compte pas : le framework partagé `Microsoft.NETCore.App` (runtime).
- Note : la version du paquet NuGet n'est pas l'`AssemblyVersion` de la DLL (voir BASELINE).
  La vérité reste la version du paquet, car c'est elle que référencent les bases de vulnérabilités.

## npm — `npm`

- Source : `package-lock.json` (lockfileVersion 3) du projet.
- Compte : chaque entrée `packages["…node_modules/<nom>"]` sans `"dev": true` — c'est exactement ce que
  `npm ci --omit=dev` installe dans le répertoire empaqueté dans `app.asar`.
- Ne compte pas : `devDependencies` (dont `electron`), le `package.json` racine.

## PyInstaller — `pypi`

- Source : `pip freeze` d'un venv propre contenant uniquement `requirements.txt` de la fixture
  (pas de PyInstaller ni de ses dépendances).
- Compte : la fermeture des distributions installées par `requirements.txt` (toutes épinglées).
- Ne compte pas : `pyinstaller`, `pyinstaller-hooks-contrib`, `altgraph`, `packaging`, `setuptools`,
  `pip` (outillage de build, `sbom/tools/requirements-build.txt`).
- Limite assumée : PyInstaller n'embarque que les modules atteints par l'analyse d'imports ; une
  distribution de la fermeture pourrait ne pas être embarquée. Dans le corpus, chaque distribution vraie
  a un module de premier niveau correspondant dans `PYZ-00.pyz` (constaté pour `py-requests`
  via l'inventaire REA ; pour `py-yaml`, le module embarqué s'appelle `yaml`).
