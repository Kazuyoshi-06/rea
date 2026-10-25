# PROBE — faisabilité de l'environnement (S1)

Sonde exécutée le 2026-10-25 sur le conteneur cloud de la session (Ubuntu 24.04.5 LTS, Linux x64).
Tout ce qui suit est **constaté** (sortie de commande), sauf mention contraire.

## Outils

| Outil           | Avant installation                         | Action                                                                                                                                                | Résultat                           |
| --------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| go              | go1.24.7 linux/amd64                       | —                                                                                                                                                     | OK                                 |
| rustc / cargo   | 1.97.0 / 1.97.0                            | —                                                                                                                                                     | OK                                 |
| cargo-auditable | absent (`no such command: auditable`)      | `cargo install cargo-auditable --locked` (1re tentative)                                                                                              | OK, v0.7.7                         |
| dotnet          | absent (`command not found`)               | 1) `dotnet-install.sh` depuis dot.net → `curl: (56) CONNECT tunnel failed, response 403` (proxy). 2) `apt-get install dotnet-sdk-8.0` (paquet Ubuntu) | OK, SDK 8.0.132                    |
| python3 / pip   | 3.13.17 / pip 24.0 (système)               | venv par fixture                                                                                                                                      | OK                                 |
| pyinstaller     | absent                                     | `pip install pyinstaller==6.10.0` dans un venv (1re tentative)                                                                                        | OK, 6.10.0                         |
| make            | GNU Make 4.3                               | —                                                                                                                                                     | OK                                 |
| node            | v22.22.0 sur PATH, `/opt/nvm` sans Node 24 | `nvm install 24.22.1` (1re tentative)                                                                                                                 | OK, v24.22.1 / npm 11.19.1         |
| GNU time        | absent                                     | `apt-get install time` (1re tentative)                                                                                                                | OK (`/usr/bin/time`, pour CPU/RSS) |

## Réseau (HTTP via le proxy de la session)

| Registre                  | URL testée                                                | Code             |
| ------------------------- | --------------------------------------------------------- | ---------------- |
| Go proxy                  | `https://proxy.golang.org/github.com/google/uuid/@v/list` | 200              |
| crates.io                 | `https://index.crates.io/config.json`                     | 200              |
| NuGet                     | `https://api.nuget.org/v3/index.json`                     | 200              |
| npm                       | `https://registry.npmjs.org/left-pad`                     | 200              |
| PyPI                      | `https://pypi.org/simple/requests/`                       | 200              |
| dot.net (installeur .NET) | `https://dot.net/v1/dotnet-install.sh`                    | **403 du proxy** |

## Verdict par écosystème

| Écosystème             | Statut             | Note                                                                                                                                                                                                                                                                                                |
| ---------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Go                     | FAISABLE           | build normal + strippé `-ldflags="-s -w"`                                                                                                                                                                                                                                                           |
| Rust (cargo-auditable) | FAISABLE           |                                                                                                                                                                                                                                                                                                     |
| .NET                   | FAISABLE           | SDK 8 via apt Ubuntu (l'installeur officiel est bloqué) ; `dotnet publish` framework-dependent                                                                                                                                                                                                      |
| npm / Electron         | FAISABLE (partiel) | ASAR construit avec `@electron/asar` 3.2.17. **Le runtime Electron n'est pas téléchargé** (devDependency, jamais empaquetée dans l'ASAR) : la fixture est l'archive `app.asar`, pas une application Electron complète. Le téléchargement des binaires Electron (GitHub releases) n'a pas été testé. |
| PyInstaller            | FAISABLE           | onefile Linux, Python 3.13 système                                                                                                                                                                                                                                                                  |

Aucun écosystème en SKIP.

## Hors périmètre de la sonde

- Windows / macOS (PE natifs, Mach-O, single-file .NET, Electron empaqueté) : non testés (Linux x64 uniquement).
- `/usr/bin/time` mesure le processus CLI REA ; les enfants éventuels sont comptés selon `wait4` (pic du plus gros, pas la somme).
