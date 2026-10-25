# BASELINE — ce que REA (brut) sort réellement

Généré par `sbom/scripts/measure_baseline.mjs` (`make baseline`). Ne pas éditer à la main.

Correspondance stricte sur (nom normalisé, version exacte). « Trouvé » = identité de composant
avec un champ version dans la sortie REA ; chemins de fichiers et noms de modules ne comptent pas
(voir _signaux nom seul_). Rappel nom seul = part des composants vrais dont le nom apparaît comme
composant REA, quelle que soit la version.

## Par écosystème (micro-moyenne)

| Écosystème | Fixtures | Vrais | Trouvés | VP  | Précision | Rappel |
| ---------- | -------- | ----- | ------- | --- | --------- | ------ |
| golang     | 4        | 10    | 10      | 10  | 100%      | 100%   |
| cargo      | 2        | 7     | 13      | 7   | 54%       | 100%   |
| nuget      | 2        | 3     | 3       | 0   | 0%        | 0%     |
| npm        | 2        | 9     | 9       | 9   | 100%      | 100%   |
| pypi       | 3        | 11    | 5       | 5   | 100%      | 45%    |

## Par fixture

| Fixture          | Commande REA                         | Vrais | Trouvés | VP  | Manquants | En trop | Précision | Rappel | Rappel nom seul | Sortie    | Durée   | CPU     | RSS max |
| ---------------- | ------------------------------------ | ----- | ------- | --- | --------- | ------- | --------- | ------ | --------------- | --------- | ------- | ------- | ------- |
| go-uuid          | `rea inspect-go-binary`              | 3     | 3       | 3   | 0         | 0       | 100%      | 100%   | 100%            | 4.3 KiB   | 1.8 s   | 2.3 s   | 358 MiB |
| go-uuid-stripped | `rea inspect-go-binary`              | 3     | 3       | 3   | 0         | 0       | 100%      | 100%   | 100%            | 4.4 KiB   | 1.8 s   | 2.4 s   | 358 MiB |
| go-jwt           | `rea inspect-go-binary`              | 2     | 2       | 2   | 0         | 0       | 100%      | 100%   | 100%            | 4.0 KiB   | 1.7 s   | 2.5 s   | 338 MiB |
| go-jwt-stripped  | `rea inspect-go-binary`              | 2     | 2       | 2   | 0         | 0       | 100%      | 100%   | 100%            | 4.0 KiB   | 1.7 s   | 2.2 s   | 357 MiB |
| rust-small       | `rea inspect-rust-binary`            | 5     | 10      | 5   | 0         | 5       | 50%       | 100%   | 100%            | 5.0 KiB   | 1.8 s   | 2.4 s   | 361 MiB |
| rust-vuln        | `rea inspect-rust-binary`            | 2     | 3       | 2   | 0         | 1       | 67%       | 100%   | 100%            | 3.8 KiB   | 2.0 s   | 2.6 s   | 364 MiB |
| dotnet-json      | `rea inspect-managed-artifact`       | 1     | 1       | 0   | 1         | 1       | 0%        | 0%     | 100%            | 457.3 KiB | 4.4 s   | 5.9 s   | 412 MiB |
| dotnet-serilog   | `rea inspect-managed-artifact`       | 2     | 2       | 0   | 2         | 2       | 0%        | 0%     | 100%            | 567.6 KiB | 7.0 s   | 9.4 s   | 417 MiB |
| npm-electron     | `rea analyze-javascript-application` | 2     | 2       | 2   | 0         | 0       | 100%      | 100%   | 100%            | 92.8 MiB  | 215.5 s | 248.2 s | 892 MiB |
| npm-cli          | `rea analyze-javascript-application` | 7     | 7       | 7   | 0         | 0       | 100%      | 100%   | 100%            | 14.0 MiB  | 11.3 s  | 15.3 s  | 489 MiB |
| py-requests      | `rea inspect-artifact`               | 5     | 0       | 0   | 5         | 0       | n/a       | 0%     | 0%              | 406.5 KiB | 2.8 s   | 3.9 s   | 464 MiB |
| py-yaml          | `rea inspect-artifact`               | 1     | 0       | 0   | 1         | 0       | n/a       | 0%     | 0%              | 281.1 KiB | 3.2 s   | 4.2 s   | 458 MiB |
| py-requests-meta | `rea inspect-artifact`               | 5     | 5       | 5   | 0         | 0       | 100%      | 100%   | 100%            | 460.5 KiB | 3.1 s   | 4.3 s   | 468 MiB |

Durée = temps mur du processus CLI (démarrage Node inclus), un seul run par cible, sans répétition ni séparation froid/chaud ;
CPU = user+sys et RSS max via `/usr/bin/time` (processus principal + enfants attendus, pic du plus gros). Pour .NET : somme/max sur toutes les DLL.

## Détail

### go-uuid

- Codes de sortie REA : 0
- Manquants : aucun
- En trop : aucun

### go-uuid-stripped

- Codes de sortie REA : 0
- Manquants : aucun
- En trop : aucun

### go-jwt

- Codes de sortie REA : 0
- Manquants : aucun
- En trop : aucun

### go-jwt-stripped

- Codes de sortie REA : 0
- Manquants : aucun
- En trop : aucun

### rust-small

- Codes de sortie REA : 0
- Manquants : aucun
- En trop :
  - `proc-macro2@1.0.107` — hors vérité terrain (kind=build)
  - `quote@1.0.47` — hors vérité terrain (kind=build)
  - `serde_derive@1.0.210` — hors vérité terrain (kind=build)
  - `syn@2.0.119` — hors vérité terrain (kind=build)
  - `unicode-ident@1.0.27` — hors vérité terrain (kind=build)

### rust-vuln

- Codes de sortie REA : 0
- Manquants : aucun
- En trop :
  - `autocfg@1.1.0` — hors vérité terrain (kind=build)

### dotnet-json

- Codes de sortie REA : 0, 0
- Manquants :
  - `Newtonsoft.Json@12.0.1` — version différente: REA=12.0.0.0 (assembly.version (AssemblyVersion)); "12.0.1" absent de la sortie brute
- En trop :
  - `Newtonsoft.Json@12.0.0.0` — nom attendu, version différente (assembly.version (AssemblyVersion))
- Signaux nom seul (non comptés) : `AssemblyRef System.Runtime 8.0.0.0`, `AssemblyRef System.Collections 8.0.0.0`, `AssemblyRef Newtonsoft.Json 12.0.0.0`, `AssemblyRef System.Console 8.0.0.0`

### dotnet-serilog

- Codes de sortie REA : 0, 0, 0
- Manquants :
  - `Serilog@3.1.1` — version différente: REA=2.0.0.0 (assembly.version (AssemblyVersion)); "3.1.1" absent de la sortie brute
  - `Serilog.Sinks.Console@5.0.1` — version différente: REA=5.0.1.0 (assembly.version (AssemblyVersion)); "5.0.1" absent de la sortie brute
- En trop :
  - `Serilog.Sinks.Console@5.0.1.0` — nom attendu, version différente (assembly.version (AssemblyVersion))
  - `Serilog@2.0.0.0` — nom attendu, version différente (assembly.version (AssemblyVersion))
- Signaux nom seul (non comptés) : `AssemblyRef System.Runtime 8.0.0.0`, `AssemblyRef Serilog 2.0.0.0`, `AssemblyRef Serilog.Sinks.Console 5.0.1.0`

### npm-electron

- Codes de sortie REA : 0
- Manquants : aucun
- En trop : aucun

### npm-cli

- Codes de sortie REA : 0
- Manquants : aucun
- En trop : aucun

### py-requests

- Codes de sortie REA : 0
- Manquants :
  - `certifi@2023.7.22` — aucun répertoire *.dist-info dans l'inventaire: pas de métadonnée de distribution (nom+version)
  - `charset-normalizer@3.3.0` — aucun répertoire *.dist-info dans l'inventaire: pas de métadonnée de distribution (nom+version)
  - `idna@3.4` — aucun répertoire *.dist-info dans l'inventaire: pas de métadonnée de distribution (nom+version)
  - `requests@2.31.0` — aucun répertoire *.dist-info dans l'inventaire: pas de métadonnée de distribution (nom+version)
  - `urllib3@1.26.17` — aucun répertoire *.dist-info dans l'inventaire: pas de métadonnée de distribution (nom+version)
- En trop : aucun
- Signaux nom seul (non comptés) : 78 modules de premier niveau dans PYZ-00.pyz, stdlib comprise ; nom normalisé identique à une distribution vraie : `certifi`, `charset_normalizer`, `idna`, `requests`, `urllib3`

### py-yaml

- Codes de sortie REA : 0
- Manquants :
  - `PyYAML@5.3.1` — aucun répertoire *.dist-info dans l'inventaire: pas de métadonnée de distribution (nom+version)
- En trop : aucun
- Signaux nom seul (non comptés) : 65 modules de premier niveau dans PYZ-00.pyz, stdlib comprise ; nom normalisé identique à une distribution vraie : aucun

### py-requests-meta

- Codes de sortie REA : 0
- Manquants : aucun
- En trop : aucun
- Signaux nom seul (non comptés) : 78 modules de premier niveau dans PYZ-00.pyz, stdlib comprise ; nom normalisé identique à une distribution vraie : `certifi`, `charset_normalizer`, `idna`, `requests`, `urllib3`
