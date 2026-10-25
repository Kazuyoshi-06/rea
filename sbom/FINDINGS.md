# FINDINGS — S1 (analyse manuelle de BASELINE.md)

Chiffres : `BASELINE.md` (généré). Ici, chaque point est marqué **[constaté]** (observé dans une sortie
de commande) ou **[supposé]** (interprétation non vérifiée).

## Précision / rappel de REA brut par écosystème

| Écosystème                       | Lecteur REA                          | Précision      | Rappel | Commentaire                                                                 |
| -------------------------------- | ------------------------------------ | -------------- | ------ | --------------------------------------------------------------------------- |
| Go (4 fixtures dont 2 strippées) | `inspect-go-binary`                  | 100 %          | 100 %  | Strip `-s -w` sans effet [constaté]                                         |
| Rust (2)                         | `inspect-rust-binary`                | 54 %           | 100 %  | Les « en trop » sont tous `kind=build` (proc-macros, build-deps) [constaté] |
| .NET (2)                         | `inspect-managed-artifact` (par DLL) | 0 %            | 0 %    | Nom 100 %, version 0 % : AssemblyVersion ≠ version NuGet [constaté]         |
| npm / ASAR (2)                   | `analyze-javascript-application`     | 100 %          | 100 %  | Coût : 93 Mio de JSON, 205 s, 947 Mio RSS pour 2 paquets [constaté]         |
| PyInstaller (2)                  | `inspect-artifact`                   | n/a (0 trouvé) | 0 %    | Aucune métadonnée de distribution dans l'artefact [constaté]                |

## Constats

1. **.NET : la version NuGet n'est nulle part dans ce que REA décode.** [constaté]
   REA rend `assembly.version` = AssemblyVersion : `Serilog` 3.1.1 → `2.0.0.0`, `Newtonsoft.Json`
   12.0.1 → `12.0.0.0`, `Serilog.Sinks.Console` 5.0.1 → `5.0.1.0`. Le binaire contient pourtant
   `AssemblyInformationalVersion` (`3.1.1-main-999d686d+…`, `12.0.1+509643a…`) et `AssemblyFileVersion`
   (`3.1.1.0`, `12.0.1.22727`) (`strings -el`). REA liste bien ces attributs (`type_name`,
   `value_sha256`), mais `decoded_fixed_string` n'est rempli que pour `TargetFrameworkAttribute`.
   `*.deps.json` (versions NuGet exactes, à côté des DLL) n'est lu par aucune commande testée :
   `inspect-artifact` refuse un répertoire de publication (`directory_requires_file`). Lire `deps.json`
   comme fichier isolé n'a pas été testé.
   Conséquence [supposé] : un appariement CVE sur `assembly.version` donnerait des faux négatifs
   (Serilog 2.0.0.0) ou des faux positifs/négatifs selon le schéma de versionnement de chaque paquet.

2. **npm : la bonne réponse est noyée.** [constaté]
   Les 9 paquets sont exacts (nom + version depuis chaque `node_modules/*/package.json`), mais
   `analyze-javascript-application` fait une reconstruction sémantique complète : pour `npm-electron`
   (lodash + ms, ASAR de 1,7 Mio), ~97,3 Mo de JSON dont 4 119 octets de nœuds `package`
   (0,004 %), 205–230 s de temps mur sur 6 exécutions, ~240–250 s CPU, 892–947 Mio RSS (2 mesures). Pour `npm-cli`, 14,7 Mo dont 11 Ko utiles.
   `inspect-artifact` sur le même ASAR répond en ~3 s mais ne donne que des chemins
   (`node_modules/lodash/package.json`), sans version.
   Aucune option `--view` « packages » n'est proposée par `analyze-javascript-application` (seul
   `javascript-routes` est documenté dans `--help`).

3. **PyInstaller : 0 % parce que l'artefact ne porte pas l'information, pas parce que REA la rate.**
   [constaté] Ni l'inventaire REA ni `pyi-archive_viewer` ne montrent de `*.dist-info` : PyInstaller
   6.10 sans hook `copy_metadata` n'embarque pas les métadonnées de distribution. REA voit les modules
   de premier niveau (`requests`, `urllib3`, `certifi`, `idna`, `charset_normalizer`, `yaml`) mêlés à
   ~60 modules stdlib, sans version. La version n'existe plus que dans le bytecode (ex.
   `requests/__version__.pyc`) [supposé, non vérifié]. Le nom de distribution peut différer du module
   (`PyYAML` ↔ `yaml`) [constaté].

4. **Rust : REA restitue fidèlement cargo-auditable, y compris ce qui n'est pas lié.** [constaté]
   Les 6 « en trop » portent tous `kind=build` dans la sortie REA (serde_derive, syn, quote,
   proc-macro2, unicode-ident, autocfg) : un filtre `kind != build` donne 100/100 sur le corpus.
   La dev-dependency (`itoa` de rust-vuln) n'apparaît pas [constaté]. REA laisse `kind` à `null` quand
   il est omis dans la section, en documentant que le format le traite comme runtime.

5. **Go : la plus simple et la plus robuste.** [constaté] 100/100, binaires strippés compris
   (`-s -w` ne retire pas `.go.buildinfo`). Sources ici `go version -m` = même donnée embarquée : la
   vérité n'est pas indépendante du binaire (voir TRUTH_RULES.md).

6. **Coût fixe du CLI.** [constaté] ~1,6–2,0 s et 338–375 Mio RSS pour lire 4 Ko de métadonnées Go ou
   Rust. Le pic RSS est mesuré par `/usr/bin/time` sur le processus CLI ; la part démarrage vs analyse
   n'a pas été séparée.

7. **Reproductibilité.** [constaté] 19/21 fichiers identiques sur 3 builds ; les 2 binaires
   PyInstaller alternent entre deux sorties (nom de l'entrée libpython `libpython3.13.so.1.0` vs
   `libpython3.13.so`). Go demande `-buildvcs=false` (sinon `vcs.revision`/`vcs.modified` du dépôt
   hôte sont embarqués). Depuis un clone dans un autre chemin, il a fallu `PathMap` pour la DLL .NET
   de l'application et la suppression de répertoires de scope vides laissés par
   `npm ci --omit=dev` pour retrouver les mêmes octets. Aucune de ces variations n'a changé le résultat
   REA (précision/rappel identiques entre dépôt et clone).

## Ce qui n'a pas été mesuré

- Électron complet (runtime + ASAR), .NET single-file / self-contained / ReadyToRun, PE Windows,
  Mach-O, Go avec `replace`, cargo sans `cargo auditable`, PyInstaller onedir et avec `copy_metadata`.
- Coûts en tokens d'agent : non mesurés (seuls octets, temps, CPU, RSS).
- Une seule exécution par cible : pas de distinction froid/chaud ni de variance.
