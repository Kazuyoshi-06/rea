# Audit du fork REA — pistes de produit dérivé

Date : 2026-10-25 · HEAD audité : `25f0f99` (identique à `morluto/rea@25f0f99`) · version `rea-agents@6.8.0` (`package.json:4`).

Légende : **[C]** constaté dans le code ou par une commande lancée · **[M]** mesuré par moi (méthode indiquée) · **[S]** supposé / non prouvé.
Mode lecture seule : aucun fichier du projet modifié, à part la création de ce rapport. Mes scripts de mesure sont dans le scratchpad de la session, hors du dépôt.

---

## 0. Environnement

| Élément | Constat |
|---|---|
| `node -v` / `npm -v` au départ | `v22.22.0` / `10.9.4` **[C]**. C'est sous le plancher `engines` (`^22.23.4 \|\| ^24.22.1 \|\| >=26.12.1`, `package.json`). |
| Version attendue | `.nvmrc` = **`24.22.1`**, et non 24.18.x comme indiqué dans la consigne **[C]**. Une 24.18 serait d'ailleurs refusée par `engines`. |
| Correction | `nvm install 24.22.1` via `/opt/nvm` : **`v24.22.1` / npm `11.19.1`** **[C]**. `packageManager` épingle `npm@11.16.0` : petit écart de mineure, sans effet bloquant ici. |
| `npm ci` | OK du premier coup, 34 s, uniquement des avertissements de dépréciation (`prebuild-install`, `inflight`, `glob@7`) **[C]**. |

## 1. Architecture réelle

### Couches **[C]** (`docs/architecture.mermaid`, `AGENTS.md` « Architecture »)
Les dépendances vont vers l'intérieur. De l'intérieur vers l'extérieur :
`src/domain/` (pur) → `src/contracts/` (schémas zod vus par l'appelant) → adaptateurs fournisseurs (`src/ghidra`, `src/hopper`, `src/go`…) → `src/application/` (workflows partagés CLI/MCP) → `src/composition/` (factories) → `src/server/` (MCP) et `src/cli/` (CLI). Point d'entrée : `scripts/rea.mjs`, qui oriente vers `src/main.ts` (MCP stdio/HTTP) ou `src/cli.ts`.
Les frontières de modules sont vérifiées par `scripts/lib/module-boundaries.mjs` et `knip.json`.

### Taille par module **[M]** (`git ls-files` + `wc -l`, `.ts` hors tests / tests)
Total : **~500 k lignes de prod** et **~775 k lignes de tests** (2 492 fichiers `.test.ts`). 3 069 fichiers sous `src/`.

| Module | Prod | Tests | | Module | Prod | Tests |
|---|---:|---:|---|---|---:|---:|
| domain | 157 864 | 100 911 | | kuna | 8 363 | 0 |
| application | 79 811 | 62 384 | | hopper | 6 562 | 3 569 |
| browser | 31 539 | 23 826 | | javascript | 6 137 | 2 353 |
| native | 28 657 | 16 604 | | adb | 5 289 | 3 656 |
| artifacts | 24 315 | 15 276 | | ida | 5 015 | 8 400 |
| process | 17 341 | 20 999 | | il2cpp | 4 947 | **0** |
| ghidra | 15 529 | 15 695 | | android | 4 893 | 130 |
| server | 13 743 | 5 985 | | gdb / rizin / frida | 2 448 / 1 881 / 1 887 | **0 / 0 / 0** |
| contracts | 13 077 | 4 376 | | go / rust | 1 080 / 1 061 | 103 / 383 |
| cli | 12 179 | 0 | | dotnet | 10 557 | 7 395 |

Remarques critiques :
- `src/domain/` (158 k lignes, 350 entrées) n'a rien d'un petit noyau métier. On y trouve le navigateur, les scénarios, la sémantique JS (`domain/javascript/javascriptSemanticAnalysis.ts`, 2 380 lignes) **[C]**.
- Plusieurs modules n'ont aucun test unitaire colocalisé (kuna, il2cpp, gdb, rizin, frida, cli) **[C]**. Ils peuvent être couverts par `tests/acceptance|boundary` : **[S]**, je ne l'ai pas vérifié module par module.

### Points d'extension **[C]**
1. **Fournisseur d'analyse « profonde »** : interface `AnalysisProvider` (`src/application/AnalysisProvider.ts:276`, avec `identity`, `capabilities`, `resolveAnalysisProfile?` et `createClient`), sélection déterministe sans repli par `src/application/binary/AnalysisProviderRegistry.ts`, câblage dans `src/composition/binary.ts:63-66` (Hopper, Ghidra, IDA, Kuna).
2. **Outil MCP/CLI autonome** (lecteur de format) : contrat zod, service applicatif, provider, `register*Tool.ts` et entrée CLI.

### Comment ajouter un outil : coût réel **[C]**
Exemple en amont, `dba8a31 feat(elf): inspect Linux kernel module metadata` : **57 fichiers, +3 160 lignes**. Fichiers touchés :
- contrat : `src/contracts/native/binaryDiagnosticsToolContracts.ts` ;
- effets : `src/contracts/toolEffects.ts` (liste manuelle, ex. `toolEffects.ts:131`) ;
- domaine : `src/domain/native/kernelModule.ts` ;
- parser et provider : `src/native/elf/KernelModule*.ts` ;
- service : `src/application/binaryDiagnostics/KernelModuleService.ts` ;
- composition : `src/composition/binaryDiagnostics.ts` ;
- enregistrement : `src/server/registerKernelModuleTool.ts` et `src/server/createServer.ts` ;
- CLI : `src/cli/binaryDiagnosticsCommands.ts` et `src/cliCommandNames.ts` ;
- disponibilité : `src/application/CapabilityInventory.ts` ;
- catalogue : `scripts/lib/catalog-builders.mjs` ;
- tests : acceptance, boundary MCP et filesystem ;
- docs : **20 README traduits** (`docs/readme/README_*.md`, 22 fichiers).

La disponibilité repose sur des chaînes `if (name === "...")` maintenues à la main (`CapabilityInventory.ts:465-476`, `:550-560`). La composition tient dans une seule fonction de 1 324 lignes (`src/server/createServer.ts`). Les contrats sont pourtant typés et le code est discipliné. **Le coût marginal d'un outil reste élevé**, et c'est la première source de conflits de merge avec l'upstream.

## 2. Santé

| Vérification | Résultat |
|---|---|
| `npm run check:fast` (turbo : typecheck + lint) | **2/2 tâches OK, 39 s, rien en cache** **[C]** |
| Sous-ensemble de tests (`npm run test:local -- <22 fichiers>`) : `src/{apkSignature,erlang,go,gpu,python,rust}/**`, `application/{go,rust}`, `domain/{elfFixedHeader,peOptionalHeader}`, `contracts/{toolEffects,inputSchemaFitInvariants}` | **22 fichiers, 267 tests verts, 32 s** **[C]**. Points lents : `inputSchemaFitInvariants.test.ts` (15 s), `PythonPycParser.test.ts` (3,8 s). |
| Pas lancé (consigne) | Stryker, `check:pr`, build, voies réelles (Ghidra/Hopper/IDA…). **Aucune vérification avec un vrai fournisseur.** |

Note : `test:local` refuse un dossier et exige des chemins de fichiers exacts (« Expected an exact repository test path ») **[C]**.

### Dette technique visible
- **Hygiène très élevée** : 0 `TODO/FIXME/HACK` dans `src/`, 3 échappements (`as any`, `@ts-ignore`, `eslint-disable`) dans tout le code de prod **[M]** (git grep). Ce n'est pas là que se trouve la dette.
- **Dette de surface** (la vraie) : **229 outils** exposés en permanence, sans aucun mécanisme de sous-ensemble ou de toolset **[C]**. Je n'ai trouvé aucune variable `REA_*TOOLS*` hormis le budget de temps `REA_MCP_TOOLS_LIST_BUDGET_MS` (`src/config/environment.ts:46`).
  - **[M]** (`zod.toJSONSchema` sur `TOOL_CONTRACTS`, ce qui approche le `tools/list` réel sans en être une mesure) : descriptions = **135 663 caractères** (≈ 34 k tokens à 4 car./token, **estimation**), schémas d'entrée complets = 813 Ko, schémas de sortie = **4,1 Mo**.
  - Le profil d'entrée « compact » plafonne chaque outil à 13 Kio (`src/config/mcpInputSchemaProfile.ts:11`). Le profil de sortie par défaut est `full` (`src/config/mcpOutputSchemaProfile.ts:14`).
  - Plus gros schéma d'entrée : `compare_web_captures` (154 Ko).
  - C'est en contradiction avec la priorité n°1 « tokens agent » d'`AGENTS.md`.
- **Surface Hopper calquée sur une GUI** : `current_address`, `goto_address`, `next_address`, `prev_address`, `current_document`… (`src/contracts/officialToolContracts.ts`, 41 outils `official-proxy`). Ce sont des concepts de curseur, mal adaptés à un agent.
- **Doublon d'adaptateur TShark** : `src/pcap/PcapProvider.ts` (1 087 lignes, `inspect_pcap_*`) et `src/captures/TsharkCaptureProvider.ts` (522 lignes, `inspect_packet_*`) utilisent le même binaire, avec la configuration partagée `REA_TSHARK_COMMAND` (`src/pcap/PcapConfiguration.ts:45`, importée depuis `TsharkCaptureProvider.ts:66`) **[C]**. Le README les présente comme deux lignes distinctes (« Recorded packets » et « Packet summaries »).
- **Incohérence de doc** : le nœud `KUNA` est défini deux fois dans `docs/architecture.mermaid:39` et `:42` **[C]**.
- **Vélocité upstream extrême** **[M]** (clone amont `--depth 3000` dans le scratchpad) : 3 978 commits dans la fenêtre récupérée, dont **776 le 2026-10-24**. 1 251 messages mentionnent un co-auteur IA (grep heuristique). Les principaux auteurs sont `morluto` (2 348) et `Kaoru0822` (356). Conséquence : **tout fork qui modifie le cœur sera impossible à rebaser en quelques jours** **[S, très probable]**.

### Couplage aux outils externes **[C]** (`src/application/CapabilityInventory.ts`, README « What you can analyze »)
| Outil | Rôle | Couplage |
|---|---|---|
| Hopper / Ghidra / IDA / Kuna | moteurs « profonds » des 41 `official-proxy` et 15 `enhanced` | BYO. Ghidra via `bridge/ghidra/*.java`, Hopper via `bridge/hopper_bridge.py`, IDA via `ida-pro-mcp` externe |
| pwntools 4.15.0 | `inspect_binary_layout`, `inspect_recorded_crash` | `REA_PWNTOOLS_PYTHON`, Linux x64 uniquement (`CapabilityInventory.ts:521-526`, `:574-579`) |
| WABT 1.0.42 | `inspect_wasm_artifact` | `REA_WABT_BIN_DIRECTORY` (`:542-548`) |
| JADX headless MCP 0.7.1 + JDK | 5 outils Android | `REA_JADX_MCP_JAR` (`:606`) |
| Apktool ≥ 2.7, adb, JEB | Android | `:611-631` |
| TShark 4.x + prlimit, sigrok-cli 0.7.2 | captures, signaux | Linux uniquement (`:528-540`) |
| Binwalk / Unblob | firmware | Linux |
| Wakaru | `recover_javascript_sources` | Linux x64 (`:514-519`) |
| Chrome/Playwright, Frida, GDB, Rizin, Cutter, objdump | runtime, debug | BYO |
| Outils Xcode (`otool`, `codesign`, `lipo`, `nm`, `vtool`) | `inspect_macho`, `inspect_signature`, `list_architectures` | `src/native/CommandRunner.ts:353-363` |

Asymétrie : PE et ELF sont lus en processus, alors que **Mach-O dépend des outils Xcode**, donc de macOS **[C]** (`MACHO_TARGET_OPERATIONS`, `CapabilityInventory.ts:229-236`).

## 3. Catalogue des outils (229, extrait de `TOOL_CONTRACTS`, `src/contracts/toolContracts.ts`) **[C]**

Marquage : ✅ = fonctionne **sans moteur externe** d'après `CapabilityInventory.ts` (`:401-405`, `:465-476`, `:550-560`, `kind === "application"` `:641`, `kind === "session"` `:661`).
Attention : beaucoup d'outils `session`/`application` sont « disponibles », mais échouent ou restent pauvres sans cible ouverte par un moteur (ex. `compare_functions`, `build_call_path`) **[S]**.

- **Réglages (2)** ✅ : `inspect_analysis_settings`, `update_analysis_settings`.
- **Moteur natif proxy (41)**, nécessitent Hopper, Ghidra, IDA ou Kuna avec une cible ouverte :
  - fonctions et types : `annotate_native_function`, `inspect_native_load_image`, `inspect_native_data_type`, `inspect_native_instruction`, `resolve_native_call_targets` ;
  - navigation par curseur : `address_name`, `current_address`, `current_procedure`, `current_document`, `goto_address`, `next_address`, `prev_address`, `procedure_address`, `resolve_containing_procedure` ;
  - commentaires et signets : `comment`, `inline_comment`, `set_comment`, `set_inline_comment`, `list_bookmarks`, `set_bookmark`, `unset_bookmark` ;
  - inventaires : `list_documents`, `list_names`, `list_procedures`, `list_segments`, `list_strings` ;
  - procédures : `procedure_assembly`, `procedure_callees`, `procedure_callers`, `procedure_info`, `procedure_references`, `procedure_pseudo_code`, `read_function_instructions` ;
  - octets et recherche : `search_bytes`, `read_bytes`, `address_to_file_offset`, `search_procedures`, `search_strings`, `xrefs` ;
  - renommage : `set_address_name`, `set_addresses_names`.
- **Natif enrichi (15)**, moteur requis : `inspect_native_dispatch_metadata`, `get_objc_classes`, `get_objc_protocols`, `batch_decompile`, `decompile_all`, `get_call_graph`, `analyze_swift_types`, `find_xrefs_to_name`, `binary_overview`, `analyze_function`, `inspect_native_api`, `trace_feature`, `trace_call_path`, `trace_native_ui_action`, `trace_native_values`.
- **macOS natif (8)**, Xcode ou LLDB : `observe_native_ui`, `capture_native_ui_scenario`, `observe_native_calls`, `inspect_macho`, `inspect_signature`, `inspect_plist`, `list_architectures`, `demangle_swift`.
- **Lecteurs natifs intégrés (10)** ✅ : `inspect_devicetree`, `inspect_pe_load_config`, `inspect_elf_notes`, `inspect_apple_ips`, `inspect_kernel_module`, `inspect_byte_entropy`, `inspect_pe_certificates`, `inspect_pe_imports`, `inspect_pe_resources`, `inspect_native_exports`.
  - Avec pwntools : `inspect_binary_layout`, `inspect_recorded_crash`.
- **Vue** ✅ : `inspect_analysis_view`.
- **Artefacts et formats (24)** :
  - intégrés ✅ : `inspect_artifact`, `extract_artifact`, `decode_interface_builder`, `inspect_keyed_archive`, `inspect_asset_catalog`, `trace_dylib_resolution`, `inspect_desktop_application`, `inspect_go_binary`, `inspect_il2cpp_metadata`, `inspect_model_artifact`, `inspect_gpu_code_objects`, `inspect_rust_binary`, `inspect_python_pyc`, `inspect_erlang_beam`, `inspect_apk_signature`, `inspect_electron_fuses` ;
  - Linux x64 : `inspect_evm_interface` ;
  - selon la version de Node : `inspect_sqlite_database` ;
  - WABT : `inspect_wasm_artifact`, `compare_wasm_interfaces` ;
  - TShark : `inspect_packet_fields`, `inspect_packet_capture` ;
  - sigrok : `inspect_signal_decoders`, `decode_signal_recording`.
- **.NET (7)** ✅ statique : `inspect_managed_artifact`, `inspect_managed_members`, `inspect_managed_native_boundaries`, `compare_managed_members`, `verify_managed_native_boundaries`, `import_managed_reconstruction`, `project_managed_application_graph`.
- **Android** :
  - JADX (5) : `inspect_android_package`, `search_android_classes`, `inspect_android_class`, `inspect_android_method`, `trace_android_references` ;
  - Apktool (2) : `inspect_apktool_client`, `decode_android_resources` ;
  - Flutter (2) ✅ : `identify_flutter_build`, `inspect_dart_aot` ;
  - JEB (4) : `inspect_jeb_client`, `open_jeb_project`, `list_jeb_units`, `decompile_jeb_item` ;
  - ADB (24) : `inspect_adb_client`, `list_adb_devices`, `inspect_adb_device`, `list_adb_packages`, `pull_adb_package`, `read_adb_logcat`, `inspect_adb_package`, `pull_adb_file`, `push_adb_file`, `capture_adb_screen`, `list_adb_processes`, `list_adb_directory`, `list_adb_features`, `list_adb_services`, `inspect_adb_display`, `inspect_adb_window`, `read_adb_setting`, `collect_adb_bugreport`, `resolve_adb_packages`, `install_adb_package`, `uninstall_adb_package`, `start_adb_app`, `start_adb_activity`, `stop_adb_app`.
- **Réseau et firmware** :
  - pcap (2) : `inspect_pcap_client`, `inspect_pcap_capture` ;
  - firmware (2) : `inspect_firmware_regions`, `extract_firmware`.
- **Web et navigateur (11)**, Chrome requis : `list_browser_targets`, `inspect_web_page`, `analyze_web_bundle`, `observe_web_session`, `discover_webmcp_tools`, `compare_web_captures`, `capture_web_screenshot`, `compare_web_screenshots`, `capture_browser_scenario`, `observe_web_execution`, `inspect_web_event_listeners`.
- **Electron et runtime JS (7)** : `list_electron_targets`, `inspect_electron_page`, `analyze_javascript_application` ✅, `reconcile_javascript_runtime`, `capture_electron_scenario`, `list_javascript_runtime_targets`, `observe_javascript_runtime`.
- **Workflows applicatifs (15)** ✅ sauf mention : `trace_application_feature`, `trace_javascript_semantics`, `compare_application_versions`, `compare_source_to_bundle`, `compare_javascript_export_shapes`, `build_reconstruction_obligation_ledger`, `evaluate_reconstruction_coverage`, `project_{android,apple,harmony}_application_graph`, `trace_web_source_location`, `trace_web_module_imports`, `export_web_scripts`, `inspect_web_network_capture`, `export_environment_bundle`, `recover_javascript_sources` (Wakaru).
- **Session et Evidence (23)** ✅ (voir la réserve plus haut) :
  - session et bundles : `open_binary`, `open_bundle_resources`, `close_binary`, `binary_session`, `export_evidence_bundle`, `import_evidence_bundle`, `get_evidence_bundle` ;
  - processus : `capture_process_scenario`, `compare_process_captures` ;
  - comparaisons : `compare_artifacts`, `match_native_functions`, `compare_functions`, `compare_bundles`, `find_changed_behavior` ;
  - traçage et vérification : `build_call_path`, `correlate_static_and_runtime`, `verify_reconstruction` ;
  - inconnues : `list_unknowns`, `record_unknown`, `update_unknown`, `verify_unknown_resolution` ;
  - navigation : `get_navigation_context`, `inspect_address_context`.
- **Consoles natives (12)** : `list_cutter_sessions`, `cutter_command`, `inspect_with_objdump`, `execute_rizin_command`, `{start,close}_gdb_session`, `gdb_console`, `gdb_session_status`, `{start,close}_rizin_debug_session`, `rizin_debug_command`, `rizin_debug_session_status`.
- **Frida (9)** : `list_frida_devices`, `list_frida_processes`, `start_frida_session`, `load_frida_script`, `resume_frida_session`, `unload_frida_script`, `frida_session_status`, `close_frida_session`, `instrument_with_frida`.

**Bilan sans moteur** : environ **60 outils** donnent un résultat utile avec Node seul. Ce sont les lecteurs PE, ELF, Go, Rust, .NET, PyInstaller, BEAM, GGUF, IL2CPP, GPU, APK-sig, Flutter, l'inventaire d'artefacts et l'analyse JS statique **[S, décompte manuel à partir des listes ci-dessus]**. Le cœur « décompilation » reste entièrement dépendant d'un moteur externe.

## 4. Lacunes, doublons, sorties pauvres

Lacunes **[C sauf mention]** :
- **Aucune notion de SBOM, purl, CVE ou OSV.** `git grep -i "cyclonedx|spdx|purl|sbom|vulnerab"` sur `src/` et `docs/` ne renvoie rien. Les occurrences « osv » sont des faux positifs (`macosVersion`, `src/application/Doctor.ts:119`).
- **Pas de lecteur intégré de la section dynamique ELF** (`DT_NEEDED`, `RPATH`, `SONAME`) dans `src/native/elf/`, qui ne contient que `ElfNoteParser` et `KernelModuleParser`. Cette information passe par pwntools (`inspect_binary_layout`) **[S, à confirmer dans la sortie pwntools]**.
- **PE `VS_VERSIONINFO` non décodé** : `inspect_pe_resources` renvoie l'arbre et les hashes, pas `FileVersion` ou `ProductName` (`src/contracts/native/binaryDiagnosticsToolContracts.ts:216-220`). Aucun `StringFileInfo` dans `src/native/pe/`.
- **Mach-O non portable** (outils Xcode, voir §2).
- **Pas d'empreinte de bibliothèques C/C++ liées statiquement** (OpenSSL, zlib, libcurl…), et ni YARA, ni capa, ni FLIRT (grep négatif).
- **Pas de manifestes JAR/Maven** (`pom.properties`) ni de `*.dist-info` Python, d'après le grep sur `src/artifacts` **[S, recherche non exhaustive]**.

Doublons et incohérences :
- Deux familles TShark (§2).
- Quatre consoles natives qui se recouvrent : Cutter, Rizin, Rizin-debug et GDB. `execute_rizin_command` et `cutter_command` sont des passe-plats de commandes brutes, avec une Evidence pauvre par nature.
- Trois façons de comparer des binaires : `compare_artifacts`, `match_native_functions` et `compare_functions`/`find_changed_behavior`.
- Mermaid : `KUNA` dupliqué.

Sorties pauvres :
- Les passe-plats bruts (`cutter_command`, `gdb_console`, `execute_rizin_command`) **[C, par nature du contrat]**.
- Les 41 outils de navigation curseur Hopper.
- Les sorties « complètes » énormes par défaut sur le web (`compare_web_captures`). Le projet est conscient du problème : commits récents `5a22ae6 fix(mcp)!: return a compact binary_session status by default`, `fc43e28 feat(browser): retain compact scenario summaries`.

## 5. Issues ouvertes

**Non accessibles dans cette session.** Le fork `Kazuyoshi-06/rea` a **0 issue ouverte** (`list_issues`) **[C]**. L'upstream `morluto/rea` n'est disponible ici qu'en lecture git, l'API Issues n'est pas couverte. Les titres et l'état réels sont donc **NOT_ENOUGH_INFO**.

Proxy **[M]** : numéros d'issues les plus cités dans les messages de commit amont (`Fixes/Refs/Part of #N`), avec le thème déduit des sujets de commit. Le titre exact reste inconnu.

| # | Réf. | Thème déduit (commits) |
|---|---:|---|
| #1957 | 27 | Kuna : timeouts, scans de chaînes, rejouabilité (`fix(kuna)…` #4343, #4318, #4169) |
| #1065 | 14 | Démarrage Ghidra, cache de snapshots, perf mémoire |
| #6678 | 12 | Résolution `require`/membres JS, sortie version CLI |
| #5910 | 10 | Nommer budgets et deadlines (ASAR, web-bundle, JEB/IDA) |
| #6480 | 9 | Release et isolation de la publication npm, deps |
| #3403 | 7 | Propriété de la sélection TShark (`refactor(pcap)` #3407), lié au doublon §2 |
| #2016 | 7 | Mesures de perf (pcap, SQLite, Flutter) |
| #4027 | 6 | Annulation et cleanup Electron/JS |
| #6612 / #6676 / #6715 | 6 chacun | `createRequire`, PyInstaller PYZ, IL2CPP aliasing |
| #32, #48, #39 | — | Trackers plateforme, process/Hopper et navigateur (`docs/roadmap.md`) |

Scopes `fix(...)` les plus fréquents en amont **[M]** : javascript 294, native 162, browser 157, artifacts 122, process 104, ghidra 102, setup 100. **L'analyse JS et le navigateur concentrent l'instabilité.**

## 6. Cinq pistes de différenciation

### A. SBOM et exposition de binaires fermés (CycloneDX/SPDX, purl, OSV)
- **Ce que REA couvre déjà, honnêtement** : **les briques d'inventaire, pas le produit.**
  - Go : chemin, version et `sum` des modules (`src/domain/go/goBinary.ts:21-36`).
  - Rust : crates, versions, sources et arêtes via cargo-auditable (`src/rust/RustAuditableReader.ts`, schéma `packageSchema` l.24-31).
  - .NET : `AssemblyRef` (`src/dotnet/ManagedMetadataInventory.ts`).
  - Imports PE et imphash (`src/native/pe/PeImportParser.ts`, `pefileImphash.ts`), build-id ELF (`ElfNoteParser.ts`), certificats Authenticode et APK.
  - PyInstaller (version de Python, membres), classification `package.json` (`src/artifacts/javascript/JavaScriptArtifactFiles.ts:634`), build moteur Flutter.
  - **Absent** : agrégation multi-écosystèmes, purl, émission CycloneDX/SPDX, correspondance OSV ou CVE, empreinte des libs C statiques, `DT_NEEDED`, `VERSIONINFO`. **REA ne couvre pas l'idée.** Il en fournit environ 30 % des entrées, et ce sont les plus faciles (écosystèmes qui embarquent leurs métadonnées).
- **Valeur** : conformité CRA européenne et achats logiciels (SBOM de binaires tiers sans source), avec un récit d'Evidence et de provenance que syft et grype n'ont pas **[S, contexte marché]**.
- **À construire** :
  - un workflow `build_binary_sbom` (mapping vers purl `pkg:golang`, `pkg:cargo`, `pkg:nuget`, `pkg:pypi`, `pkg:npm`, sérialisation CycloneDX 1.6 et SPDX 2.3) ;
  - un matcher OSV hors-ligne (export zip épinglé, comparaison de versions par écosystème) ;
  - un lecteur `DT_NEEDED` et `VERSIONINFO` ;
  - plus tard, des empreintes de libs C.
- **Oracle** :
  - corpus de fixtures construites en CI avec une vérité terrain générée par l'outil natif (`go version -m`, `rust-audit-info`, lockfiles npm et NuGet) ;
  - précision et rappel des composants = 100 % sur Go et Rust ;
  - validation par les schémas JSON officiels CycloneDX 1.6 et SPDX ;
  - versions vulnérables épinglées détectées, version corrigée non signalée, exécution réseau coupé.
- **Effort** : 4 à 5 sessions pour un MVP Go, Rust, .NET, npm et OSV **[S]**. L'empreinte des libs C est un chantier à part (plusieurs semaines **[S]**).
- **Risques** : faux négatifs C/C++ (la majorité des binaires fermés) ; bruit des correspondances OSV (plages de versions, *backports*) ; concurrence directe avec syft, grype et cdxgen sur les binaires Go et Rust.

### B. « REA Lean » : MCP économe en tokens
- **Valeur** : 229 outils et environ 34 k tokens de descriptions, c'est un coût fixe pour chaque session agent (§2). Un serveur avec toolsets activables et un routeur à 5-10 méta-outils se distinguerait nettement.
- **Déjà là** : profils compacts d'entrée et de sortie (`mcpInputSchemaProfile.ts`, `mcpOutputSchemaProfile.ts`), `CapabilityInventory`, et un banc de mesure dans `experiments/analysis-efficiency/` (`agent-trial.py`).
- **À construire** : un filtre `REA_TOOLSETS` au moment de l'enregistrement (`createServer.ts`), un découpage en familles et un mode « découverte paresseuse ».
- **Oracle** : taille en octets et en tokens de `tools/list` (tokenizer fixe) ; taux de réussite identique sur un jeu de tâches fixe.
- **Effort** : 1 à 2 sessions **[S]**.
- **Risques** : piste facile à reprendre par l'upstream (faible fossé concurrentiel) ; conflits dans `createServer.ts`.

### C. Patch-diffing orienté avis de sécurité (« 1-day »)
- **Valeur** : à partir de deux versions d'un binaire, localiser la fonction corrigée et produire un rapport d'Evidence.
- **Déjà là** : `compare_artifacts`, `match_native_functions`, `compare_functions`, `find_changed_behavior` (contrats dans `src/contracts/sessionToolContracts.ts`) et des moteurs Ghidra/IDA.
- **À construire** : classement des fonctions modifiées par pertinence sécurité, heuristiques (bornes et vérifications ajoutées), sortie lisible.
- **Oracle** : paires de versions OSS avant et après un correctif CVE connu (commit de correctif = vérité terrain) ; la fonction corrigée doit figurer dans le top-k.
- **Effort** : 4 à 6 sessions **[S]**.
- **Risques** : dépendance forte à Ghidra (lourd en CI) ; résultats bruités sur les binaires optimisés ou strippés ; concurrence de BinDiff et Diaphora.

### D. Vérificateur de provenance et d'intégrité de distribution
- **Valeur** : vérifier signatures, build-id, empreintes et reproductibilité des artefacts livrés, avec une sortie in-toto/SLSA.
- **Déjà là** : Authenticode (`src/native/pe/PeCertificateParser.ts`), APK v1-v3.1 (`src/apkSignature/`), `inspect_signature` (macOS), fusibles Electron, digests d'artefacts (`src/domain/artifactIntegrity.ts`).
- **À construire** : politique de vérification déclarative, chaînes de confiance, attestation de sortie.
- **Oracle** : fixtures signées, re-signées et altérées (1 octet modifié) ; verdict attendu déterministe.
- **Effort** : 3 sessions **[S]**.
- **Risques** : marché étroit ; validation X.509 complète (révocation, horodatage) coûteuse.

### E. Triage de firmware IoT (extraction, inventaire, exposition)
- **Valeur** : à partir d'une image firmware, produire la liste des binaires, de leurs composants et de leurs CVE.
- **Déjà là** : Binwalk et Unblob (`src/firmware/`), devicetree, lecteurs ELF, transmission vers l'analyse native.
- **À construire** : la piste A, plus l'empreinte BusyBox, OpenSSL et noyau (`.modinfo` déjà lu par `KernelModuleParser.ts`).
- **Oracle** : images OpenWrt publiques versionnées, dont la liste de paquets officielle sert de vérité terrain.
- **Effort** : piste A + 3 sessions **[S]**.
- **Risques** : dépend de Linux et d'outils externes ; dépend aussi de l'empreinte C (le point dur de A).

## 7. Recommandation

**Commencer par la piste A, réduite aux écosystèmes qui embarquent leurs métadonnées** (Go, Rust, .NET, npm/Electron, PyInstaller), avec une correspondance OSV hors-ligne. Raisons :
1. C'est la seule piste où REA apporte déjà des parseurs fiables et testés (tests Go et Rust verts ci-dessus), sans moteur externe : CI légère et oracle 100 % automatisable.
2. Le fossé concurrentiel est réel : l'Evidence et la provenance par composant (`src/domain/evidence.ts`) et l'exposition MCP n'existent pas dans syft ou grype **[S]**.
3. Elle prépare naturellement E (firmware), puis C.

**Contrainte d'architecture, la plus importante** : vu la vélocité amont (§2), **ne pas modifier le cœur**. Construire le produit comme **un paquet séparé** qui consomme REA par son CLI JSON (ex. `src/cli/goCommands.ts`) ou par MCP. Le fork ne devrait porter que des ajouts isolés (nouveaux lecteurs `DT_NEEDED` et `VERSIONINFO`), proposables en PR amont. `createServer.ts` et `CapabilityInventory.ts` restent intacts.

### Découpage en sessions cloud autonomes
| # | Objectif | Critère de réussite vérifiable |
|---|---|---|
| S1 | Corpus de vérité terrain : Dockerfile/CI qui compile 10 à 15 fixtures (Go, Rust `cargo auditable`, .NET, npm/Electron, PyInstaller) avec dépendances épinglées, dont certaines vulnérables, et génère `truth/*.json` à partir de l'outil natif | `make corpus && make truth` est reproductible (digests identiques sur deux exécutions) ; au moins 1 fixture par écosystème |
| S2 | Paquet `rea-sbom` : appel de `rea` (go, rust), mapping purl, CycloneDX 1.6 avec propriétés d'Evidence (offset, digest) | CI : validation par le schéma officiel CycloneDX 1.6 (ajv) ; **précision = rappel = 100 %** sur les fixtures Go et Rust |
| S3 | Extension .NET, npm (ASAR / `node_modules/*/package.json`) et PyInstaller ; bibliothèques natives non versionnées marquées `unknown` | Rappel ≥ 95 % sur ces écosystèmes ; 0 composant inventé (précision 100 %) ; les inconnues sont explicites |
| S4 | Correspondance OSV hors-ligne (export zip épinglé par date, versions semver, NuGet, PEP 440) et section `vulnerabilities` CycloneDX | Exécution sans réseau ; les CVE attendues des fixtures sont détectées et les versions corrigées ne sont pas signalées (ex. `golang.org/x/text` < 0.3.8 / GO-2022-1059, `time` < 0.2.23 / RUSTSEC-2020-0071, **IDs à revérifier**) |
| S5 | Export SPDX 2.3, outil MCP `build_binary_sbom`, banc comparatif avec syft et grype sur le même corpus | Validation `pyspdxtools` ; tableau précision/rappel REA vs syft généré automatiquement en CI |

Une S6 optionnelle (lecteurs `DT_NEEDED` et `VERSIONINFO` dans le fork, en vue d'une PR amont) aurait pour critère : tests boundary MCP et CLI verts, et `check:fast` vert.

## Limites de cet audit
- Pas de build, pas de `tools/list` réel : les tailles de catalogue sont des approximations par `zod.toJSONSchema`.
- Aucun fournisseur réel lancé. Les tests ne couvrent que 22 fichiers sur 2 492.
- Issues amont inaccessibles par API.
- Les efforts sont des estimations **[S]**.
