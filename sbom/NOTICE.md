# NOTICE — sources consultées pour les formats binaires (S5)

Les lecteurs `lib/readers/executable.mjs`, `gobuildinfo.mjs` et `cargoauditable.mjs` sont écrits
pour ce dépôt. **Aucun code n'a été importé ni recopié** depuis `src/` de REA ni depuis la
bibliothèque standard Go (`debug/buildinfo`, `debug/elf`, `debug/pe`, `debug/macho`), ni depuis
une autre implémentation. Ce fichier liste chaque source lue pendant la session S5 pour
comprendre un format, sa licence, et ce qui en a été retenu.

## Sources lues

| Source (fichier lu)                                                                                                                                                    | Licence           | Retenu                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `~/.cargo/registry/src/index.crates.io-*/cargo-auditable-0.7.7/README.md` (crate installé par `cargo install`)                                                         | MIT OR Apache-2.0 | Le JSON est compressé en zlib et placé dans une section de lien nommée `.dep-v0` ; ELF, PE et Mach-O sont pris en charge (WebAssembly aussi, non traité ici)                                                                                                                                    |
| `~/.cargo/registry/src/index.crates.io-*/auditable-serde-0.9.0/src/lib.rs`, **commentaires de documentation** (l. 25–125) des types `VersionInfo`, `Package`, `Source` | MIT OR Apache-2.0 | Champs `packages[]` (`name`, `version`, `source`, `kind`, `dependencies` = indices dans le tableau, `root`) et `format` ; valeurs par défaut quand un champ est omis (`kind` runtime, `dependencies` vide, `root` faux, `format` 0) ; signification des formats 0, 1, 8 ; un seul paquet racine |
| `sbom/baseline/raw/go-jwt.json.gz`, `rust-vuln.json.gz` (sorties JSON de REA enregistrées en S1)                                                                       | celle du dépôt    | **Sorties, pas code** : quels faits REA rapporte et leur sens observable (`module_location` = octets bruts du bloc modules, sentinelles comprises ; `format_version` = champ `format` du JSON ; `kind` laissé `null` quand omis). Sert de contrat pour le test différentiel                     |
| Octets des fixtures (`readelf -S`, `python3 zlib.decompress` sur `corpus/out/rust-vuln/rust-vuln`, `corpus/out/go-jwt*/`)                                              | —                 | Vérification de la disposition : `.go.buildinfo` (alignée 16, en-tête de 32 octets, drapeau 2 = inline), `.dep-v0` (166 octets zlib → 326 octets de JSON avec `"format":1`)                                                                                                                     |
| `sbom/lib/readers/cli-metadata.mjs` (S3, ce dépôt)                                                                                                                     | celle du dépôt    | Lecture d'en-tête PE déjà écrite en S3 (e_lfanew, COFF, en-tête optionnel PE32/PE32+, répertoires de données) ; déplacée dans `executable.mjs`, `cli-metadata.mjs` l'utilise désormais                                                                                                          |

## Connaissance préalable (aucun fichier lu pendant la session)

Les dispositions suivantes ont été écrites de mémoire, à partir des spécifications publiques que
je connaissais déjà, puis vérifiées sur les octets des fixtures et contre REA (test différentiel) :

- **ELF** (System V gABI) : `e_ident` (classe, ordre des octets), `e_shoff`, `e_shentsize`,
  `e_shnum`, `e_shstrndx`, numérotation étendue (section 0 : `sh_size`, `sh_link`), entrées de table
  de sections 32/64 bits, `SHT_NOBITS`.
- **PE/COFF** (spécification Microsoft) : en-tête de section (40 octets), noms longs `/<n>` dans la
  table de chaînes COFF, limite de 96 sections du chargeur Windows.
- **Mach-O** (disposition de `<mach-o/loader.h>`, `<mach-o/fat.h>`) : nombres magiques, en-têtes
  32/64, `LC_SEGMENT` / `LC_SEGMENT_64`, structures `section` / `section_64`, types zerofill,
  `fat_arch` / `fat_arch_64`.
- **Buildinfo Go** : marqueur `"\xff Go buildinf:"`, en-tête de 32 octets aligné sur 16 (taille de
  pointeur, drapeaux : bit 0 gros-boutien, bit 1 chaînes inline depuis Go 1.18), deux chaînes
  préfixées par un varint LEB128 non signé, sentinelles de 16 octets autour du bloc modules
  (utilisé seulement si l'octet avant la sentinelle finale est `\n`), lignes `path` / `mod` /
  `dep` / `=>` / `build`, emplacement (`.go.buildinfo`, `__go_buildinfo`, `.data` en PE).
  **Constat d'honnêteté** : cette connaissance vient à l'origine de la lecture, avant cette
  session, de la documentation et du code de la bibliothèque standard Go (BSD-3-Clause). Rien n'en
  a été relu ni copié pendant S5 ; le code de `gobuildinfo.mjs` est structuré différemment
  (Result typé, lignes inconnues conservées, recherche bornée).
- **Section cargo-auditable en Mach-O** (`__dep_v0`) : nom déjà utilisé comme marqueur en S2
  (`lib/scan.mjs`), non relu dans une source en S5 ; vérifié uniquement sur un Mach-O synthétique
  (aucun Mach-O réel construit, voir S5_REPORT.md).
