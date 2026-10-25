# Décisions du propriétaire avant publication

Ce fichier liste ce qui **n'est pas décidé** et ne doit pas l'être par un agent. Tant que ces
points sont ouverts, `package.json` reste `version: 0.0.0`, `private: true`, et la documentation
utilise le marqueur `<NOM-DU-PROJET>`. `scripts/extract.sh <répertoire> <nom>` produit la copie
autonome ; il ne publie rien et ne crée aucun fichier de licence.

## 1. Nom du projet

- À choisir : nom du dépôt, nom du paquet npm (`scripts/extract.sh` le reçoit en argument et le
  valide selon les règles npm), nom de la commande (aujourd'hui `sbom-scan`).
- Lié : l'**espace de noms du format** porte encore l'origine REA. Propriétés CycloneDX
  `rea-sbom:*`, outil `rea-sbom` dans les evidence (`reader.tool`), format d'index
  `rea-sbom-osv-index/2`. Les renommer est un **changement cassant** du format
  (`rea-sbom:format-version` à incrémenter, index à reconstruire) : à faire une seule fois, avec
  le nom définitif, ou à garder tel quel.
- Lié : les identifiants de règles synthétiques des tests ont été renommés `SYN-TEST-*` /
  `SYN-PLAT-*` (S7) ; rien d'autre ne dépend du nom.

## 2. Licence

- **Aucun fichier `LICENSE` n'existe dans ce répertoire**, volontairement. Sans licence explicite,
  le code n'est réutilisable par personne d'autre que son auteur.
- REA, dont ce répertoire est issu (fork), est sous **licence MIT** (`LICENSE` à la racine de REA :
  « MIT License, Copyright (c) 2026 morluto »). Le code de `lib/` a été écrit pour ce répertoire ;
  `NOTICE.md` décrit chaque source lue pour comprendre les formats, sa licence et ce qui en a été
  retenu, ainsi que les fichiers de ce répertoire dont l'origine est REA ou un tiers (sorties REA
  enregistrées, schémas CycloneDX, enregistrements OSV).
- Points à trancher : licence choisie ; conservation de la mention MIT de REA pour ce qui en
  provient (au minimum les sorties enregistrées `baseline/raw/` et l'historique des rapports, qui
  décrivent REA) ; compatibilité avec les licences des données embarquées en test (OSV :
  CC-BY 4.0 et licences par source ; schémas CycloneDX : Apache-2.0, voir `schemas/README.md`).

## 3. Dépôt cible

- Hébergement, organisation, visibilité (public / privé).
- Historique : `scripts/extract.sh` copie **sans historique git**. Garder l'historique (filtrage
  de l'historique de ce fork sur `sbom/`) est une autre option, qui emporterait les commits
  REA touchant `sbom/` et leurs auteurs.
- Oracle REA : dans la copie autonome il est optionnel (`SBOM_REA_ROOT`, voir `oracle/rea.mjs`) ;
  le garder, le documenter comme outil de développement, ou le supprimer avec
  `test/differential/`, `scripts/run_rea.mjs`, `scripts/measure_baseline.mjs`,
  `scripts/measure_s2.mjs` et `baseline/raw/` (ce dernier est lu par
  `test/binary-adapters.test.mjs`, qui serait à adapter).
- Rapports de session (`S*_REPORT.md`, `BASELINE.md`, `PROBE*.md`, `FINDINGS.md`) : historique
  qui parle de REA ; les garder, les déplacer (`docs/history/`) ou les retirer.

## 4. Politique de sécurité

- Le scanner lit des fichiers potentiellement hostiles. Les lecteurs sont bornés et testés
  (`test/resources.test.mjs`, `test/robustness.test.mjs`), mais **aucun bac à sable** n'isole le
  processus : à écrire dans la politique.
- À décider : canal de signalement (adresse, avis de sécurité de la forge), délai de réponse
  visé, versions maintenues, divulgation coordonnée, portée (lecteurs de formats, appariement
  OSV, `scripts/vulndb.mjs` qui télécharge des archives).
- Aucun fichier `SECURITY.md` n'est créé tant que ces points ne sont pas tranchés.

## 5. Processus de contribution

- À décider : acceptation des contributions externes, accord de contribution (DCO, CLA ou
  aucun), style de commit (ce fork utilise Conventional Commits), revue obligatoire, CI
  (`make sbom-test` sans réseau une fois le corpus construit ; construction du corpus avec
  réseau et chaînes d'outils Go, Rust, .NET, Python, Node).
- Formatage : dans REA, les fichiers étaient formatés par l'outil du dépôt parent (`oxfmt`, via
  son crochet de commit). La copie autonome **n'a aucune configuration de formatage** (rien n'a
  été copié depuis REA) : choisir un formateur et sa configuration.
- Politique de dépendances : aujourd'hui aucune dépendance à l'exécution ; dépendances de test
  épinglées (`package-lock.json`, `tools/package-lock.json`, `tools/requirements-build.txt`).
