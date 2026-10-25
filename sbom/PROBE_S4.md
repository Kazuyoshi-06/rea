# PROBE_S4 — joignabilité des sources de vulnérabilités (S4)

Sonde exécutée le 2026-10-25 depuis le conteneur de la session (proxy HTTPS de la session, curl).
Tout ce qui suit est **constaté** (code HTTP renvoyé), sauf mention contraire. Budget « 10 commandes
max » : 2 invocations shell, mais **11 requêtes HTTP** au total (une de plus que le budget, dite ici
plutôt que cachée) : 5 `GET` partiels (`-r 0-1023`), 5 `HEAD` sur les exports OSV, 1 `POST`.

## Résultat

| Source                                  | Requête                                                              | Code | Constat                                                                                   |
| --------------------------------------- | -------------------------------------------------------------------- | ---- | ----------------------------------------------------------------------------------------- |
| Export OSV Go                           | `HEAD https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip` | 200  | `content-length` 12 594 328, `last-modified` 2026-10-24 03:03:12 GMT ; `GET -r` → 206 zip |
| Export OSV crates.io                    | `HEAD …/crates.io/all.zip`                                           | 200  | 3 654 719 octets, 2026-10-24 08:47:51 GMT                                                 |
| Export OSV npm                          | `HEAD …/npm/all.zip`                                                 | 200  | 219 092 980 octets, 2026-10-25 15:32:59 GMT                                               |
| Export OSV NuGet                        | `HEAD …/NuGet/all.zip`                                               | 200  | 2 676 989 octets, 2026-10-21 12:18:07 GMT                                                 |
| Export OSV PyPI                         | `HEAD …/PyPI/all.zip`                                                | 200  | 37 065 123 octets, 2026-10-25 11:33:01 GMT                                                |
| API OSV                                 | `GET https://api.osv.dev/v1/vulns/GHSA-w73w-5m7g-f7qc`               | 200  | JSON (2 426 octets)                                                                       |
| Base Go officielle                      | `GET https://vuln.go.dev/index/db.json` (`-r 0-1023`)                | 206  | JSON (35 octets)                                                                          |
| PyPI (plan B : champ `vulnerabilities`) | `GET https://pypi.org/pypi/requests/2.19.0/json` (`-r 0-1023`)       | 206  | JSON ; le champ `vulnerabilities` n'a pas été lu (1 Kio seulement)                        |
| npm (plan B : avis en masse)            | `POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk`  | 200  | corps `{"lodash":["4.17.15"]}` ; réponse non examinée                                     |
| NuGet (plan B : index de service)       | `GET https://api.nuget.org/v3/index.json` (`-r 0-1023`)              | 206  | JSON ; la ressource `VulnerabilityInfo` n'a pas été cherchée dans l'index                 |

**Format attendu des exports, vérifié** : `<Écosystème>/all.zip` existe pour les cinq écosystèmes, avec
ces noms exacts (`Go`, `crates.io`, `npm`, `NuGet`, `PyPI`). Les archives ont ensuite été téléchargées
en entier (`make vulndb`, 1re tentative, aucune erreur) : un fichier JSON OSV par avis ; l'archive npm
est au format ZIP64 (230 777 entrées) [constaté à la lecture].

**Verdict : l'export OSV est joignable ; la partie B est implémentée.** Le plan B (pypi.org,
registry.npmjs.org, api.nuget.org) n'a pas servi.

## Constaté plus tard dans la session (hors sonde)

- `api.deps.dev` est **bloqué** par le proxy (`403 … no rule or allowlist entry allows host
  "api.deps.dev"`), vu dans les messages d'osv-scanner pendant B5 : osv-scanner ne résout pas les
  dépendances transitives des `requirements.txt`, mais apparie bien les versions épinglées.
- `proxy.golang.org` (go install d'osv-scanner) et `pypi.org` (pip install pip-audit, puis pip-audit
  lui-même) sont joignables ; `npm audit` (registry.npmjs.org) et `dotnet list package --vulnerable`
  (api.nuget.org) ont répondu.
