# Mini OSV corpus (offline tests)

Records in OSV JSON format used by `test/vulns.test.mjs` without the real snapshot.

- `GHSA-*`, `GO-*`, `RUSTSEC-*`, `PYSEC-*`: copied unchanged (re-indented, keys sorted) from the
  OSV exports of snapshot `osv-72f8333dd7306195` (see `vulndb/SNAPSHOT.json`); they cover the
  vulnerable packages of the S1 corpus. OSV data: https://osv.dev (CC-BY 4.0 / per-source licenses).
- `SYN-TEST-*`: synthetic records written for edge cases (several intervals, `last_affected`,
  `limit`, GIT ranges with and without `versions`, withdrawn, unparseable event, PEP 503 and NuGet
  case-insensitive names, Go `+incompatible` pseudo-version). They are not real advisories.
