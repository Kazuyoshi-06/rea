# OSV records for the Go platform filter (S6 B, `test/platform.test.mjs`)

- `GO-2026-5024.json` (golang.org/x/sys) and `GO-2026-6604.json` (stdlib): copied unchanged
  (re-indented, keys sorted) from the OSV Go export of snapshot `osv-5668560afe1cbc0d` (see
  `vulndb/SNAPSHOT.json`). Both restrict their vulnerable imports to `goos: ["windows"]`; S5 found
  them reported on Linux binaries. OSV data: https://osv.dev (CC-BY 4.0 / per-source licenses).
- `SYN-PLAT-*`: synthetic records (not real advisories) for the edge cases: a windows-only record
  whose alias twin has no platform information, `goarch` only, one restricted import next to an
  unrestricted one, `goos` and `goarch` on the same import.
