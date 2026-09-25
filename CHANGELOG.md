# Changelog

## Sapper 1.0.1 (2026-09-25)

- Client commands accept `--addr` as `host:port`, the same form the server takes; `http://` is added when there is no scheme. Before, `--addr localhost:8089` failed with "unsupported protocol scheme".

## Sapper 1.0.0 (2026-09-25)

The first release of Sapper, a maintained continuation of [Minefield](https://github.com/bitbomdev/minefield) (archived in August 2025). Module `github.com/Perruer/sapper`, command `sapper`.

### New

- `sapper report`: every vulnerability with the products it reaches and a shortest dependency path to each, most urgent first (CISA KEV, then EPSS, then the number of products). Table, Markdown or JSON; `--kev-only`, `--min-epss`, `--limit`; `sapper report <ID or CVE>` for one vulnerability.
- `sapper ingest kev`, `epss` and `vex`: the CISA KEV catalog, daily EPSS files (gzipped or not; only CVEs in the graph are stored) and OpenVEX documents. Products marked `not_affected` or `fixed` are listed apart.
- Records of one vulnerability under several IDs (GHSA, GO, CVE aliases) are merged into one finding.
- API: `IngestKEV`, `IngestEPSS`, `IngestVEX` and `ReportService.Report`.
- `sapper llm` works with any OpenAI-compatible API (`--base-url`, `--model`, `SAPPER_LLM_*`), including local models; it no longer needs a vector database or OpenAI embeddings.
- `sapper version`.
- Release binaries for Linux, macOS and Windows (amd64, arm64) and a multi-arch image on `ghcr.io/perruer/sapper`.

### Fixed

- SBOM relationships: with the protobom version Minefield used, the dependsOn edges of CycloneDX documents were lost; current protobom keeps SPDX's "X_OF" orientation, which Minefield read backwards, creating cycles that made most packages dependents of each other. Each edge type now maps to a direction, and non-dependency relationships are ignored.
- OSV version ranges: range events were sorted by comparing the wrong elements; `"introduced": "0"` now covers every version, including Go pseudo-versions; ECOSYSTEM ranges compare versions segment by segment instead of as strings. Together these removed both missed and false matches.
- The SQLite storage implements custom data (it returned "not implemented").
- An in-memory SQLite database uses a single connection (each new connection used to open an empty database); a file database uses WAL and waits for locks.
- ZIP archives are read in memory; they were extracted to the temp folder and never removed.
- Loading OSV records no longer re-reads the whole graph for every record: the Go database of osv.dev (9,351 records) loads in seconds instead of many minutes.

### Changed

- SQLite through a pure-Go driver: no cgo or C compiler, one static binary.
- The server keeps its database in `$SAPPER_DATA_DIR` or the user data folder by default instead of in memory; `--use-in-memory` restores the old behaviour.
- Go 1.26 and current dependencies (protobom 0.6, connect 1.21, gorm 1.31, go-redis v9, tablewriter v1, x/net and x/text without advisories).
- The server flags `--use-openai-llm` and `--vector-db-path` are deprecated and do nothing.
- Tests: Redis tests and the end-to-end test run on an in-process Redis unless `TEST_REDIS_URL` is set.
