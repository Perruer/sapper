<p align="center"><img src="images/sapper_mark.svg" width="96" alt="Sapper"></p>

<h1 align="center">Sapper</h1>

<p align="center">
  <b>Find where a vulnerable package sits across all of your products, and fix what is exploited first.</b>
</p>

<p align="center">
  <a href="https://github.com/Perruer/sapper/actions/workflows/ci.yml"><img src="https://github.com/Perruer/sapper/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Perruer/sapper/releases"><img src="https://img.shields.io/github/v/release/Perruer/sapper" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0"></a>
</p>

<p align="center">English · <a href="README.ru.md">Русский</a></p>

---

Feed Sapper the SBOMs of everything you ship and the vulnerability data you trust. It builds one dependency graph for all of them and answers, in milliseconds:

- which of our products reach this CVE, directly or through other packages, and how;
- which vulnerabilities are known to be exploited (CISA KEV) or likely to be (EPSS), so they go first;
- which products a VEX statement already clears.

Sapper runs as a single binary with a local SQLite database, and nothing leaves your network: every data source is a file you give it.

It is a maintained continuation of [Minefield](https://github.com/bitbomdev/minefield) by BitBom, archived in August 2025. The graph engine and its roaring-bitmap cache come from Minefield ([paper](docs/paper.md)).

```
$ sapper report --limit 4
┌──────────────────────────────────────┬──────────┬─────────────────────┬───────┬──────────┬──────────────────────────────────────────────────────────────────────┐
│            VULNERABILITY             │ SEVERITY │         KEV         │  EPSS │ PRODUCTS │                             EXAMPLE PATH                             │
├──────────────────────────────────────┼──────────┼─────────────────────┼───────┼──────────┼──────────────────────────────────────────────────────────────────────┤
│ GHSA-qppj-fm5r-hxr3 / CVE-2023-44487 │ MODERATE │ yes, due 2023-10-31 │ 1.000 │ 4        │ cloudprober > golang.org/x/net@v0.0.0-20210503060351-7fd8e65b6420    │
│ GHSA-45x7-px36-x8w8 / CVE-2023-48795 │ MODERATE │                     │ 0.933 │ 2        │ cloudprober > golang.org/x/crypto@v0.0.0-20201012173705-84dcc777aaee │
│ GHSA-4v7x-pqxf-cx7m / CVE-2023-45288 │ MODERATE │                     │ 0.920 │ 4        │ cloudprober > golang.org/x/net@v0.0.0-20210503060351-7fd8e65b6420    │
│ GHSA-39qc-96h7-956f / CVE-2019-9512  │ HIGH     │                     │ 0.834 │ 2        │ credstore > golang.org/x/net@v0.0.0-20181217023233-e147a9138326      │
└──────────────────────────────────────┴──────────┴─────────────────────┴───────┴──────────┴──────────────────────────────────────────────────────────────────────┘
```

<sub>From the test SBOMs in this repository, the Go database of osv.dev, the KEV catalog and EPSS scores of September 2026. Paths shortened.</sub>

## What's new compared to Minefield

| | Minefield | Sapper 1.0 |
| --- | --- | --- |
| Vulnerability report | — | `sapper report`: products reached, a path to each, table/Markdown/JSON |
| Prioritisation | — | CISA KEV, EPSS, OpenVEX |
| Records of one vulnerability (GHSA, GO, CVE) | separate results | merged into one finding |
| Build | needs cgo and a C compiler (SQLite) | one static binary, pure Go |
| Default database | in memory, lost on restart | a file in the user data folder |
| SQLite storage | custom data "not implemented" | complete |
| SBOM dependencies | the dependsOn edges of CycloneDX documents were lost; with current protobom, "X_OF" relationships came in reversed | every dependency relationship, in the right direction |
| Version ranges | events compared in the wrong order; ECOSYSTEM versions compared as strings | follows the OSV rules; 10.0 > 9.1, 1.0rc1 < 1.0 |
| Loading the Go database of osv.dev (9,351 records) | minutes, re-reading the graph per record | seconds |
| ZIP archives | extracted to the temp folder and never removed | read in memory |
| `sapper llm` | OpenAI only, needs a vector database on the server's disk | any OpenAI-compatible API, including Ollama |
| Dependencies | x/net and x/text with advisories | current; govulncheck clean |
| Releases | none tagged | binaries for Linux, macOS and Windows; multi-arch image |

The full list is in the [changelog](CHANGELOG.md).

## Install

Download a binary from the [releases](https://github.com/Perruer/sapper/releases) (Linux, macOS, Windows; amd64 and arm64), or:

```bash
go install github.com/Perruer/sapper@latest
```

or run the server in Docker:

```bash
docker run -d -p 127.0.0.1:8089:8089 -v sapper-data:/data ghcr.io/perruer/sapper
```

## Quick start

```bash
sapper server &                                   # keeps its database in the user data folder

sapper ingest sbom ./sboms                        # CycloneDX or SPDX, JSON; files, folders or .zip
sapper ingest osv ./Go-all.zip                    # OSV records, e.g. https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip
sapper ingest kev known_exploited_vulnerabilities.json
sapper ingest epss epss_scores-current.csv.gz
sapper ingest vex ./our-product.openvex.json      # optional
sapper cache                                      # precomputes the graph for queries and leaderboards

sapper report                                     # everything, most urgent first
sapper report CVE-2023-44487 --format markdown    # one vulnerability: products and paths
sapper report --kev-only --format json > kev.json
```

Where to get the data:

| Data | Source |
| --- | --- |
| SBOMs | your build (Syft, cdxgen, Trivy, GitHub's dependency graph export...) |
| OSV records | [osv.dev](https://google.github.io/osv.dev/data/): `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip` |
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| EPSS | https://epss.empiricalsecurity.com/epss_scores-current.csv.gz |
| VEX | your own [OpenVEX](https://github.com/openvex/spec) documents |

Load vulnerabilities after SBOMs, and EPSS after vulnerabilities: only the scores of CVEs in the graph are stored.

## The report

`sapper report` lists every vulnerability that reaches a product, where a product is a node nothing else depends on (usually the root component of an SBOM). For each one it shows the vulnerable packages, every product it reaches with one shortest dependency path, the severity from the advisory, KEV data (date added, due date, ransomware use) and the EPSS score.

Order: vulnerabilities in KEV first, then by EPSS, then by the number of products. Products that a VEX statement marks `not_affected` or `fixed` move to a separate list. Filters: `--kev-only`, `--min-epss 0.1`, `--limit 20`. Formats: `table`, `markdown`, `json`.

The Markdown and JSON output are meant for tickets and compliance records, for example the vulnerability handling and reporting that the EU Cyber Resilience Act asks of manufacturers. Sapper gives you the facts; what you have to report is for you to decide.

## Querying the graph

```bash
sapper query custom "dependents library pkg:golang/golang.org/x/net@v0.23.0"
sapper query custom "dependencies vuln pkg:github.com/google/cadvisor@"
sapper query custom "dependents library pkg:A xor dependents library pkg:B"
sapper query globsearch "*GHSA*"
sapper leaderboard custom "dependents library"      # packages ranked by how many depend on them
```

A query is `dependencies|dependents <type> <name>`, where the type is `library` or `vuln`, combined with `and`, `or`, `xor` and brackets. Names are package URLs as they appear in your SBOMs.

`sapper llm` turns plain-language questions into these queries. It works with any OpenAI-compatible chat API:

```bash
SAPPER_LLM_API_KEY=sk-... sapper llm                                   # OpenAI
sapper llm --base-url http://localhost:11434/v1 --model qwen2.5-coder  # Ollama, no key
```

## Storage

The server uses SQLite by default: `sapper.db` in `$SAPPER_DATA_DIR`, or in the user data folder (`~/.local/share/sapper`, `~/Library/Application Support/sapper`, `%LOCALAPPDATA%\sapper`). `--storage-path` picks another file, `--use-in-memory` keeps it in memory. For a shared server, Redis also works: `--storage-type redis --storage-addr host:6379`.

The server listens on `localhost:8089`; the CLI commands talk to it (`--addr`). The API is [Connect](https://connectrpc.com/) (gRPC and JSON over HTTP), defined in [api/v1/service.proto](api/v1/service.proto).

## Development

```bash
go test ./...          # unit and end-to-end tests; Redis runs in-process
make build             # bin/sapper
make generate          # after changing api/v1/service.proto (needs buf)
```

## Support the project

Sapper is maintained in my free time. If it saves you a day of CVE triage, you can support it:

- [Boosty](https://boosty.to/mikio_kuroki/donate)
- USDT / TRX (TRC-20): `TXUBW4e88SDTfrnJRKfbhYfFcggufbonc1`
- USDT / USDC / ETH (ERC-20): `0x1378491169064702786b2E5b58c6375776177E8A`
- TON / USDT (TON): `UQAhI7EKzoa-JuKOfv0ULMzA3FrmpxsDkXj8Qevwj2z1cMRN`

## License

[Apache-2.0](LICENSE), like Minefield. Sapper is a continuation of [Minefield](https://github.com/bitbomdev/minefield) by BitBom; see [NOTICE](NOTICE). The original README is in [docs/upstream-README.md](docs/upstream-README.md). Sapper is not affiliated with or endorsed by BitBom.
