# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| Sapper 1.x | Yes |
| Minefield (bitbomdev) | No, archived in August 2025 |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on https://github.com/Perruer/sapper. Do not open a public issue for them.

I will confirm the report within a few days and publish a fix and an advisory as soon as I can.

## Deployment notes

- The server has no authentication. It listens on `localhost:8089` by default; if you expose it, put it behind a proxy that authenticates, and use `--cors` to list the origins allowed to call it from a browser.
- `sapper ingest` loads whatever files you give it. Vulnerability data is only as trustworthy as its source; the air-gapped design means nothing is fetched behind your back, not that inputs are verified.
- `sapper llm` sends your questions and the query results to the model provider you configure. Use a local model (`--base-url`) if the graph must not leave your network.
