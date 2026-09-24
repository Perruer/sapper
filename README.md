# Sapper

Sapper finds where a vulnerable package sits across all of your products. Feed it the SBOMs of everything you ship, and it answers questions like "which of our releases depend on this package, directly or through other packages?" in milliseconds, without sending anything outside your network.

It is a maintained continuation of [Minefield](https://github.com/bitbomdev/minefield) by BitBom, which was archived in August 2025. The graph engine and its roaring-bitmap cache come from Minefield; see [docs/paper.md](docs/paper.md).

> Work in progress. The first release is being prepared.

Plans for the first release:

- one binary with no external services: SQLite in pure Go by default, Redis optional;
- current dependencies, Go toolchain and SBOM formats;
- prioritisation data: CISA Known Exploited Vulnerabilities, EPSS, VEX statements;
- a "blast radius" report for a CVE across all products, useful for EU Cyber Resilience Act reporting;
- any LLM provider for natural-language queries, not only OpenAI;
- a Docker image and a GitHub Action.

## Credits

Sapper is based on Minefield by BitBom. The original README is kept in [docs/upstream-README.md](docs/upstream-README.md).

## License

Apache License 2.0, like Minefield. See [LICENSE](LICENSE).
