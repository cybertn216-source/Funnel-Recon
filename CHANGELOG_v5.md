# FunnelRecon v5 — SydneySpider

This is an **additive** upgrade over the FunnelRecon v4 source archive.

- New `internal/intelligence/` module: A/AAAA/CNAME mapping, optional SecurityTrails historical DNS, optional Shodan InternetDB snapshot, local CISA KEV matching, offline Graphviz map, and separately-authorized bounded TCP-connect tests.
- The v4 crawling, archives, classification, JS/secret detection, diffing, JSON candidates, existing flags and normal behavior remain intact when the new flags are omitted.
- `-intel-only` provides a shorter host infrastructure workflow; it still enumerates and probes authorized hosts.
- Historical addresses are **unverified hypotheses**. Neither historical DNS nor internet search data establishes a current origin or permission to scan an IP. InternetDB CVEs may belong to shared infrastructure and are not confirmed vulnerabilities.
- See `docs/INFRASTRUCTURE_GUIDE.md` for source module map and safety boundaries.

Test status at packaging time: standard-library intelligence module tests and race tests passed. The CLI and existing scanner packages were type-checked using temporary external-dependency shims because this packaging environment could not download PTerm, SQLite, and x/net. The project **must be built and fully tested with the real dependencies** after `go mod tidy` in WSL; the offline shims are not shipped.
