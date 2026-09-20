# FunnelRecon v5: infrastructure intelligence developer guide

Created by SydneySpider. The v4 crawler and secret engine are unchanged. New infrastructure code lives in `internal/intelligence/`; four existing files contain additive integration hooks.

## Trust boundaries

1. `scanner.Run` builds an authorized `Scope` from `-d` or `-l`, then enumerates/probes exactly as in v4. Only those hosts are handed to `intelligence.Collect`.
2. `NetResolver` performs bounded A/AAAA/CNAME lookups of those names. Only public IP answers enter the map; private, reserved, loopback, link-local and documentation addresses are dropped, even when `-allow-private` is enabled for the original web scan.
3. Historical DNS is **opt-in** (`-dns-history` + `SECURITYTRAILS_API_KEY`). The key travels only as an APIKEY HTTP header to `api.securitytrails.com`; it does not appear in report URLs. A maximum of 20 record observations per record type per hostname is parsed from the first provider page. No historical IP is used as an active request destination.
4. InternetDB is **opt-in** (`-internetdb`) and queries current public DNS addresses only. Its port, CPE and CVE data may reflect other tenants of shared infrastructure and may be stale. A CVE is an IP-level dataset reference, never proof of exploitability or a target-specific bug.
5. `-kev-file` takes an already-downloaded official CISA KEV JSON catalog. The matcher only adds a `in_cisa_kev` boolean for existing CVE identifiers. No arbitrary products or guessed CVEs are added.
6. TCP verification is **off by default**. It is enabled only with both `-verify-ports` and `-verify-ips` containing exact, explicitly approved public IP addresses (no CIDRs/hostnames). Addresses must ALSO be found in CURRENT DNS; historical-only IPs cannot be probed. At most 16 selected ports per IP; the existing global limiter gates the TCP connection attempts. Only a TCP-connect boolean is reported; no banners, login attempts or payloads.
7. JSON adds an optional top-level `infrastructure` object and optional numeric statistics. All v4 fields and the existing candidate/diff formats stay intact. Graphviz DOT exports carry evidence and must be kept private.

## Files to modify

- `internal/intelligence/types.go`: JSON models and required scope-independent interfaces.
- `internal/intelligence/parse.go`: history response normalization, InternetDB parsing, CVE allow-format, CISA KEV import, public IP policy.
- `internal/intelligence/collect.go`: capped worker pool for DNS, optional provider enrichment, exact-IP active gating. Injected `Resolver`, `Fetch`, and `wait` callbacks make tests fully offline.
- `internal/intelligence/map.go`: deterministic, DOT-escaped network diagram. Solid edges are current observations; dashed edges are historical.
- `internal/intelligence/intelligence_test.go`: synthetic fixtures; extend whenever a provider schema or trust guard changes.
- `internal/scanner/client.go`: the **only** additional provider allowlist entries and provider authentication header. All remote lookups reuse `Client.Fetch` and its global ticker. Do not add `http.Get` inside intelligence packages.
- `internal/scanner/pipeline.go`: single additive infrastructure hook between host probing and crawling. It also implements `-intel-only` without touching later phases.
- `internal/scanner/types.go` and `cmd/funnelrecon/main.go`: flags, additive report fields, conservative CLI text, and DOT export.

## Example JSON interpretation

```json
{
  "infrastructure": {
    "note": "Infrastructure intelligence is observational ...",
    "dns_records": [{"host":"example.org","type":"A","value":"PUBLIC_IP","source":"SecurityTrails historical DNS","status":"historical association; unverified, may be shared or reassigned"}],
    "ip_observations": [{"ip":"PUBLIC_IP","status":"historical-only association; not a confirmed origin"}]
  }
}
```

`PUBLIC_IP` is illustrative. A record observed long ago can now point at an unrelated organization's infrastructure. Never attempt to bypass a CDN or contact a possible origin based on this map alone. Confirm the program permits any direct testing and that the IP itself is explicitly authorized.

## Testing and validation

```bash
# New package uses only the standard library and pre-existing internal/utils.
go test -race ./internal/intelligence ./internal/utils

# With your normal Go network access and build prerequisites:
go mod tidy
CGO_ENABLED=1 go test ./...
CGO_ENABLED=1 go test -race ./...
CGO_ENABLED=1 go vet ./...
CGO_ENABLED=1 go build -o funnelrecon ./cmd/funnelrecon
```

The `go.mod` external dependencies are unchanged from v4; `go mod tidy` downloads them and creates `go.sum` in a normal internet-connected WSL system. A local dependency shim can type-check the executable but CANNOT substitute for real PTerm, SQLite, and HTML parser integration tests.

## Future additions

- Import authorized asset ownership data (ASN/IP ranges) **without** treating DNS or WHOIS as permission by itself.
- Compare two saved JSON snapshots for DNS/IP drift without contacting targets again.
- Add verified product/version inventory from authenticated or owner-provided SBOM evidence before doing CVE matching.
- Extend ReconHQ's importer to render the optional `infrastructure` object; existing candidate ingestion remains compatible but cannot yet display the graph automatically.
