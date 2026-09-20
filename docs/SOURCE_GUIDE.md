# FunnelRecon v4 — commented source tour

Created by **SydneySpider**. This document accompanies the purpose comments
at the top of **every Go source and test file**. Function-level comments mark
security-sensitive boundaries and extension points. Comments explain *why*, not
just restate the code. No original scanner package layout was replaced.

## Execution order and where to make changes

`cmd/funnelrecon/main.go` parses flags, prints banner, hooks progress/watcher,
invokes `scanner.Run`, prints findings, and saves exports. To add a flag, also
update `scanner.Config`, validate it in `pipeline.Run`, and add README help.

`internal/scanner/pipeline.go` orchestrates existing phases:

1. Interpret `-d`/`-l` as the exact allowed scope.
2. Enumerate and probe hosts (bounded worker pool and CNAME check).
3. Crawl discovered HTML and retrieve passive archive URLs.
4. Download discovered JS and extract routes (unchanged `jsanalyzer.Analyze`);
   **v4** also inspects each downloaded JS body with `secretanalyzer.Detector`.
5. Fetch a limited set of HTML form pages; collect form input names only.
6. **v4:** fetch up to `-max-secret-resources` *already discovered* query-free
   HTML/JSON/config/text links via `Client.Fetch`; inspect textual responses.
7. Apply contextual dedup, optional SQLite diff, classify and export.

The v4 additions are only one call in the existing JS worker and one bounded
supplemental pass. v2/v3 endpoint enumeration, crawling, form handling,
classification, takeover checks and history were not rewritten.

## File-by-file map

| File | Why it exists / safe extension point |
| --- | --- |
| `cmd/funnelrecon/main.go` | CLI flags, printing, redacted finding rendering. Do not print raw body matches. |
| `internal/banner/banner.go` | ASCII branding. Safe to change freely. |
| `internal/jsanalyzer/analyze.go` | Existing literal JS route discovery and compatibility detection; v4's secret rules are elsewhere. |
| `internal/scanner/archive.go` | Historical Wayback and Common Crawl URLs; archived does not mean live. |
| `internal/scanner/classify.go` | Backward-compatibility classifier shim. |
| `internal/scanner/client.go` | All HTTP requests, DNS/IP policy, redirect checks, rate limiter, timeouts, max response body. Never bypass it. |
| `internal/scanner/crawler.go` | Bounded BFS; only query-free GET pages are visited. |
| `internal/scanner/diff.go` | SQLite history, keyed by scope and URL structure. Does not avoid fetches. |
| `internal/scanner/enum.go` | crt.sh/OTX enumeration and live-host probes. |
| `internal/scanner/filter.go` | Static filtering, structural dedup and terminal parameter highlighting. |
| `internal/scanner/forms.go` | HTML form scraping, safe supplementary GETs, never submits forms or saves field values. |
| `internal/scanner/output.go` | Restricted-permission `.txt`/`.json` export. No secrets in exported finding fields. |
| `internal/scanner/pipeline.go` | Integration point for all phases, source attribution and result stats. |
| `internal/scanner/secrets.go` | **New:** observed text resource eligibility and bounded worker pool. Modify the extension allowlist here. |
| `internal/scanner/signatures.go` | URL parameter name categories; these are vulnerability *hints*, not credentials. |
| `internal/scanner/takeover.go` | DNS/provider indicators only; never claim a third-party resource. |
| `internal/scanner/types.go` | `Config`, JSON `Report`, counters and lead types. Add only redacted secret metadata. |
| `internal/secretanalyzer/doc.go` | New package's invariants and extension guide. |
| `internal/secretanalyzer/signatures.go` | **New:** distinctive credential formats, assignment pattern, credential-bearing URI candidates. |
| `internal/secretanalyzer/detector.go` | **New:** process-local HMAC fingerprints, line location, offline matching, caps and dedup. |
| `internal/secretanalyzer/context.go` | **New:** text MIME and binary/UTF-8 guard. |
| `internal/secretanalyzer/entropy.go` | **New:** Shannon entropy for contextual candidates; never use entropy alone to claim a leak. |
| `internal/secretanalyzer/validator.go` | **New:** offline placeholder/false-positive filters, NOT live key validation. |
| `internal/secretanalyzer/output.go` | **New:** deterministic count-only category summaries. |
| `internal/utils/files.go` | Host-list ingestion. |
| `internal/utils/scope.go` | Exact domain allowlist, URL redaction and private-IP denial. Security-critical. |
| `*_test.go` | Synthetic test fixtures and local-only HTTP server checks. Change tests alongside any signature, scope or HTTP behavior. |

## How to add a signature

Open `internal/secretanalyzer/signatures.go`. Compile a **specific** provider
format into a regex variable and add it to `formatRules` with a human-readable
label. For generic strings, keep a strong key-assignment context; broad
high-entropy matching alone produces too many false positives. Add both a
positive fixture and a placeholder/false-positive fixture to
`internal/secretanalyzer/detector_test.go`. Never use real credentials as
fixtures, and never commit live secret strings in any test or documentation.

Follow the match flow in `detector.go`: a match stays in local variables,
`placeholder` checks it, HMAC fingerprints it, and only `Finding` (source,
type, line, confidence, opaque fingerprint, unverified status) escapes. Do
**not** add fields such as `Value`, `Snippet`, `Token`, or `Password` to Finding.
Fingerprints are intentionally different across runs, making low-entropy
password guessing from exports harder; they support deduplication *within* a
run, not across separate runs.

## How to increase coverage responsibly

The scanner does **not** guess `.env`, `/config.json`, source maps or backup
paths. It fetches text/config resources only if the live crawl explicitly
observed their URLs. A URL discovered *only* via an archive is not fetched by
the secret resource pass. JS is fetched by the original JS pass. Only
query-free URLs are fetched by the additional pass, which excludes API paths,
likely action paths and binary/static assets. When an observed JSON/config
file has a non-text MIME such as `application/octet-stream`, it is not parsed.

Use `-max-js` to change how many discovered JS files are checked and
`-max-secret-resources` to change the **additional** observed textual-resource
cap (`0` disables the extra pass, not JS). Each extra body is at most 1 MiB,
regardless of `-max-body`; `-workers` and `-rps` still apply. Each regex
examines up to 1,000 matches/rule/resource; at most 200 distinct findings
are kept per resource, so extreme bundles may need offline, explicitly
approved review. Bodies are not persisted. No form submission or credential
validation is performed, and `0 findings` can be a valid result.

## Testing without any real target

```bash
CGO_ENABLED=1 go test ./...
CGO_ENABLED=1 go test -race ./...
go vet ./...
# The detector's tests use only synthetic values; the scanner uses httptest.
go test ./internal/secretanalyzer ./internal/scanner -run 'Test(Secret|Detect|Entropy|False)' -v
```

Real PTerm, `golang.org/x/net/html` and SQLite dependencies are needed for full
integration tests; `go mod tidy` downloads them on a network-connected WSL
machine. Do not ship or use the developer-only offline shims for production.

## Data handling and authorized scope

Run only within an approved program's scope, and verify its active-scan rules.
Finding metadata and endpoint URLs can themselves be sensitive; export files
use mode `0600`, but follow your program's retention and reporting policy.
For potential credential exposure, report minimal redacted evidence and the
source location to the owner; don't use a found secret to authenticate,
retrieve extra data, or contact an external validation service.

`secretanalyzer.SafeSource` additionally drops query strings and masks
credential-shaped or high-entropy path segments in secret finding source URLs.
Some asset filenames may therefore appear as `REDACTED.js`; do not weaken
source redaction just to gain a more precise filename in terminal output.
