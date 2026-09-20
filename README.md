# FunnelRecon
 ______                      _ ____
 |  ____|                    | |  _ \\
 | |__ _   _ _ __  _ __   ___| | |_) |___  ___ ___  _ __
 |  __| | | | '_ \\| '_ \\ / _ \\ |  _ </ _ \\/ __/ _ \\| '_ \\
 | |  | |_| | | | | | | |  __/ | | \\ |  __/ (_| (_) | | | |
 |_|   \\__,_|_| |_|_| |_|\\___|_|_|  \\_\\___|\\___\\___/|_| |_|
**FunnelRecon** — authorized URL reconnaissance by **SydneySpider**.

A bounded, rate-limited Go CLI that enumerates subdomains, probes live hosts, crawls pages, looks up historical URLs, inspects scoped JavaScript, and reports **unverified parameter heuristics**. It never sends exploitation payloads, submits forms, or prints extracted credential values.

## Requirements

Go 1.23+, internet access during the initial dependency installation (`github.com/pterm/pterm` and `github.com/mattn/go-sqlite3`), and a C compiler (`gcc` / `build-essential`) for the SQLite driver. Linux/WSL is the primary target. Build with `CGO_ENABLED=1`.

```bash
sudo apt update && sudo apt install -y build-essential
go mod tidy
CGO_ENABLED=1 go build -o funnelrecon ./cmd/funnelrecon
```

## Usage

```bash
./funnelrecon -d example.com -authorized -workers 12 -rps 5 -o report.json
./funnelrecon -l hosts.txt -authorized -no-archive -o urls.txt
./funnelrecon -d YOUR_AUTHORIZED_DOMAIN -authorized -watcher -workers 3 -rps 1 -depth 1 -no-archive -o watched.json
./funnelrecon -d YOUR_AUTHORIZED_DOMAIN -authorized -diff -diff-db ./funnelrecon.sqlite -o new-endpoints.txt
# Repeat the same -diff command: previously seen endpoint structures are not reprinted.
```

`-d` scope contains the specified domain and subdomains. `-l` scope permits **only exact listed hosts**. The `-authorized` flag acknowledges permission to test the chosen scope. No default domain or wordlist is bundled. Nonstandard ports discovered through links are excluded by default.

| Option | Default | Meaning |
| --- | --- | --- |
| `-workers` | `12` | Worker pool (1–128) |
| `-rps` | `5` | Global request rate (1–100 req/s) |
| `-depth` | `2` | Breadth-first crawl depth (0–5) |
| `-max-hosts` | `50` | Maximum enumerated hosts |
| `-max-urls` | `5000` | Global unique URL cap |
| `-max-archive` | `100` | Archive results per provider per host; 0 disables |
| `-max-js` | `200` | Maximum JS files fetched |
| `-max-body` | `8388608` | Maximum bytes per HTTP body |
| `-timeout` | `12s` | Per-request timeout |
| `-allow-private` | off | Allow local/private IPs for explicitly authorized internal tests |
| `-no-archive` | off | Skip archive APIs |
| `-o` | empty | `.txt` candidate URLs (or new endpoints with `-diff`) or `.json` full report |
| `-watcher` / `--watcher` | off | Verbose stage, sanitized request/status, discovered URL, and JS event log; Ctrl+C stops |
| `-diff` / `--diff` | off | Store scanned endpoint signatures in SQLite; print/export new endpoints only |
| `-diff-db` | `.funnelrecon.sqlite` | SQLite history path; relative to current working directory |

## New features (additive to the existing scan pipeline)

- **Contextual deduplication:** final URL results are grouped by scheme + host + path + sorted query parameter names, ignoring parameter **values**. For example `/api?id=1` and `/api?id=2` become a single endpoint; other parameter sets remain distinct. Different sources are merged. Static images, scripts, stylesheets, fonts, and other common static files are filtered out of final endpoint results. JavaScript is **analyzed first**, then filtered from endpoint output. The crawl itself also avoids queuing most static files.
- **JavaScript:** the original bounded, scoped JS downloader and regex module is retained. It extracts literal API routes and flags AWS access-key-ID and JWT-shaped strings. **Credential values are never printed or exported**; findings contain only type, source, and fingerprint. Detection does not establish key validity.
- **Subdomain takeover checks:** for each discovered host, resolve its CNAME. Only recognized GitHub Pages, Heroku, and AWS service aliases are checked; unresolved DNS or provider-associated 404/410 fingerprints are marked *potential — manual verification required*. No attempts to register, claim, or take over resources are performed. This can produce false positives, and a non-finding does not guarantee safety. Host resolution and HTTP requests remain scope-limited.
- **Parameter signals:** original SSRF/LFI/open-redirect/SQLi heuristic classification is retained, with suspicious parameter **names** highlighted red in terminal output. These are leads, not confirmed vulnerabilities or severity assessments.
- **SQLite diff:** `-diff` saves the final deduplicated, non-static endpoint signatures in a local SQLite database, keyed by **exact scan scope and scope mode**; subsequent scans print only signatures not previously stored. Runs are persisted transactionally after normal completion. The `.txt` export contains *new endpoints* under `-diff`, while `.json` adds `diff_enabled`, `new_endpoints`, and takeover findings. Existing non-diff `.txt` exports continue to contain only heuristic candidates. The full scan still runs; diff changes reporting, not traffic.
- **Watcher and theme:** `-watcher` replaces the progress bars with detailed stage and HTTP request/status events. URL parameter values are redacted in watcher messages; the regular report still contains normalized URL examples. Cyan progress bars replace the former green completion indicators. The banner (including “Created by: SydneySpider”) also appears on `-h`.

The diff database stores representative URL examples, so treat it as potentially sensitive. It is created with mode `0600`, should be kept inside your WSL home directory, and should not be committed to a public repository. Choose a fresh `-diff-db` for a new history. The SQLite driver requires CGO; if Go reports missing gcc, install `build-essential`.

The tool enforces the scope on fetched targets and HTTP redirects and blocks non-public IP destinations by default (including cloud-metadata link-local addresses). A global token ticker gates every HTTP request, including archive requests. `max-hosts`, `max-urls`, `max-js`, response-size limits, request timeout, and worker pools bound resources. URLs with query strings are collected but not actively crawled to avoid replaying potentially state-changing GET links. The crawler reads link, script, and form-action attributes but **never submits forms**. It does not brute-force hidden paths; it extracts paths actually referenced by in-scope HTML and JavaScript. Historical URLs are treated as leads, not automatically as live URLs. No robots.txt parser is included: honor your target's program rules and reduce or disable active crawling if required.

Optional OTX authentication: set `OTX_API_KEY` in the environment; it is only sent to the OTX provider.

## Findings

The URL classifier flags potential SSRF, LFI/path traversal, SQL injection, and open redirect parameter names. `HIGH SIGNAL` and `MEDIUM SIGNAL` are **triage signals, not vulnerability severity or proof**. JavaScript analysis recognizes simple literal routes and AWS access-key IDs / JWT-shaped strings, and exports **only type and short SHA-256 fingerprint**, never the matched value. It cannot prove that any key is valid. Dynamic routes, bundled code requiring runtime interpretation, source maps, and vulnerability verification are intentionally outside this MVP.

Without `-diff`, TXT contains one deduplicated candidate URL per line and can be consumed by other tooling after a separate authorization review. JSON includes source attribution, signals, summary counts, warnings, and redacted secret indicators. Outputs are created with `0600` file permissions.

## Module map

- `cmd/funnelrecon`: CLI, flags, PTerm progress, output rendering.
- `internal/banner`: SydneySpider banner.
- `internal/utils`: host validation, scope boundaries, URL normalization, IP safety, input lists.
- `internal/scanner`: original bounded HTTP client, CRT/OTX enumeration, live probing, crawling, archive integration, classifier, exports; new `filter.go`, `takeover.go`, `diff.go` add isolated functionality.
- `internal/jsanalyzer`: literal route extraction and redacted secret indicators.

## Tests

```bash
CGO_ENABLED=1 go test ./...
CGO_ENABLED=1 go test -race ./...
```

Provider APIs may impose rate limits, vary their data, return errors, or omit results. Failed provider requests are warnings, not silent false negatives. The Common Crawl integration queries the first current index listed in `collinfo.json`, rather than all historical indexes. Wayback's CDX can occasionally reject or throttle requests.

## v3: additive signature dictionary, HTML forms, and API path leads

This release retains the v2 enumeration, crawler, archive/JS pipeline, scope
checks, timeouts, global request limiter, contextual deduplication, SQLite
history, and redacted secret analysis. New files are `internal/scanner/signatures.go`
and `internal/scanner/forms.go`; only small hooks were added to the pipeline,
CLI, model and parameter highlighter.

- **Parameter dictionary:** the five requested categories are matched using
  *complete case-insensitive parameter names*. Overlaps are deliberate: `id`
  gets both `[SQLi]` and `[XSS]`, and `page` gets several tags. `SSRF / Open Redirect`
  shows separate `[SSRF]` and `[Open Redirect]` tags, neither of which is proof.
  `[SQLi]` is yellow, `[SSRF]`/`[Open Redirect]` red, `[IDOR]` magenta,
  `[XSS]` cyan, and `[LFI/Path Traversal]` yellow. These are colored **categories**,
  not validated vulnerability severities. No payloads are generated.
- **HTML forms:** the new HTML parser uses `golang.org/x/net/html` (a separate
  Go module, not the Go standard library). A supplemental worker pool performs
  up to `-max-form-pages` *query-free GET requests* on scoped, likely HTML pages
  while skipping static resources, APIs, common action/logout paths, and
  query-bearing URLs. It uses the *existing* restricted client, rate limit and
  1 MiB response cap. It extracts scoped `action` URLs, GET/POST methods, and
  input/select/textarea *names and types only*. It never submits a form, stores
  input values, or converts POST fields into GET requests. GET form names are
  represented as empty query parameters for dedup and classification. POST
  input-name leads have a distinct `method: "POST"` in JSON and `POST` in the
  terminal; their URL is the form action, without fabricated query strings.
  HTML parsing ignores external form actions and invalid/oversized input names.
  Forms with no matching signature are still available under `forms` in JSON.
- **Naked API hints:** an API-like, query-free path receives the tag
  `[Potential API - Needs Fuzzing]`. This is route discovery only; FunnelRecon
  does not run Arjun, ffuf, or any fuzzing payloads.
- **New reporting:** candidates include `tags` and optionally `method`.
  JSON includes `forms`, `forms_discovered`, `html_pages_inspected`, and
  `potential_apis`. Existing `.txt` candidate export and `-diff` behavior are
  unchanged. `-diff` still keys history by URL structure, not HTTP method or
  POST body fields; JSON retains observed forms for review even when a URL was
  already recorded. Use a new `-diff-db` if you want a fresh history.

```bash
# Install new dependency, then build inside WSL:
go mod tidy
CGO_ENABLED=1 go build -o funnelrecon ./cmd/funnelrecon

# Conservative authorized test (form collection on):
./funnelrecon -d YOUR_AUTHORIZED_DOMAIN -authorized -workers 3 -rps 1 -depth 1 -max-form-pages 20 -no-archive -watcher -o leads.json

# Disable the supplemental form GETs:
./funnelrecon -d YOUR_AUTHORIZED_DOMAIN -authorized -max-form-pages 0 -o leads.json
```

**Authorization:** verify that the program permits active crawling and form-page
GETs before enabling this feature. Some GET routes can still trigger actions;
the skip list is conservative but cannot recognize every custom application.
The dictionary intentionally has many false positives (such as pagination
`page`, ordinary `id` and Next.js image `url`). Nothing tagged here is a
confirmed SQLi, SSRF, XSS, IDOR, LFI, or open redirect without separate evidence.

---

## v4 — Secret Discovery Engine (additive to v3)

This section **supersedes earlier v2/v3 descriptions of AWS/JWT-only detection**;
those remain historical release notes. The v3 core scan and file layout are
preserved. All Go source and test files now have purpose/extension comments;
start with [`docs/SOURCE_GUIDE.md`](docs/SOURCE_GUIDE.md) to understand every
file and find precisely where to extend a rule.

The new `internal/secretanalyzer` package recognizes **indicators**, not proven
usable credentials:

- Distinctive formats: AWS access-key IDs, JWT-shaped tokens, GitHub/GitLab/Slack
  tokens, production-looking Stripe secret keys, and private-key PEM blocks.
- Contextual assignments such as `api_key`, `apiToken`, `client_secret`,
  `aws_secret_access_key`, or `password`, with entropy and placeholder filters.
- Database/broker connection strings where a password is actually embedded.

The existing JavaScript download worker now applies these rules to downloaded
JS bodies; it still extracts routes via the original `jsanalyzer.Analyze`.
The **new supplementary worker pool** inspects a bounded selection of
*observed* HTML, JSON, XML and textual configuration links. It never guesses
paths, submits forms, replays query URLs, actively tests credentials, or sends
matched content to another host. Historical-only URLs are skipped in this
extra pass. Scope, public-IP blocking, redirects, timeout and the same global
request limiter are enforced by the original HTTP client.

Only metadata (`type`, `source`, `line`, `confidence`, `status`, and HMAC
`fingerprint`) is exported. The actual matched credential is **never printed
or saved** by this module. Its per-run randomized HMAC fingerprints let the
scanner deduplicate findings within a run without publishing unsalted
password hashes. The legacy JSON `js_findings` remains JS-only for consumers;
the new `secret_findings` includes JS and extra resources. The statistics
`secret_indicators` counts the new combined list, and
`secret_resources_inspected` shows how many additional resources completed
review. `-diff` still changes endpoint reporting only; JSON continues to hold
unverified secret indicators, while the CLI suppresses repeat printing with
`-diff`. Review JSON privately regardless of output mode.

**New flag:** `-max-secret-resources 80` (range `0..2000`); `0` disables extra
text-resource fetches **but does not disable existing JS analysis**. An extra
body is capped at 1 MiB; the existing `-max-js`, `-max-body`, `-workers` and
`-rps` controls still apply. A single resource is limited to 1,000 matches
per rule and 200 reported distinct indicators, so a scan is not exhaustive.
Do not assume a zero-findings report means a site is free of leaked data.

```bash
# Build on your WSL machine with normal, REAL Go dependencies:
sudo apt install -y build-essential
CGO_ENABLED=1 go mod tidy
CGO_ENABLED=1 go test ./...
CGO_ENABLED=1 go build -o funnelrecon ./cmd/funnelrecon

# Low-impact example: substitute your OWN authorized hostname:
./funnelrecon -d YOUR_AUTHORIZED_DOMAIN -authorized -watcher \
  -workers 3 -rps 1 -depth 1 -max-js 300 -max-secret-resources 60 \
  -no-archive -o report.json

# Display only redacted secret metadata (requires jq):
jq '.statistics, .secret_findings, .warnings' report.json

# Unit tests need no access to a real site:
go test ./internal/secretanalyzer ./internal/scanner -run 'Test(Secret|Detect|Entropy|False)' -v
```

The extra HTML/text requests are opt-out: use `-max-secret-resources 0` if your
scope permits only passive or original JS testing. Detectors are conservative,
can miss secrets, and can flag synthetic or public identifiers. Validate a
potential report **without using discovered credentials to authenticate**.
Source URLs and endpoint reports can contain sensitive metadata; keep your
output inside WSL and do not publish it. See the source guide for changing
signatures and adding synthetic tests.

**v4 source URL hygiene:** secret finding source locations have query strings
removed and token-like path components replaced with `REDACTED`. If an asset
filename is redacted, use scoped, approved local records to find the original;
never print a credential-bearing URL to restore its exact spelling.

---

## v5 — Infrastructure intelligence and historical DNS mapping (additive)

**Status:** extends FunnelRecon v4, preserving its original scope, crawler, archives, JS/secret scanning, URL classification, SQLite URL diff and existing JSON fields. Infrastructure intelligence is **opt-in** so existing commands behave exactly as before.

### New capabilities

- **Current DNS map:** bounded A, AAAA and CNAME observations for explicitly scoped discovered hosts, with public-IP filtering and source attribution.
- **Historical DNS:** optional SecurityTrails historical A/AAAA API (`-dns-history`; requires `SECURITYTRAILS_API_KEY`). Historical records have first/last seen dates when provided, and are labeled historical association, *not* proven current origin. API access may require a provider subscription and may be rate limited.
- **Candidate IP correlation:** deduplicates and maps public IPs to observed scoped hostnames; current and historical-only observations are clearly distinguished. Cloudflare/CDN, hosting and shared IPs are not treated as bypass targets or evidence of ownership.
- **Passive ports and CVEs:** `-internetdb` opts in to Shodan InternetDB's public IP snapshot, including reported ports, CPEs and CVE identifiers for **current** DNS IPs only. Results may be stale, shared, incorrect or inapplicable to the target website. They are not verified vulnerabilities; no exploit attempts occur.
- **CISA KEV correlation:** `-kev-file /path/to/known_exploited_vulnerabilities.json` annotates only CVE identifiers already reported by the passive dataset. Obtain this catalog through the official CISA KEV website; download and store the file separately. This does not prove an affected target or actual exploitation.
- **Graphviz DOT export:** `-map infrastructure.dot` maps `host -> IP` and `host -> CNAME`. Solid edges mean current observations; dashed edges represent historical records. `first_seen` and `last_seen` appear on historical labels when available.
- **Strictly opt-in TCP-connect checks:** `-verify-ports -verify-ips exact-approved-ips.txt -ports 80,443` only attempts TCP connects to addresses on BOTH the user's exact public-IP allowlist AND the scan's present-day DNS results. Never scans an historical-only IP. Uses the shared global request limiter and does not grab banners or exploit anything. IP authorization must be separately confirmed; domain-only scope does **not** establish permission to scan a shared provider IP.
- **`-intel-only`:** run enumeration/host probing and infrastructure enrichment, skipping expensive crawling, archived URL mining, JS downloading and secret scanning. It still sends normal host-probe requests as described in v4.

### Quick-start in Ubuntu / WSL

```bash
cd ~/FunnelRecon-v5
go mod tidy
CGO_ENABLED=1 go build -o funnelrecon ./cmd/funnelrecon

# Current DNS only; no passive IP provider lookup or port scanning.
./funnelrecon -d YOUR_AUTHORIZED_DOMAIN -authorized \
  -intel -intel-only -workers 3 -rps 1 \
  -map infrastructure.dot -o infrastructure.json

# Richer passive research, only if program rules permit provider lookups:
export SECURITYTRAILS_API_KEY='YOUR_OWN_API_KEY'
./funnelrecon -d YOUR_AUTHORIZED_DOMAIN -authorized \
  -intel -dns-history -internetdb -max-intel-hosts 25 -max-intel-ips 30 \
  -workers 3 -rps 2 -map infrastructure.dot -o full-report.json

# Visualize your private map after installing Graphviz (optional):
dot -Tsvg infrastructure.dot -o infrastructure.svg
```

`-dns-history`, `-internetdb`, `-intel-only`, `-verify-ports`, and `-map` automatically turn on `-intel`. `-max-intel-hosts` is 20 and `-max-intel-ips` is 30 by default; valid limits are 1–500 for both when enrichment is enabled. The host cap prioritizes the explicit scope root(s). The historical feed parses at most 20 A and 20 AAAA observations per host from its first API page. `-timeout` should be 1–120 seconds when using intelligence.

Optional, **only if the bug bounty program separately authorizes each public IP** in `approved-ips.txt` (one exact IP per line, no ranges or CIDRs):

```bash
./funnelrecon -d YOUR_AUTHORIZED_DOMAIN -authorized \
  -intel-only -verify-ports -verify-ips approved-ips.txt \
  -ports 80,443 -workers 2 -rps 1 -o approved-ip-checks.json
```

Never put a historical or guessed origin IP into an active-target list merely because it appeared in passive DNS. Historical DNS, InternetDB, and CVE data are *observations*, not proof of an origin, target ownership, vulnerability or impact. No CDN bypass, unscoped HTTP requests, credential validation, CVE exploitation or arbitrary-wide port ranges are implemented. Provider calls use HTTPS, explicit allowlisted hosts, the original global limiter, bounded bodies and timeout. API credentials are headers, never query parameters or JSON output. Outputs and DOT files are written mode `0600`.

Full design and module-extension notes: [`docs/INFRASTRUCTURE_GUIDE.md`](docs/INFRASTRUCTURE_GUIDE.md).

**Existing dashboard compatibility:** v4 JSON fields such as `candidates`, `forms` and `secret_findings` are unchanged. ReconHQ's existing importer can continue processing those; it will need a future additive importer change to display the new `infrastructure` section and graph.
