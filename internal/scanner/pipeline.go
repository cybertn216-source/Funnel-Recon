// Original scan pipeline: scope -> enumerate -> probe -> crawl ->
// archives -> JS -> forms -> v4 text-secret pass -> dedup -> diff -> report.
// Add supplementary phases at marked hooks; retain original worker pools.
package scanner

import (
	"context"
	"fmt"
	"funnelrecon/internal/intelligence"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"funnelrecon/internal/jsanalyzer"
	"funnelrecon/internal/secretanalyzer"
	"funnelrecon/internal/utils"
)

// Progress receives a stage and its completed/total counters.
type Progress func(stage string, done, total int)

// Run coordinates the original phases with the optional additive passes.
// The shared client enforces scope, rate, redirects and response-size limits.
func Run(ctx context.Context, cfg Config, progress Progress) (Report, error) {
	report := Report{Tool: "FunnelRecon", Creator: "SydneySpider", ScannedAt: time.Now().UTC(), Candidates: []Candidate{}, JSFindings: []jsanalyzer.Secret{}, SecretFindings: []secretanalyzer.Finding{}, LiveHosts: []string{}, DiffEnabled: cfg.Diff}
	if (cfg.Domain == "") == (cfg.List == "") {
		return report, fmt.Errorf("provide exactly one of -d or -l")
	}
	if cfg.MaxIntelHosts < 0 || cfg.MaxIntelHosts > 500 || cfg.MaxIntelIPs < 0 || cfg.MaxIntelIPs > 500 {
		return report, fmt.Errorf("intel limits must be within 0..500")
	}
	if cfg.Workers < 1 || cfg.Workers > 128 || cfg.RPS < 1 || cfg.RPS > 100 || cfg.MaxHosts < 1 || cfg.MaxURLs < 1 || cfg.MaxArchive < 0 || cfg.MaxJS < 0 || cfg.MaxFormPages < 0 || cfg.MaxFormPages > 1000 || cfg.MaxSecretResources < 0 || cfg.MaxSecretResources > 2000 || cfg.MaxDepth < 0 || cfg.MaxDepth > 5 || cfg.MaxBody < 1024 || cfg.Timeout <= 0 {
		return report, fmt.Errorf("invalid limits (workers 1..128; rps 1..100; depth 0..5)")
	}
	var roots []string
	var err error
	subdomains := cfg.Domain != ""
	if subdomains {
		h, e := utils.Host(cfg.Domain)
		if e != nil {
			return report, e
		}
		roots = []string{h}
	} else {
		roots, err = utils.ReadHosts(cfg.List)
		if err != nil {
			return report, err
		}
	}
	scope, err := utils.NewScope(roots, subdomains)
	if err != nil {
		return report, err
	}
	report.Scope = scope.Hosts()
	// One detector per run: process-local keyed fingerprints support safe dedup.
	detector, err := secretanalyzer.New()
	if err != nil {
		return report, fmt.Errorf("initialize redacted secret fingerprints: %w", err)
	}
	client := NewClient(scope, cfg.RPS, cfg.Timeout, cfg.AllowPrivate, cfg.MaxBody)
	defer client.Close()
	emit := func(message string) {
		if cfg.Watcher && cfg.OnEvent != nil {
			cfg.OnEvent(message)
		}
	}
	if cfg.Watcher {
		client.OnEvent = emit
	}
	emit(fmt.Sprintf("Scope: %v; workers=%d rps=%d depth=%d", report.Scope, cfg.Workers, cfg.RPS, cfg.MaxDepth))
	hosts := roots
	if subdomains {
		emit("Enumerating certificate transparency and OTX passive DNS")
		hosts, report.Warnings = client.Enumerate(ctx, roots[0], cfg.MaxHosts)
	}
	if len(hosts) > cfg.MaxHosts {
		report.Warnings = append(report.Warnings, fmt.Sprintf("host cap: retained %d of %d", cfg.MaxHosts, len(hosts)))
		hosts = hosts[:cfg.MaxHosts]
	}
	report.Statistics.DiscoveredHosts = len(hosts)
	if progress != nil {
		progress("Probe", 0, len(hosts))
	}
	type hostResult struct {
		host, seed string
		live       bool
		takeover   *TakeoverFinding
	}
	hostJobs := make(chan string, cfg.Workers)
	hostResults := make(chan hostResult, cfg.Workers)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range hostJobs {
				seed, live := client.Probe(ctx, host)
				takeover := client.CheckTakeover(ctx, host, seed)
				hostResults <- hostResult{host: host, seed: seed, live: live, takeover: takeover}
			}
		}()
	}
	go func() {
		for _, host := range hosts {
			hostJobs <- host
		}
		close(hostJobs)
		wg.Wait()
		close(hostResults)
	}()
	seeds := []string{}
	completed := 0
	for r := range hostResults {
		completed++
		if r.takeover != nil {
			report.Takeovers = append(report.Takeovers, *r.takeover)
			emit("POTENTIAL TAKEOVER " + r.host + " -> " + r.takeover.CNAME + " (verify manually)")
		}
		emit(fmt.Sprintf("Host %s: reachable=%t", r.host, r.live))
		if r.live {
			report.LiveHosts = append(report.LiveHosts, r.host)
			seeds = append(seeds, r.seed)
		}
		if progress != nil {
			progress("Probe", completed, len(hosts))
		}
	}
	sort.Strings(report.LiveHosts)
	sort.Slice(report.Takeovers, func(i, j int) bool { return report.Takeovers[i].Host < report.Takeovers[j].Host })
	report.Statistics.TakeoverCandidates = len(report.Takeovers)
	sort.Strings(seeds)
	report.Statistics.LiveHosts = len(seeds)
	// Additive infrastructure phase after DNS/host discovery, before crawling.
	// Historical addresses are never used as HTTP crawl seeds. In particular,
	// a past DNS A record does not establish a current origin or ownership.
	if cfg.Intel {
		if cfg.MaxIntelHosts == 0 || cfg.MaxIntelIPs == 0 {
			return report, fmt.Errorf("-intel requires positive -max-intel-hosts and -max-intel-ips")
		}
		ports, parseErr := intelligence.ParsePorts(cfg.TCPPorts)
		if parseErr != nil {
			return report, fmt.Errorf("-ports: %w", parseErr)
		}
		emit("Infrastructure: current DNS, optional historical records and IP-level passive intelligence")
		if progress != nil {
			progress("Infrastructure", 0, 1)
		}
		info, infoErr := intelligence.Collect(ctx, append(append([]string{}, roots...), hosts...), intelligence.Config{
			Workers: cfg.Workers, MaxHosts: cfg.MaxIntelHosts, MaxIPs: cfg.MaxIntelIPs,
			TimeoutSeconds: max(1, int(cfg.Timeout.Seconds())), History: cfg.DNSHistory,
			HistoryKey: os.Getenv("SECURITYTRAILS_API_KEY"), InternetDB: cfg.InternetDB,
			KEVFile: cfg.KEVFile, VerifyTCP: cfg.VerifyPorts,
			VerifyIPsFile: cfg.VerifyIPFile, Ports: ports,
		}, intelligence.NetResolver{}, client.Fetch, client.Wait)
		if infoErr != nil {
			return report, fmt.Errorf("infrastructure enrichment: %w", infoErr)
		}
		report.Infrastructure = &info
		if cfg.Watcher {
			for index, record := range info.DNS {
				if index >= 100 {
					emit(fmt.Sprintf("Infrastructure DNS event cap: showing 100 of %d records; complete data in JSON/map", len(info.DNS)))
					break
				}
				emit(fmt.Sprintf("DNS %s %s -> %s (%s; first=%s last=%s)", record.Host, record.Type, record.Value, record.Status, record.FirstSeen, record.LastSeen))
			}
		}
		report.Statistics.InfraRecords = len(info.DNS)
		report.Statistics.InfraIPs = len(info.IPs)
		for _, ip := range info.IPs {
			report.Statistics.PassivePorts += len(ip.PassivePorts)
			report.Statistics.CVEReferences += len(ip.CVEs)
		}
		report.Warnings = append(report.Warnings, info.Warnings...)
		if progress != nil {
			progress("Infrastructure", 1, 1)
		}
		emit(fmt.Sprintf("Infrastructure complete: DNS=%d IPs=%d passive ports=%d IP-level CVE refs=%d", report.Statistics.InfraRecords, report.Statistics.InfraIPs, report.Statistics.PassivePorts, report.Statistics.CVEReferences))
	}
	if cfg.IntelOnly {
		sort.Strings(report.Warnings)
		return report, nil
	}
	if len(seeds) == 0 {
		report.Warnings = append(report.Warnings, "No reachable scoped hosts; no active crawling performed")
		return report, nil
	}
	emit("Crawling scoped, query-free HTML pages")
	if progress != nil {
		progress("Crawl", 0, cfg.MaxURLs)
	}
	crawled := client.Crawl(ctx, seeds, cfg.Workers, cfg.MaxDepth, cfg.MaxURLs, func(done, total int) {
		if progress != nil {
			progress("Crawl", done, cfg.MaxURLs)
		}
	})
	// Preserve discovery source attribution without exceeding the global URL cap.
	sources := map[string]map[string]bool{}
	add := func(raw, source string) bool {
		normal, ok := utils.NormalizeURL(raw, scope)
		if !ok {
			return false
		}
		if IsStaticAsset(normal) && !IsJS(normal) {
			return false
		}
		if existing, yes := sources[normal]; yes {
			existing[source] = true
			return false
		}
		if len(sources) >= cfg.MaxURLs {
			return false
		}
		sources[normal] = map[string]bool{source: true}
		emit("Discovered (" + source + "): " + safeWatchURLString(normal))
		return true
	}
	crawlURLs := make([]string, 0, len(crawled))
	for raw := range crawled {
		crawlURLs = append(crawlURLs, raw)
	}
	sort.Strings(crawlURLs)
	for _, raw := range crawlURLs {
		add(raw, crawled[raw])
	}
	if !cfg.NoArchive && cfg.MaxArchive > 0 {
		emit("Querying Wayback and Common Crawl archives")
		index, err := client.LatestCommonCrawl(ctx)
		if err != nil {
			report.Warnings = append(report.Warnings, "Common Crawl index: "+err.Error())
		}
		if progress != nil {
			progress("Archives", 0, len(report.LiveHosts))
		}
		type archiveResult struct {
			host           string
			urls, warnings []string
		}
		jobs := make(chan string, cfg.Workers)
		results := make(chan archiveResult, cfg.Workers)
		var archiveWG sync.WaitGroup
		for i := 0; i < cfg.Workers; i++ {
			archiveWG.Add(1)
			go func() {
				defer archiveWG.Done()
				for host := range jobs {
					urls, warnings := client.Archive(ctx, host, index, cfg.MaxArchive)
					results <- archiveResult{host: host, urls: urls, warnings: warnings}
				}
			}()
		}
		go func() {
			for _, h := range report.LiveHosts {
				jobs <- h
			}
			close(jobs)
			archiveWG.Wait()
			close(results)
		}()
		done := 0
		for r := range results {
			done++
			report.Warnings = append(report.Warnings, r.warnings...)
			sort.Strings(r.urls)
			for _, raw := range r.urls {
				add(raw, "archive")
			}
			if progress != nil {
				progress("Archives", done, len(report.LiveHosts))
			}
		}
	}
	jsURLs := []string{}
	for raw := range sources {
		if IsJS(raw) {
			jsURLs = append(jsURLs, raw)
		}
	}
	sort.Strings(jsURLs)
	if len(jsURLs) > cfg.MaxJS {
		report.Warnings = append(report.Warnings, fmt.Sprintf("JS cap: retained %d of %d files", cfg.MaxJS, len(jsURLs)))
		jsURLs = jsURLs[:cfg.MaxJS]
	}
	emit(fmt.Sprintf("Analyzing %d scoped JavaScript files", len(jsURLs)))
	if progress != nil {
		progress("JavaScript", 0, len(jsURLs))
	}
	type jsResult struct {
		source    string
		endpoints []string
		secrets   []secretanalyzer.Finding
		err       error
	}
	jsJobs := make(chan string, cfg.Workers)
	jsResults := make(chan jsResult, cfg.Workers)
	var jsWG sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		jsWG.Add(1)
		go func() {
			defer jsWG.Done()
			for raw := range jsJobs {
				body, typ, _, err := client.Fetch(ctx, raw, false, cfg.MaxBody)
				if err != nil {
					jsResults <- jsResult{source: raw, err: err}
					continue
				}
				// Keep the original JS endpoint extractor; the new detector broadens
				// credential coverage without changing discovery behavior.
				endpoints, _ := jsanalyzer.Analyze(raw, body)
				var secrets []secretanalyzer.Finding
				if secretanalyzer.TextResource(typ, body) {
					secrets = detector.Detect(safeWatchURLString(raw), body)
				}
				jsResults <- jsResult{source: raw, endpoints: endpoints, secrets: secrets}
			}
		}()
	}
	go func() {
		for _, raw := range jsURLs {
			jsJobs <- raw
		}
		close(jsJobs)
		jsWG.Wait()
		close(jsResults)
	}()
	secretSet := map[string]bool{}
	completed = 0
	for r := range jsResults {
		completed++
		if r.err == nil {
			report.Statistics.JSFiles++
			emit(fmt.Sprintf("JS inspected %s; routes=%d redacted-secret-indicators=%d", safeWatchURLString(r.source), len(r.endpoints), len(r.secrets)))
			base, _ := url.Parse(r.source)
			for _, ref := range r.endpoints {
				target, e := url.Parse(ref)
				if e != nil {
					continue
				}
				add(base.ResolveReference(target).String(), "javascript")
			}
			for _, s := range r.secrets {
				key := s.Source + s.Type + s.Fingerprint
				if !secretSet[key] {
					secretSet[key] = true
					// Preserve v3 JSON compatibility for JS-only finding consumers.
					report.JSFindings = append(report.JSFindings, jsanalyzer.Secret{Source: s.Source, Type: s.Type, Fingerprint: s.Fingerprint})
					report.SecretFindings = append(report.SecretFindings, s)
				}
			}
		} else {
			report.Warnings = append(report.Warnings, fmt.Sprintf("JS %s: %v", r.source, r.err))
		}
		if progress != nil {
			progress("JavaScript", completed, len(jsURLs))
		}
	}
	// Supplemental, bounded HTML form discovery. This leaves the original
	// crawl, passive sources and JS phases unchanged. No forms are submitted.
	if cfg.MaxFormPages > 0 {
		emit(fmt.Sprintf("Checking up to %d query-free HTML pages for form actions/input names", cfg.MaxFormPages))
		forms, warnings, inspected := client.DiscoverForms(ctx, sources, cfg.Workers, cfg.MaxFormPages, progress, emit)
		report.Forms = forms
		report.Warnings = append(report.Warnings, warnings...)
		report.Statistics.HTMLPagesInspected = inspected
		report.Statistics.Forms = len(forms)
		for _, f := range forms {
			add(f.Action, "form-action")
			if discovered := FormGETURL(f); discovered != "" {
				add(discovered, "form-get-inputs")
			}
		}
	}
	// Additive pass: inspect only previously observed, query-free public text
	// resources. The scoped HTTP client and its global rate limit are reused.
	// JS was analyzed in the original worker pool and is not downloaded again.
	if cfg.MaxSecretResources > 0 {
		emit(fmt.Sprintf("Inspecting up to %d observed HTML/JSON/config resources for redacted secret indicators", cfg.MaxSecretResources))
		found, warnings, inspected := client.DiscoverSecretResources(ctx, sources, cfg.Workers, cfg.MaxSecretResources, cfg.MaxBody, detector, progress, emit)
		report.SecretFindings = append(report.SecretFindings, found...)
		report.Warnings = append(report.Warnings, warnings...)
		report.Statistics.SecretResourcesInspected = inspected
	}
	// Analyze JS before excluding static resources from the final endpoint list.
	beforeFilter := len(sources)
	sources = ContextualDedup(sources)
	emit(fmt.Sprintf("Filtering/static and contextual dedup: %d -> %d endpoint structures", beforeFilter, len(sources)))
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	var fresh map[string]bool
	if cfg.Diff {
		report.NewEndpoints = []string{}
		path := cfg.DiffDB
		if path == "" {
			path = ".funnelrecon.sqlite"
		}
		var err error
		fresh, err = SaveNewEndpoints(ctx, path, DiffScopeKey(scope), sources)
		if err != nil {
			return report, fmt.Errorf("diff database: %w", err)
		}
		for raw := range fresh {
			report.NewEndpoints = append(report.NewEndpoints, raw)
		}
		sort.Strings(report.NewEndpoints)
		report.Statistics.NewEndpoints = len(report.NewEndpoints)
		emit(fmt.Sprintf("Diff: %d new endpoint structures", len(report.NewEndpoints)))
	}
	keys := make([]string, 0, len(sources))
	for raw := range sources {
		keys = append(keys, raw)
	}
	sort.Strings(keys)
	for _, raw := range keys {
		signals, tags, risk := ClassifyWithTags(raw)
		if risk == "API DISCOVERY" {
			report.Statistics.NakedAPIs++
		}
		if len(signals) == 0 || (cfg.Diff && !fresh[raw]) {
			continue
		}
		ss := make([]string, 0, len(sources[raw]))
		for s := range sources[raw] {
			ss = append(ss, s)
		}
		sort.Strings(ss)
		report.Candidates = append(report.Candidates, Candidate{URL: raw, Source: ss, Signals: signals, Tags: tags, Risk: risk, Status: "unverified name/path heuristic; not a confirmed vulnerability"})
	}
	// Diff keys representative URL structures, not literal value samples.
	// Match POST action signatures against the *new* structure set as well.
	freshSignatures := map[string]bool{}
	if cfg.Diff {
		for raw := range fresh {
			if sig, ok := EndpointSignature(raw); ok {
				freshSignatures[sig] = true
			}
		}
	}
	// POST form field names are hints only. Preserve the HTTP method: never
	// synthesize or send a GET request with POST-only field names.
	postSeen := map[string]bool{}
	for _, form := range report.Forms {
		if form.Method != "POST" {
			continue
		}
		if cfg.Diff {
			sig, ok := EndpointSignature(form.Action)
			if !ok || !freshSignatures[sig] {
				continue
			}
		}
		signals, tags := FormInputSignals(form.Inputs)
		if len(tags) == 0 {
			continue
		}
		inputNames := make([]string, 0, len(form.Inputs))
		for _, input := range form.Inputs {
			inputNames = append(inputNames, input.Name)
		}
		key := form.Action + "\x00" + strings.Join(inputNames, "\x00")
		if postSeen[key] {
			continue
		}
		postSeen[key] = true
		report.Candidates = append(report.Candidates, Candidate{
			URL: form.Action, Method: "POST", Source: []string{"html-form"},
			Signals: signals, Tags: tags, Risk: "FORM INPUT LEAD",
			Status: "unverified HTML input name; no form submission performed",
		})
	}
	sort.Slice(report.Candidates, func(i, j int) bool {
		if report.Candidates[i].URL == report.Candidates[j].URL {
			return report.Candidates[i].Method < report.Candidates[j].Method
		}
		return report.Candidates[i].URL < report.Candidates[j].URL
	})
	sort.Slice(report.SecretFindings, func(i, j int) bool {
		a, b := report.SecretFindings[i], report.SecretFindings[j]
		return a.Source+a.Type+a.Fingerprint < b.Source+b.Type+b.Fingerprint
	})
	sort.Slice(report.JSFindings, func(i, j int) bool {
		a, b := report.JSFindings[i], report.JSFindings[j]
		return a.Source+a.Type+a.Fingerprint < b.Source+b.Type+b.Fingerprint
	})
	sort.Strings(report.Warnings)
	report.Statistics.URLs = len(sources)
	report.Statistics.Candidates = len(report.Candidates)
	report.Statistics.SecretIndicators = len(report.SecretFindings)
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	return report, nil
}
