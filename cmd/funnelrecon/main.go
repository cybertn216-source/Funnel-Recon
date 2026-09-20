// Command funnelrecon owns CLI flags, terminal rendering, cancellation and exports.
// To add a flag: extend scanner.Config, register it here, validate in pipeline.Run,
// and document its traffic effects. Never print a raw matched credential.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"funnelrecon/internal/banner"
	"funnelrecon/internal/intelligence"
	"funnelrecon/internal/scanner"
	"funnelrecon/internal/secretanalyzer"
	"github.com/pterm/pterm"
)

// main connects CLI flags and terminal output to the scanner.Run pipeline.
func main() {
	cfg := scanner.Config{}
	flag.StringVar(&cfg.Domain, "d", "", "authorized root domain, includes subdomains")
	flag.StringVar(&cfg.List, "l", "", "file of exact authorized hosts (one per line)")
	flag.IntVar(&cfg.Workers, "workers", 12, "concurrent HTTP worker limit (1..128)")
	flag.IntVar(&cfg.RPS, "rps", 5, "global HTTP request rate per second (1..100)")
	flag.IntVar(&cfg.MaxHosts, "max-hosts", 50, "maximum enumerated hosts")
	flag.IntVar(&cfg.MaxURLs, "max-urls", 5000, "maximum unique discovered URLs")
	flag.IntVar(&cfg.MaxArchive, "max-archive", 100, "archive records per provider per host (0 disables)")
	flag.IntVar(&cfg.MaxJS, "max-js", 200, "maximum JavaScript files to analyze")
	flag.IntVar(&cfg.MaxFormPages, "max-form-pages", 50, "maximum query-free HTML pages to check for forms (0 disables; max 1000)")
	flag.IntVar(&cfg.MaxSecretResources, "max-secret-resources", 80, "additional observed, query-free text resources to inspect for redacted secret indicators (0 disables extra pass; JS still checked)")
	flag.IntVar(&cfg.MaxDepth, "depth", 2, "crawl depth (0..5)")
	flag.Int64Var(&cfg.MaxBody, "max-body", 8<<20, "maximum body bytes in memory per HTTP response")
	flag.DurationVar(&cfg.Timeout, "timeout", 12*time.Second, "per-request timeout")
	flag.BoolVar(&cfg.AllowPrivate, "allow-private", false, "permit private IPs (only for approved internal testing)")
	flag.BoolVar(&cfg.NoArchive, "no-archive", false, "disable historical archive lookups")
	flag.BoolVar(&cfg.Watcher, "watcher", false, "log every stage, HTTP request/status, discovery, and JS analysis (verbose)")
	flag.BoolVar(&cfg.Diff, "diff", false, "store endpoint structures in SQLite and show only unseen endpoints")
	flag.StringVar(&cfg.DiffDB, "diff-db", ".funnelrecon.sqlite", "SQLite history path for -diff")
	flag.StringVar(&cfg.Out, "o", "", "save candidate URLs to .txt or full report to .json")
	// Passive infrastructure enrichment does not automatically scan candidate origins.
	flag.BoolVar(&cfg.Intel, "intel", false, "collect bounded current DNS infrastructure observations")
	flag.BoolVar(&cfg.IntelOnly, "intel-only", false, "only run enumeration, host probe and infrastructure enrichment; skip crawl")
	flag.BoolVar(&cfg.DNSHistory, "dns-history", false, "query historical A/AAAA records (requires SECURITYTRAILS_API_KEY)")
	flag.BoolVar(&cfg.InternetDB, "internetdb", false, "opt-in passive IP-level ports, CPE and CVE references from Shodan")
	flag.StringVar(&cfg.KEVFile, "kev-file", "", "local CISA KEV JSON catalog to annotate IP-level CVE references")
	flag.IntVar(&cfg.MaxIntelHosts, "max-intel-hosts", 20, "maximum scoped hosts to enrich (1..500)")
	flag.IntVar(&cfg.MaxIntelIPs, "max-intel-ips", 30, "maximum public IPs to map (1..500)")
	flag.BoolVar(&cfg.VerifyPorts, "verify-ports", false, "opt-in bounded TCP connect checks; requires exact IP allowlist")
	flag.StringVar(&cfg.VerifyIPFile, "verify-ips", "", "file of explicitly authorized exact public IPs for -verify-ports")
	flag.StringVar(&cfg.TCPPorts, "ports", "80,443", "up to 16 comma-separated TCP ports when -verify-ports is enabled")
	flag.StringVar(&cfg.MapOut, "map", "", "export observed host/IP/CNAME relationships to Graphviz .dot file")
	authorized := flag.Bool("authorized", false, "confirm permission to scan every host in the chosen scope")
	flag.Usage = func() {
		banner.Print()
		fmt.Fprintln(os.Stderr, "FunnelRecon by SydneySpider — scoped URL reconnaissance\nUsage: funnelrecon -d example.com -authorized [-o findings.json]\n   or: funnelrecon -l hosts.txt -authorized [-o urls.txt]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if cfg.IntelOnly || cfg.DNSHistory || cfg.InternetDB || cfg.VerifyPorts || cfg.MapOut != "" {
		cfg.Intel = true
	}
	if cfg.VerifyPorts && cfg.VerifyIPFile == "" {
		fmt.Fprintln(os.Stderr, "-verify-ports requires -verify-ips with explicitly authorized public IPs")
		os.Exit(2)
	}
	if cfg.MapOut != "" && (!strings.HasSuffix(strings.ToLower(cfg.MapOut), ".dot") || cfg.MapOut == cfg.Out) {
		fmt.Fprintln(os.Stderr, "-map must be a distinct .dot file")
		os.Exit(2)
	}
	if !*authorized {
		fmt.Fprintln(os.Stderr, "Specify -authorized only when you have permission for the entire target scope.")
		flag.Usage()
		os.Exit(2)
	}
	if (cfg.Domain == "") == (cfg.List == "") {
		flag.Usage()
		os.Exit(2)
	}
	banner.Print()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var logMu sync.Mutex
	cfg.OnEvent = func(message string) {
		logMu.Lock()
		defer logMu.Unlock()
		fmt.Println(pterm.FgLightCyan.Sprint("[WATCH] ") + message)
	}
	stage := ""
	lineOpen := false
	progress := func(next string, done, total int) {
		if cfg.Watcher {
			cfg.OnEvent(fmt.Sprintf("%s %d/%d", next, done, total))
			return
		}
		if next != stage {
			if lineOpen {
				fmt.Println()
				lineOpen = false
			}
			stage = next
			pterm.Info.Println(next)
		}
		if total <= 0 {
			return
		}
		if next == "Crawl" {
			fmt.Printf("\r\033[2K%s", pterm.FgLightCyan.Sprint(fmt.Sprintf("Crawl: %d pages processed (limit %d)", done, total)))
		} else {
			width := 28
			filled := done * width / total
			if filled > width {
				filled = width
			}
			fmt.Printf("\r\033[2K%s", pterm.FgLightCyan.Sprint(fmt.Sprintf("%-11s [%s%s] %d/%d", next, strings.Repeat("█", filled), strings.Repeat("░", width-filled), done, total)))
		}
		lineOpen = true
	}
	report, err := scanner.Run(ctx, cfg, progress)
	if lineOpen {
		fmt.Println()
	}
	if err != nil {
		pterm.Error.Println(err)
		os.Exit(1)
	}
	pterm.Println(pterm.FgLightCyan.Sprint(fmt.Sprintf("Live hosts: %d | endpoint structures: %d | JS: %d | candidates: %d | takeover indicators: %d | redacted secrets: %d | forms: %d | potential APIs: %d", report.Statistics.LiveHosts, report.Statistics.URLs, report.Statistics.JSFiles, report.Statistics.Candidates, report.Statistics.TakeoverCandidates, report.Statistics.SecretIndicators, report.Statistics.Forms, report.Statistics.NakedAPIs)))
	if cfg.Diff {
		pterm.Info.Printf("New endpoint structures: %d (SQLite: %s)\n", len(report.NewEndpoints), cfg.DiffDB)
		for _, raw := range report.NewEndpoints {
			pterm.Println(pterm.FgLightCyan.Sprint("[NEW] ") + raw)
		}
	}
	for _, candidate := range report.Candidates {
		color := pterm.FgLightYellow
		if candidate.Risk == "HIGH SIGNAL" {
			color = pterm.FgLightRed
		}
		prefix := color.Sprint("["+candidate.Risk+"] ") + colorSignatureTags(candidate.Tags) + " "
		if candidate.Method != "" {
			prefix += candidate.Method + " "
		}
		if cfg.Diff {
			prefix = "  " + prefix
		} // -diff printed new endpoints above.
		pterm.Println(prefix + scanner.HighlightParameters(candidate.URL, func(key string) string { return pterm.FgLightRed.Sprint(key) }))
		pterm.Println("  " + strings.Join(candidate.Signals, ", "))
	}
	if !cfg.Diff {
		for _, s := range report.SecretFindings {
			pterm.Warning.Printf("[SECRET INDICATOR: REDACTED] %s | %s:%d | fingerprint %s | %s (not validated)\n", s.Type, s.Source, s.Line, s.Fingerprint, s.Confidence)
		}
	}
	if !cfg.Diff && len(report.SecretFindings) > 0 {
		// Category totals expose detection coverage without printing a value.
		for _, count := range secretanalyzer.CountByType(report.SecretFindings) {
			pterm.Info.Printf("Secret indicator category: %s = %d (unverified)\n", count.Type, count.Count)
		}
	}
	if !cfg.Diff {
		for _, t := range report.Takeovers {
			pterm.Warning.Printf("[POTENTIAL TAKEOVER - VERIFY] %s -> %s (%s): %s\n", t.Host, t.CNAME, t.Provider, t.Evidence)
		}
	}
	if report.Infrastructure != nil {
		i := report.Infrastructure
		pterm.Info.Printf("Infrastructure: DNS records=%d | public IP hypotheses=%d | passive port observations=%d | IP-level CVE references=%d\n", len(i.DNS), len(i.IPs), report.Statistics.PassivePorts, report.Statistics.CVEReferences)
		for _, p := range i.IPs {
			pterm.Println(pterm.FgLightCyan.Sprint("[INFRA - UNVERIFIED] ") + p.IP + " | " + p.Status + " | hosts: " + strings.Join(p.RelatedHosts, ","))
			if len(p.PassivePorts) > 0 {
				pterm.Info.Printf("  InternetDB passive ports: %v (third-party snapshot)\n", p.PassivePorts)
			}
			for _, cve := range p.CVEs {
				pterm.Warning.Printf("  [IP CVE REFERENCE, NOT VERIFIED] %s | KEV=%t\n", cve.ID, cve.KEV)
			}
		}
		for _, p := range i.VerifiedPorts {
			pterm.Info.Printf("TCP %s:%d: %s\n", p.IP, p.Port, p.Status)
		}
	}
	if len(report.Warnings) > 0 {
		pterm.Warning.Printf("%d source/request warnings (see JSON output for details)\n", len(report.Warnings))
	}
	if cfg.MapOut != "" {
		if report.Infrastructure == nil {
			pterm.Error.Println("No infrastructure data to map")
			os.Exit(1)
		}
		if err := intelligence.ExportDOT(cfg.MapOut, *report.Infrastructure); err != nil {
			pterm.Error.Println(err)
			os.Exit(1)
		}
		pterm.Info.Println("Wrote infrastructure map " + cfg.MapOut)
	}
	if cfg.Out != "" {
		if err := scanner.Export(cfg.Out, report); err != nil {
			pterm.Error.Println(err)
			os.Exit(1)
		}
		pterm.Info.Println("Wrote " + cfg.Out)
	}
}

// Only terminal formatting is colored; JSON/TXT retain plain-text tags/URLs.
// colorSignatureTags colors category names in terminal only, not exported URLs.
func colorSignatureTags(tags []string) string {
	colored := make([]string, 0, len(tags))
	for _, tag := range tags {
		label := "[" + tag + "]"
		switch tag {
		case "SQLi":
			colored = append(colored, pterm.FgLightYellow.Sprint(label))
		case "SSRF", "Open Redirect":
			colored = append(colored, pterm.FgLightRed.Sprint(label))
		case "IDOR":
			colored = append(colored, pterm.FgLightMagenta.Sprint(label))
		case "XSS":
			colored = append(colored, pterm.FgLightCyan.Sprint(label))
		case "LFI/Path Traversal":
			colored = append(colored, pterm.FgLightYellow.Sprint(label))
		default:
			colored = append(colored, pterm.FgLightBlue.Sprint(label))
		}
	}
	return strings.Join(colored, " ")
}
