package intelligence

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"funnelrecon/internal/utils"
)

// NetResolver converts standard DNS answers to the small Resolver interface.
type NetResolver struct{}

func (NetResolver) LookupIPAddr(ctx context.Context, host string) ([]IPAddr, error) {
	entries, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	out := make([]IPAddr, 0, len(entries))
	for _, e := range entries {
		out = append(out, IPAddr{IP: e.IP.String()})
	}
	return out, err
}
func (NetResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, host)
}

type hostResult struct {
	records  []DNSRecord
	warnings []string
}

// Collect performs current DNS first, then optional historical API reads.
// All hosts MUST have passed scanner.Scope.Contains prior to this call.
// All remote HTTPS requests go through the existing scoped, rate-limited Fetch.
func Collect(ctx context.Context, hosts []string, cfg Config, resolver Resolver, fetch Fetch, wait func(context.Context) error) (Report, error) {
	report := Report{Note: "Infrastructure intelligence is observational. Historical DNS does not prove a current origin or authorization. IP-level CVEs and ports may describe shared/CDN infrastructure, not this website.", DNS: []DNSRecord{}, IPs: []IPObservation{}}
	if cfg.MaxHosts < 1 || cfg.MaxHosts > 500 || cfg.MaxIPs < 1 || cfg.MaxIPs > 500 || cfg.Workers < 1 || cfg.Workers > 128 || cfg.TimeoutSeconds < 1 || cfg.TimeoutSeconds > 120 {
		return report, fmt.Errorf("invalid infrastructure limits")
	}
	if cfg.VerifyTCP && (cfg.VerifyIPsFile == "" || len(cfg.Ports) == 0 || wait == nil) {
		return report, fmt.Errorf("TCP verification requires exact -verify-ips file and -ports")
	}
	if cfg.History && cfg.HistoryKey == "" {
		report.Warnings = append(report.Warnings, "historical DNS requested but SECURITYTRAILS_API_KEY is unset; only current DNS will be collected")
	}
	kev, err := LoadKEV(cfg.KEVFile)
	if err != nil {
		return report, fmt.Errorf("KEV catalog: %w", err)
	}
	// Preserve caller order so scanner can prioritize the explicitly authorized
	// root(s) over a large alphabetically sorted subdomain enumeration.
	set := map[string]bool{}
	names := []string{}
	for _, h := range hosts {
		n, e := utils.Host(h)
		if e == nil && !set[n] {
			set[n] = true
			names = append(names, n)
		}
	}
	if len(names) > cfg.MaxHosts {
		report.Warnings = append(report.Warnings, fmt.Sprintf("infra host cap: retained %d of %d", cfg.MaxHosts, len(names)))
		names = names[:cfg.MaxHosts]
	}
	workers := cfg.Workers
	if workers > 4 {
		workers = 4
	}
	if workers > len(names) {
		workers = len(names)
	}
	jobs := make(chan string)
	results := make(chan hostResult, len(names))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				res := hostResult{}
				// An IP explicitly listed in the original scan scope is already an
				// address: do not issue nonsensical DNS lookups for it.
				if direct := net.ParseIP(host); direct != nil {
					if PublicAddress(host) {
						typ := "A"
						if direct.To4() == nil {
							typ = "AAAA"
						}
						res.records = append(res.records, DNSRecord{Host: host, Type: typ, Value: direct.String(), Source: "explicit scoped IP", Status: "explicit authorized IP address; service identity not verified"})
					}
					results <- res
					continue
				}
				queryCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
				addresses, e := resolver.LookupIPAddr(queryCtx, host)
				cancel()
				if e != nil {
					res.warnings = append(res.warnings, fmt.Sprintf("current DNS %s: lookup failed", host))
				}
				for _, entry := range addresses {
					if !PublicAddress(entry.IP) {
						continue
					}
					ip := net.ParseIP(entry.IP)
					t := "A"
					if ip.To4() == nil {
						t = "AAAA"
					}
					res.records = append(res.records, DNSRecord{Host: host, Type: t, Value: ip.String(), Source: "current resolver", Status: "current DNS target; may be CDN/shared"})
				}
				cnameCtx, cancelCNAME := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
				cname, e := resolver.LookupCNAME(cnameCtx, host)
				cancelCNAME()
				cname = strings.TrimSuffix(strings.ToLower(cname), ".")
				if e == nil && cname != "" && cname != host {
					if n, err := utils.Host(cname); err == nil {
						res.records = append(res.records, DNSRecord{Host: host, Type: "CNAME", Value: n, Source: "current resolver", Status: "current DNS alias; provider ownership not verified"})
					}
				}
				if cfg.History && cfg.HistoryKey != "" {
					for _, typ := range []string{"a", "aaaa"} {
						endpoint := "https://api.securitytrails.com/v1/history/" + url.PathEscape(host) + "/dns/" + typ
						body, _, _, e := fetch(ctx, endpoint, true, 2<<20)
						if e != nil {
							res.warnings = append(res.warnings, fmt.Sprintf("SecurityTrails history %s %s: request failed: %v", host, typ, e))
							continue
						}
						parsed, e := ParseHistory(host, typ, body, 20)
						if e != nil {
							res.warnings = append(res.warnings, fmt.Sprintf("SecurityTrails history %s %s: invalid response", host, typ))
							continue
						}
						res.records = append(res.records, parsed...)
					}
				}
				results <- res
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, h := range names {
			select {
			case jobs <- h:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	seen := map[string]bool{}
	for result := range results {
		report.Warnings = append(report.Warnings, result.warnings...)
		for _, r := range result.records {
			key := r.Host + "|" + r.Type + "|" + r.Value + "|" + r.Source + "|" + r.FirstSeen + "|" + r.LastSeen
			if !seen[key] {
				seen[key] = true
				report.DNS = append(report.DNS, r)
			}
		}
	}
	sort.Slice(report.DNS, func(i, j int) bool {
		a, b := report.DNS[i], report.DNS[j]
		return a.Host+a.Type+a.Value+a.Source+a.FirstSeen < b.Host+b.Type+b.Value+b.Source+b.FirstSeen
	})
	// Prefer CURRENT DNS IPs within the cap, then historical-only addresses.
	ordered := []string{}
	states := map[string]*IPObservation{}
	for _, historical := range []bool{false, true} {
		for _, r := range report.DNS {
			if r.Type != "A" && r.Type != "AAAA" {
				continue
			}
			isHistorical := strings.Contains(r.Status, "historical")
			if isHistorical != historical {
				continue
			}
			p := states[r.Value]
			if p == nil {
				if len(states) >= cfg.MaxIPs {
					continue
				}
				p = &IPObservation{IP: r.Value, Status: "historical-only association; not a confirmed origin"}
				states[r.Value] = p
				ordered = append(ordered, r.Value)
			}
			if !isHistorical {
				p.Status = "current DNS address; could be CDN/shared"
			}
			p.Sources = uniqueSorted(append(p.Sources, r.Source))
			p.RelatedHosts = uniqueSorted(append(p.RelatedHosts, r.Host))
		}
	}
	sort.Strings(ordered)
	for _, ip := range ordered {
		report.IPs = append(report.IPs, *states[ip])
	}
	if cfg.InternetDB {
		// Historical-only addresses are deliberately not enriched: they may have
		// been reassigned to someone else since the historical observation.
		for i := range report.IPs {
			p := &report.IPs[i]
			if strings.Contains(p.Status, "historical-only") {
				continue
			}
			body, _, status, e := fetch(ctx, "https://internetdb.shodan.io/"+url.PathEscape(p.IP), true, 1<<20)
			if status == 404 {
				report.Warnings = append(report.Warnings, "InternetDB has no record for "+p.IP)
				continue
			}
			if e != nil {
				report.Warnings = append(report.Warnings, "InternetDB "+p.IP+": lookup failed")
				continue
			}
			enriched, e := ParseInternetDB(p.IP, body, kev)
			if e != nil {
				report.Warnings = append(report.Warnings, "InternetDB "+p.IP+": invalid response")
				continue
			}
			p.PassivePorts = enriched.PassivePorts
			p.CPEs = enriched.CPEs
			p.CVEs = enriched.CVEs
			p.Dataset = enriched.Dataset
		}
	}
	if cfg.VerifyTCP {
		allowed, e := ReadIPAllowlist(cfg.VerifyIPsFile)
		if e != nil {
			return report, fmt.Errorf("TCP allowlist: %w", e)
		}
		// ONLY current DNS IPs explicitly enumerated in the user's separate
		// IP allowlist are eligible. Historical IPs are never active targets.
		for _, p := range report.IPs {
			if !allowed[p.IP] || strings.Contains(p.Status, "historical-only") {
				continue
			}
			for _, port := range cfg.Ports {
				if ctx.Err() != nil {
					break
				}
				if e := wait(ctx); e != nil {
					break
				}
				dialctx, cancel := context.WithTimeout(ctx, time.Second)
				conn, e := (&net.Dialer{}).DialContext(dialctx, "tcp", net.JoinHostPort(p.IP, fmt.Sprint(port)))
				cancel()
				status := "not reachable / filtered / timed out"
				if e == nil {
					status = "TCP connect succeeded; service identity unknown"
					conn.Close()
				}
				report.VerifiedPorts = append(report.VerifiedPorts, PortObservation{IP: p.IP, Port: port, Status: status})
			}
		}
	}
	sort.Slice(report.VerifiedPorts, func(i, j int) bool {
		a, b := report.VerifiedPorts[i], report.VerifiedPorts[j]
		if a.IP == b.IP {
			return a.Port < b.Port
		}
		return a.IP < b.IP
	})
	sort.Strings(report.Warnings)
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	return report, nil
}
func uniqueSorted(ss []string) []string {
	set := map[string]bool{}
	for _, s := range ss {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ReadIPAllowlist requires exact PUBLIC IPv4/IPv6 addresses, not CIDRs or
// hostnames, to prevent broadening a domain authorization to a provider ASN.
func ReadIPAllowlist(path string) (map[string]bool, error) {
	st, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if st.Size() > 64<<10 {
		return nil, fmt.Errorf("allowlist too large")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	out := map[string]bool{}
	for i, raw := range strings.Split(string(b), "\n") {
		v := strings.TrimSpace(raw)
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		if !PublicAddress(v) {
			return nil, fmt.Errorf("line %d: not an exact public IP", i+1)
		}
		out[net.ParseIP(v).String()] = true
		if len(out) > 128 {
			return nil, fmt.Errorf("allowlist exceeds 128 IPs")
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty allowlist")
	}
	return out, nil
}

// ParsePorts rejects ranges, duplicates, and large port lists. No default
// active probing occurs and user-provided ports never expand crawler scope.
func ParsePorts(raw string) ([]int, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 16 {
		return nil, fmt.Errorf("maximum 16 TCP ports")
	}
	seen := map[int]bool{}
	ports := []int{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("empty port")
		}
		var n int
		if _, e := fmt.Sscanf(p, "%d", &n); e != nil || fmt.Sprint(n) != p || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		if !seen[n] {
			ports = append(ports, n)
			seen[n] = true
		}
	}
	sort.Ints(ports)
	return ports, nil
}
