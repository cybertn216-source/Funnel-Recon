package intelligence

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"

	"funnelrecon/internal/utils"
)

// PublicAddress rejects private, link-local, test-network, multicast and other
// forbidden IPs using the same address policy as the original HTTP client.
func PublicAddress(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && utils.PublicIP(ip)
}

// ParseHistory decodes SecurityTrails v1 history records. Provider schema
// variations are tolerated; invalid and private entries are discarded.
func ParseHistory(host, recordType string, body []byte, limit int) ([]DNSRecord, error) {
	if recordType != "a" && recordType != "aaaa" {
		return nil, fmt.Errorf("unsupported history type")
	}
	var payload struct {
		Records []struct {
			FirstSeen string `json:"first_seen"`
			LastSeen  string `json:"last_seen"`
			Values    []struct {
				IP    string `json:"ip"`
				Value string `json:"value"`
			} `json:"values"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("invalid history JSON: %w", err)
	}
	if limit < 1 {
		return nil, nil
	}
	seen := map[string]bool{}
	results := []DNSRecord{}
	for _, record := range payload.Records {
		for _, value := range record.Values {
			ip := value.IP
			if ip == "" {
				ip = value.Value
			}
			if !PublicAddress(ip) {
				continue
			}
			ip = net.ParseIP(ip).String()
			key := ip + "|" + record.FirstSeen + "|" + record.LastSeen
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, DNSRecord{Host: host, Type: strings.ToUpper(recordType), Value: ip, Source: "SecurityTrails historical DNS", FirstSeen: safeDate(record.FirstSeen), LastSeen: safeDate(record.LastSeen), Status: "historical association; unverified, may be shared or reassigned"})
			if len(results) >= limit {
				return results, nil
			}
		}
	}
	return results, nil
}

var plausibleDate = regexp.MustCompile(`^[0-9TZ:+. -]{1,40}$`)

// safeDate excludes untrusted control characters from provider timestamps.
func safeDate(s string) string {
	s = strings.TrimSpace(s)
	if !plausibleDate.MatchString(s) {
		return ""
	}
	return s
}

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// ParseInternetDB only preserves fields needed for IP-level risk triage. Do
// not copy hostnames from InternetDB: they can belong to unrelated tenants.
func ParseInternetDB(ip string, body []byte, kev map[string]bool) (IPObservation, error) {
	var payload struct {
		IP    string   `json:"ip"`
		Ports []int    `json:"ports"`
		CPEs  []string `json:"cpes"`
		Vulns []string `json:"vulns"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return IPObservation{}, err
	}
	if !PublicAddress(ip) || payload.IP != ip {
		return IPObservation{}, fmt.Errorf("IP mismatch in provider response")
	}
	o := IPObservation{IP: ip, Dataset: "Shodan InternetDB (third-party snapshot)", Status: "third-party IP observation; not verified on target"}
	ports := map[int]bool{}
	for _, p := range payload.Ports {
		if p > 0 && p <= 65535 {
			ports[p] = true
		}
	}
	for p := range ports {
		o.PassivePorts = append(o.PassivePorts, p)
	}
	sort.Ints(o.PassivePorts)
	cpes := map[string]bool{}
	for _, c := range payload.CPEs {
		if len(c) > 0 && len(c) < 200 {
			cpes[c] = true
		}
	}
	for c := range cpes {
		o.CPEs = append(o.CPEs, c)
	}
	sort.Strings(o.CPEs)
	ids := map[string]bool{}
	for _, id := range payload.Vulns {
		if cveID.MatchString(id) {
			ids[id] = true
		}
	}
	for id := range ids {
		o.CVEs = append(o.CVEs, CVEReference{ID: id, KEV: kev[id], Status: "IP-level correlation only; verify product/version, tenancy and applicability"})
	}
	sort.Slice(o.CVEs, func(i, j int) bool { return o.CVEs[i].ID < o.CVEs[j].ID })
	return o, nil
}

// LoadKEV loads an already-downloaded CISA KEV JSON catalog, and does not
// access the internet. A cap prevents accidentally loading huge untrusted files.
func LoadKEV(path string) (map[string]bool, error) {
	out := map[string]bool{}
	if path == "" {
		return out, nil
	}
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if stat.Size() > 16<<20 {
		return nil, fmt.Errorf("KEV file too large")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cat struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, err
	}
	for _, v := range cat.Vulnerabilities {
		if cveID.MatchString(v.CVEID) {
			out[v.CVEID] = true
		}
	}
	return out, nil
}
