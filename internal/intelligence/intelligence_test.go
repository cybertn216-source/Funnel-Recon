package intelligence

// Tests use synthetic public addresses, mocked DNS and mocked HTTP fetches.
// No test contacts a real domain, scans a port or uses a real API key.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testResolver struct{}

func (testResolver) LookupIPAddr(_ context.Context, h string) ([]IPAddr, error) {
	if h == "app.example.org" {
		return []IPAddr{{IP: "8.8.8.8"}, {IP: "127.0.0.1"}}, nil
	}
	return []IPAddr{{IP: "9.9.9.9"}}, nil
}
func (testResolver) LookupCNAME(_ context.Context, h string) (string, error) {
	if h == "app.example.org" {
		return "edge.vendor.example.", nil
	}
	return h + ".", nil
}

func TestPublicAddressesAndHistory(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.0.2.4", "2001:db8::1", "not-an-ip"} {
		if PublicAddress(ip) {
			t.Errorf("blocked IP accepted: %s", ip)
		}
	}
	if !PublicAddress("8.8.8.8") || !PublicAddress("2606:4700:4700::1111") {
		t.Fatal("public IP rejected")
	}
	data := []byte(`{"records":[{"first_seen":"2022-01-01","last_seen":"2023-01-01","values":[{"ip":"1.1.1.1"},{"ip":"10.0.0.1"}]}]}`)
	recs, e := ParseHistory("app.example.org", "a", data, 10)
	if e != nil || len(recs) != 1 || recs[0].Value != "1.1.1.1" || !strings.Contains(recs[0].Status, "unverified") {
		t.Fatalf("history: %+v, %v", recs, e)
	}
	if _, e = ParseHistory("app.example.org", "txt", data, 10); e == nil {
		t.Fatal("unsupported history allowed")
	}
}

func TestInternetDBAndKEV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kev.json")
	if e := os.WriteFile(path, []byte(`{"vulnerabilities":[{"cveID":"CVE-2024-12345"}]}`), 0600); e != nil {
		t.Fatal(e)
	}
	kev, e := LoadKEV(path)
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte(`{"ip":"8.8.8.8","ports":[443,80,443,-1],"cpes":["cpe:/a:example:app:1"],"vulns":["CVE-2024-12345","bad-cve"]}`)
	obs, e := ParseInternetDB("8.8.8.8", payload, kev)
	if e != nil || len(obs.PassivePorts) != 2 || obs.PassivePorts[0] != 80 || len(obs.CVEs) != 1 || !obs.CVEs[0].KEV {
		t.Fatalf("parsed: %+v %v", obs, e)
	}
	if _, e = ParseInternetDB("1.1.1.1", payload, kev); e == nil {
		t.Fatal("provider IP mismatch accepted")
	}
}

func TestMappingAndActiveGuard(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow.txt")
	if e := os.WriteFile(allow, []byte("8.8.8.8\n"), 0600); e != nil {
		t.Fatal(e)
	}
	allowed, e := ReadIPAllowlist(allow)
	if e != nil || !allowed["8.8.8.8"] {
		t.Fatal(e)
	}
	if e := os.WriteFile(allow, []byte("8.8.8.0/24\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadIPAllowlist(allow); e == nil {
		t.Fatal("CIDR allowed as exact ownership")
	}
	if _, e = ParsePorts("1-65535"); e == nil {
		t.Fatal("port range accepted")
	}
	if _, e = ParsePorts("80,443,65536"); e == nil {
		t.Fatal("invalid port accepted")
	}
	p, e := ParsePorts("443,80,443")
	if e != nil || len(p) != 2 || p[0] != 80 {
		t.Fatalf("ports: %v %v", p, e)
	}
	graph := filepath.Join(dir, "map.dot")
	if e := ExportDOT(graph, Report{DNS: []DNSRecord{{Host: "app.example.org", Value: "8.8.8.8", Type: "A", Source: "current resolver", Status: "current DNS target"}, {Host: "app.example.org", Value: "1.1.1.1", Type: "A", Source: "history", Status: "historical association"}}}); e != nil {
		t.Fatal(e)
	}
	body, e := os.ReadFile(graph)
	if e != nil || !strings.Contains(string(body), "style=dashed") || !strings.Contains(string(body), "style=solid") {
		t.Fatalf("graph: %s %v", body, e)
	}
	stat, _ := os.Stat(graph)
	if stat.Mode().Perm() != 0600 {
		t.Fatal("graph not private")
	}
	if EscapeDOT("evil\" -> bad") != "\"evil\\\" -> bad\"" {
		t.Fatal("DOT escaping broken")
	}
}

func TestCollectProviderBoundariesAndCorrelation(t *testing.T) {
	var requested []string
	fetch := func(_ context.Context, endpoint string, provider bool, _ int64) ([]byte, string, int, error) {
		if !provider {
			t.Fatal("unscoped fetch")
		}
		requested = append(requested, endpoint)
		if strings.Contains(endpoint, "securitytrails") {
			if strings.HasSuffix(endpoint, "/a") {
				return []byte(`{"records":[{"first_seen":"2021-01-01","values":[{"ip":"1.1.1.1"}]}]}`), "application/json", 200, nil
			}
			return []byte(`{"records":[]}`), "application/json", 200, nil
		}
		if endpoint != "https://internetdb.shodan.io/8.8.8.8" {
			t.Fatalf("historical-only IP queried: %s", endpoint)
		}
		return []byte(`{"ip":"8.8.8.8","ports":[443],"vulns":["CVE-2024-12345"]}`), "application/json", 200, nil
	}
	cfg := Config{Workers: 2, MaxHosts: 2, MaxIPs: 3, TimeoutSeconds: 2, History: true, HistoryKey: "dummy", InternetDB: true}
	result, e := Collect(context.Background(), []string{"app.example.org"}, cfg, testResolver{}, fetch, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(result.DNS) != 3 {
		t.Fatalf("DNS: %+v", result.DNS)
	}
	if len(result.IPs) != 2 {
		t.Fatalf("IPs: %+v", result.IPs)
	}
	for _, entry := range result.IPs {
		if entry.IP == "1.1.1.1" && (len(entry.CVEs) != 0 || !strings.Contains(entry.Status, "historical")) {
			t.Fatalf("historical enriched: %+v", entry)
		}
	}
	if len(requested) != 3 {
		t.Fatalf("calls: %v", requested)
	}
	encoded, e := json.Marshal(result)
	if e != nil || !strings.Contains(string(encoded), "cve_references") {
		t.Fatalf("JSON: %s %v", encoded, e)
	}
}

func TestCollectRejectsActiveWithoutExplicitAllowlist(t *testing.T) {
	_, e := Collect(context.Background(), []string{"app.example.org"}, Config{Workers: 1, MaxHosts: 1, MaxIPs: 1, TimeoutSeconds: 1, VerifyTCP: true, Ports: []int{80}}, testResolver{}, nil, nil)
	if e == nil {
		t.Fatal("TCP verification did not require explicit allowlist and limiter")
	}
}
