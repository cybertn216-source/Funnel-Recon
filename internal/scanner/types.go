// Shared scan configuration and JSON report models. The v4 secret finding
// type excludes raw credential material by design.
package scanner

import (
	"funnelrecon/internal/intelligence"
	"funnelrecon/internal/jsanalyzer"
	"funnelrecon/internal/secretanalyzer"
	"time"
)

// Config holds bounded scan settings. New network features must expose a cap.
type Config struct {
	Domain             string
	List               string
	Workers            int
	RPS                int
	MaxHosts           int
	MaxURLs            int
	MaxArchive         int
	MaxJS              int
	MaxDepth           int
	Timeout            time.Duration
	MaxBody            int64
	MaxFormPages       int
	MaxSecretResources int // Additional observed HTML/JSON/config URLs to inspect; 0 disables this pass.
	AllowPrivate       bool
	NoArchive          bool
	Watcher            bool
	OnEvent            func(string)
	Diff               bool
	DiffDB             string
	Out                string
	// Additive infrastructure collection. Disabled unless -intel (or a subflag).
	Intel         bool
	IntelOnly     bool
	DNSHistory    bool
	InternetDB    bool
	KEVFile       string
	MaxIntelHosts int
	MaxIntelIPs   int
	VerifyPorts   bool
	VerifyIPFile  string
	TCPPorts      string
	MapOut        string
}

// Candidate is an unverified parameter/path lead, NOT a confirmed finding.
type Candidate struct {
	Method  string   `json:"method,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	URL     string   `json:"url"`
	Source  []string `json:"source"`
	Signals []string `json:"signals"`
	Risk    string   `json:"risk"`
	Status  string   `json:"status"`
}

// Statistics summarizes completed work and coverage limits.
type Statistics struct {
	DiscoveredHosts          int `json:"discovered_hosts"`
	LiveHosts                int `json:"live_hosts"`
	URLs                     int `json:"urls"`
	JSFiles                  int `json:"js_files_analyzed"`
	Candidates               int `json:"candidates"`
	SecretIndicators         int `json:"secret_indicators"`
	SecretResourcesInspected int `json:"secret_resources_inspected,omitempty"`
	TakeoverCandidates       int `json:"takeover_candidates"`
	NewEndpoints             int `json:"new_endpoints,omitempty"`
	HTMLPagesInspected       int `json:"html_pages_inspected,omitempty"`
	Forms                    int `json:"forms_discovered,omitempty"`
	NakedAPIs                int `json:"potential_apis,omitempty"`
	InfraRecords             int `json:"infrastructure_dns_records,omitempty"`
	InfraIPs                 int `json:"infrastructure_ips,omitempty"`
	PassivePorts             int `json:"passive_port_observations,omitempty"`
	CVEReferences            int `json:"unverified_ip_cve_references,omitempty"`
}

// Report contains redacted findings and scoped discovery metadata only.
type Report struct {
	Tool           string                   `json:"tool"`
	Creator        string                   `json:"creator"`
	ScannedAt      time.Time                `json:"scanned_at"`
	Scope          []string                 `json:"scope"`
	LiveHosts      []string                 `json:"live_hosts"`
	Statistics     Statistics               `json:"statistics"`
	Candidates     []Candidate              `json:"candidates"`
	Forms          []FormFinding            `json:"forms,omitempty"`
	JSFindings     []jsanalyzer.Secret      `json:"js_findings"`
	SecretFindings []secretanalyzer.Finding `json:"secret_findings"`
	Takeovers      []TakeoverFinding        `json:"takeover_findings,omitempty"`
	NewEndpoints   []string                 `json:"new_endpoints,omitempty"`
	DiffEnabled    bool                     `json:"diff_enabled,omitempty"`
	Warnings       []string                 `json:"warnings,omitempty"`
	Infrastructure *intelligence.Report     `json:"infrastructure,omitempty"`
}
