// Package intelligence adds bounded infrastructure enrichment to FunnelRecon.
// It deliberately distinguishes historical DNS associations from proven origins,
// and third-party CVE correlations from verified vulnerabilities.
package intelligence

import "context"

// Fetch is supplied by scanner.Client.Fetch, preserving its shared request
// limiter, public-IP checks, provider allowlist, redirect and response limits.
type Fetch func(context.Context, string, bool, int64) ([]byte, string, int, error)

// Resolver is replaceable for deterministic tests. Production uses net.DefaultResolver.
type Resolver interface {
	LookupIPAddr(context.Context, string) ([]IPAddr, error)
	LookupCNAME(context.Context, string) (string, error)
}

// IPAddr is the minimal testable representation of a resolved address.
type IPAddr struct{ IP string }

// Config limits how many scoped hosts and public IPs enrichment can inspect.
// Provider lookups are off unless explicitly enabled at the CLI.
type Config struct {
	Workers        int
	MaxHosts       int
	MaxIPs         int
	TimeoutSeconds int
	History        bool
	InternetDB     bool
	HistoryKey     string
	KEVFile        string
	VerifyTCP      bool
	VerifyIPsFile  string
	Ports          []int
}

// DNSRecord holds only DNS metadata. Historical data is not a claim of ownership.
type DNSRecord struct {
	Host      string `json:"host"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Source    string `json:"source"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Status    string `json:"status"`
}

// IPObservation correlates a public address with passive third-party observations.
// These CVEs belong to an IP-level dataset and MUST NOT be labeled as target bugs.
type IPObservation struct {
	IP           string         `json:"ip"`
	Sources      []string       `json:"sources"`
	RelatedHosts []string       `json:"related_hosts"`
	Status       string         `json:"status"`
	PassivePorts []int          `json:"passive_ports,omitempty"`
	CPEs         []string       `json:"cpes,omitempty"`
	CVEs         []CVEReference `json:"cve_references,omitempty"`
	Dataset      string         `json:"dataset,omitempty"`
}

// CVEReference is a dataset correlation, NOT an exploitability assertion.
type CVEReference struct {
	ID     string `json:"id"`
	KEV    bool   `json:"in_cisa_kev"`
	Status string `json:"status"`
}

// PortObservation contains an optional, allowlisted TCP connect result only.
type PortObservation struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Status string `json:"status"`
}

// Report is an optional additive JSON field: old report consumers can ignore it.
type Report struct {
	Note          string            `json:"note"`
	DNS           []DNSRecord       `json:"dns_records"`
	IPs           []IPObservation   `json:"ip_observations"`
	VerifiedPorts []PortObservation `json:"tcp_connect_checks,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
}
