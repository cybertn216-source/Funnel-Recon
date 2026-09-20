// Hostname and URL allowlists, query redaction and public-IP rules.
// Security-sensitive: update scope tests when changing these guards.
package utils

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var dnsName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

// Scope is an explicit allowlist. Domain mode includes subdomains; list mode does not.
type Scope struct {
	roots      []string
	Subdomains bool
}

func Host(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		raw = u.Hostname()
	}
	raw = strings.TrimSuffix(raw, ".")
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String(), nil
	}
	if len(raw) == 0 || len(raw) > 253 || strings.ContainsAny(raw, "/@?#\\ ") || !dnsName.MatchString(raw) || strings.Contains(raw, "..") {
		return "", errors.New("invalid hostname")
	}
	for _, part := range strings.Split(raw, ".") {
		if len(part) == 0 || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return "", errors.New("invalid DNS label")
		}
	}
	return raw, nil
}
func NewScope(hosts []string, subdomains bool) (Scope, error) {
	set := map[string]bool{}
	for _, h := range hosts {
		host, err := Host(h)
		if err != nil {
			return Scope{}, err
		}
		set[host] = true
	}
	if len(set) == 0 {
		return Scope{}, errors.New("empty scope")
	}
	roots := make([]string, 0, len(set))
	for h := range set {
		roots = append(roots, h)
	}
	sort.Strings(roots)
	return Scope{roots: roots, Subdomains: subdomains}, nil
}
func (s Scope) Hosts() []string { return append([]string(nil), s.roots...) }
func (s Scope) Contains(host string) bool {
	host, err := Host(host)
	if err != nil {
		return false
	}
	for _, root := range s.roots {
		if host == root || (s.Subdomains && strings.HasSuffix(host, "."+root)) {
			return true
		}
	}
	return false
}
func (s Scope) ContainsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.User == nil && s.Contains(u.Hostname())
}

var sensitiveKey = regexp.MustCompile(`(?i)(?:token|secret|password|passwd|api[_-]?key|authorization|auth|session|signature|credential|access[_-]?key|jwt|^code$)`)
var embeddedToken = regexp.MustCompile(`(?i)(?:AKIA|ASIA)[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)

func NormalizeURL(raw string, scope Scope) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || !scope.Contains(u.Hostname()) {
		return "", false
	}
	host, err := Host(u.Hostname())
	if err != nil {
		return "", false
	}
	if port := u.Port(); port != "" {
		if (u.Scheme == "http" && port != "80") || (u.Scheme == "https" && port != "443") {
			return "", false // No unapproved alternate ports in discovered URLs.
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u.Host = host
	u.Fragment = ""
	u.RawFragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	q := u.Query()
	for k, vals := range q {
		for i, v := range vals {
			if sensitiveKey.MatchString(k) || embeddedToken.MatchString(v) {
				vals[i] = "REDACTED"
			}
		}
		q[k] = vals
	}
	if u.RawQuery != "" {
		u.RawQuery = q.Encode()
	}
	return u.String(), true
}

// Deny non-public IP ranges even when a public DNS name resolves to one.
var blockedPrefixes = func() []netip.Prefix {
	raw := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "2001:db8::/32"}
	p := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p = append(p, netip.MustParsePrefix(s))
	}
	return p
}()

func PublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// RedactEmbeddedTokens removes credential-shaped strings from watch-only paths.
func RedactEmbeddedTokens(s string) string { return embeddedToken.ReplaceAllString(s, "REDACTED") }
