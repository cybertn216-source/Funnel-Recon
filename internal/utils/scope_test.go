// Tests for scope behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package utils

import (
	"net"
	"strings"
	"testing"
)

func TestScopeBoundary(t *testing.T) {
	s, e := NewScope([]string{"example.com"}, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, h := range []string{"example.com", "api.example.com"} {
		if !s.Contains(h) {
			t.Fatalf("should allow %s", h)
		}
	}
	for _, h := range []string{"example.com.evil.org", "notexample.com", "evil.org"} {
		if s.Contains(h) {
			t.Fatalf("should block %s", h)
		}
	}
	exact, _ := NewScope([]string{"example.com"}, false)
	if exact.Contains("api.example.com") {
		t.Fatal("exact scope accepted subdomain")
	}
}
func TestNormalizeRedactsSecrets(t *testing.T) {
	s, _ := NewScope([]string{"example.com"}, true)
	u, ok := NormalizeURL("https://api.example.com/a?token=verysecret&id=4#frag", s)
	if !ok || strings.Contains(u, "verysecret") || strings.Contains(u, "#") || !strings.Contains(u, "id=4") {
		t.Fatalf("bad normalized URL: %q", u)
	}
	if _, ok = NormalizeURL("https://api.example.com.evil.net/", s); ok {
		t.Fatal("scope bypass")
	}
}
func TestPublicIP(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "fd00::1"} {
		if PublicIP(net.ParseIP(ip)) {
			t.Errorf("allowed private IP %s", ip)
		}
	}
	if !PublicIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("blocked public IP")
	}
}

func TestRejectAlternatePorts(t *testing.T) {
	s, _ := NewScope([]string{"example.com"}, true)
	if _, ok := NormalizeURL("https://example.com:8443/private", s); ok {
		t.Fatal("unapproved alternate port accepted")
	}
	if _, ok := NormalizeURL("https://example.com:443/allowed", s); !ok {
		t.Fatal("default HTTPS port rejected")
	}
}
