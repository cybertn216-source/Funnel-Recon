// Tests for secrets behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"funnelrecon/internal/secretanalyzer"
	"funnelrecon/internal/utils"
)

// TestSecretResourceEligibility proves that the optional pass will not replay
// query strings, fetch passive-only historical URLs, or re-download JS.
func TestSecretResourceEligibility(t *testing.T) {
	cases := []struct {
		url     string
		origins map[string]bool
		want    bool
	}{
		{"https://example.com/config.json", map[string]bool{"crawl": true}, true},
		{"https://example.com/", map[string]bool{"live": true}, true},
		{"https://example.com/config.json", map[string]bool{"archive": true}, false},
		{"https://example.com/config.json?id=2", map[string]bool{"crawl": true}, false},
		{"https://example.com/app.js", map[string]bool{"crawl": true}, false},
		{"https://example.com/api/users", map[string]bool{"crawl": true}, false},
		{"https://example.com/logout", map[string]bool{"crawl": true}, false},
	}
	for _, tc := range cases {
		if got := secretResourceEligible(tc.url, tc.origins); got != tc.want {
			t.Errorf("eligible(%s) = %t; want %t", tc.url, got, tc.want)
		}
	}
}

// TestSecretScanFetchesOnlyObservedText exercises the new pass with an
// in-memory local server, NOT an actual third-party bug-bounty target.
func TestSecretScanFetchesOnlyObservedText(t *testing.T) {
	var fetched atomic.Int64
	secret := "AKIA" + strings.Repeat("P", 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"aws_access_key_id":"` + secret + `"}`))
	}))
	defer server.Close()
	scope, err := utils.NewScope([]string{"127.0.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(scope, 100, 3*time.Second, true, 1<<20)
	defer client.Close()
	detector, err := secretanalyzer.New()
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]map[string]bool{
		server.URL + "/config.json":   {"crawl": true},
		server.URL + "/ignored.js":    {"crawl": true},
		server.URL + "/archived.json": {"archive": true},
	}
	found, warnings, inspected := client.DiscoverSecretResources(context.Background(), sources, 2, 5, 1<<20, detector, nil, nil)
	if len(warnings) != 0 || inspected != 1 || fetched.Load() != 1 || len(found) != 1 {
		t.Fatalf("unexpected scan: inspected=%d requests=%d found=%d warnings=%v", inspected, fetched.Load(), len(found), warnings)
	}
	if strings.Contains(found[0].Fingerprint, secret) || found[0].Type != "AWS access key ID" {
		t.Fatal("secret output exposure or incorrect finding")
	}
}
