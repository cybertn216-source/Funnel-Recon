// Tests for analyze behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package jsanalyzer

import (
	"strings"
	"testing"
)

func TestAnalyzeRedactsAndExtracts(t *testing.T) {
	key := "AKIA" + strings.Repeat("A", 16)
	jwt := "eyJ" + strings.Repeat("a", 10) + ".eyJ" + strings.Repeat("b", 10) + "." + strings.Repeat("c", 12)
	data := []byte(`fetch('/api/v1/users?id=2'); var key='` + key + `'; var jwt='` + jwt + `';`)
	endpoints, found := Analyze("https://example.com/app.js", data)
	if len(endpoints) != 1 || endpoints[0] != "/api/v1/users?id=2" {
		t.Fatalf("endpoints: %v", endpoints)
	}
	if len(found) != 2 {
		t.Fatalf("expected two secret indicators: %v", found)
	}
	for _, s := range found {
		if strings.Contains(s.Fingerprint, key) || strings.Contains(s.Fingerprint, jwt) || s.Fingerprint == "" {
			t.Fatal("credential leaked")
		}
	}
}
