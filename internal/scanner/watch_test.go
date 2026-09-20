// Tests for watch behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import (
	"net/url"
	"strings"
	"testing"
)

func TestWatchURLRedactsValues(t *testing.T) {
	secret := "AKIA" + strings.Repeat("X", 16)
	u, _ := url.Parse("https://example.org/" + secret + "/api?token=TOPSECRET&id=43")
	got := safeWatchURL(u)
	if strings.Contains(got, secret) || strings.Contains(got, "TOPSECRET") || strings.Contains(got, "id=43") {
		t.Fatal("watcher leaked secret or query values: " + got)
	}
	if !strings.Contains(got, "token") || !strings.Contains(got, "id") {
		t.Fatal("watcher hid parameter names: " + got)
	}
}
