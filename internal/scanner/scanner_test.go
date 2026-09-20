// Tests for scanner behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import (
	"context"
	"funnelrecon/internal/utils"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	signals, risk := Classify("https://example.com/load?url=abc&id=1")
	if len(signals) != 4 || risk != "HIGH SIGNAL" {
		t.Fatalf("unexpected classification: %v %s", signals, risk)
	}
	if sig, _ := Classify("https://example.com/"); len(sig) != 0 {
		t.Fatal("plain URL flagged")
	}
}
func TestExtractScope(t *testing.T) {
	scope, _ := utils.NewScope([]string{"example.com"}, true)
	links := ExtractLinks("https://example.com/", []byte(`<a href="/api?id=1">x</a><script src="/assets/app.js"></script><a href="https://example.com.evil.io/steal">x</a>`), scope)
	if len(links) != 2 {
		t.Fatalf("unexpected links: %v", links)
	}
	for _, link := range links {
		if strings.Contains(link, "evil.io") {
			t.Fatal("scope escaped")
		}
	}
}
func TestRedirectScopeAndPrivateBlock(t *testing.T) {
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer outside.Close()
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.net/", http.StatusFound)
	}))
	defer inside.Close()
	scope, _ := utils.NewScope([]string{"127.0.0.1"}, false)
	private := NewClient(scope, 100, 3*time.Second, false, 2048)
	defer private.Close()
	_, _, _, err := private.Fetch(context.Background(), inside.URL, false, 2048)
	if err == nil {
		t.Fatal("private address bypassed")
	}
	permitted := NewClient(scope, 100, 3*time.Second, true, 2048)
	defer permitted.Close()
	_, _, _, err = permitted.Fetch(context.Background(), inside.URL, false, 2048)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected scoped redirect block, got %v", err)
	}
}
