// Tests for filter behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import (
	"reflect"
	"strings"
	"testing"
)

func TestEndpointSignatureDedupsValuesAndKeyOrder(t *testing.T) {
	a, ok := EndpointSignature("https://example.org/api?b=2&a=1")
	if !ok {
		t.Fatal("first URL rejected")
	}
	b, ok := EndpointSignature("https://example.org/api?a=9&b=100")
	if !ok || a != b {
		t.Fatalf("different signatures: %q %q", a, b)
	}
	c, _ := EndpointSignature("https://example.org/api?a=9&c=100")
	if a == c {
		t.Fatal("different parameter names were merged")
	}
	d, _ := EndpointSignature("http://example.org/api?a=9&b=100")
	if a == d {
		t.Fatal("schemes merged")
	}
}

func TestContextualDedupStaticFilteringAndAttribution(t *testing.T) {
	in := map[string]map[string]bool{
		"https://example.org/api?id=2":         {"archive": true},
		"https://example.org/api?id=1":         {"crawl": true},
		"https://example.org/api?file=x":       {"javascript": true},
		"https://example.org/site.css":         {"crawl": true},
		"https://example.org/app.js":           {"crawl": true},
		"https://example.org/logo.JPG?cache=1": {"archive": true},
	}
	got := ContextualDedup(in)
	if len(got) != 2 {
		t.Fatalf("wanted 2 structures, got %v", got)
	}
	if !reflect.DeepEqual(got["https://example.org/api?id=1"], map[string]bool{"crawl": true, "archive": true}) {
		t.Fatalf("lost source attribution: %v", got)
	}
	if IsStaticAsset("https://example.org/api?file=logo.png") {
		t.Fatal("filtered API query value")
	}
}

func TestHighlightParametersDoesNotModifyExports(t *testing.T) {
	raw := "https://example.org/x?id=1&url=abc&safe=2&redirect=here"
	got := HighlightParameters(raw, func(key string) string { return "<" + key + ">" })
	if !strings.Contains(got, "<url>=abc") || !strings.Contains(got, "<redirect>=here") || !strings.Contains(got, "safe=2") {
		t.Fatal(got)
	}
	if raw != "https://example.org/x?id=1&url=abc&safe=2&redirect=here" {
		t.Fatal("mutated URL")
	}
}
