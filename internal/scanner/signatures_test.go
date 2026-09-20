// Tests for signatures behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import (
	"reflect"
	"testing"
)

func TestDictionaryExactAndOverlappingMatches(t *testing.T) {
	if !reflect.DeepEqual(ParameterTags("PAGE"), []string{"LFI/Path Traversal", "SSRF", "Open Redirect", "XSS"}) {
		t.Fatalf("missing overlapping PAGE tags: %v", ParameterTags("PAGE"))
	}
	if !reflect.DeepEqual(ParameterTags("id"), []string{"SQLi", "XSS"}) {
		t.Fatalf("id: %v", ParameterTags("id"))
	}
	if !reflect.DeepEqual(ParameterTags("user_id"), []string{"IDOR"}) {
		t.Fatal("user_id should be IDOR")
	}
	if len(ParameterTags("request_id")) != 0 || len(ParameterTags("sortBy")) != 0 {
		t.Fatal("substring matched as full name")
	}
	if !reflect.DeepEqual(ParameterTags("ReturnUrl"), []string{"Open Redirect"}) {
		t.Fatal("lost existing ReturnUrl detection")
	}
	if len(VulnerabilitySignatures) != 5 {
		t.Fatal("missing vulnerability groups")
	}
}

func TestClassifyWithTagsAndNakedAPI(t *testing.T) {
	signals, tags, risk := ClassifyWithTags("https://example.org/api/v1/users?id=1&redirect=%2F")
	if risk != "HIGH SIGNAL" || len(signals) != 4 || !reflect.DeepEqual(tags, []string{"SQLi", "XSS", "SSRF", "Open Redirect"}) {
		t.Fatalf("signals %v, tags %v risk %q", signals, tags, risk)
	}
	signals, tags, risk = ClassifyWithTags("https://example.org/api/v1/users")
	if risk != "API DISCOVERY" || len(signals) != 1 || !reflect.DeepEqual(tags, []string{APITag}) {
		t.Fatalf("naked API %v %v %s", signals, tags, risk)
	}
	for _, raw := range []string{"https://example.org/", "https://example.org/api/list?id=1", "https://example.org/static/app.js", "https://example.org/_next/image"} {
		if IsPotentialAPI(raw) {
			t.Fatalf("unexpected API: %q", raw)
		}
	}
	if !IsPotentialAPI("https://api.example.org/v2/items") || !IsPotentialAPI("https://example.org/graphql") {
		t.Fatal("missed API")
	}
}

func TestFormInputSignals(t *testing.T) {
	signals, tags := FormInputSignals([]FormInput{{Name: "user_id"}, {Name: "email"}, {Name: "csrf_token"}})
	if !reflect.DeepEqual(tags, []string{"XSS", "IDOR"}) || len(signals) != 2 {
		t.Fatalf("signals %v tags %v", signals, tags)
	}
}

func TestSupplementalHTMLFetchSafety(t *testing.T) {
	allowed := []string{"https://example.org/", "https://example.org/account", "https://example.org/login.html"}
	denied := []string{"https://example.org/api/users", "https://example.org/logout", "https://example.org/reset", "https://example.org/search?q=hi", "https://example.org/images/x.png", "https://example.org/report.json"}
	for _, raw := range allowed {
		if !safeHTMLFetchPath(raw) {
			t.Fatalf("safe HTML page was skipped: %q", raw)
		}
	}
	for _, raw := range denied {
		if safeHTMLFetchPath(raw) {
			t.Fatalf("unsafe supplemental GET permitted: %q", raw)
		}
	}
}
