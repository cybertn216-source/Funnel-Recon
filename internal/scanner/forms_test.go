// Tests for forms behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"funnelrecon/internal/utils"
)

func TestExtractFormsScopedNeverStoresValues(t *testing.T) {
	scope, _ := utils.NewScope([]string{"example.org"}, false)
	source := `<!doctype html><html><body>
        <form method="POST" action="/api/users?next=%2F">
            <input name="user_id" type="hidden" value="SECRET_VALUE">
            <input name="q" value="another secret"><input name="q" value="duplicate">
            <input name="bad&#10;name" value="no"><input disabled name="ignored" value="no">
            <select name="account_id"><option>data</option></select>
        </form><form action="https://external.test/steal"><input name="token"></form>
        <form action="/search"><input name="search"><input name="csrf_token" value="DONT_PRINT"></form>
        <form><input name="page" value="3"></form>
        </body></html>`
	forms := ExtractForms("https://example.org/landing", []byte(source), scope)
	if len(forms) != 3 {
		t.Fatalf("got %d forms: %+v", len(forms), forms)
	}
	if forms[0].Method != "POST" || forms[0].Action != "https://example.org/api/users?next=%2F" {
		t.Fatalf("POST form: %+v", forms[0])
	}
	names := []string{}
	for _, input := range forms[0].Inputs {
		names = append(names, input.Name)
	}
	if !reflect.DeepEqual(names, []string{"account_id", "q", "user_id"}) {
		t.Fatalf("names: %v", names)
	}
	for _, f := range forms {
		if strings.Contains(f.Action, "external") {
			t.Fatal("out of scope action accepted")
		}
		for _, input := range f.Inputs {
			if strings.Contains(input.Name, "SECRET") || strings.Contains(input.Type, "SECRET") {
				t.Fatal("stored secret value")
			}
		}
	}
	get := FormGETURL(forms[1])
	if get != "https://example.org/search?csrf_token=&search=" {
		t.Fatalf("GET form params %q", get)
	}
	if FormGETURL(forms[0]) != "" {
		t.Fatal("synthesized GET for POST")
	}
	if forms[2].Action != "https://example.org/landing" {
		t.Fatalf("missing action not resolved: %s", forms[2].Action)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDiscoverFormsBoundedReadOnly(t *testing.T) {
	scope, _ := utils.NewScope([]string{"example.org"}, false)
	c := NewClient(scope, 100, time.Second, false, 1024*1024)
	defer c.Close()
	calls := []string{}
	c.HTTP.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls = append(calls, req.Method+" "+req.URL.String())
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(`<form method="POST" action="/api/save"><input name="invoice_id" value="SECRET"></form>`))}, nil
	})
	sources := map[string]map[string]bool{
		"https://example.org/home":        {"crawl": true},
		"https://example.org/list?page=4": {"crawl": true},
		"https://example.org/logout":      {"crawl": true},
		"https://example.org/api/users":   {"crawl": true},
	}
	forms, warnings, checked := c.DiscoverForms(context.Background(), sources, 2, 10, nil, nil)
	if checked != 1 || len(warnings) != 0 || len(forms) != 1 {
		t.Fatalf("checked %d; warnings %v; forms %v", checked, warnings, forms)
	}
	if !reflect.DeepEqual(calls, []string{"GET https://example.org/home"}) {
		t.Fatalf("unexpected outbound request(s): %v", calls)
	}
	if forms[0].Method != "POST" || forms[0].Inputs[0].Name != "invoice_id" {
		t.Fatal("bad form extraction")
	}
}
