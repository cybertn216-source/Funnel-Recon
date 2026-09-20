// Tests for detector behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package secretanalyzer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDetectRedactsAndFindsSeveralFormats(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	aws := "AKIA" + strings.Repeat("B", 16)
	gh := "ghp_" + strings.Repeat("zQ7a", 10)
	uri := "postgres://app:uQ6rT9vW2xY5zA8b@db.example.com/app"
	data := []byte("const aws='" + aws + "';\nconst github='" + gh + "';\nconst client_secret = 'qF8nB2tL7pR5zX9v';\nconst db='" + uri + "';")
	findings := d.Detect("https://example.com/app.js", data)
	if len(findings) != 4 {
		t.Fatalf("expected four indicators, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Fingerprint == "" || f.Status == "" || f.Line == 0 || strings.Contains(f.Fingerprint, aws) || strings.Contains(f.Fingerprint, gh) {
			t.Fatalf("unsafe finding: %+v", f)
		}
	}
	// A process-local HMAC cannot be correlated across runs.
	other, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if d.Detect("x", []byte(aws))[0].Fingerprint == other.Detect("x", []byte(aws))[0].Fingerprint {
		t.Fatal("fingerprint was not keyed")
	}
}

func TestFalsePositivesAndContentGuard(t *testing.T) {
	d, _ := New()
	body := []byte(`const api_key="YOUR_API_KEY_HERE"; const password="aaaaaaaaaaaaaaaa"; const url="https://example.com"; sk_test_` + strings.Repeat("A", 24))
	if findings := d.Detect("x", body); len(findings) != 0 {
		t.Fatalf("unexpected placeholders: %+v", findings)
	}
	if TextResource("image/png", []byte("fake text")) || TextResource("text/html", []byte{'a', 0, 'b'}) || !TextResource("application/json; charset=utf-8", []byte(`{"a":1}`)) {
		t.Fatal("MIME guard broken")
	}
}

func TestEntropy(t *testing.T) {
	if ShannonEntropy("aaaaaaaaaaaaaaaa") != 0 || ShannonEntropy("aB3dE5fG7hJ9") < 3 {
		t.Fatal("entropy calculation")
	}
}

// TestAdditionalFormatsAndJSONRedaction keeps every new output field free of
// raw values. All strings in these test fixtures are synthetic and unusable.
func TestAdditionalFormatsAndJSONRedaction(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	awsSecret := "qW7tY4pL9vR2sN8fG5hJ1kC6bX3mZ0aD7eF4uT9r"
	pem := "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("Q2FmZVRlc3Q=", 6) + "\n-----END PRIVATE KEY-----"
	values := []string{
		"glpat-" + strings.Repeat("9rTx", 8),
		"xoxb-" + strings.Repeat("7jKp", 9),
		"sk_live_" + strings.Repeat("kR9z", 8),
		pem,
		awsSecret,
	}
	body := strings.Join([]string{
		`const token = "` + values[0] + `";`,
		`const slack = "` + values[1] + `";`,
		`const stripe = "` + values[2] + `";`,
		`const pem = "` + values[3] + `";`,
		`const aws_secret_access_key = "` + values[4] + `";`,
	}, "\n")
	findings := d.Detect("https://example.com/test.js", []byte(body))
	if len(findings) < 5 {
		t.Fatalf("expected provider, PEM, and AWS-secret indicators, found %d: %+v", len(findings), findings)
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if strings.Contains(string(encoded), value) {
			t.Fatal("raw credential string entered exported JSON")
		}
	}
}

// TestNoPasswordlessURIs avoids mistaking a public endpoint for leaked DB creds.
func TestNoPasswordlessURIs(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`postgres://db.example.com/app redis://localhost:6379/0`)
	if got := d.Detect("https://example.com/page", body); len(got) != 0 {
		t.Fatalf("password-free URIs are not leaked credentials: %+v", got)
	}
}

// TestSafeSourceURL prevents a source URL from becoming a side channel for a
// credential accidentally embedded in an asset path or query parameter.
func TestSafeSourceURL(t *testing.T) {
	token := "ghp_" + strings.Repeat("A7bQ", 8)
	source := "https://example.com/assets/" + token + ".js?token=" + token
	clean := SafeSource(source)
	if strings.Contains(clean, token) || strings.Contains(clean, "?token=") {
		t.Fatalf("source contains possible credential: %s", clean)
	}
	if SafeSource("not-a-url") != "[source unavailable]" {
		t.Fatal("invalid source should not be printed verbatim")
	}
}
