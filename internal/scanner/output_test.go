// Tests for output behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExport(t *testing.T) {
	dir := t.TempDir()
	report := Report{Tool: "FunnelRecon", Creator: "SydneySpider", Candidates: []Candidate{{URL: "https://example.com/?id=1"}}}
	txt := filepath.Join(dir, "urls.txt")
	if err := Export(txt, report); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(txt)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "https://example.com/?id=1\n" {
		t.Fatalf("txt: %q", b)
	}
	st, err := os.Stat(txt)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %v, %v", st.Mode(), err)
	}
	js := filepath.Join(dir, "report.json")
	if err := Export(js, report); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(js)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err = json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Candidates) != 1 {
		t.Fatal("missing JSON candidate")
	}
	report.DiffEnabled = true
	report.NewEndpoints = []string{"https://example.com/new", "https://example.com/newer"}
	if err := Export(txt, report); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(txt)
	if err != nil || string(b) != "https://example.com/new\nhttps://example.com/newer\n" {
		t.Fatalf("diff TXT: %q, %v", b, err)
	}
	report.DiffEnabled = false
	report.Candidates = []Candidate{
		{URL: "https://example.com/api/save", Method: "GET"},
		{URL: "https://example.com/api/save", Method: "POST"},
	}
	if err := Export(txt, report); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(txt)
	if err != nil || string(b) != "https://example.com/api/save\n" {
		t.Fatalf("duplicate TXT URLs: %q %v", b, err)
	}
	if err := Export(filepath.Join(dir, "invalid.html"), report); err == nil || !strings.Contains(err.Error(), ".txt") {
		t.Fatal("invalid export extension accepted")
	}
}
