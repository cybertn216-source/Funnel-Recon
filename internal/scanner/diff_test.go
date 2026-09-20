// Tests for diff behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"funnelrecon/internal/utils"
)

func TestSQLiteDiffHistory(t *testing.T) {
	driver := false
	for _, name := range sql.Drivers() {
		if name == "sqlite3" {
			driver = true
		}
	}
	if !driver {
		t.Skip("real SQLite driver unavailable in offline dependency shim")
	}
	dbPath := filepath.Join(t.TempDir(), "history.sqlite")
	scope, _ := utils.NewScope([]string{"example.org"}, true)
	first := map[string]map[string]bool{
		"https://example.org/api?id=1":  {"crawl": true},
		"https://example.org/?file=abc": {"archive": true},
	}
	newOnFirst, err := SaveNewEndpoints(context.Background(), dbPath, DiffScopeKey(scope), first)
	if err != nil || len(newOnFirst) != 2 {
		t.Fatalf("first scan: %v %v", newOnFirst, err)
	}
	newOnSecond, err := SaveNewEndpoints(context.Background(), dbPath, DiffScopeKey(scope), map[string]map[string]bool{
		"https://example.org/api?id=99":   {"crawl": true},
		"https://example.org/?file=other": {"crawl": true},
		"https://example.org/new?url=x":   {"crawl": true},
	})
	if err != nil || len(newOnSecond) != 1 || !newOnSecond["https://example.org/new?url=x"] {
		t.Fatalf("second scan: %v %v", newOnSecond, err)
	}
	scope2, _ := utils.NewScope([]string{"example.org"}, false)
	newInDifferentScope, err := SaveNewEndpoints(context.Background(), dbPath, DiffScopeKey(scope2), first)
	if err != nil || len(newInDifferentScope) != 2 {
		t.Fatalf("scope partition: %v %v", newInDifferentScope, err)
	}
	if st, err := os.Stat(dbPath); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("unsafe database permissions: %v %v", st, err)
	}
}
