// SQLite endpoint-history logic; store structural signatures only.
// The diff engine reports new URLs; it does not reduce active scan traffic.
package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"funnelrecon/internal/utils"
	_ "github.com/mattn/go-sqlite3"
)

// DiffScopeKey isolates history for the exact authorized scope and scope mode.
func DiffScopeKey(scope utils.Scope) string {
	mode := "exact"
	if scope.Subdomains {
		mode = "subdomains"
	}
	return mode + ":" + strings.Join(scope.Hosts(), "\x00")
}

// SaveNewEndpoints commits a completed scan in a single SQLite transaction.
// Its returned set contains only previously unseen endpoint structures.
func SaveNewEndpoints(ctx context.Context, path, scopeKey string, sources map[string]map[string]bool) (map[string]bool, error) {
	if path == "" {
		return nil, fmt.Errorf("diff database path cannot be empty")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS endpoints (
		scope TEXT NOT NULL, signature TEXT NOT NULL, url TEXT NOT NULL,
		first_seen TEXT NOT NULL, PRIMARY KEY (scope, signature)
	)`); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO endpoints (scope, signature, url, first_seen) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	keys := make([]string, 0, len(sources))
	for raw := range sources {
		keys = append(keys, raw)
	}
	sort.Strings(keys)
	fresh := make(map[string]bool)
	when := time.Now().UTC().Format(time.RFC3339)
	for _, raw := range keys {
		sig, ok := EndpointSignature(raw)
		if !ok {
			continue
		}
		result, err := stmt.ExecContext(ctx, scopeKey, sig, raw, when)
		if err != nil {
			return nil, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if rows > 0 {
			fresh[raw] = true
		}
	}
	if err := stmt.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return fresh, nil
}
