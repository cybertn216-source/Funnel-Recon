// TXT/JSON report export. Treat findings as sensitive metadata and
// keep restrictive file permissions; never introduce a raw credential field.
package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Export(path string, report Report) error {
	if path == "" {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".txt" && ext != ".json" {
		return fmt.Errorf("output must end with .txt or .json")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	if ext == ".json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		if report.DiffEnabled {
			for _, raw := range report.NewEndpoints {
				if _, err := fmt.Fprintln(w, raw); err != nil {
					return err
				}
			}
		} else {
			seenURLs := map[string]bool{}
			for _, candidate := range report.Candidates {
				if seenURLs[candidate.URL] {
					continue
				}
				seenURLs[candidate.URL] = true
				if _, err := fmt.Fprintln(w, candidate.URL); err != nil {
					return err
				}
			}
		}
	}
	return w.Flush()
}
