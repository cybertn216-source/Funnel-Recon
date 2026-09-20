package intelligence

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// EscapeDOT quotes untrusted DNS labels before graph rendering. No shell is run.
func EscapeDOT(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return "\"" + s + "\""
}

// ExportDOT renders host -> IP / CNAME provenance, visually separating
// historical dotted edges from present-day solid edges. Historical edges
// are associations, not a discovered "real origin" or ownership assertion.
func ExportDOT(path string, report Report) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	if _, err = fmt.Fprintln(w, "digraph FunnelRecon {\n  rankdir=LR;\n  graph [label=\"FunnelRecon infrastructure observations (unverified)\"];\n  node [shape=box];"); err != nil {
		return err
	}
	records := append([]DNSRecord(nil), report.DNS...)
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		return a.Host+a.Source+a.Value < b.Host+b.Source+b.Value
	})
	for _, r := range records {
		style := "solid"
		if strings.Contains(r.Status, "historical") {
			style = "dashed"
		}
		label := r.Type + " | " + r.Source
		if r.FirstSeen != "" || r.LastSeen != "" {
			label += " | " + r.FirstSeen + " .. " + r.LastSeen
		}
		if _, err = fmt.Fprintf(w, "  %s -> %s [label=%s, style=%s];\n", EscapeDOT(r.Host), EscapeDOT(r.Value), EscapeDOT(label), style); err != nil {
			return err
		}
	}
	if _, err = fmt.Fprintln(w, "}"); err != nil {
		return err
	}
	return w.Flush()
}
