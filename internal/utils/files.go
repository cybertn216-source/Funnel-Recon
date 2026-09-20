// Read exact authorized host lists from disk; validate before scanning.
package utils

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

func ReadHosts(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := map[string]bool{}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 1024*1024)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, e := Host(line)
		if e != nil {
			return nil, fmt.Errorf("invalid host %q: %w", line, e)
		}
		set[h] = true
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(set))
	for h := range set {
		result = append(result, h)
	}
	sort.Strings(result)
	return result, nil
}
