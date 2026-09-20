// Safe aggregate reporting: counts only, never snippets or matched values.
package secretanalyzer

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

// TypeCount reports the number of indicators with one category label.
type TypeCount struct {
	Type  string
	Count int
}

// CountByType prepares deterministic, credential-free terminal summaries.
func CountByType(findings []Finding) []TypeCount {
	counts := map[string]int{}
	for _, finding := range findings {
		counts[finding.Type]++
	}
	result := make([]TypeCount, 0, len(counts))
	for kind, count := range counts {
		result = append(result, TypeCount{Type: kind, Count: count})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Type < result[j].Type })
	return result
}

// SafeSource strips query values and credential-shaped path segments from
// finding source locations. A redacted filename can reduce precision but is
// preferable to publishing a token that was embedded in an asset path.
func SafeSource(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "[source unavailable]"
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	segments := strings.Split(u.Path, "/")
	for i, segment := range segments {
		// Mask provider-format secrets even if they are short or low entropy.
		for _, rule := range formatRules {
			if rule.Pattern.MatchString(segment) {
				segment = "REDACTED"
				break
			}
		}
		stem := strings.TrimSuffix(segment, path.Ext(segment))
		if len(stem) >= 20 && ShannonEntropy(stem) >= 3.2 {
			segment = "REDACTED" + path.Ext(segment)
		}
		segments[i] = segment
	}
	u.Path = strings.Join(segments, "/")
	u.RawPath = ""
	return u.String()
}
