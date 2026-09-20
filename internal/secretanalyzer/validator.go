// Offline false-positive suppression; no API calls or authentication.
package secretanalyzer

import "strings"

// placeholder keeps common sample and redacted values out of reported leads.
// It is intentionally conservative, and cannot distinguish every fake key.
func placeholder(value string) bool {
	s := strings.ToLower(strings.TrimSpace(value))
	if len(s) < 8 {
		return true
	}
	for _, marker := range []string{"example", "sample", "placeholder", "redacted", "changeme", "replace", "dummy", "your_", "your-", "xxxx", "testtoken", "notasecret", "undefined", "localhost", "${", "{{"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func plausibleValue(value string) bool {
	if placeholder(value) || strings.HasPrefix(value, "http") || strings.Contains(value, "//") || strings.Contains(value, "/api/") {
		return false
	}
	return ShannonEntropy(value) >= 3.2
}
