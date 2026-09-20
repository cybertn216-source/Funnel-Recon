// Reject unsupported or binary HTTP content before regex scanning.
package secretanalyzer

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// TextResource gates content BEFORE calling Detect. MIME and extension are
// hints, not trust signals; reject binary and unsupported payloads even if a
// server mislabels them. Empty Content-Type is accepted only for text-looking
// bodies, which is common for older sites and local configuration files.
func TextResource(contentType string, body []byte) bool {
	if len(body) == 0 || !utf8.Valid(body) || bytes.IndexByte(body, 0) != -1 {
		return false
	}
	mime := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mime == "" || strings.HasPrefix(mime, "text/") || strings.Contains(mime, "json") || strings.Contains(mime, "javascript") || strings.Contains(mime, "xml") || strings.HasSuffix(mime, "+yaml") || strings.Contains(mime, "yaml") {
		return true
	}
	return false
}
