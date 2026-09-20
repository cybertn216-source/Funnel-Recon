// Static-asset filtering, context-aware URL dedup and colored parameter
// highlighting. Do not filter JavaScript before its analysis stage.
package scanner

import (
	"net/url"
	"sort"
	"strings"
)

// IsStaticAsset excludes non-endpoint resources from final results. JavaScript
// stays in discovery until after the existing JS analysis phase has completed.
func IsStaticAsset(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	path := strings.ToLower(u.Path)
	for _, suffix := range []string{
		".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif", ".tiff", ".avif", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wav", ".pdf",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// EndpointSignature ignores parameter values but keeps scheme, host, path and
// the sorted set of parameter names. Call only on already normalized scoped URLs.
func EndpointSignature(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	keys := make([]string, 0, len(u.Query()))
	for key := range u.Query() {
		keys = append(keys, url.QueryEscape(key))
	}
	sort.Strings(keys)
	return u.Scheme + "://" + strings.ToLower(u.Host) + u.EscapedPath() + "?" + strings.Join(keys, "&"), true
}

// ContextualDedup merges source attribution for equivalent parameter structures.
// Sort input to pick a stable representative URL across runs.
func ContextualDedup(sources map[string]map[string]bool) map[string]map[string]bool {
	keys := make([]string, 0, len(sources))
	for raw := range sources {
		keys = append(keys, raw)
	}
	sort.Strings(keys)
	chosen := make(map[string]string, len(keys))
	result := make(map[string]map[string]bool, len(keys))
	for _, raw := range keys {
		if IsStaticAsset(raw) {
			continue
		}
		sig, ok := EndpointSignature(raw)
		if !ok {
			continue
		}
		if representative, exists := chosen[sig]; exists {
			for source := range sources[raw] {
				result[representative][source] = true
			}
			continue
		}
		chosen[sig] = raw
		result[raw] = make(map[string]bool, len(sources[raw]))
		for source := range sources[raw] {
			result[raw][source] = true
		}
	}
	return result
}

// HighlightParameters adds terminal formatting to suspicious parameter names.
// The caller provides the color function; raw URLs are never modified in exports.
func HighlightParameters(raw string, color func(string) string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	prefix, _, _ := strings.Cut(raw, "?")
	parts := strings.Split(u.RawQuery, "&")
	for i, part := range parts {
		key, value, hasValue := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			continue
		}
		if len(ParameterTags(decoded)) > 0 {
			parts[i] = color(key)
			if hasValue {
				parts[i] += "=" + value
			}
		}
	}
	return prefix + "?" + strings.Join(parts, "&")
}
