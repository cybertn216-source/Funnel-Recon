// Five user-defined vulnerability-parameter dictionaries and API hints.
// Tags indicate parameter names, not proof of an exploitable vulnerability.
package scanner

import (
	"net/url"
	"sort"
	"strings"
)

// VulnerabilitySignatures intentionally follows the requested name-based
// dictionary. A match is a research lead, never evidence of exploitability.
// Keep original overlapping entries: one parameter may carry multiple tags.
var VulnerabilitySignatures = map[string][]string{
	"LFI/Path Traversal":   {"file", "document", "folder", "root", "path", "pg", "style", "pdf", "template", "dir_path", "doc", "page", "lang"},
	"SSRF / Open Redirect": {"dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to"},
	"SQLi":                 {"id", "user", "q", "search", "category", "sort", "select", "update", "query", "username", "pass", "order", "keyword", "list"},
	"XSS":                  {"q", "s", "search", "id", "lang", "keyword", "query", "page", "kw", "year", "view", "email", "type", "name", "p", "month", "image", "list"},
	"IDOR":                 {"user_id", "account_id", "invoice_id", "order_id", "profile_id", "receipt", "token", "uuid"},
}

// Preserve previously recognized aliases without altering the requested five
// dictionary groups. They are still unverified name-only leads.
var supplementalSignatures = map[string][]string{
	"target":       {"SSRF", "Open Redirect"},
	"destination":  {"SSRF", "Open Redirect"},
	"webhook":      {"SSRF"},
	"redirect_url": {"Open Redirect"},
	"returnurl":    {"Open Redirect"},
	"filename":     {"LFI/Path Traversal"},
	"filepath":     {"LFI/Path Traversal"},
	"include":      {"LFI/Path Traversal"},
	"item":         {"SQLi"},
}

var signatureGroups = []struct {
	category string
	tags     []string
}{
	{"LFI/Path Traversal", []string{"LFI/Path Traversal"}},
	{"SSRF / Open Redirect", []string{"SSRF", "Open Redirect"}},
	{"SQLi", []string{"SQLi"}},
	{"XSS", []string{"XSS"}},
	{"IDOR", []string{"IDOR"}},
}

// ParameterTags matches complete, case-insensitive names (never substrings).
func ParameterTags(key string) []string {
	result := []string{}
	key = strings.ToLower(strings.TrimSpace(key))
	for _, group := range signatureGroups {
		for _, name := range VulnerabilitySignatures[group.category] {
			if key == name {
				result = append(result, group.tags...)
				break
			}
		}
	}
	return append(result, supplementalSignatures[key]...)
}

const APITag = "Potential API - Needs Fuzzing"

// IsPotentialAPI identifies likely API paths, not an invitation to send fuzzing
// payloads. Paths with any query parameters are not "naked".
func IsPotentialAPI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.RawQuery != "" {
		return false
	}
	path := strings.ToLower(u.EscapedPath())
	if IsStaticAsset(raw) {
		return false
	}
	if strings.HasPrefix(strings.ToLower(u.Hostname()), "api.") && path != "/" {
		return true
	}
	if path == "/api" || strings.HasPrefix(path, "/api/") || path == "/graphql" || strings.HasPrefix(path, "/graphql/") || path == "/rest" || strings.HasPrefix(path, "/rest/") || path == "/rpc" || strings.HasPrefix(path, "/rpc/") {
		return true
	}
	// A versioned top-level route is only a hint; avoid generic /v1 by itself.
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && len(parts[0]) >= 2 && len(parts[0]) <= 4 && parts[0][0] == 'v' {
		digits := parts[0][1:]
		for _, ch := range digits {
			if ch < '0' || ch > '9' {
				return false
			}
		}
		return parts[1] != ""
	}
	return false
}

// ClassifyWithTags reports every matching category and parameter name without
// testing any payloads. A query-free API path receives the distinct API tag.
func ClassifyWithTags(raw string) (signals, tags []string, risk string) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, nil, ""
	}
	keys := make([]string, 0, len(u.Query()))
	for key := range u.Query() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	tagSet := map[string]bool{}
	for _, key := range keys {
		for _, tag := range ParameterTags(key) {
			signals = append(signals, tag+" (parameter: "+key+")")
			if !tagSet[tag] {
				tags = append(tags, tag)
				tagSet[tag] = true
			}
		}
	}
	if len(tags) > 0 {
		return signals, tags, "HIGH SIGNAL"
	}
	if IsPotentialAPI(raw) {
		return []string{"API-like path with no observed query parameters"}, []string{APITag}, "API DISCOVERY"
	}
	return nil, nil, ""
}

// Classify preserves the original two-return API for callers.
func Classify(raw string) ([]string, string) {
	signals, _, risk := ClassifyWithTags(raw)
	return signals, risk
}

// FormInputSignals classifies names found in HTML without inventing query
// strings for POST forms. Input values and form bodies are never retained.
func FormInputSignals(inputs []FormInput) (signals, tags []string) {
	set := map[string]bool{}
	ordered := append([]FormInput(nil), inputs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	for _, input := range ordered {
		for _, tag := range ParameterTags(input.Name) {
			signals = append(signals, tag+" (form input: "+input.Name+")")
			if !set[tag] {
				tags = append(tags, tag)
				set[tag] = true
			}
		}
	}
	return signals, tags
}
