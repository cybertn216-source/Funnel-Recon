// Offline redacted secret matching with HMAC fingerprints and false-positive
// filters; values remain function-local. Never add a value to Finding.
package secretanalyzer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// Finding is deliberately an allowlist: there is no Value, Snippet, or Match
// field. Source URLs should themselves be handled as potentially sensitive.
type Finding struct {
	Source      string `json:"source"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Line        int    `json:"line,omitempty"`
	Confidence  string `json:"confidence"`
	Status      string `json:"status"`
}

// Detector creates a random, process-local HMAC key. Fingerprints are useful
// for deduplication WITHIN ONE RUN, but cannot be used to guess weak passwords
// from a known, unsalted digest or correlate secrets across different runs.
type Detector struct{ fingerprintKey [32]byte }

func New() (*Detector, error) {
	d := new(Detector)
	_, err := rand.Read(d.fingerprintKey[:])
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Detect performs offline pattern/context matching on an already-fetched body.
// No credential leaves this function. The caller is responsible for scope,
// MIME-type checks, response limits and network rate limiting.
func (d *Detector) Detect(source string, body []byte) []Finding {
	if !utf8.Valid(body) || len(body) == 0 {
		return nil
	}
	text := string(body)
	// Precompute newline offsets so line numbers do not require re-scanning
	// the entire document for every finding in a minified multi-MB bundle.
	newlines := make([]int, 0, 128)
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			newlines = append(newlines, i)
		}
	}
	seen := make(map[string]Finding)
	add := func(kind, match, confidence string, offset int) {
		if len(seen) >= 200 || (kind != "Database/broker URI with embedded password" && placeholder(match)) {
			return
		}
		mac := hmac.New(sha256.New, d.fingerprintKey[:])
		mac.Write([]byte(match))
		fingerprint := hex.EncodeToString(mac.Sum(nil))[:16]
		key := kind + "\x00" + fingerprint
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = Finding{
			Source: SafeSource(source), Type: kind, Fingerprint: fingerprint,
			Line:       1 + sort.SearchInts(newlines, offset),
			Confidence: confidence,
			Status:     "unverified exposure indicator; no credential validation attempted",
		}
	}
	for _, rule := range formatRules {
		for _, loc := range rule.Pattern.FindAllStringIndex(text, 1000) {
			value := text[loc[0]:loc[1]]
			if rule.Name == "Private key block" && len(value) > 32768 {
				continue
			}
			// Stripe test keys are not production credentials; do not present as leaks.
			if rule.Name == "Stripe secret-key format" && strings.HasPrefix(value, "sk_test_") {
				continue
			}
			add(rule.Name, value, "format", loc[0])
		}
	}
	for _, loc := range assignment.FindAllStringSubmatchIndex(text, 1000) {
		name := strings.ToLower(text[loc[2]:loc[3]])
		value := text[loc[4]:loc[5]]
		// Ignore non-credential identifiers, demonstration strings, and likely
		// public build-time variables. For a generic value, high entropy plus
		// an explicit secret-like assignment are BOTH necessary.
		if !plausibleValue(value) {
			continue
		}
		kind := "Hardcoded secret-like assignment"
		if strings.Contains(name, "password") || name == "passwd" || name == "pwd" {
			kind = "Hardcoded password-like assignment"
		}
		if strings.Contains(name, "aws") && strings.Contains(name, "secret") {
			kind = "AWS secret access key-like assignment"
		}
		add(kind, value, "context + entropy", loc[4])
	}
	for _, loc := range connectionURI.FindAllStringIndex(text, 1000) {
		candidate := strings.TrimRight(text[loc[0]:loc[1]], `.,);]}`)
		if len(candidate) > 2048 {
			continue
		}
		u, err := url.Parse(candidate)
		if err != nil || u.User == nil {
			continue
		}
		password, exists := u.User.Password()
		if !exists || password == "" || placeholder(password) {
			continue
		}
		// Hash the URI for uniqueness but NEVER persist or display it.
		add("Database/broker URI with embedded password", candidate, "credential-bearing URI", loc[0])
	}
	found := make([]Finding, 0, len(seen))
	for _, finding := range seen {
		found = append(found, finding)
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].Source != found[j].Source {
			return found[i].Source < found[j].Source
		}
		if found[i].Line != found[j].Line {
			return found[i].Line < found[j].Line
		}
		return found[i].Type+found[i].Fingerprint < found[j].Type+found[j].Fingerprint
	})
	return found
}
