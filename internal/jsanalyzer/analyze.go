// Legacy JavaScript route extraction and compatibility signatures. The v4
// secretanalyzer detects additional patterns; do not print matched values here.
package jsanalyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

type Secret struct {
	Source      string `json:"source"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	// Never persist the actual credential.
}

var endpointRE = regexp.MustCompile(`["'\x60]((?:https?://|/|\.\.?/|api/|v[0-9]+/)[^"'\x60\s<>\\]{1,400})["'\x60]`)
var awsRE = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
var jwtRE = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)

func Analyze(source string, data []byte) ([]string, []Secret) {
	text := string(data)
	urls := map[string]bool{}
	secrets := map[string]Secret{}
	for _, m := range endpointRE.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			urls[strings.ReplaceAll(m[1], `\/`, `/`)] = true
		}
	}
	for typ, re := range map[string]*regexp.Regexp{"AWS access key ID": awsRE, "JWT": jwtRE} {
		for _, m := range re.FindAllString(text, -1) {
			hash := sha256.Sum256([]byte(m))
			id := hex.EncodeToString(hash[:])[:12]
			secrets[typ+id] = Secret{Source: source, Type: typ, Fingerprint: id}
		}
	}
	out := make([]string, 0, len(urls))
	for u := range urls {
		out = append(out, u)
	}
	found := make([]Secret, 0, len(secrets))
	for _, s := range secrets {
		found = append(found, s)
	}
	return out, found
}
