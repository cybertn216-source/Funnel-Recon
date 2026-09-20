// Add distinctive format signatures and assignment regexes here;
// update detector tests to cover both true matches and common placeholders.
package secretanalyzer

import "regexp"

// Compile each regex once: goroutines may safely reuse regexp.Regexp objects.
// Format rules identify distinctive provider strings; generic rules require a
// contextual assignment to avoid labeling every random ID as a credential.
var (
	awsAccessID = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	jwtPattern  = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	githubToken = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,255}\b`)
	gitlabToken = regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,255}\b`)
	slackToken  = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,200}\b`)
	stripeKey   = regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{20,255}\b`)
	// Accept only named private-key PEM blocks; public keys/certificates are not secrets.
	privateKey = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]{32,}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)
	// An assignment is a stronger signal than a bare random-looking string.
	// 1 = variable/property name, 2 = quote, 3 = possible value. Do not log 3.
	assignment = regexp.MustCompile(`(?i)["']?\b(api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|aws[_-]?secret[_-]?access[_-]?key|db[_-]?password|database[_-]?password|password|passwd|pwd)\b["']?\s*[:=]\s*["'\x60]([^"'\x60\r\n]{12,256})["'\x60]`)
	// Match connection strings as candidates only; detector.go checks for an
	// actual non-empty password and avoids anonymous or publicly usable URLs.
	connectionURI = regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^\s"'<>\x60]{8,}`)
)

// FormatRule binds a stable, human-readable label to its recognition pattern.
// New provider formats belong here, not inside the scanner pipeline.
type FormatRule struct {
	Name    string
	Pattern *regexp.Regexp
}

var formatRules = []FormatRule{
	{"AWS access key ID", awsAccessID},
	{"JWT-shaped token", jwtPattern},
	{"GitHub token format", githubToken},
	{"GitLab token format", gitlabToken},
	{"Slack token format", slackToken},
	{"Stripe secret-key format", stripeKey},
	{"Private key block", privateKey},
}
