// Passive takeover indicators from DNS and recognizable provider errors.
// Never try to register or claim third-party services.
package scanner

import (
	"context"
	"errors"
	"net"
	"strings"
)

// TakeoverFinding is a passive/DNS + HTTP triage indicator, not proof of takeover.
type TakeoverFinding struct {
	Host     string `json:"host"`
	CNAME    string `json:"cname"`
	Provider string `json:"provider"`
	Evidence string `json:"evidence"`
	Status   string `json:"status"`
}

func takeoverProvider(cname string) string {
	name := strings.TrimSuffix(strings.ToLower(cname), ".")
	for _, rule := range []struct{ suffix, provider string }{
		{"github.io", "GitHub Pages"},
		{"herokudns.com", "Heroku"},
		{"herokuapp.com", "Heroku"},
		{"s3.amazonaws.com", "AWS S3"},
		{"elasticbeanstalk.com", "AWS Elastic Beanstalk"},
		{"cloudfront.net", "AWS CloudFront"},
	} {
		if name == rule.suffix || strings.HasSuffix(name, "."+rule.suffix) {
			return rule.provider
		}
	}
	// Region-specific bucket website endpoints, e.g. bucket.s3-website-us-east-1.amazonaws.com.
	if strings.HasSuffix(name, ".amazonaws.com") && (strings.Contains(name, ".s3-website-") || strings.Contains(name, ".s3-website.") || strings.HasPrefix(name, "s3-website-")) {
		return "AWS S3"
	}
	return ""
}

func takeoverEvidence(provider string, status int, body []byte, unresolved bool) string {
	if unresolved {
		return "CNAME exists but the hostname has no resolvable IP address"
	}
	if status != 404 && status != 410 {
		return ""
	}
	page := strings.ToLower(string(body))
	patterns := map[string][]string{
		"GitHub Pages":          {"there isn't a github pages site here", "there is no github pages site here"},
		"Heroku":                {"no such app", "there's nothing here, yet", "heroku | no such app"},
		"AWS S3":                {"nosuchbucket", "the specified bucket does not exist"},
		"AWS Elastic Beanstalk": {"404 not found", "not found"},
		"AWS CloudFront":        {"the request could not be satisfied"},
	}
	for _, marker := range patterns[provider] {
		if strings.Contains(page, marker) {
			return "provider-associated HTTP not-found response (" + provider + ")"
		}
	}
	return ""
}

// CheckTakeover sends at most two bounded HTTP GETs, and only to the approved
// hostname (never directly to the CNAME's third-party hostname).
func (c *Client) CheckTakeover(ctx context.Context, host, seed string) *TakeoverFinding {
	cname, err := net.DefaultResolver.LookupCNAME(ctx, host)
	if err != nil || strings.EqualFold(strings.TrimSuffix(cname, "."), host) {
		return nil
	}
	provider := takeoverProvider(cname)
	if provider == "" {
		return nil
	}
	finding := &TakeoverFinding{Host: host, CNAME: cname, Provider: provider, Status: "potential; manual verification required"}
	if _, err := net.DefaultResolver.LookupIPAddr(ctx, host); err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			finding.Evidence = takeoverEvidence(provider, 0, nil, true)
			return finding
		}
		return nil // timeout/SERVFAIL/cancellation is not proof of dangling DNS
	}
	urls := []string{"https://" + host + "/", "http://" + host + "/"}
	if seed != "" {
		urls = []string{seed}
	}
	for _, raw := range urls {
		body, _, status, _ := c.Fetch(ctx, raw, false, 64<<10)
		if evidence := takeoverEvidence(provider, status, body, false); evidence != "" {
			finding.Evidence = evidence
			return finding
		}
		if status != 0 { // a real response is evidence; do not switch to HTTP unnecessarily
			break
		}
	}
	return nil
}
