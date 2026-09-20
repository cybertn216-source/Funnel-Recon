// Tests for takeover behavior. Use synthetic
// fixtures and local httptest servers rather than third-party targets.
package scanner

import "testing"

func TestTakeoverProviderBoundaries(t *testing.T) {
	cases := map[string]string{
		"abc.github.io.":                             "GitHub Pages",
		"abc.herokudns.com.":                         "Heroku",
		"abc.herokuapp.com.":                         "Heroku",
		"bucket.s3.amazonaws.com.":                   "AWS S3",
		"bucket.s3-website-us-east-1.amazonaws.com.": "AWS S3",
		"test.cloudfront.net.":                       "AWS CloudFront",
		"github.io.attacker.org.":                    "",
		"notgithub.io.":                              "",
		"foo.other.com.":                             "",
	}
	for name, want := range cases {
		if got := takeoverProvider(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

func TestTakeoverEvidenceRequiresSpecific404OrUnresolved(t *testing.T) {
	if got := takeoverEvidence("AWS S3", 404, []byte(`<Error><Code>NoSuchBucket</Code></Error>`), false); got == "" {
		t.Fatal("missed S3")
	}
	if got := takeoverEvidence("GitHub Pages", 404, []byte("There isn't a GitHub Pages site here."), false); got == "" {
		t.Fatal("missed GitHub Pages")
	}
	if got := takeoverEvidence("Heroku", 404, []byte("No such app"), false); got == "" {
		t.Fatal("missed Heroku")
	}
	if got := takeoverEvidence("AWS S3", 200, []byte("NoSuchBucket"), false); got != "" {
		t.Fatal("flagged HTTP 200")
	}
	if got := takeoverEvidence("GitHub Pages", 404, []byte("ordinary application 404"), false); got != "" {
		t.Fatal("generic 404 flagged")
	}
	if got := takeoverEvidence("Heroku", 0, nil, true); got == "" {
		t.Fatal("missed unresolved alias")
	}
}
