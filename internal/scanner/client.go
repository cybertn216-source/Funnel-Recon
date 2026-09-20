// Scoped HTTP client: redirect constraints, public-IP checks, timeouts,
// global request rate and bounded response bodies. All added fetches MUST
// call Client.Fetch; never use a default unscoped http.Get.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"funnelrecon/internal/utils"
)

type Client struct {
	HTTP         *http.Client
	Scope        utils.Scope
	limiter      <-chan time.Time
	ticker       *time.Ticker
	maxBody      int64
	allowPrivate bool
	OnEvent      func(string)
}

func NewClient(scope utils.Scope, rps int, timeout time.Duration, allowPrivate bool, maxBody int64) *Client {
	if rps < 1 {
		rps = 1
	}
	if rps > 100 {
		rps = 100
	}
	ticker := time.NewTicker(time.Second / time.Duration(rps))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{MaxIdleConns: 128, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 16, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: timeout / 2, ResponseHeaderTimeout: timeout, DisableCompression: false}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if allowPrivate || utils.PublicIP(ip) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
		}
		return nil, fmt.Errorf("no permitted address for %s", host)
	}
	c := &Client{Scope: scope, limiter: ticker.C, ticker: ticker, maxBody: maxBody, allowPrivate: allowPrivate}
	c.HTTP = &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if c.OnEvent != nil {
			c.OnEvent("REDIRECT " + safeWatchURL(req.URL))
		}
		if len(via) >= 3 {
			return errors.New("redirect limit exceeded")
		}
		// API provider redirects are allowed only to the original provider.
		original := via[0].URL.Hostname()
		if isProvider(original) {
			if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Hostname(), original) || req.URL.Port() != via[0].URL.Port() {
				return errors.New("provider redirected to another host")
			}
			return nil
		}
		if !scope.ContainsURL(req.URL.String()) || (!allowPrivate && unusualPort(req.URL)) {
			return errors.New("redirect escaped target scope")
		}
		return nil
	}}
	return c
}
func unusualPort(u *url.URL) bool {
	p := u.Port()
	return p != "" && !((u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443"))
}
func (c *Client) Close() { c.ticker.Stop(); c.HTTP.CloseIdleConnections() }

// Wait uses the SAME global request budget for optional explicit TCP connects.
func (c *Client) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.limiter:
		return nil
	}
}
func isProvider(h string) bool {
	switch h {
	case "crt.sh", "otx.alienvault.com", "web.archive.org", "index.commoncrawl.org", "api.securitytrails.com", "internetdb.shodan.io":
		return true
	}
	return false
}
func (c *Client) Fetch(ctx context.Context, raw string, provider bool, maxSize int64) ([]byte, string, int, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", 0, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, "", 0, errors.New("unsupported scheme")
	}
	if provider {
		if !isProvider(u.Hostname()) || u.Scheme != "https" {
			return nil, "", 0, errors.New("untrusted provider URL")
		}
	} else if !c.Scope.ContainsURL(raw) || (!c.allowPrivate && unusualPort(u)) {
		return nil, "", 0, errors.New("out-of-scope URL or nonstandard port")
	}
	if u.User != nil {
		return nil, "", 0, errors.New("credentialed URL rejected")
	}
	select {
	case <-ctx.Done():
		return nil, "", 0, ctx.Err()
	case <-c.limiter:
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, "", 0, err
	}
	if c.OnEvent != nil {
		c.OnEvent("GET " + safeWatchURL(u))
	}
	req.Header.Set("User-Agent", "FunnelRecon/0.1 (authorized security research; SydneySpider)")
	req.Header.Set("Accept", "text/html,application/json,application/javascript,text/javascript,*/*;q=0.5")
	if u.Hostname() == "api.securitytrails.com" {
		if key := os.Getenv("SECURITYTRAILS_API_KEY"); key != "" {
			req.Header.Set("APIKEY", key)
		}
	}
	if u.Hostname() == "otx.alienvault.com" {
		if key := os.Getenv("OTX_API_KEY"); key != "" {
			req.Header.Set("X-OTX-API-KEY", key)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		if c.OnEvent != nil {
			c.OnEvent("REQUEST ERROR " + safeWatchURL(u) + " (connection, timeout or scoped redirect)")
		}
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	if c.OnEvent != nil {
		c.OnEvent(fmt.Sprintf("HTTP %d %s", resp.StatusCode, safeWatchURL(u)))
	}
	if maxSize <= 0 || maxSize > c.maxBody {
		maxSize = c.maxBody
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, "", resp.StatusCode, err
	}
	if int64(len(body)) > maxSize {
		return nil, "", resp.StatusCode, fmt.Errorf("response over %s bytes", strconv.FormatInt(maxSize, 10))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return body, resp.Header.Get("Content-Type"), resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, resp.Header.Get("Content-Type"), resp.StatusCode, nil
}

// safeWatchURL avoids leaking credential-bearing query values in verbose output.
func safeWatchURL(u *url.URL) string {
	keys := make([]string, 0, len(u.Query()))
	for key := range u.Query() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	path := utils.RedactEmbeddedTokens(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	out := u.Scheme + "://" + u.Host + path
	if len(keys) > 0 {
		out += "?" + strings.Join(keys, "&") + "=[REDACTED values]"
	}
	return out
}

func safeWatchURLString(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	return safeWatchURL(u)
}
