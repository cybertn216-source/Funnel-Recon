// Passive Wayback/Common Crawl lookups. Archive URLs are leads, not proof
// the archived endpoint is live. Provider fetches use the shared HTTP limiter.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var indexID = regexp.MustCompile(`^CC-MAIN-[0-9]{4}-[0-9]{2}$`)

func (c *Client) LatestCommonCrawl(ctx context.Context) (string, error) {
	b, _, _, err := c.Fetch(ctx, "https://index.commoncrawl.org/collinfo.json", true, 2<<20)
	if err != nil {
		return "", err
	}
	var records []struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(b, &records); err != nil {
		return "", err
	}
	for _, r := range records {
		if indexID.MatchString(r.ID) {
			return "https://index.commoncrawl.org/" + r.ID + "-index", nil
		}
	}
	return "", fmt.Errorf("no usable Common Crawl index")
}
func (c *Client) Archive(ctx context.Context, host, index string, limit int) ([]string, []string) {
	if limit < 1 {
		return nil, nil
	}
	type reply struct {
		urls   []string
		err    error
		source string
	}
	ch := make(chan reply, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		q := url.Values{"url": {host + "/*"}, "output": {"json"}, "fl": {"original"}, "collapse": {"urlkey"}, "limit": {strconv.Itoa(limit)}}
		b, _, _, err := c.Fetch(ctx, "https://web.archive.org/cdx/search/cdx?"+q.Encode(), true, 8<<20)
		if err != nil {
			ch <- reply{err: err, source: "Wayback"}
			return
		}
		var rows [][]string
		if err = json.Unmarshal(b, &rows); err != nil {
			ch <- reply{err: err, source: "Wayback"}
			return
		}
		urls := make([]string, 0)
		for i, r := range rows {
			if i == 0 || len(r) == 0 {
				continue
			}
			urls = append(urls, r[0])
			if len(urls) >= limit {
				break
			}
		}
		ch <- reply{urls: urls, source: "Wayback"}
	}()
	go func() {
		defer wg.Done()
		if index == "" {
			ch <- reply{source: "Common Crawl"}
			return
		}
		q := url.Values{"url": {host + "/*"}, "output": {"json"}, "pageSize": {strconv.Itoa(limit)}}
		b, _, _, err := c.Fetch(ctx, index+"?"+q.Encode(), true, 8<<20)
		if err != nil {
			ch <- reply{err: err, source: "Common Crawl"}
			return
		}
		urls := make([]string, 0)
		for _, line := range bytes.Split(b, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			var record struct {
				URL string `json:"url"`
			}
			if err = json.Unmarshal(line, &record); err != nil {
				continue
			}
			if record.URL != "" {
				urls = append(urls, record.URL)
			}
			if len(urls) >= limit {
				break
			}
		}
		ch <- reply{urls: urls, source: "Common Crawl"}
	}()
	go func() { wg.Wait(); close(ch) }()
	urls := make([]string, 0)
	warnings := []string{}
	set := map[string]bool{}
	for r := range ch {
		if r.err != nil {
			warnings = append(warnings, fmt.Sprintf("%s for %s: %v", r.source, host, r.err))
			continue
		}
		for _, raw := range r.urls {
			if !set[raw] && strings.HasPrefix(raw, "http") {
				set[raw] = true
				urls = append(urls, raw)
			}
		}
	}
	return urls, warnings
}
