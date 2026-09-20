// Bounded breadth-first HTML discovery. Do not automatically replay
// query-bearing URLs or generate paths that were not discovered in scope.
package scanner

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"funnelrecon/internal/utils"
)

var attributeRE = regexp.MustCompile(`(?i)\b(?:href|src|action)\s*=\s*["']([^"'<>]+)["']`)
var inlinePathRE = regexp.MustCompile(`["']((?:/api/|/v[0-9]+/|/graphql|/admin/)[^"'\s<>]{0,300})["']`)

func IsJS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasSuffix(strings.ToLower(u.Path), ".js")
}
func isPage(typ, raw string) bool {
	if strings.Contains(strings.ToLower(typ), "text/html") || strings.Contains(strings.ToLower(typ), "application/xhtml") {
		return true
	}
	// Some sites omit Content-Type; never interpret JS, JSON or binary extensions as HTML.
	return typ == "" && !IsJS(raw) && !strings.Contains(strings.ToLower(raw), ".json")
}
func ExtractLinks(base string, body []byte, scope utils.Scope) []string {
	u, err := url.Parse(base)
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	matches := attributeRE.FindAllSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			if s, ok := resolve(u, string(m[1]), scope); ok {
				set[s] = true
			}
		}
	}
	for _, m := range inlinePathRE.FindAllSubmatch(body, -1) {
		if len(m) > 1 {
			if s, ok := resolve(u, string(m[1]), scope); ok {
				set[s] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
}
func resolve(base *url.URL, ref string, scope utils.Scope) (string, bool) {
	ref = strings.TrimSpace(strings.ReplaceAll(ref, "&amp;", "&"))
	if ref == "" || strings.HasPrefix(ref, "#") {
		return "", false
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	return utils.NormalizeURL(base.ResolveReference(parsed).String(), scope)
}

// Crawl performs a breadth-first search. Only query-free GET pages are visited;
// query URLs are retained as evidence without replaying state-changing links.
func (c *Client) Crawl(ctx context.Context, seeds []string, workers, maxDepth, maxURLs int, progress func(done, total int)) map[string]string {
	discovered := map[string]string{}
	current := []string{}
	add := func(raw, source string) bool {
		normal, ok := utils.NormalizeURL(raw, c.Scope)
		if !ok {
			return false
		}
		if IsStaticAsset(normal) && !IsJS(normal) {
			return false
		}
		if _, exists := discovered[normal]; exists {
			return false
		}
		if len(discovered) >= maxURLs {
			return false
		}
		discovered[normal] = source
		return true
	}
	for _, seed := range seeds {
		if add(seed, "live") {
			current = append(current, seed)
		}
	}
	processed := 0
	type result struct{ links []string }
	for depth := 0; depth <= maxDepth && len(current) > 0; depth++ {
		work := make(chan string, workers)
		results := make(chan result, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for raw := range work {
					if ctx.Err() != nil {
						results <- result{}
						continue
					}
					u, e := url.Parse(raw)
					if e != nil || u.RawQuery != "" || IsJS(raw) {
						results <- result{}
						continue
					}
					body, typ, _, e := c.Fetch(ctx, raw, false, 1<<20)
					if e != nil || !isPage(typ, raw) {
						results <- result{}
						continue
					}
					results <- result{links: ExtractLinks(raw, body, c.Scope)}
				}
			}()
		}
		go func() {
			for _, v := range current {
				work <- v
			}
			close(work)
			wg.Wait()
			close(results)
		}()
		next := []string{}
		for r := range results {
			processed++
			for _, link := range r.links {
				if add(link, "crawl") {
					u, _ := url.Parse(link)
					if u.RawQuery == "" && !IsJS(link) && depth < maxDepth {
						next = append(next, link)
					}
				}
			}
			if progress != nil {
				progress(processed, len(discovered))
			}
		}
		current = next
	}
	return discovered
}
