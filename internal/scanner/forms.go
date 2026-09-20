// Optional HTML form parser and constrained supplemental GET pass.
// It records form input NAMES, never values, and never submits forms.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"funnelrecon/internal/utils"
	"golang.org/x/net/html"
)

// FormInput intentionally excludes values, placeholders, cookies, and bodies.
// Name is the only value needed for a parameter-name heuristic.
type FormInput struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type FormFinding struct {
	Page   string      `json:"page"`
	Action string      `json:"action"`
	Method string      `json:"method"`
	Inputs []FormInput `json:"inputs"`
}

func htmlAttr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

// ExtractForms parses an already-fetched HTML response; it NEVER submits forms.
// Actions are resolved relative to the fetched page and restricted to scope.
func ExtractForms(page string, body []byte, scope utils.Scope) []FormFinding {
	base, err := url.Parse(page)
	if err != nil {
		return nil
	}
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	forms := make([]FormFinding, 0)
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if len(forms) >= 30 {
			return
		}
		if node.Type == html.ElementNode && node.Data == "form" {
			action, exists := htmlAttr(node, "action")
			if !exists || strings.TrimSpace(action) == "" {
				action = page
			}
			if strings.HasPrefix(strings.TrimSpace(action), "#") {
				action = page
			}
			target, ok := resolve(base, action, scope)
			if !ok {
				return
			}
			method, _ := htmlAttr(node, "method")
			method = strings.ToUpper(strings.TrimSpace(method))
			if method == "" {
				method = "GET"
			}
			if method != "GET" && method != "POST" {
				return
			}
			inputs := []FormInput{}
			have := map[string]bool{}
			var visit func(*html.Node)
			visit = func(n *html.Node) {
				if len(inputs) >= 64 {
					return
				}
				if n != node && n.Type == html.ElementNode && n.Data == "form" {
					return
				}
				if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "textarea" || n.Data == "select") {
					if _, disabled := htmlAttr(n, "disabled"); !disabled {
						name, present := htmlAttr(n, "name")
						name = strings.TrimSpace(name)
						// Only ordinary HTML parameter names; prevents control chars,
						// huge untrusted strings, and terminal escape sequences.
						if present && validFormInputName(name) && !have[name] {
							kind, _ := htmlAttr(n, "type")
							if n.Data != "input" {
								kind = n.Data
							}
							if kind == "" {
								kind = "text"
							}
							kind = strings.ToLower(strings.TrimSpace(kind))
							// Restrict exported control types to ordinary identifiers.
							if len(kind) > 32 {
								kind = "other"
							}
							for _, r := range kind {
								if r < 'a' || r > 'z' {
									kind = "other"
									break
								}
							}
							inputs = append(inputs, FormInput{Name: name, Type: kind})
							have[name] = true
						}
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					visit(c)
				}
			}
			visit(node)
			sort.Slice(inputs, func(i, j int) bool { return inputs[i].Name < inputs[j].Name })
			names := make([]string, 0, len(inputs))
			for _, input := range inputs {
				names = append(names, input.Name)
			}
			key := method + "\x00" + target + "\x00" + strings.Join(names, "\x00")
			if !seen[key] {
				forms = append(forms, FormFinding{Page: page, Action: target, Method: method, Inputs: inputs})
				seen[key] = true
			}
			return // Inputs have already been traversed, avoid nested form duplicates.
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return forms
}

func validFormInputName(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == '[' || r == ']' {
			continue
		}
		return false
	}
	return true
}

// safeHTMLFetchPath adds a conservative guard to supplemental GETs. The base
// crawler is unchanged. No query URLs, API paths, logout, destructive actions,
// or resources with binary/script file extensions are fetched in this pass.
func safeHTMLFetchPath(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery != "" || IsStaticAsset(raw) || IsPotentialAPI(raw) {
		return false
	}
	path := strings.ToLower(u.Path)
	if strings.Contains(path, "/_next/") || strings.Contains(path, "/graphql") || strings.Contains(path, "/rpc/") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		switch segment {
		case "logout", "logoff", "signout", "delete", "remove", "destroy", "unsubscribe", "reset", "revoke", "disable", "activate", "confirm", "purchase", "checkout", "pay":
			return false
		}
	}
	if dot := strings.LastIndexByte(path, '.'); dot >= 0 && dot > strings.LastIndexByte(path, '/') {
		return strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm")
	}
	return true
}

// DiscoverForms supplements the existing crawler without changing its traversal
// or concurrency. It reuses the same scoped HTTP client, global rate limiter,
// redirects, timeouts and response-size guard.
func (c *Client) DiscoverForms(ctx context.Context, sources map[string]map[string]bool, workers, maxPages int, progress Progress, emit func(string)) ([]FormFinding, []string, int) {
	if maxPages <= 0 {
		return nil, nil, 0
	}
	pages := []string{}
	for raw := range sources {
		if safeHTMLFetchPath(raw) {
			pages = append(pages, raw)
		}
	}
	// Prefer live and crawled pages over historical URLs (which may be stale).
	sort.Slice(pages, func(i, j int) bool {
		weight := func(s string) int {
			if sources[s]["live"] {
				return 0
			}
			if sources[s]["crawl"] {
				return 1
			}
			if sources[s]["javascript"] {
				return 2
			}
			return 3
		}
		a, b := weight(pages[i]), weight(pages[j])
		if a != b {
			return a < b
		}
		return pages[i] < pages[j]
	})
	if len(pages) > maxPages {
		pages = pages[:maxPages]
	}
	if progress != nil {
		progress("Forms", 0, len(pages))
	}
	type result struct {
		page    string
		forms   []FormFinding
		err     error
		checked bool
	}
	jobs := make(chan string, workers)
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for raw := range jobs {
				if ctx.Err() != nil {
					results <- result{page: raw, err: ctx.Err()}
					continue
				}
				body, typ, _, err := c.Fetch(ctx, raw, false, 1<<20)
				if err != nil {
					results <- result{page: raw, err: err}
					continue
				}
				if !isPage(typ, raw) || !bytes.Contains(bytes.ToLower(body), []byte("<form")) {
					results <- result{page: raw, checked: true}
					continue
				}
				results <- result{page: raw, checked: true, forms: ExtractForms(raw, body, c.Scope)}
			}
		}()
	}
	go func() {
		defer close(results)
		for _, raw := range pages {
			select {
			case jobs <- raw:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return
			}
		}
		close(jobs)
		wg.Wait()
	}()
	found := []FormFinding{}
	warnings := []string{}
	errorsSeen := 0
	pagesChecked := 0
	completed := 0
	for r := range results {
		completed++
		if r.checked {
			pagesChecked++
		}
		if r.err != nil {
			errorsSeen++
			if errorsSeen <= 8 {
				warnings = append(warnings, fmt.Sprintf("HTML form fetch %s: %v", safeWatchURLString(r.page), r.err))
			}
		}
		for _, f := range r.forms {
			found = append(found, f)
			if emit != nil {
				names := make([]string, 0, len(f.Inputs))
				for _, input := range f.Inputs {
					names = append(names, input.Name)
				}
				shown := names
				if len(shown) > 12 {
					shown = shown[:12]
				}
				note := strings.Join(shown, ", ")
				if len(shown) < len(names) {
					note += fmt.Sprintf(" (+%d more)", len(names)-len(shown))
				}
				emit(fmt.Sprintf("Form %s %s; input names [%s] (never submitted)", f.Method, safeWatchURLString(f.Action), note))
			}
		}
		if progress != nil {
			progress("Forms", completed, len(pages))
		}
	}
	if errorsSeen > 8 {
		warnings = append(warnings, fmt.Sprintf("%d more HTML form fetch errors omitted", errorsSeen-8))
	}
	sort.Slice(found, func(i, j int) bool {
		a, b := found[i], found[j]
		return a.Action+"\x00"+a.Method+"\x00"+a.Page < b.Action+"\x00"+b.Method+"\x00"+b.Page
	})
	return found, warnings, pagesChecked
}

// GET form names are added as *empty* query values so downstream existing
// dedup/diff processing can recognize their parameter structure. POST fields
// are reported separately and never turned into synthetic GET requests.
func FormGETURL(f FormFinding) string {
	if f.Method != "GET" {
		return ""
	}
	u, err := url.Parse(f.Action)
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, input := range f.Inputs {
		if _, ok := q[input.Name]; !ok {
			q.Set(input.Name, "")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
