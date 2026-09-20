// Certificate and passive DNS enumeration, host liveness probing.
// Always constrain discovered hosts using the authorized scope.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"

	"funnelrecon/internal/utils"
)

func (c *Client) Enumerate(ctx context.Context, root string, maxHosts int) ([]string, []string) {
	type reply struct {
		hosts  []string
		err    error
		source string
	}
	results := make(chan reply, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		u := "https://crt.sh/?q=" + url.QueryEscape("%."+root) + "&output=json"
		b, _, _, err := c.Fetch(ctx, u, true, 8<<20)
		if err != nil {
			results <- reply{err: err, source: "crt.sh"}
			return
		}
		var records []struct {
			Name string `json:"name_value"`
		}
		if err = json.Unmarshal(b, &records); err != nil {
			results <- reply{err: err, source: "crt.sh"}
			return
		}
		names := make([]string, 0)
		for _, r := range records {
			names = append(names, strings.FieldsFunc(r.Name, func(r rune) bool { return r == '\n' || r == ',' })...)
		}
		results <- reply{hosts: names, source: "crt.sh"}
	}()
	go func() {
		defer wg.Done()
		u := "https://otx.alienvault.com/api/v1/indicators/domain/" + url.PathEscape(root) + "/passive_dns"
		b, _, _, err := c.Fetch(ctx, u, true, 8<<20)
		if err != nil {
			results <- reply{err: err, source: "OTX"}
			return
		}
		var records struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		if err = json.Unmarshal(b, &records); err != nil {
			results <- reply{err: err, source: "OTX"}
			return
		}
		names := make([]string, 0, len(records.PassiveDNS))
		for _, r := range records.PassiveDNS {
			names = append(names, r.Hostname)
		}
		results <- reply{hosts: names, source: "OTX"}
	}()
	go func() { wg.Wait(); close(results) }()
	set := map[string]bool{root: true}
	warnings := []string{}
	for r := range results {
		if r.err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", r.source, r.err))
			continue
		}
		for _, n := range r.hosts {
			n = strings.TrimPrefix(strings.TrimSpace(n), "*.")
			h, err := utils.Host(n)
			if err == nil && c.Scope.Contains(h) {
				set[h] = true
			}
		}
	}
	hosts := make([]string, 0, len(set))
	for h := range set {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if len(hosts) > maxHosts {
		warnings = append(warnings, fmt.Sprintf("host cap: retained %d of %d hosts", maxHosts, len(hosts)))
		hosts = hosts[:maxHosts]
		if !contains(hosts, root) {
			hosts[len(hosts)-1] = root
			sort.Strings(hosts)
		}
	}
	return hosts, warnings
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
func (c *Client) Probe(ctx context.Context, host string) (string, bool) {
	if _, err := net.LookupHost(host); err != nil {
		return "", false
	}
	for _, scheme := range []string{"https://", "http://"} {
		urlHost := host
		if strings.Contains(host, ":") {
			urlHost = "[" + host + "]"
		}
		raw := scheme + urlHost + "/"
		_, _, status, err := c.Fetch(ctx, raw, false, 128<<10)
		if err == nil || status >= 200 && status < 500 {
			return raw, true
		}
	}
	return "", false
}
