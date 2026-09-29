package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// probeOrigin is the foreign origin httpsec sends to test for Origin
// reflection. It is deliberately obviously synthetic so that an administrator
// reading their logs can tell it apart from a real cross-origin request.
const probeOrigin = "https://httpsec-probe.invalid"

type httpClient struct {
	cl *http.Client

	robotsMu sync.Mutex
	robots   map[string]*robotsRules
}

func newHTTPClient(opts Options) *httpClient {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		MaxIdleConns:          4,
		IdleConnTimeout:       20 * time.Second,
		// Certificate problems are findings, not errors: httpsec must still
		// be able to report on the headers of a host whose certificate is
		// expired or self-signed. The chain is verified properly, and
		// reported on, by the dedicated TLS probe in tls.go.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // G402: see comment above
			MinVersion:         tls.VersionTLS10,
		},
	}
	return &httpClient{
		cl: &http.Client{
			Transport: tr,
			Timeout:   opts.Timeout * 2,
		},
		robots: make(map[string]*robotsRules),
	}
}

// do performs one request, recording the redirect chain rather than letting
// net/http swallow it.
func (c *httpClient) do(ctx context.Context, method, rawURL string, opts Options, header http.Header, withBody bool) *HTTPResponse {
	rec := &HTTPResponse{RequestURL: rawURL, Method: method, FinalURL: rawURL}

	u, err := url.Parse(rawURL)
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	if err := opts.Limiter.Wait(ctx, u.Hostname()); err != nil {
		rec.Error = err.Error()
		return rec
	}

	var hops []Hop
	cl := *c.cl
	cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		prev := via[len(via)-1]
		hops = append(hops, Hop{
			URL:      prev.URL.String(),
			Scheme:   prev.URL.Scheme,
			Host:     prev.URL.Host,
			Location: req.URL.String(),
		})
		if len(via) >= opts.MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", opts.MaxRedirects)
		}
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, nil)
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	started := time.Now()
	resp, err := cl.Do(req)
	rec.DurationMs = time.Since(started).Milliseconds()
	if err != nil {
		rec.Error = trimError(err)
		rec.Redirects = hops
		return rec
	}
	defer func() { _ = resp.Body.Close() }()

	rec.StatusCode = resp.StatusCode
	rec.Proto = resp.Proto
	rec.FinalURL = resp.Request.URL.String()
	rec.Headers = map[string][]string(resp.Header.Clone())
	rec.Redirects = statusedHops(hops, resp)
	if resp.TLS != nil {
		rec.TLSVersion = tlsVersionName(resp.TLS.Version)
	}

	limit := int64(opts.MaxBody)
	if !withBody {
		limit = 4096
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil && rec.Error == "" {
		rec.Error = "read body: " + trimError(err)
	}
	rec.BodyBytes = len(body)
	if int64(len(body)) > limit {
		body = body[:limit]
		rec.BodyTruncated = true
	}
	if withBody {
		rec.Body = string(body)
	}
	return rec
}

// statusedHops fills in the status code of each recorded hop. net/http does
// not hand the intermediate responses to CheckRedirect, so the codes are
// recovered from the response chain instead.
func statusedHops(hops []Hop, resp *http.Response) []Hop {
	var codes []int
	for r := resp; r != nil; r = r.Request.Response {
		if r != resp {
			codes = append([]int{r.StatusCode}, codes...)
		}
		if r.Request == nil {
			break
		}
	}
	for i := range hops {
		if i < len(codes) {
			hops[i].StatusCode = codes[i]
		}
	}
	return hops
}

func (c *httpClient) get(ctx context.Context, rawURL string, opts Options, withBody bool) *HTTPResponse {
	if withBody && opts.RespectRobots && !c.robotsAllows(ctx, rawURL, opts) {
		r := c.do(ctx, http.MethodGet, rawURL, opts, nil, false)
		r.Body = ""
		r.Error = strings.TrimSpace(r.Error + " (body not retrieved: disallowed by robots.txt)")
		return r
	}
	return c.do(ctx, http.MethodGet, rawURL, opts, nil, withBody)
}

func (c *httpClient) method(ctx context.Context, method, rawURL string, opts Options) *HTTPResponse {
	return c.do(ctx, method, rawURL, opts, nil, false)
}

// probeCORS sends a synthetic foreign Origin, and then the literal "null"
// origin, and records how the server answers both.
func (c *httpClient) probeCORS(ctx context.Context, rawURL string, opts Options) *CORSProbe {
	p := &CORSProbe{SentOrigin: probeOrigin, SentNullOrigin: true}

	h := http.Header{}
	h.Set("Origin", probeOrigin)
	r := c.do(ctx, http.MethodGet, rawURL, opts, h, false)
	if r.Error != "" {
		p.Error = r.Error
		return p
	}
	p.AllowOrigin = r.Header("Access-Control-Allow-Origin")
	p.AllowCredentials = r.Header("Access-Control-Allow-Credentials")
	p.AllowMethods = r.Header("Access-Control-Allow-Methods")
	p.AllowHeaders = r.Header("Access-Control-Allow-Headers")
	p.ExposeHeaders = r.Header("Access-Control-Expose-Headers")
	p.Vary = strings.Join(r.HeaderValues("Vary"), ", ")

	hn := http.Header{}
	hn.Set("Origin", "null")
	rn := c.do(ctx, http.MethodGet, rawURL, opts, hn, false)
	if rn.Error == "" {
		p.NullAllowOrigin = rn.Header("Access-Control-Allow-Origin")
		p.NullAllowCreds = rn.Header("Access-Control-Allow-Credentials")
	}
	return p
}

func (c *httpClient) securityTxt(ctx context.Context, host, port string, opts Options) *HTTPResponse {
	base := "https://" + host
	if port != "443" {
		base = "https://" + net.JoinHostPort(host, port)
	}
	r := c.do(ctx, http.MethodGet, base+"/.well-known/security.txt", opts, nil, true)
	if r.Error == "" && r.StatusCode == http.StatusNotFound {
		// RFC 9116 allows the legacy top-level location during migration.
		if alt := c.do(ctx, http.MethodGet, base+"/security.txt", opts, nil, true); alt.Error == "" && alt.StatusCode == http.StatusOK {
			return alt
		}
	}
	return r
}

// robotsAllows implements the narrow slice of robots.txt that matters here:
// User-agent groups and Disallow/Allow prefixes for the path being fetched.
//
// httpsec only consults robots.txt before retrieving HTML for mixed-content
// analysis, and only when asked to (batch mode turns it on). Header and TLS
// probes are not crawling and are not gated on it; see docs/decisions.md.
func (c *httpClient) robotsAllows(ctx context.Context, rawURL string, opts Options) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	key := u.Scheme + "://" + u.Host

	c.robotsMu.Lock()
	rules, cached := c.robots[key]
	c.robotsMu.Unlock()

	if !cached {
		r := c.do(ctx, http.MethodGet, key+"/robots.txt", opts, nil, true)
		if r.Error != "" || r.StatusCode != http.StatusOK {
			rules = &robotsRules{} // unreachable or absent robots.txt allows everything
		} else {
			rules = parseRobots(r.Body)
		}
		c.robotsMu.Lock()
		c.robots[key] = rules
		c.robotsMu.Unlock()
	}
	return rules.allows(u.Path)
}

type robotsRule struct {
	prefix string
	allow  bool
}

type robotsRules struct {
	rules []robotsRule
}

// robotsAgent is the product token httpsec matches robots.txt groups
// against. It is the first token of the User-Agent, which is what RFC 9309
// says a crawler should use.
const robotsAgent = "httpsec"

// parseRobots extracts the rules that apply to httpsec, preferring an exact
// user-agent group over the wildcard group.
func parseRobots(body string) *robotsRules {
	var wildcard, specific []robotsRule
	var active []string
	inGroup := false

	for _, raw := range strings.Split(body, "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch key {
		case "user-agent":
			if !inGroup {
				active = nil
			}
			active = append(active, strings.ToLower(value))
			inGroup = true
		case "disallow", "allow":
			inGroup = false
			if value == "" && key == "disallow" {
				continue // "Disallow:" with no value means allow all
			}
			rule := robotsRule{prefix: value, allow: key == "allow"}
			for _, a := range active {
				switch {
				case a == "*":
					wildcard = append(wildcard, rule)
				case strings.Contains(robotsAgent, a):
					specific = append(specific, rule)
				}
			}
		default:
			inGroup = false
		}
	}
	if len(specific) > 0 {
		return &robotsRules{rules: specific}
	}
	return &robotsRules{rules: wildcard}
}

// allows applies the longest-match rule, with Allow winning ties, which is
// what RFC 9309 specifies.
func (r *robotsRules) allows(path string) bool {
	if path == "" {
		path = "/"
	}
	best := robotsRule{}
	found := false
	for _, rule := range r.rules {
		if !strings.HasPrefix(path, rule.prefix) {
			continue
		}
		if !found || len(rule.prefix) > len(best.prefix) || (len(rule.prefix) == len(best.prefix) && rule.allow) {
			best, found = rule, true
		}
	}
	if !found {
		return true
	}
	return best.allow
}

func trimError(err error) string {
	s := err.Error()
	// Unwrap the url.Error prefix, which repeats information already in the
	// recorded request URL.
	if i := strings.Index(s, ": "); i > 0 && strings.HasPrefix(s, "Get \"") {
		if j := strings.Index(s, "\": "); j > 0 {
			s = s[j+3:]
		}
	}
	return strings.TrimSpace(s)
}
