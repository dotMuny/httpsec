package headers

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// MaxRedirectHops is how many hops a plain-HTTP redirect may take before
// httpsec reports the chain as unusually long.
//
// Three is deliberate rather than tidy: the common shape apex -> www ->
// /locale/ is three hops and is not a misconfiguration, so flagging it would
// be noise on a large fraction of real sites. Four or more usually means two
// redirect layers that nobody has reconciled.
const MaxRedirectHops = 3

// AnalyzeRedirect evaluates the plain-HTTP behaviour of the host.
//
// If the HTTP request failed outright the control is not evaluated at all:
// httpsec cannot tell a host that refuses port 80 from one it could not reach,
// and guessing would be worse than saying nothing.
func AnalyzeRedirect(host string, plain *probe.HTTPResponse) []finding.Finding {
	if plain == nil || plain.Error != "" {
		return nil
	}

	final, err := url.Parse(plain.FinalURL)
	if err != nil {
		return nil
	}
	hops := plain.Redirects

	if final.Scheme != "https" {
		return []finding.Finding{finding.New("redirect.no-https",
			fmt.Sprintf("http://%s returned %d and ended at %s without upgrading to HTTPS.", host, plain.StatusCode, plain.FinalURL)).
			WithEvidence(chainEvidence(plain))}
	}

	var out []finding.Finding
	clean := true

	// Any hop after the first that is still plain HTTP exposes the request
	// again, even though the chain ends on HTTPS.
	for i, h := range hops {
		if i > 0 && h.Scheme == "http" {
			clean = false
			out = append(out, finding.New("redirect.chain-through-http",
				"Hop "+fmt.Sprint(i+1)+" of the redirect chain is plain HTTP: "+h.URL).
				WithEvidence(chainEvidence(plain)))
			break
		}
	}

	if len(hops) > 0 {
		first := hops[0]
		if first.StatusCode != 0 && first.StatusCode != 301 && first.StatusCode != 308 {
			clean = false
			out = append(out, finding.New("redirect.not-permanent",
				fmt.Sprintf("The first redirect is %d; use 301 or 308 so browsers cache the upgrade.", first.StatusCode)).
				WithEvidence(chainEvidence(plain)))
		}
		if loc, err := url.Parse(first.Location); err == nil && loc.Hostname() != "" && !strings.EqualFold(loc.Hostname(), host) {
			clean = false
			out = append(out, finding.New("redirect.cross-host",
				"http://"+host+" redirects straight to "+loc.Hostname()+", so the browser never records an HSTS entry for "+host+".").
				WithEvidence(chainEvidence(plain)))
		}
	}
	if len(hops) > MaxRedirectHops {
		clean = false
		out = append(out, finding.New("redirect.long-chain",
			fmt.Sprintf("The chain has %d redirects; each one is a round trip and another chance to drop out of HTTPS.", len(hops))).
			WithEvidence(chainEvidence(plain)))
	}

	if clean {
		out = append(out, finding.New("redirect.ok",
			"http://"+host+" redirects to "+plain.FinalURL).WithEvidence(chainEvidence(plain)))
	}
	return out
}

func chainEvidence(r *probe.HTTPResponse) string {
	var b strings.Builder
	for _, h := range r.Redirects {
		fmt.Fprintf(&b, "%d %s -> %s\n", h.StatusCode, h.URL, h.Location)
	}
	fmt.Fprintf(&b, "%d %s", r.StatusCode, r.FinalURL)
	return b.String()
}

// mixedContentPatterns finds plain-HTTP subresource references. This is a
// deliberately shallow scan of the returned HTML: it catches the declared
// references that a reviewer would grep for, and does not pretend to see what
// scripts load at runtime.
var mixedContentPatterns = []struct {
	name   string
	active bool
	re     *regexp.Regexp
}{
	{"script", true, regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']?(http://[^"'\s>]+)`)},
	{"iframe", true, regexp.MustCompile(`(?is)<iframe\b[^>]*\bsrc\s*=\s*["']?(http://[^"'\s>]+)`)},
	{"stylesheet", true, regexp.MustCompile(`(?is)<link\b[^>]*\bhref\s*=\s*["']?(http://[^"'\s>]+)`)},
	{"object", true, regexp.MustCompile(`(?is)<object\b[^>]*\bdata\s*=\s*["']?(http://[^"'\s>]+)`)},
	{"embed", true, regexp.MustCompile(`(?is)<embed\b[^>]*\bsrc\s*=\s*["']?(http://[^"'\s>]+)`)},
	{"image", false, regexp.MustCompile(`(?is)<img\b[^>]*\bsrc\s*=\s*["']?(http://[^"'\s>]+)`)},
	{"media", false, regexp.MustCompile(`(?is)<(?:audio|video|source)\b[^>]*\bsrc\s*=\s*["']?(http://[^"'\s>]+)`)},
}

// AnalyzeMixedContent scans the retrieved HTML for http:// subresources.
func AnalyzeMixedContent(r *probe.HTTPResponse) []finding.Finding {
	if r == nil || r.Body == "" {
		return nil
	}
	active := map[string][]string{}
	passive := map[string][]string{}

	for _, p := range mixedContentPatterns {
		for _, m := range p.re.FindAllStringSubmatch(r.Body, -1) {
			if len(m) < 2 {
				continue
			}
			if p.active {
				active[p.name] = appendCapped(active[p.name], m[1])
			} else {
				passive[p.name] = appendCapped(passive[p.name], m[1])
			}
		}
	}

	var out []finding.Finding
	if len(active) > 0 {
		out = append(out, finding.New("mixed-content.active",
			"Active content is referenced over plain HTTP: "+summarise(active)).
			WithEvidence(evidenceFor(active)))
	}
	if len(passive) > 0 {
		out = append(out, finding.New("mixed-content.passive",
			"Passive content is referenced over plain HTTP: "+summarise(passive)).
			WithEvidence(evidenceFor(passive)))
	}
	if len(out) == 0 {
		detail := "No http:// subresource references were found in the retrieved HTML."
		if r.BodyTruncated {
			detail += " Note that the body was truncated, so this only covers the part httpsec read."
		}
		out = append(out, finding.New("mixed-content.none", detail))
	}
	return out
}

func appendCapped(s []string, v string) []string {
	if len(s) >= 5 {
		return s
	}
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

func summarise(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s (%d)", k, len(m[k])))
	}
	return strings.Join(parts, ", ")
}

func evidenceFor(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, u := range m[k] {
			fmt.Fprintf(&b, "%s: %s\n", k, u)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// AnalyzeSecurityTxt validates /.well-known/security.txt against RFC 9116.
func AnalyzeSecurityTxt(r *probe.HTTPResponse) []finding.Finding {
	if r == nil || r.Error != "" {
		return nil
	}
	if r.StatusCode != 200 {
		return []finding.Finding{finding.New("security-txt.missing",
			fmt.Sprintf("%s returned %d.", r.RequestURL, r.StatusCode))}
	}

	var contacts []string
	var expires string
	var problems []string

	for _, line := range strings.Split(r.Body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "contact":
			contacts = append(contacts, value)
		case "expires":
			expires = value
		}
	}

	if len(contacts) == 0 {
		problems = append(problems, "no Contact field (RFC 9116 requires at least one)")
	}
	if expires == "" {
		problems = append(problems, "no Expires field (RFC 9116 requires exactly one)")
	}
	if ct := r.Header("Content-Type"); ct != "" && !strings.Contains(strings.ToLower(ct), "text/plain") {
		problems = append(problems, "served as "+ct+" rather than text/plain")
	}
	if len(problems) > 0 {
		return []finding.Finding{finding.New("security-txt.invalid",
			strings.Join(problems, "; ")+".").WithEvidence(truncate(r.Body, 400))}
	}

	t, err := parseRFC3339(expires)
	if err != nil {
		return []finding.Finding{finding.New("security-txt.invalid",
			"Expires is not a valid RFC 3339 timestamp: "+expires).WithEvidence(truncate(r.Body, 400))}
	}
	if t.Before(time.Now()) {
		return []finding.Finding{finding.New("security-txt.expired",
			"The Expires field is "+expires+", which is in the past.").WithEvidence(truncate(r.Body, 400))}
	}

	return []finding.Finding{finding.New("security-txt.ok",
		"Contact: "+strings.Join(contacts, ", ")+" (expires "+expires+").").WithEvidence(truncate(r.Body, 400))}
}

// parseRFC3339 parses a timestamp the way RFC 3339 actually defines it.
//
// time.RFC3339 only accepts an uppercase "Z" for UTC, but RFC 3339's ABNF
// inherits case-insensitive literals from RFC 5234, so a lowercase "z" is
// valid and real sites use it. Rejecting it would report a correct
// security.txt as malformed, which is worse than being lenient here.
func parseRFC3339(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if n := len(v); n > 0 && v[n-1] == 'z' {
		return time.Parse(time.RFC3339, v[:n-1]+"Z")
	}
	return time.Time{}, fmt.Errorf("not an RFC 3339 timestamp: %q", v)
}

// dangerousMethods are the verbs httpsec reports when a server advertises
// them, because they usually mean a module is enabled that nobody intended to
// expose.
var dangerousMethods = map[string]bool{
	"PUT": true, "DELETE": true, "CONNECT": true, "TRACE": true, "TRACK": true,
	"PROPFIND": true, "PROPPATCH": true, "MKCOL": true, "COPY": true, "MOVE": true,
	"LOCK": true, "UNLOCK": true, "SEARCH": true, "DEBUG": true,
}

// AnalyzeMethods evaluates the OPTIONS response and the TRACE probe.
func AnalyzeMethods(options, trace *probe.HTTPResponse) []finding.Finding {
	var out []finding.Finding

	if trace != nil && trace.Error == "" && trace.StatusCode == 200 {
		out = append(out, finding.New("methods.trace-enabled",
			"A TRACE request returned 200, so the server echoes requests back to the client.").
			WithEvidence(fmt.Sprintf("TRACE %s -> %d", trace.RequestURL, trace.StatusCode)))
	}

	var advertised []string
	if options != nil && options.Error == "" {
		raw := options.Header("Allow")
		if raw == "" {
			raw = options.Header("Access-Control-Allow-Methods")
		}
		for _, m := range strings.Split(raw, ",") {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				advertised = append(advertised, m)
			}
		}
	}
	var risky []string
	for _, m := range advertised {
		if dangerousMethods[m] {
			risky = append(risky, m)
		}
	}
	if len(risky) > 0 {
		out = append(out, finding.New("methods.dangerous-allowed",
			"OPTIONS advertises "+strings.Join(risky, ", ")+".").
			WithEvidence("Allow: "+strings.Join(advertised, ", ")))
	}

	if len(out) == 0 {
		detail := "TRACE is refused"
		if len(advertised) > 0 {
			detail += " and OPTIONS advertises only " + strings.Join(advertised, ", ")
		}
		out = append(out, finding.New("methods.ok", detail+"."))
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
