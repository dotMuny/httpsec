// Package cookies parses Set-Cookie headers and evaluates each cookie's
// attributes.
package cookies

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// LongExpiry is the lifetime above which a persistent cookie is reported.
const LongExpiry = 400 * 24 * time.Hour

// sessionNamePattern matches cookie names that suggest the cookie carries
// authentication state, which raises the cost of exposing it to JavaScript.
var sessionNamePattern = regexp.MustCompile(`(?i)(^|[_.-])(sess(ion)?|sid|auth|token|jwt|login|remember|csrf|xsrf)([_.-]|$)|^(jsessionid|phpsessid|asp\.net_sessionid|connect\.sid)$`)

// Cookie is one parsed Set-Cookie header.
type Cookie struct {
	Raw      string
	Name     string
	Secure   bool
	HTTPOnly bool
	SameSite string
	Domain   string
	Path     string
	Expires  time.Time
	MaxAge   int
}

// Parse extracts the cookies from a response's Set-Cookie headers.
func Parse(r *probe.HTTPResponse) []Cookie {
	raws := r.HeaderValues("Set-Cookie")
	if len(raws) == 0 {
		return nil
	}
	resp := &http.Response{Header: http.Header{"Set-Cookie": raws}}
	parsed := resp.Cookies()

	out := make([]Cookie, 0, len(parsed))
	for i, c := range parsed {
		raw := ""
		if i < len(raws) {
			raw = raws[i]
		}
		// Match the raw header to the parsed cookie by name where possible,
		// since net/http drops cookies it cannot parse and the indices would
		// otherwise drift.
		for _, candidate := range raws {
			if strings.HasPrefix(strings.TrimSpace(candidate), c.Name+"=") {
				raw = candidate
				break
			}
		}
		out = append(out, Cookie{
			Raw:      strings.TrimSpace(raw),
			Name:     c.Name,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: sameSiteName(c.SameSite),
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  c.Expires,
			MaxAge:   c.MaxAge,
		})
	}
	return out
}

func sameSiteName(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// LooksLikeSession reports whether a cookie name suggests it carries session
// or authentication state.
func LooksLikeSession(name string) bool {
	return sessionNamePattern.MatchString(name)
}

// Analyze evaluates every cookie on the response.
func Analyze(host string, r *probe.HTTPResponse) []finding.Finding {
	cs := Parse(r)
	if len(cs) == 0 {
		return []finding.Finding{finding.New("cookie.none", "The response set no cookies.")}
	}

	var out []finding.Finding
	clean := true

	for _, c := range cs {
		problems := false

		if !c.Secure {
			problems = true
			out = append(out, finding.New("cookie.no-secure",
				"Cookie "+c.Name+" has no Secure attribute, so it is sent over plain HTTP.").
				WithSubject(c.Name).WithEvidence(c.Raw))
		}
		if !c.HTTPOnly {
			problems = true
			id := "cookie.no-httponly"
			detail := "Cookie " + c.Name + " is readable from JavaScript."
			if LooksLikeSession(c.Name) {
				id = "cookie.session-no-httponly"
				detail = "Cookie " + c.Name + " looks like a session or token cookie and is readable from JavaScript."
			}
			out = append(out, finding.New(id, detail).WithSubject(c.Name).WithEvidence(c.Raw))
		}
		switch c.SameSite {
		case "":
			problems = true
			out = append(out, finding.New("cookie.no-samesite",
				"Cookie "+c.Name+" has no SameSite attribute, so the browser default applies and it is not the same everywhere.").
				WithSubject(c.Name).WithEvidence(c.Raw))
		case "None":
			if !c.Secure {
				problems = true
				out = append(out, finding.New("cookie.samesite-none-insecure",
					"Cookie "+c.Name+" is SameSite=None without Secure, which browsers reject outright.").
					WithSubject(c.Name).WithEvidence(c.Raw))
			}
		}

		if v := checkPrefix(c); v != "" {
			problems = true
			out = append(out, finding.New("cookie.prefix-violation", v).
				WithSubject(c.Name).WithEvidence(c.Raw))
		}
		if d := strings.TrimPrefix(c.Domain, "."); d != "" && isBroadDomain(d, host) {
			problems = true
			out = append(out, finding.New("cookie.broad-domain",
				"Cookie "+c.Name+" is scoped to "+d+", so every subdomain of it receives and can overwrite the cookie.").
				WithSubject(c.Name).WithEvidence(c.Raw))
		}
		if lifetime, ok := lifetimeOf(c); ok && lifetime > LongExpiry {
			problems = true
			out = append(out, finding.New("cookie.long-expiry",
				fmt.Sprintf("Cookie %s persists for about %.0f days.", c.Name, lifetime.Hours()/24)).
				WithSubject(c.Name).WithEvidence(c.Raw))
		}

		if problems {
			clean = false
		}
	}

	if clean {
		out = append(out, finding.New("cookie.ok",
			fmt.Sprintf("All %d cookies carry Secure, HttpOnly and an explicit SameSite.", len(cs))))
	}
	return out
}

// checkPrefix validates the __Host- and __Secure- name prefixes, which the
// browser only honours when the attributes match.
func checkPrefix(c Cookie) string {
	switch {
	case strings.HasPrefix(c.Name, "__Host-"):
		var missing []string
		if !c.Secure {
			missing = append(missing, "Secure")
		}
		if c.Path != "/" {
			missing = append(missing, `Path="/"`)
		}
		if c.Domain != "" {
			missing = append(missing, "no Domain attribute")
		}
		if len(missing) > 0 {
			return "Cookie " + c.Name + " uses the __Host- prefix but does not satisfy it: needs " +
				strings.Join(missing, ", ") + ". Browsers reject the cookie outright."
		}
	case strings.HasPrefix(c.Name, "__Secure-"):
		if !c.Secure {
			return "Cookie " + c.Name + " uses the __Secure- prefix without the Secure attribute, so browsers reject it."
		}
	}
	return ""
}

// isBroadDomain reports whether a cookie Domain is wider than the host it was
// set from. The check is deliberately conservative: it only fires when the
// Domain is a strict parent of the host.
func isBroadDomain(domain, host string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if domain == "" || host == "" || domain == host {
		return false
	}
	return strings.HasSuffix(host, "."+domain)
}

func lifetimeOf(c Cookie) (time.Duration, bool) {
	if c.MaxAge > 0 {
		return time.Duration(c.MaxAge) * time.Second, true
	}
	if !c.Expires.IsZero() {
		d := time.Until(c.Expires)
		if d > 0 {
			return d, true
		}
	}
	return 0, false
}
