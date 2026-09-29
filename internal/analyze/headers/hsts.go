// Package headers evaluates the HTTP response headers recorded in an
// Observation. There is one file per family of headers, each with its own
// parser: the point of httpsec is to judge the value, not just its presence.
package headers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/dotMuny/httpsec/data"
	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// HSTSMinMaxAge is the shortest max-age httpsec considers adequate: 180 days,
// the value Mozilla Observatory uses as its floor.
const HSTSMinMaxAge = 15552000

// HSTSPreloadMaxAge is what hstspreload.org requires.
const HSTSPreloadMaxAge = 31536000

// HSTS is a parsed Strict-Transport-Security value.
type HSTS struct {
	Raw               string
	MaxAge            int64
	HasMaxAge         bool
	IncludeSubDomains bool
	Preload           bool
	Malformed         bool
	Unknown           []string
}

// ParseHSTS parses a Strict-Transport-Security header value.
func ParseHSTS(v string) HSTS {
	h := HSTS{Raw: strings.TrimSpace(v)}
	if h.Raw == "" {
		h.Malformed = true
		return h
	}
	for _, part := range strings.Split(v, ";") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		name, value, hasValue := strings.Cut(p, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch name {
		case "max-age":
			if !hasValue {
				h.Malformed = true
				continue
			}
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				h.Malformed = true
				continue
			}
			h.MaxAge, h.HasMaxAge = n, true
		case "includesubdomains":
			h.IncludeSubDomains = true
		case "preload":
			h.Preload = true
		default:
			h.Unknown = append(h.Unknown, name)
		}
	}
	if !h.HasMaxAge {
		h.Malformed = true
	}
	return h
}

type preloadFile struct {
	Updated  string `json:"updated"`
	Complete bool   `json:"complete"`
	Note     string `json:"note"`
	Domains  []struct {
		Name              string `json:"name"`
		IncludeSubdomains bool   `json:"include_subdomains"`
	} `json:"domains"`
}

var preload preloadFile

func init() {
	if err := json.Unmarshal(data.HSTSPreload, &preload); err != nil {
		panic("headers: cannot parse embedded hsts-preload.json: " + err.Error())
	}
}

// PreloadListUpdated is the date the embedded preload subset was refreshed.
func PreloadListUpdated() string { return preload.Updated }

// IsPreloaded reports whether a host is covered by the embedded subset of the
// Chrome preload list. A false result means "not in the embedded subset",
// never "not preloaded": the subset is documented as incomplete and the
// finding wording reflects that.
func IsPreloaded(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range preload.Domains {
		if h == d.Name {
			return true
		}
		if d.IncludeSubdomains && strings.HasSuffix(h, "."+d.Name) {
			return true
		}
	}
	return false
}

// AnalyzeHSTS evaluates Strict-Transport-Security.
func AnalyzeHSTS(host string, https, plain *probe.HTTPResponse) []finding.Finding {
	var out []finding.Finding

	if plain != nil && plain.Error == "" && plain.HasHeader("Strict-Transport-Security") {
		if strings.HasPrefix(plain.FinalURL, "http://") {
			out = append(out, finding.New("hsts.over-http",
				"Strict-Transport-Security is also emitted on plain HTTP responses, where browsers must ignore it.").
				WithEvidence(plain.Header("Strict-Transport-Security")))
		}
	}

	raw := https.Header("Strict-Transport-Security")
	if !https.HasHeader("Strict-Transport-Security") {
		if IsPreloaded(host) {
			return append(out,
				finding.New("hsts.missing", "No Strict-Transport-Security header, although the domain appears in the embedded preload subset. Removing the header is how a domain eventually falls off the list.").WithEvidence(""),
				finding.New("hsts.preloaded", "Found in the embedded Chrome preload subset (updated "+preload.Updated+")."))
		}
		return append(out, finding.New("hsts.missing", "No Strict-Transport-Security header on the HTTPS response."))
	}

	h := ParseHSTS(raw)
	switch {
	case h.Malformed:
		return append(out, finding.New("hsts.malformed",
			"The header could not be parsed: max-age is missing or is not a non-negative integer.").WithEvidence(raw))
	case h.MaxAge == 0:
		out = append(out, finding.New("hsts.max-age-zero",
			"max-age=0 instructs browsers to forget the HSTS entry for this host.").WithEvidence(raw))
	case h.MaxAge < HSTSMinMaxAge:
		out = append(out, finding.New("hsts.max-age-low",
			fmt.Sprintf("max-age is %d seconds (%.0f days); at least %d seconds (180 days) is expected, and %d (one year) is required for preloading.",
				h.MaxAge, float64(h.MaxAge)/86400, HSTSMinMaxAge, HSTSPreloadMaxAge)).WithEvidence(raw))
	}

	if !h.IncludeSubDomains {
		out = append(out, finding.New("hsts.no-subdomains",
			"includeSubDomains is not set, so subdomains may still be reached over plain HTTP.").WithEvidence(raw))
	}

	switch {
	case IsPreloaded(host):
		out = append(out, finding.New("hsts.preloaded",
			"Found in the embedded Chrome preload subset (updated "+preload.Updated+").").WithEvidence(raw))
	case !h.Preload:
		out = append(out, finding.New("hsts.no-preload",
			"The preload token is absent and the domain is not in the embedded preload subset, so the first request of a new browser profile is still unprotected.").WithEvidence(raw))
	}

	if !h.Malformed && h.MaxAge >= HSTSMinMaxAge && h.IncludeSubDomains {
		out = append(out, finding.New("hsts.ok",
			fmt.Sprintf("max-age=%d with includeSubDomains.", h.MaxAge)).WithEvidence(raw))
	}
	return out
}
