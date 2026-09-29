package headers

import (
	"sort"
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// AnalyzeNoSniff evaluates X-Content-Type-Options.
func AnalyzeNoSniff(r *probe.HTTPResponse) []finding.Finding {
	if !r.HasHeader("X-Content-Type-Options") {
		return []finding.Finding{finding.New("nosniff.missing",
			"No X-Content-Type-Options header, so browsers may MIME-sniff responses whose declared type they distrust.")}
	}
	raw := strings.TrimSpace(r.Header("X-Content-Type-Options"))
	if strings.EqualFold(raw, "nosniff") {
		return []finding.Finding{finding.New("nosniff.ok", "X-Content-Type-Options: nosniff").WithEvidence(raw)}
	}
	return []finding.Finding{finding.New("nosniff.invalid",
		"The only value browsers act on is nosniff; anything else is ignored.").WithEvidence(raw)}
}

// referrerPolicies maps each defined token to whether it can send the full
// URL to a cross-origin destination.
var referrerPolicies = map[string]bool{
	"no-referrer":                     false,
	"no-referrer-when-downgrade":      true,
	"same-origin":                     false,
	"origin":                          false,
	"strict-origin":                   false,
	"origin-when-cross-origin":        false,
	"strict-origin-when-cross-origin": false,
	"unsafe-url":                      true,
}

// AnalyzeReferrerPolicy evaluates Referrer-Policy. The header may carry a
// comma-separated list, in which case browsers use the last token they
// recognise, which is how sites deploy a new value with a fallback.
func AnalyzeReferrerPolicy(r *probe.HTTPResponse) []finding.Finding {
	values := r.HeaderValues("Referrer-Policy")
	if len(values) == 0 {
		return []finding.Finding{finding.New("referrer-policy.missing",
			"No Referrer-Policy header, so the browser default applies and it is not the same in every browser.")}
	}
	raw := strings.Join(values, ", ")

	var tokens []string
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			if s := strings.ToLower(strings.TrimSpace(t)); s != "" {
				tokens = append(tokens, s)
			}
		}
	}

	effective := ""
	for _, t := range tokens {
		if _, ok := referrerPolicies[t]; ok {
			effective = t
		}
	}
	if effective == "" {
		return []finding.Finding{finding.New("referrer-policy.unknown",
			"None of the tokens is a defined referrer policy, so the browser falls back to its default.").WithEvidence(raw)}
	}
	if referrerPolicies[effective] {
		return []finding.Finding{finding.New("referrer-policy.leaky",
			"The effective policy is "+effective+", which sends the full URL, including path and query, to cross-origin destinations.").WithEvidence(raw)}
	}
	return []finding.Finding{finding.New("referrer-policy.ok",
		"The effective policy is "+effective+".").WithEvidence(raw)}
}

// riskyFeatures are the Permissions-Policy features httpsec expects a site to
// deny unless it actually uses them.
var riskyFeatures = []string{
	"camera", "microphone", "geolocation", "payment",
}

// otherNotableFeatures are reported when left open but are not required for
// the control to pass.
var otherNotableFeatures = []string{
	"usb", "serial", "bluetooth", "midi", "display-capture",
	"idle-detection", "xr-spatial-tracking", "screen-wake-lock",
}

// PermissionsPolicy is a parsed Permissions-Policy value: feature name to
// allowlist.
type PermissionsPolicy struct {
	Raw      string
	Features map[string][]string
	Invalid  []string
}

// Denied reports whether a feature is present with an empty allowlist.
func (p PermissionsPolicy) Denied(feature string) bool {
	al, ok := p.Features[feature]
	return ok && len(al) == 0
}

// ParsePermissionsPolicy parses the structured-fields dictionary form,
// feature=(), feature=*, feature=(self "https://x").
func ParsePermissionsPolicy(raw string) PermissionsPolicy {
	p := PermissionsPolicy{Raw: strings.TrimSpace(raw), Features: map[string][]string{}}
	for _, item := range splitTopLevel(raw, ',') {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, value, ok := strings.Cut(item, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || name == "" {
			p.Invalid = append(p.Invalid, item)
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.TrimPrefix(value, "(")
		value = strings.TrimSuffix(value, ")")
		var allow []string
		for _, f := range strings.Fields(value) {
			f = strings.Trim(f, `"`)
			if f != "" {
				allow = append(allow, f)
			}
		}
		p.Features[name] = allow
	}
	return p
}

// splitTopLevel splits on sep while ignoring separators inside parentheses or
// quotes, which is what the structured-fields grammar requires.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, quoted, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			quoted = !quoted
		case '(':
			if !quoted {
				depth++
			}
		case ')':
			if !quoted && depth > 0 {
				depth--
			}
		case sep:
			if !quoted && depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// AnalyzePermissionsPolicy evaluates Permissions-Policy and reports which
// powerful features remain reachable.
func AnalyzePermissionsPolicy(r *probe.HTTPResponse) []finding.Finding {
	var out []finding.Finding
	if r.HasHeader("Feature-Policy") {
		out = append(out, finding.New("permissions-policy.legacy-feature-policy",
			"The obsolete Feature-Policy header is present; current browsers only read Permissions-Policy, which uses a different syntax.").
			WithEvidence(r.Header("Feature-Policy")))
	}
	if !r.HasHeader("Permissions-Policy") {
		return append(out, finding.New("permissions-policy.missing",
			"No Permissions-Policy header, so camera, microphone, geolocation and payment keep their default availability."))
	}

	raw := r.Header("Permissions-Policy")
	p := ParsePermissionsPolicy(raw)

	var open []string
	for _, f := range riskyFeatures {
		if !p.Denied(f) {
			open = append(open, f)
		}
	}
	var notable []string
	for _, f := range otherNotableFeatures {
		if _, declared := p.Features[f]; declared && !p.Denied(f) {
			notable = append(notable, f)
		}
	}
	sort.Strings(notable)

	if len(open) == 0 {
		detail := "camera, microphone, geolocation and payment are denied"
		if len(notable) > 0 {
			detail += "; still allowed: " + strings.Join(notable, ", ")
		}
		return append(out, finding.New("permissions-policy.ok", detail+".").WithEvidence(raw))
	}
	detail := "Not denied: " + strings.Join(append(open, notable...), ", ") + "."
	if len(p.Invalid) > 0 {
		detail += " Unparseable items: " + strings.Join(p.Invalid, ", ") + "."
	}
	return append(out, finding.New("permissions-policy.open-features", detail).WithEvidence(raw))
}
