// Package csp parses Content-Security-Policy headers and evaluates the
// quality of the policy they express.
//
// It lives in its own package because the interesting part of auditing CSP is
// not noticing that the header is missing: it is deciding whether a policy
// that exists actually restricts anything. That needs a real parser, a model
// of directive fallback, and a notion of which sources are effectively
// wildcards.
package csp

import (
	"sort"
	"strings"
)

// Directive is one directive of a policy, with its source list in the order
// the policy declared it.
type Directive struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Policy is a parsed Content-Security-Policy header value.
type Policy struct {
	Raw        string      `json:"raw"`
	ReportOnly bool        `json:"report_only"`
	Directives []Directive `json:"directives"`

	// Duplicates records directives declared more than once. CSP says the
	// first occurrence wins and the rest are ignored, which is a common
	// source of policies that do not do what their author believes.
	Duplicates []string `json:"duplicates,omitempty"`
	// Unknown records directive names no current browser implements.
	Unknown []string `json:"unknown,omitempty"`
	// Deprecated records directives that browsers have stopped honouring.
	Deprecated []string `json:"deprecated,omitempty"`
	// Empty records directives declared with no source list where one is
	// required.
	Empty []string `json:"empty,omitempty"`

	index map[string][]string
}

// fetchDirectives fall back to default-src when they are not declared.
var fetchDirectives = map[string]bool{
	"child-src":       true,
	"connect-src":     true,
	"default-src":     true,
	"font-src":        true,
	"frame-src":       true,
	"img-src":         true,
	"manifest-src":    true,
	"media-src":       true,
	"object-src":      true,
	"prefetch-src":    true,
	"script-src":      true,
	"script-src-attr": true,
	"script-src-elem": true,
	"style-src":       true,
	"style-src-attr":  true,
	"style-src-elem":  true,
	"worker-src":      true,
}

// standaloneDirectives do not inherit from default-src. Forgetting that is
// the single most common CSP mistake httpsec sees.
var standaloneDirectives = map[string]bool{
	"base-uri":                  true,
	"form-action":               true,
	"frame-ancestors":           true,
	"navigate-to":               true,
	"report-to":                 true,
	"report-uri":                true,
	"require-trusted-types-for": true,
	"sandbox":                   true,
	"trusted-types":             true,
	"upgrade-insecure-requests": true,
}

// deprecatedDirectives are parsed but no longer enforced by current browsers.
var deprecatedDirectives = map[string]string{
	"block-all-mixed-content": "removed from the specification; use upgrade-insecure-requests or fix the URLs",
	"plugin-types":            "removed along with plugin support",
	"referrer":                "never standardised; use the Referrer-Policy header",
	"require-sri-for":         "never shipped; use integrity attributes",
	"navigate-to":             "removed from the specification",
	"prefetch-src":            "removed from the specification",
	// report-uri is formally deprecated, but it is still the only reporting
	// form Safari understands, so a policy that carries both it and report-to
	// is correct rather than stale. checkReporting handles the case where
	// report-to is missing.
}

// noValueDirectives take no source list.
var noValueDirectives = map[string]bool{
	"upgrade-insecure-requests": true,
	"block-all-mixed-content":   true,
	"sandbox":                   true, // sandbox may be empty, which is the most restrictive form
}

// Parse splits a Content-Security-Policy header value into directives.
// Parsing never fails: a browser skips what it cannot understand and so does
// this parser, recording the fact instead.
func Parse(raw string, reportOnly bool) *Policy {
	p := &Policy{Raw: strings.TrimSpace(raw), ReportOnly: reportOnly, index: map[string][]string{}}

	for _, segment := range strings.Split(raw, ";") {
		fields := strings.Fields(segment)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		values := fields[1:]

		if _, seen := p.index[name]; seen {
			p.Duplicates = appendUnique(p.Duplicates, name)
			continue // first declaration wins
		}

		known := fetchDirectives[name] || standaloneDirectives[name] || noValueDirectives[name] ||
			deprecatedDirectives[name] != ""
		if !known {
			p.Unknown = appendUnique(p.Unknown, name)
		}
		if _, dep := deprecatedDirectives[name]; dep {
			p.Deprecated = appendUnique(p.Deprecated, name)
		}
		if len(values) == 0 && !noValueDirectives[name] && known {
			p.Empty = appendUnique(p.Empty, name)
		}

		norm := make([]string, 0, len(values))
		for _, v := range values {
			norm = append(norm, normaliseSource(v))
		}
		p.Directives = append(p.Directives, Directive{Name: name, Values: norm})
		p.index[name] = norm
	}
	return p
}

// normaliseSource lowercases the parts of a source expression that are
// case-insensitive while leaving nonce and hash payloads alone, since those
// are base64 and case-sensitive.
func normaliseSource(v string) string {
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "'nonce-") || strings.HasPrefix(lower, "'sha256-") ||
		strings.HasPrefix(lower, "'sha384-") || strings.HasPrefix(lower, "'sha512-") {
		return v
	}
	return lower
}

// Has reports whether a directive was declared explicitly.
func (p *Policy) Has(name string) bool {
	_, ok := p.index[name]
	return ok
}

// Values returns the source list of a directive exactly as declared, with no
// fallback applied.
func (p *Policy) Values(name string) []string {
	return p.index[name]
}

// Effective returns the source list that actually applies to a directive,
// following the default-src fallback for fetch directives. The second return
// value reports whether anything applies at all.
func (p *Policy) Effective(name string) ([]string, bool) {
	if v, ok := p.index[name]; ok {
		return v, true
	}
	// script-src-elem and style-src-elem fall back to script-src / style-src
	// before reaching default-src.
	switch name {
	case "script-src-elem", "script-src-attr":
		if v, ok := p.index["script-src"]; ok {
			return v, true
		}
	case "style-src-elem", "style-src-attr":
		if v, ok := p.index["style-src"]; ok {
			return v, true
		}
	}
	if fetchDirectives[name] {
		if v, ok := p.index["default-src"]; ok {
			return v, true
		}
	}
	return nil, false
}

// EffectiveSource names the directive that actually supplies the source list
// for name: itself, the directive it falls back to, or "" when nothing does.
func (p *Policy) EffectiveSource(name string) string {
	if p.Has(name) {
		return name
	}
	switch name {
	case "script-src-elem", "script-src-attr":
		if p.Has("script-src") {
			return "script-src"
		}
	case "style-src-elem", "style-src-attr":
		if p.Has("style-src") {
			return "style-src"
		}
	}
	if fetchDirectives[name] && p.Has("default-src") {
		return "default-src"
	}
	return ""
}

// DirectiveNames returns the declared directive names, sorted.
func (p *Policy) DirectiveNames() []string {
	out := make([]string, 0, len(p.index))
	for k := range p.index {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Keyword helpers. Source-list keywords are always written in single quotes.

// HasKeyword reports whether a source list contains a quoted keyword.
func HasKeyword(values []string, keyword string) bool {
	want := "'" + strings.Trim(keyword, "'") + "'"
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// HasNonce reports whether a source list contains at least one nonce.
func HasNonce(values []string) bool {
	for _, v := range values {
		if strings.HasPrefix(strings.ToLower(v), "'nonce-") {
			return true
		}
	}
	return false
}

// HasHash reports whether a source list contains at least one hash source.
func HasHash(values []string) bool {
	for _, v := range values {
		l := strings.ToLower(v)
		if strings.HasPrefix(l, "'sha256-") || strings.HasPrefix(l, "'sha384-") || strings.HasPrefix(l, "'sha512-") {
			return true
		}
	}
	return false
}

// IsNone reports whether a source list is exactly 'none'.
func IsNone(values []string) bool {
	return len(values) == 1 && strings.EqualFold(values[0], "'none'")
}

// Wildcards returns the sources in a list that allow effectively any host.
//
// A bare "*" is the obvious case. Scheme-only sources such as https: and
// http: are just as broad. data: and blob: are worse in a script context,
// because the attacker supplies the content itself. A leading "*." is a
// subdomain wildcard and is only as risky as the domain it is under, so it is
// reported separately by the analyser rather than here.
func Wildcards(values []string) []string {
	var out []string
	for _, v := range values {
		switch strings.ToLower(v) {
		case "*", "https:", "http:", "data:", "blob:", "filesystem:", "mediastream:", "*:":
			out = append(out, v)
		}
	}
	return out
}

// SubdomainWildcards returns sources of the form *.example.com.
func SubdomainWildcards(values []string) []string {
	var out []string
	for _, v := range values {
		if strings.HasPrefix(v, "*.") {
			out = append(out, v)
		}
	}
	return out
}

// Hosts returns the host sources of a list, stripped of scheme, port and
// path, which is the form the bypass list is keyed on.
func Hosts(values []string) []string {
	var out []string
	for _, v := range values {
		if strings.HasPrefix(v, "'") {
			continue
		}
		h := v
		if i := strings.Index(h, "://"); i >= 0 {
			h = h[i+3:]
		}
		if strings.HasSuffix(h, ":") {
			continue // scheme-only source
		}
		if i := strings.IndexByte(h, '/'); i >= 0 {
			h = h[:i]
		}
		if i := strings.LastIndexByte(h, ':'); i >= 0 {
			h = h[:i]
		}
		h = strings.TrimSuffix(h, ".")
		if h == "" || h == "*" {
			continue
		}
		out = append(out, strings.ToLower(h))
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}
