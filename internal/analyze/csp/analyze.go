package csp

import (
	"fmt"
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
)

// Input is everything the CSP analysis needs, extracted from the Observation
// by the caller. Keeping it a plain struct is what lets the CSP tests run
// against header values alone.
type Input struct {
	// Enforced holds the values of every Content-Security-Policy header.
	Enforced []string
	// ReportOnly holds the values of every Content-Security-Policy-Report-Only
	// header.
	ReportOnly []string
}

// Result carries the findings plus the parsed policy, so that reports can
// show the directive breakdown without parsing the header again.
type Result struct {
	Findings []finding.Finding
	Policy   *Policy
}

// Analyze evaluates a site's CSP posture.
func Analyze(in Input) Result {
	enforced := splitPolicies(in.Enforced)
	reportOnly := splitPolicies(in.ReportOnly)

	switch {
	case len(enforced) == 0 && len(reportOnly) == 0:
		return Result{Findings: noPolicyFindings(finding.New("csp.missing",
			"No Content-Security-Policy or Content-Security-Policy-Report-Only header was returned."))}
	case len(enforced) == 0:
		p := Parse(reportOnly[0], true)
		f := finding.New("csp.report-only-only",
			"A Content-Security-Policy-Report-Only header is present but nothing is enforced.").
			WithEvidence(p.Raw)
		return Result{Findings: noPolicyFindings(f), Policy: p}
	}

	// The effective policy of several enforced headers is their intersection,
	// which is at least as strict as any one of them. httpsec evaluates the
	// first and flags the rest rather than computing the intersection; see
	// docs/decisions.md.
	p := Parse(enforced[0], false)
	out := []finding.Finding{
		finding.New("csp.present", fmt.Sprintf("An enforced policy with %d directives is deployed.", len(p.Directives))).
			WithEvidence(p.Raw),
	}
	if len(enforced) > 1 {
		out = append(out, finding.New("csp.multiple-policies",
			fmt.Sprintf("%d enforced Content-Security-Policy headers were returned; the browser applies all of them and httpsec evaluated the first.", len(enforced))).
			WithEvidence(strings.Join(enforced, " || ")))
	}
	if len(reportOnly) > 0 {
		out = append(out, finding.New("csp.report-only-present",
			"A Report-Only policy is deployed alongside the enforced one.").
			WithEvidence(reportOnly[0]))
	}

	out = append(out, checkHygiene(p)...)
	out = append(out, checkDefaultSrc(p)...)
	out = append(out, checkScriptSrc(p)...)
	out = append(out, checkStyleSrc(p)...)
	out = append(out, checkObjectSrc(p)...)
	out = append(out, checkBaseURI(p)...)
	out = append(out, checkFrameAncestors(p)...)
	out = append(out, checkReporting(p)...)

	return Result{Findings: out, Policy: p}
}

// noPolicyFindings expands "there is no enforced policy" into a failure for
// every CSP control, so that the score reflects the whole missing layer
// rather than one control.
func noPolicyFindings(head finding.Finding) []finding.Finding {
	const d = "No enforced Content-Security-Policy applies, so this control has nothing to restrict it."
	return []finding.Finding{
		head,
		finding.New("csp.script-src.missing", d),
		finding.New("csp.style-src.missing", d),
		finding.New("csp.default-src.missing", d),
		finding.New("csp.object-src.missing", d),
		finding.New("csp.base-uri.missing", d),
		finding.New("csp.frame-ancestors.missing", d),
	}
}

// splitPolicies flattens header values into individual policies. A single
// header may carry several policies separated by commas, and a server may
// also send the header more than once.
func splitPolicies(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func checkHygiene(p *Policy) []finding.Finding {
	var out []finding.Finding
	var problems []string
	if len(p.Unknown) > 0 {
		problems = append(problems, "unknown directives: "+strings.Join(p.Unknown, ", "))
	}
	if len(p.Duplicates) > 0 {
		problems = append(problems, "directives declared more than once (only the first counts): "+strings.Join(p.Duplicates, ", "))
	}
	if len(p.Empty) > 0 {
		problems = append(problems, "directives with an empty source list: "+strings.Join(p.Empty, ", "))
	}
	if len(problems) > 0 {
		out = append(out, finding.New("csp.parse-error", strings.Join(problems, "; ")).WithEvidence(p.Raw))
	}
	if len(p.Deprecated) > 0 {
		var notes []string
		for _, d := range p.Deprecated {
			notes = append(notes, fmt.Sprintf("%s (%s)", d, deprecatedDirectives[d]))
		}
		out = append(out, finding.New("csp.deprecated-directive", strings.Join(notes, "; ")).WithEvidence(p.Raw))
	}
	return out
}

func checkDefaultSrc(p *Policy) []finding.Finding {
	if !p.Has("default-src") {
		return []finding.Finding{finding.New("csp.default-src.missing",
			"The policy has no default-src, so every fetch directive it does not name is unrestricted. Declared directives: "+
				strings.Join(p.DirectiveNames(), ", ")).WithEvidence(p.Raw)}
	}
	v := p.Values("default-src")
	if w := Wildcards(v); len(w) > 0 {
		return []finding.Finding{finding.New("csp.default-src.permissive",
			"default-src allows "+strings.Join(w, " ")+", which does not restrict the directives falling back to it.").
			WithEvidence("default-src " + strings.Join(v, " "))}
	}
	return []finding.Finding{finding.New("csp.default-src.ok",
		"default-src "+strings.Join(v, " ")).WithEvidence("default-src " + strings.Join(v, " "))}
}

func checkScriptSrc(p *Policy) []finding.Finding {
	values, ok := p.Effective("script-src")
	src := p.EffectiveSource("script-src")
	if !ok {
		return []finding.Finding{finding.New("csp.script-src.missing",
			"Neither script-src nor default-src is declared.").WithEvidence(p.Raw)}
	}
	evidence := src + " " + strings.Join(values, " ")

	var out []finding.Finding
	clean := true

	nonced := HasNonce(values) || HasHash(values)
	strictDynamic := HasKeyword(values, "strict-dynamic")

	if HasKeyword(values, "unsafe-inline") {
		if nonced {
			out = append(out, finding.New("csp.script-src.unsafe-inline-ignored",
				"'unsafe-inline' is present but so is a nonce or hash, so CSP3 browsers ignore it. It only affects browsers that predate CSP2.").
				WithEvidence(evidence))
		} else {
			clean = false
			out = append(out, finding.New("csp.script-src.unsafe-inline",
				"'unsafe-inline' is allowed for scripts and no nonce or hash is present, so any injected script tag or inline handler executes.").
				WithEvidence(evidence))
		}
	}
	if HasKeyword(values, "unsafe-eval") {
		clean = false
		out = append(out, finding.New("csp.script-src.unsafe-eval",
			"'unsafe-eval' is allowed, which re-enables eval(), new Function() and string-argument timers.").
			WithEvidence(evidence))
	}

	// With 'strict-dynamic' and a nonce or hash, CSP3 browsers ignore host
	// and scheme sources entirely, so flagging them would be wrong.
	hostSourcesMatter := !strictDynamic || !nonced

	if hostSourcesMatter {
		var wide, data []string
		for _, w := range Wildcards(values) {
			if w == "data:" || w == "blob:" || w == "filesystem:" {
				data = append(data, w)
				continue
			}
			wide = append(wide, w)
		}
		if len(wide) > 0 {
			clean = false
			out = append(out, finding.New("csp.script-src.wildcard",
				"script-src allows "+strings.Join(wide, " ")+", so scripts may be loaded from any host.").
				WithEvidence(evidence))
		}
		if len(data) > 0 {
			clean = false
			out = append(out, finding.New("csp.script-src.data-uri",
				"script-src allows "+strings.Join(data, " ")+", which lets an attacker supply the script body inline.").
				WithEvidence(evidence))
		}
		for _, h := range Hosts(values) {
			if b, hit := LookupBypass(h); hit {
				clean = false
				out = append(out, finding.New("csp.script-src.bypassable-host",
					fmt.Sprintf("script-src allowlists %s. %s", h, b.Reason)).
					WithSubject(h).WithEvidence(evidence))
			}
		}
	}

	switch {
	case strictDynamic && nonced:
		out = append(out, finding.New("csp.script-src.strict-dynamic",
			"script-src combines 'strict-dynamic' with a nonce or hash, so host allowlist bypasses do not apply.").
			WithEvidence(evidence))
	case clean:
		out = append(out, finding.New("csp.script-src.ok",
			"script-src restricts scripts to "+strings.Join(values, " ")).WithEvidence(evidence))
	}
	return out
}

func checkStyleSrc(p *Policy) []finding.Finding {
	values, ok := p.Effective("style-src")
	src := p.EffectiveSource("style-src")
	if !ok {
		return []finding.Finding{finding.New("csp.style-src.missing",
			"Neither style-src nor default-src is declared.").WithEvidence(p.Raw)}
	}
	evidence := src + " " + strings.Join(values, " ")
	if HasKeyword(values, "unsafe-inline") && !HasNonce(values) && !HasHash(values) {
		return []finding.Finding{finding.New("csp.style-src.unsafe-inline",
			"'unsafe-inline' is allowed for stylesheets.").WithEvidence(evidence)}
	}
	return []finding.Finding{finding.New("csp.style-src.ok",
		"style-src restricts styles to "+strings.Join(values, " ")).WithEvidence(evidence)}
}

func checkObjectSrc(p *Policy) []finding.Finding {
	values, ok := p.Effective("object-src")
	src := p.EffectiveSource("object-src")
	if !ok {
		return []finding.Finding{finding.New("csp.object-src.missing",
			"Neither object-src nor default-src is declared, so plugin content is unrestricted.").WithEvidence(p.Raw)}
	}
	evidence := src + " " + strings.Join(values, " ")
	if IsNone(values) {
		return []finding.Finding{finding.New("csp.object-src.ok", evidence).WithEvidence(evidence)}
	}
	return []finding.Finding{finding.New("csp.object-src.permissive",
		"object-src resolves to "+strings.Join(values, " ")+" rather than 'none'.").WithEvidence(evidence)}
}

func checkBaseURI(p *Policy) []finding.Finding {
	if !p.Has("base-uri") {
		return []finding.Finding{finding.New("csp.base-uri.missing",
			"base-uri is not declared and does not inherit from default-src, so an injected <base> tag can retarget every relative script URL.").
			WithEvidence(p.Raw)}
	}
	v := p.Values("base-uri")
	evidence := "base-uri " + strings.Join(v, " ")
	if w := Wildcards(v); len(w) > 0 {
		return []finding.Finding{finding.New("csp.base-uri.permissive",
			"base-uri allows "+strings.Join(w, " ")+".").WithEvidence(evidence)}
	}
	return []finding.Finding{finding.New("csp.base-uri.ok", evidence).WithEvidence(evidence)}
}

func checkFrameAncestors(p *Policy) []finding.Finding {
	if !p.Has("frame-ancestors") {
		return []finding.Finding{finding.New("csp.frame-ancestors.missing",
			"frame-ancestors is not declared and does not inherit from default-src.").WithEvidence(p.Raw)}
	}
	v := p.Values("frame-ancestors")
	evidence := "frame-ancestors " + strings.Join(v, " ")
	for _, s := range v {
		if s == "*" || s == "https:" || s == "http:" {
			return []finding.Finding{finding.New("csp.frame-ancestors.permissive",
				"frame-ancestors allows "+s+", so any site may frame this page.").WithEvidence(evidence)}
		}
	}
	return []finding.Finding{finding.New("csp.frame-ancestors.ok", evidence).WithEvidence(evidence)}
}

func checkReporting(p *Policy) []finding.Finding {
	if p.Has("report-uri") && !p.Has("report-to") {
		return []finding.Finding{finding.New("csp.reporting.uri-without-to",
			"The policy uses report-uri without a matching report-to group.").
			WithEvidence("report-uri " + strings.Join(p.Values("report-uri"), " "))}
	}
	return nil
}
