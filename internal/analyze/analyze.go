// Package analyze turns an Observation into findings.
//
// The hard rule of this package, and the reason the whole tool is arranged
// this way: nothing under internal/analyze performs network I/O. Every
// analyser takes recorded evidence and returns findings, which is what makes
// the analysis reproducible from the JSON fixtures in testdata/observations.
package analyze

import (
	"time"

	"github.com/dotMuny/httpsec/internal/analyze/cookies"
	"github.com/dotMuny/httpsec/internal/analyze/csp"
	"github.com/dotMuny/httpsec/internal/analyze/headers"
	"github.com/dotMuny/httpsec/internal/analyze/tlsconf"
	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// Result is the output of a full analysis.
type Result struct {
	Findings []finding.Finding
	// Policy is the parsed enforced CSP, when there is one. Reports use it to
	// show the directive breakdown.
	Policy *csp.Policy
	// Notes explain why parts of the analysis were skipped.
	Notes []string
}

// Run analyses an Observation. now is injected so that certificate expiry
// checks are deterministic in tests.
func Run(obs *probe.Observation, now time.Time) Result {
	var res Result
	add := func(fs ...finding.Finding) { res.Findings = append(res.Findings, fs...) }

	httpUsable := obs.HTTPS != nil && obs.HTTPS.Error == "" && obs.HTTPS.StatusCode > 0

	switch {
	case obs.WasSkipped(probe.GroupHTTP):
		res.Notes = append(res.Notes, "HTTP probes were skipped (--tls-only), so header, cookie and CSP controls were not evaluated.")
	case !httpUsable:
		reason := "no response"
		if obs.HTTPS != nil && obs.HTTPS.Error != "" {
			reason = obs.HTTPS.Error
		}
		res.Notes = append(res.Notes, "The HTTPS request failed ("+reason+"), so header, cookie and CSP controls were not evaluated.")
	default:
		r := obs.HTTPS

		cspRes := csp.Analyze(csp.Input{
			Enforced:   r.HeaderValues("Content-Security-Policy"),
			ReportOnly: r.HeaderValues("Content-Security-Policy-Report-Only"),
		})
		add(cspRes.Findings...)
		res.Policy = cspRes.Policy

		hasFrameAncestors := cspRes.Policy != nil && !cspRes.Policy.ReportOnly && cspRes.Policy.Has("frame-ancestors")

		add(headers.AnalyzeHSTS(obs.Host, r, obs.PlainHTTP)...)
		add(headers.AnalyzeFraming(r, hasFrameAncestors)...)
		add(headers.AnalyzeNoSniff(r)...)
		add(headers.AnalyzeReferrerPolicy(r)...)
		add(headers.AnalyzePermissionsPolicy(r)...)
		add(headers.AnalyzeIsolation(r)...)
		add(headers.AnalyzeDisclosure(r)...)
		add(headers.AnalyzeLegacyHeaders(r)...)
		add(cookies.Analyze(obs.Host, r)...)

		if obs.WasSkipped(probe.GroupCORS) {
			res.Notes = append(res.Notes, "The CORS probe was skipped.")
		} else {
			add(headers.AnalyzeCORS(obs.CORS)...)
		}

		add(headers.AnalyzeRedirect(obs.Host, obs.PlainHTTP)...)
		if obs.PlainHTTP != nil && obs.PlainHTTP.Error != "" {
			res.Notes = append(res.Notes, "http://"+obs.Host+" could not be reached ("+obs.PlainHTTP.Error+"), so the HTTPS upgrade control was not evaluated.")
		}

		if obs.WasSkipped(probe.GroupBody) || r.Body == "" {
			res.Notes = append(res.Notes, "No HTML body was retrieved, so mixed content was not analysed.")
		} else {
			add(headers.AnalyzeMixedContent(r)...)
		}

		add(headers.AnalyzeSecurityTxt(obs.SecurityTxt)...)
		add(headers.AnalyzeMethods(obs.Options, obs.Trace)...)
	}

	switch {
	case obs.WasSkipped(probe.GroupTLS):
		res.Notes = append(res.Notes, "TLS probes were skipped (--headers-only), so no TLS control was evaluated.")
	case obs.TLS == nil:
		res.Notes = append(res.Notes, "No TLS evidence was recorded.")
	default:
		add(tlsconf.Analyze(obs.Host, obs.TLS, now)...)
	}

	finding.Sort(res.Findings)
	return res
}
