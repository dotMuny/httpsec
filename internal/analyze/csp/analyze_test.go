package csp

import (
	"strings"
	"testing"

	"github.com/dotMuny/httpsec/internal/finding"
)

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func has(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func get(t *testing.T, fs []finding.Finding, id string) finding.Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %s not found in %v", id, ids(fs))
	return finding.Finding{}
}

func analyzeHeader(policy string) []finding.Finding {
	return Analyze(Input{Enforced: []string{policy}}).Findings
}

func TestNoPolicyAtAllFailsEveryCSPControl(t *testing.T) {
	fs := Analyze(Input{}).Findings
	for _, want := range []string{
		"csp.missing", "csp.script-src.missing", "csp.style-src.missing",
		"csp.default-src.missing", "csp.object-src.missing",
		"csp.base-uri.missing", "csp.frame-ancestors.missing",
	} {
		if !has(fs, want) {
			t.Errorf("missing %s; got %v", want, ids(fs))
		}
	}
}

func TestReportOnlyAloneIsNotAPolicy(t *testing.T) {
	fs := Analyze(Input{ReportOnly: []string{"default-src 'self'"}}).Findings
	if !has(fs, "csp.report-only-only") {
		t.Fatalf("want csp.report-only-only, got %v", ids(fs))
	}
	if has(fs, "csp.present") {
		t.Error("a report-only policy must not count as present")
	}
	if !has(fs, "csp.script-src.missing") {
		t.Error("report-only leaves scripts unrestricted, so the control should fail")
	}
}

func TestReportOnlyAlongsideEnforcedIsInformational(t *testing.T) {
	fs := Analyze(Input{
		Enforced:   []string{"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"},
		ReportOnly: []string{"default-src 'none'"},
	}).Findings
	f := get(t, fs, "csp.report-only-present")
	if f.Severity != finding.SeverityInfo {
		t.Errorf("severity = %s, want info", f.Severity)
	}
}

func TestMultiplePoliciesAreFlagged(t *testing.T) {
	fs := Analyze(Input{Enforced: []string{"default-src 'self'", "script-src 'none'"}}).Findings
	if !has(fs, "csp.multiple-policies") {
		t.Errorf("want csp.multiple-policies, got %v", ids(fs))
	}
}

func TestCommaSeparatedPoliciesInOneHeaderCountAsSeveral(t *testing.T) {
	fs := analyzeHeader("default-src 'self', script-src 'none'")
	if !has(fs, "csp.multiple-policies") {
		t.Errorf("a comma separates policies; got %v", ids(fs))
	}
}

func TestUnsafeInlineWithoutNonceIsHigh(t *testing.T) {
	fs := analyzeHeader("script-src 'self' 'unsafe-inline'")
	f := get(t, fs, "csp.script-src.unsafe-inline")
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if has(fs, "csp.script-src.ok") {
		t.Error("script-src must not also pass")
	}
}

func TestUnsafeInlineWithNonceIsIgnoredByBrowsers(t *testing.T) {
	fs := analyzeHeader("script-src 'self' 'unsafe-inline' 'nonce-abc123'")
	if has(fs, "csp.script-src.unsafe-inline") {
		t.Errorf("a nonce makes 'unsafe-inline' inert; got %v", ids(fs))
	}
	f := get(t, fs, "csp.script-src.unsafe-inline-ignored")
	if f.Severity != finding.SeverityInfo {
		t.Errorf("severity = %s, want info", f.Severity)
	}
}

func TestUnsafeInlineWithHashIsIgnoredByBrowsers(t *testing.T) {
	fs := analyzeHeader("script-src 'unsafe-inline' 'sha256-AAAA'")
	if !has(fs, "csp.script-src.unsafe-inline-ignored") {
		t.Errorf("a hash source also neutralises 'unsafe-inline'; got %v", ids(fs))
	}
}

func TestUnsafeEval(t *testing.T) {
	fs := analyzeHeader("script-src 'self' 'unsafe-eval'")
	if !has(fs, "csp.script-src.unsafe-eval") {
		t.Errorf("got %v", ids(fs))
	}
}

func TestWildcardScriptSrc(t *testing.T) {
	for _, policy := range []string{"script-src *", "script-src https:", "script-src 'self' http:"} {
		fs := analyzeHeader(policy)
		if !has(fs, "csp.script-src.wildcard") {
			t.Errorf("%q should be a wildcard; got %v", policy, ids(fs))
		}
	}
}

func TestDataURIScriptSrcIsReportedSeparately(t *testing.T) {
	fs := analyzeHeader("script-src 'self' data:")
	if !has(fs, "csp.script-src.data-uri") {
		t.Errorf("got %v", ids(fs))
	}
	if has(fs, "csp.script-src.wildcard") {
		t.Error("data: should not also be reported as a host wildcard")
	}
}

func TestBypassableHostIsDetected(t *testing.T) {
	fs := analyzeHeader("script-src 'self' https://ajax.googleapis.com")
	f := get(t, fs, "csp.script-src.bypassable-host")
	if f.Subject != "ajax.googleapis.com" {
		t.Errorf("subject = %q", f.Subject)
	}
	if !strings.Contains(f.Detail, "Angular") {
		t.Errorf("the detail should say why the host is a problem: %q", f.Detail)
	}
}

func TestStrictDynamicSuppressesHostFindings(t *testing.T) {
	// With 'strict-dynamic' and a nonce, CSP3 browsers ignore host and scheme
	// sources entirely, so reporting them would be wrong.
	fs := analyzeHeader("script-src 'nonce-abc' 'strict-dynamic' https: https://ajax.googleapis.com")
	for _, unwanted := range []string{"csp.script-src.wildcard", "csp.script-src.bypassable-host"} {
		if has(fs, unwanted) {
			t.Errorf("%s should be suppressed by strict-dynamic; got %v", unwanted, ids(fs))
		}
	}
	f := get(t, fs, "csp.script-src.strict-dynamic")
	if f.Severity != finding.SeverityPass {
		t.Errorf("severity = %s, want pass", f.Severity)
	}
}

func TestStrictDynamicWithoutNonceDoesNotSuppress(t *testing.T) {
	fs := analyzeHeader("script-src 'strict-dynamic' https:")
	if !has(fs, "csp.script-src.wildcard") {
		t.Errorf("without a nonce, strict-dynamic does not apply; got %v", ids(fs))
	}
	if has(fs, "csp.script-src.strict-dynamic") {
		t.Error("strict-dynamic should not pass without a nonce or hash")
	}
}

func TestScriptSrcInheritsFromDefaultSrc(t *testing.T) {
	fs := analyzeHeader("default-src 'self' 'unsafe-inline'")
	f := get(t, fs, "csp.script-src.unsafe-inline")
	if !strings.HasPrefix(f.Evidence, "default-src") {
		t.Errorf("evidence should name the directive it came from: %q", f.Evidence)
	}
}

func TestScriptSrcOkWhenRestrictive(t *testing.T) {
	fs := analyzeHeader("script-src 'self' https://cdn.example.com")
	if !has(fs, "csp.script-src.ok") {
		t.Errorf("got %v", ids(fs))
	}
}

func TestStyleSrc(t *testing.T) {
	if !has(analyzeHeader("style-src 'self' 'unsafe-inline'"), "csp.style-src.unsafe-inline") {
		t.Error("inline styles should be reported")
	}
	if !has(analyzeHeader("style-src 'self' 'unsafe-inline' 'nonce-a'"), "csp.style-src.ok") {
		t.Error("a nonce neutralises inline styles too")
	}
	if !has(analyzeHeader("style-src 'self'"), "csp.style-src.ok") {
		t.Error("a restrictive style-src should pass")
	}
	if !has(analyzeHeader("script-src 'none'"), "csp.style-src.missing") {
		t.Error("no style-src and no default-src should fail the control")
	}
}

func TestObjectSrc(t *testing.T) {
	if !has(analyzeHeader("object-src 'none'"), "csp.object-src.ok") {
		t.Error("object-src 'none' should pass")
	}
	if !has(analyzeHeader("object-src 'self'"), "csp.object-src.permissive") {
		t.Error("anything other than 'none' should be reported")
	}
	if !has(analyzeHeader("script-src 'none'"), "csp.object-src.missing") {
		t.Error("no object-src and no default-src should fail the control")
	}
	if !has(analyzeHeader("default-src 'none'"), "csp.object-src.ok") {
		t.Error("object-src should inherit default-src 'none'")
	}
}

func TestBaseURI(t *testing.T) {
	if !has(analyzeHeader("default-src 'self'"), "csp.base-uri.missing") {
		t.Error("base-uri does not inherit, so it should be reported as missing")
	}
	if !has(analyzeHeader("base-uri 'none'"), "csp.base-uri.ok") {
		t.Error("base-uri 'none' should pass")
	}
	if !has(analyzeHeader("base-uri *"), "csp.base-uri.permissive") {
		t.Error("a wildcard base-uri should be reported")
	}
}

func TestFrameAncestors(t *testing.T) {
	if !has(analyzeHeader("default-src 'self'"), "csp.frame-ancestors.missing") {
		t.Error("frame-ancestors does not inherit, so it should be reported as missing")
	}
	if !has(analyzeHeader("frame-ancestors 'self' https://partner.example"), "csp.frame-ancestors.ok") {
		t.Error("an explicit list should pass")
	}
	if !has(analyzeHeader("frame-ancestors *"), "csp.frame-ancestors.permissive") {
		t.Error("frame-ancestors * should be reported")
	}
	if !has(analyzeHeader("frame-ancestors https:"), "csp.frame-ancestors.permissive") {
		t.Error("a scheme-only frame-ancestors should be reported")
	}
}

func TestDefaultSrc(t *testing.T) {
	if !has(analyzeHeader("script-src 'none'"), "csp.default-src.missing") {
		t.Error("a policy with no default-src should be reported")
	}
	if !has(analyzeHeader("default-src *"), "csp.default-src.permissive") {
		t.Error("default-src * should be reported")
	}
	if !has(analyzeHeader("default-src 'self'"), "csp.default-src.ok") {
		t.Error("default-src 'self' should pass")
	}
}

func TestReportUriWithoutReportTo(t *testing.T) {
	if !has(analyzeHeader("default-src 'self'; report-uri /csp"), "csp.reporting.uri-without-to") {
		t.Error("report-uri without report-to should be reported")
	}
	if has(analyzeHeader("default-src 'self'; report-uri /csp; report-to grp"), "csp.reporting.uri-without-to") {
		t.Error("with report-to present there is nothing to report")
	}
}

func TestHygieneFindings(t *testing.T) {
	fs := analyzeHeader("script-src 'self'; frobnicate 'self'; script-src *; img-src")
	f := get(t, fs, "csp.parse-error")
	for _, want := range []string{"unknown", "more than once", "empty source list"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q should mention %q", f.Detail, want)
		}
	}
}

func TestDeprecatedDirective(t *testing.T) {
	fs := analyzeHeader("default-src 'self'; block-all-mixed-content")
	f := get(t, fs, "csp.deprecated-directive")
	if !strings.Contains(f.Detail, "block-all-mixed-content") {
		t.Errorf("detail = %q", f.Detail)
	}
}

func TestGoldenPolicyProducesNoProblems(t *testing.T) {
	policy := "default-src 'none'; script-src 'nonce-r4nd0m' 'strict-dynamic'; " +
		"style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"object-src 'none'; base-uri 'none'; frame-ancestors 'none'; " +
		"report-to csp; report-uri /csp"
	fs := analyzeHeader(policy)
	for _, f := range fs {
		if f.Severity.IsProblem() {
			t.Errorf("unexpected problem %s: %s", f.ID, f.Detail)
		}
	}
}

func TestRealWorldPolicies(t *testing.T) {
	// Policies in the shape large sites actually deploy them. The expectations
	// were checked by hand against the CSP specification.
	cases := []struct {
		name   string
		policy string
		want   []string
		unwant []string
	}{
		{
			name: "github-like nonce policy",
			policy: "default-src 'none'; base-uri 'self'; " +
				"script-src github.githubassets.com; style-src 'unsafe-inline' github.githubassets.com; " +
				"img-src 'self' data: github.githubassets.com; connect-src 'self'; " +
				"frame-ancestors 'none'; form-action 'self'",
			want:   []string{"csp.style-src.unsafe-inline", "csp.object-src.ok", "csp.base-uri.ok", "csp.frame-ancestors.ok"},
			unwant: []string{"csp.script-src.unsafe-inline", "csp.script-src.wildcard"},
		},
		{
			name:   "marketing site with an allowlist full of CDNs",
			policy: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://www.google.com",
			want: []string{
				"csp.script-src.unsafe-inline", "csp.script-src.unsafe-eval",
				"csp.script-src.bypassable-host", "csp.base-uri.missing", "csp.frame-ancestors.missing",
			},
		},
		{
			name:   "wide open",
			policy: "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'",
			want: []string{
				"csp.default-src.permissive", "csp.script-src.unsafe-inline",
				"csp.script-src.unsafe-eval", "csp.script-src.wildcard", "csp.script-src.data-uri",
				"csp.object-src.permissive",
			},
		},
		{
			name:   "frame-ancestors only, as a clickjacking-only deployment",
			policy: "frame-ancestors 'self'",
			want:   []string{"csp.frame-ancestors.ok", "csp.script-src.missing", "csp.default-src.missing"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := analyzeHeader(c.policy)
			for _, w := range c.want {
				if !has(fs, w) {
					t.Errorf("want %s; got %v", w, ids(fs))
				}
			}
			for _, u := range c.unwant {
				if has(fs, u) {
					t.Errorf("did not want %s; got %v", u, ids(fs))
				}
			}
		})
	}
}

func TestEveryEmittedIDIsInTheCatalogue(t *testing.T) {
	// finding.New panics on an unknown ID, so exercising a wide spread of
	// policies is enough to prove the analyser only emits catalogued IDs.
	policies := []string{
		"", "default-src 'self'", "script-src 'unsafe-inline' 'unsafe-eval' * data:",
		"script-src 'nonce-a' 'strict-dynamic'", "object-src 'self'", "base-uri *",
		"frame-ancestors *", "report-uri /x", "weird-src 'self'; img-src",
		"block-all-mixed-content; default-src https://cdnjs.cloudflare.com",
	}
	for _, p := range policies {
		in := Input{}
		if p != "" {
			in.Enforced = []string{p}
		}
		for _, f := range Analyze(in).Findings {
			if _, ok := finding.Lookup(f.ID); !ok {
				t.Errorf("policy %q produced uncatalogued ID %s", p, f.ID)
			}
		}
	}
}
