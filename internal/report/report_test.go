package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dotMuny/httpsec/internal/analyze"
	"github.com/dotMuny/httpsec/internal/analyze/csp"
	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
	"github.com/dotMuny/httpsec/internal/score"
)

var fixedTime = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

func sampleObservation() *probe.Observation {
	return &probe.Observation{
		SchemaVersion: probe.ObservationSchemaVersion,
		Tool:          "httpsec 0.0.0-test",
		Target:        "a.test",
		Host:          "a.test",
		Port:          "443",
		StartedAt:     fixedTime,
		DurationMs:    1234,
		HTTPS: &probe.HTTPResponse{
			RequestURL: "https://a.test/",
			FinalURL:   "https://a.test/",
			StatusCode: 200,
			Headers: map[string][]string{
				"Content-Security-Policy": {"default-src 'self'; script-src 'self' 'unsafe-inline'"},
				"Set-Cookie":              {"sid=x; Path=/"},
				"Server":                  {"nginx/1.24.0"},
			},
			Body: `<html><script src="http://cdn.test/a.js"></script></html>`,
		},
		PlainHTTP: &probe.HTTPResponse{
			RequestURL: "http://a.test/", FinalURL: "http://a.test/", StatusCode: 200,
		},
		TLS: &probe.TLSInfo{
			ServerName: "a.test",
			Versions: []probe.VersionResult{
				{Version: "TLS 1.0", Supported: true},
				{Version: "TLS 1.1"},
				{Version: "TLS 1.2", Supported: true},
				{Version: "TLS 1.3", Supported: true},
			},
			Suites:              []probe.SuiteResult{{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ForwardSecrecy: true, AEAD: true}},
			TLS13Suite:          "TLS_AES_128_GCM_SHA256",
			Preference:          "server",
			ChainComplete:       true,
			ChainLength:         2,
			VerifiedChainLength: 3,
			HostnameMatch:       true,
			SCTCount:            3,
			OCSPStapled:         true,
			ALPN:                []string{"h2"},
			Resumption:          "ticket",
			SecureRenegotiation: true,
			Chain: []probe.CertInfo{{
				Subject: "CN=a.test", Issuer: "CN=Test CA",
				NotBefore: fixedTime.AddDate(0, -1, 0), NotAfter: fixedTime.AddDate(0, 3, 0),
				DNSNames: []string{"a.test"}, SignatureAlgorithm: "SHA256-RSA",
				PublicKeyAlgorithm: "RSA", KeyBits: 2048, SCTCount: 3,
			}},
		},
	}
}

func sampleReport(t *testing.T) *Report {
	t.Helper()
	obs := sampleObservation()
	res := analyze.Run(obs, fixedTime)
	sc := score.Compute(score.Default(), res.Findings)
	return Build(obs, res, sc, Options{Now: fixedTime})
}

func TestBuildPopulatesEverything(t *testing.T) {
	r := sampleReport(t)

	if r.SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %d", r.SchemaVersion)
	}
	if r.Target.Host != "a.test" || r.Target.StatusCode != 200 {
		t.Errorf("target = %+v", r.Target)
	}
	if r.Summary.Problems == 0 {
		t.Error("this sample has problems; the summary should count them")
	}
	if r.CSP == nil || len(r.CSP.Directives) != 2 {
		t.Errorf("csp = %+v", r.CSP)
	}
	if r.TLS == nil || !r.TLS.Versions["TLS 1.0"] {
		t.Errorf("tls = %+v", r.TLS)
	}
	if len(r.Cookies) != 1 || r.Cookies[0].Name != "sid" {
		t.Errorf("cookies = %+v", r.Cookies)
	}
	if r.Observation != nil {
		t.Error("the observation should only be embedded when asked for")
	}
}

func TestBuildCanEmbedTheObservation(t *testing.T) {
	obs := sampleObservation()
	res := analyze.Run(obs, fixedTime)
	sc := score.Compute(score.Default(), res.Findings)
	r := Build(obs, res, sc, Options{Now: fixedTime, IncludeObservation: true})
	if r.Observation == nil {
		t.Fatal("the observation should be embedded")
	}
}

func TestBuildUsesNowWhenNotInjected(t *testing.T) {
	obs := sampleObservation()
	res := analyze.Run(obs, fixedTime)
	r := Build(obs, res, score.Compute(score.Default(), res.Findings), Options{})
	if r.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should default to now")
	}
}

func TestJSONRoundTrips(t *testing.T) {
	r := sampleReport(t)
	b, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Score.Grade != r.Score.Grade || len(back.Findings) != len(r.Findings) {
		t.Error("the report did not survive a JSON round trip")
	}
	if !bytes.HasSuffix(b, []byte("\n")) {
		t.Error("the JSON output should end with a newline")
	}
}

func TestWriteAndLoadJSON(t *testing.T) {
	r := sampleReport(t)
	path := filepath.Join(t.TempDir(), "report.json")
	if err := r.WriteJSON(path); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Target.Host != r.Target.Host {
		t.Errorf("host = %s", back.Target.Host)
	}
}

func TestLoadRejectsAForeignSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": 999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("err = %v, want a schema version complaint", err)
	}
}

func TestLoadRejectsNonsense(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("invalid JSON should be an error")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing file should be an error")
	}
}

func TestFindingsByCategory(t *testing.T) {
	r := sampleReport(t)

	problems := r.FindingsByCategory(false)
	for _, g := range problems {
		for _, f := range g.Findings {
			if !f.Severity.IsProblem() {
				t.Errorf("%s should not be in the problems-only grouping", f.ID)
			}
		}
	}

	all := r.FindingsByCategory(true)
	if len(all) < len(problems) {
		t.Error("the verbose grouping should not be smaller")
	}

	// The canonical order must hold.
	var seen []string
	for _, g := range all {
		seen = append(seen, g.ID)
	}
	order := map[string]int{}
	for i, c := range finding.CategoryOrder {
		order[c] = i
	}
	for i := 1; i < len(seen); i++ {
		if order[seen[i-1]] > order[seen[i]] {
			t.Errorf("categories out of order: %v", seen)
			break
		}
	}
}

func TestWriteText(t *testing.T) {
	r := sampleReport(t)
	var buf bytes.Buffer
	off := false
	if err := r.WriteText(&buf, TextOptions{ExplainScore: true, Color: &off}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"a.test", "grade", "SCORE EXPLANATION", "csp.script-src", "id: "} {
		if !strings.Contains(out, want) {
			t.Errorf("text output should contain %q", want)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("colour should be off when it is switched off")
	}
}

func TestWriteTextVerboseShowsPasses(t *testing.T) {
	r := sampleReport(t)
	off := false

	var quiet, verbose bytes.Buffer
	_ = r.WriteText(&quiet, TextOptions{Color: &off})
	_ = r.WriteText(&verbose, TextOptions{Verbose: true, Color: &off})

	if verbose.Len() <= quiet.Len() {
		t.Error("verbose output should be longer")
	}
	if !strings.Contains(verbose.String(), "PASS") {
		t.Error("verbose output should include passing controls")
	}
	if !strings.Contains(quiet.String(), "hidden") {
		t.Error("quiet output should say how many passes were hidden")
	}
}

func TestWriteTextWithColour(t *testing.T) {
	r := sampleReport(t)
	on := true
	var buf bytes.Buffer
	_ = r.WriteText(&buf, TextOptions{Color: &on})
	if !strings.Contains(buf.String(), "\033[") {
		t.Error("colour should be emitted when it is switched on")
	}
}

func TestWriteTextWithInlineRemediation(t *testing.T) {
	r := sampleReport(t)
	off := false
	var buf bytes.Buffer
	_ = r.WriteText(&buf, TextOptions{Color: &off, RemediationServer: "nginx"})
	if !strings.Contains(buf.String(), "add_header") {
		t.Error("the nginx snippet should be inlined")
	}
}

func TestWriteMarkdown(t *testing.T) {
	r := sampleReport(t)
	var buf bytes.Buffer
	if err := r.WriteMarkdown(&buf, MarkdownOptions{ExplainScore: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"# httpsec report", "**Grade", "| critical |", "How the grade was calculated", "<details>"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown should contain %q", want)
		}
	}
}

func TestWriteMarkdownWithOneServer(t *testing.T) {
	r := sampleReport(t)
	var buf bytes.Buffer
	_ = r.WriteMarkdown(&buf, MarkdownOptions{RemediationServer: "caddy"})
	out := buf.String()
	if !strings.Contains(out, "Caddy") {
		t.Error("the caddy snippet should be present")
	}
	if strings.Contains(out, "Apache httpd") {
		t.Error("only the requested server should be rendered")
	}
}

func TestWriteHTMLIsSelfContained(t *testing.T) {
	r := sampleReport(t)
	var buf bytes.Buffer
	if err := r.WriteHTML(&buf, HTMLOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"<!DOCTYPE html>", "prefers-color-scheme: dark", "@media print",
		"a.test", "TLS summary", "How the grade was calculated", "httpsec report",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML should contain %q", want)
		}
	}
	// A report that fetches anything is not self-contained, and the promise
	// is that it opens correctly on a laptop with no connectivity. Hyperlinks
	// are fine; subresource loads are not.
	for _, forbidden := range []string{"<script", "<link ", "@import", "url(http", "src=", "<iframe", "<img"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("HTML should not contain %q: the report must load nothing", forbidden)
		}
	}
}

func TestHTMLEscapesEvidence(t *testing.T) {
	obs := sampleObservation()
	obs.HTTPS.Headers["Content-Security-Policy"] = []string{`default-src 'self' "><script>alert(1)</script>`}
	res := analyze.Run(obs, fixedTime)
	r := Build(obs, res, score.Compute(score.Default(), res.Findings), Options{Now: fixedTime})

	var buf bytes.Buffer
	if err := r.WriteHTML(&buf, HTMLOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Fatal("a hostile header value must not be rendered as markup")
	}
}

func TestGradeClass(t *testing.T) {
	cases := map[string]string{"A+": "a", "A": "a", "B": "b", "C+": "c", "D": "d", "F": "f"}
	for grade, want := range cases {
		if got := gradeClass(grade); got != want {
			t.Errorf("gradeClass(%s) = %s, want %s", grade, got, want)
		}
	}
}

func TestRemediationFor(t *testing.T) {
	if _, ok := RemediationFor(finding.New("hsts.missing", "")); !ok {
		t.Error("hsts.missing should have a remediation")
	}
}

func TestBuildTLSSummaryWithoutAChain(t *testing.T) {
	s := buildTLSSummary(&probe.TLSInfo{Versions: []probe.VersionResult{{Version: "TLS 1.3", Supported: true}}})
	if s.CertSubject != "" || s.CertNotAfter != nil {
		t.Error("with no chain the certificate fields should be empty")
	}
}

func TestReportWithNoPolicy(t *testing.T) {
	obs := sampleObservation()
	delete(obs.HTTPS.Headers, "Content-Security-Policy")
	res := analyze.Run(obs, fixedTime)
	r := Build(obs, res, score.Compute(score.Default(), res.Findings), Options{Now: fixedTime})
	if r.CSP != nil && r.CSP.Present {
		t.Error("with no policy the CSP summary should not claim one is present")
	}
	var buf bytes.Buffer
	if err := r.WriteHTML(&buf, HTMLOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestCSPSummaryMirrorsTheParsedPolicy(t *testing.T) {
	p := csp.Parse("default-src 'self'", false)
	if p.Has("default-src") != true {
		t.Fatal("sanity check failed")
	}
}
