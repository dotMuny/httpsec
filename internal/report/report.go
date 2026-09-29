// Package report renders a scan as text, HTML, JSON or Markdown, and diffs
// two JSON reports.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/dotMuny/httpsec/internal/analyze"
	"github.com/dotMuny/httpsec/internal/analyze/cookies"
	"github.com/dotMuny/httpsec/internal/analyze/csp"
	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
	"github.com/dotMuny/httpsec/internal/remediate"
	"github.com/dotMuny/httpsec/internal/score"
)

// SchemaVersion identifies the JSON report layout. Any change to the shape of
// Report, or of anything it embeds, must bump it. A test enforces that.
const SchemaVersion = 1

// Report is the complete result of a scan, and the JSON document other tools
// consume.
type Report struct {
	SchemaVersion int                `json:"schema_version"`
	Tool          string             `json:"tool"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Target        Target             `json:"target"`
	Score         score.Score        `json:"score"`
	Summary       Summary            `json:"summary"`
	Findings      []finding.Finding  `json:"findings"`
	CSP           *CSPSummary        `json:"csp,omitempty"`
	TLS           *TLSSummary        `json:"tls,omitempty"`
	Cookies       []CookieSummary    `json:"cookies,omitempty"`
	Notes         []string           `json:"notes,omitempty"`
	Errors        []string           `json:"errors,omitempty"`
	Observation   *probe.Observation `json:"observation,omitempty"`
}

// Target identifies what was scanned.
type Target struct {
	Input      string `json:"input"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	FinalURL   string `json:"final_url,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// Summary counts findings per severity.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Pass     int `json:"pass"`
	Problems int `json:"problems"`
}

// CSPSummary is the parsed policy, so a consumer does not have to parse the
// header again.
type CSPSummary struct {
	Present    bool            `json:"present"`
	ReportOnly bool            `json:"report_only"`
	Raw        string          `json:"raw"`
	Directives []csp.Directive `json:"directives,omitempty"`
}

// TLSSummary is the headline TLS facts, in report-friendly form.
type TLSSummary struct {
	Versions      map[string]bool `json:"versions"`
	Suites        []string        `json:"tls12_suites,omitempty"`
	TLS13Suite    string          `json:"tls13_suite,omitempty"`
	Preference    string          `json:"cipher_preference"`
	ALPN          []string        `json:"alpn,omitempty"`
	OCSPStapled   bool            `json:"ocsp_stapled"`
	ChainLength   int             `json:"chain_length"`
	CertSubject   string          `json:"certificate_subject,omitempty"`
	CertIssuer    string          `json:"certificate_issuer,omitempty"`
	CertNotAfter  *time.Time      `json:"certificate_not_after,omitempty"`
	CertSANs      []string        `json:"certificate_sans,omitempty"`
	CertKey       string          `json:"certificate_key,omitempty"`
	CertSignature string          `json:"certificate_signature,omitempty"`
}

// CookieSummary is one cookie's attributes, for the report tables.
type CookieSummary struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Options controls what Build puts in the report.
type Options struct {
	// IncludeObservation embeds the raw evidence, which makes the report
	// self-contained but much larger.
	IncludeObservation bool
	// Now is the generation timestamp; injected for deterministic tests.
	Now time.Time
}

// Build assembles a Report from an Observation, its analysis and its score.
func Build(obs *probe.Observation, res analyze.Result, sc score.Score, opts Options) *Report {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	r := &Report{
		SchemaVersion: SchemaVersion,
		Tool:          obs.Tool,
		GeneratedAt:   now.UTC(),
		Target: Target{
			Input:      obs.Target,
			Host:       obs.Host,
			Port:       obs.Port,
			DurationMs: obs.DurationMs,
		},
		Score:    sc,
		Findings: res.Findings,
		Notes:    res.Notes,
		Errors:   obs.Errors,
	}
	if obs.HTTPS != nil {
		r.Target.FinalURL = obs.HTTPS.FinalURL
		r.Target.StatusCode = obs.HTTPS.StatusCode
	}
	r.Summary = summarise(res.Findings)

	if res.Policy != nil {
		r.CSP = &CSPSummary{
			Present:    !res.Policy.ReportOnly,
			ReportOnly: res.Policy.ReportOnly,
			Raw:        res.Policy.Raw,
			Directives: res.Policy.Directives,
		}
	}
	if obs.TLS != nil {
		r.TLS = buildTLSSummary(obs.TLS)
	}
	if obs.HTTPS != nil {
		r.Cookies = buildCookieSummary(obs.HTTPS)
	}
	if opts.IncludeObservation {
		r.Observation = obs
	}
	return r
}

func summarise(fs []finding.Finding) Summary {
	c := finding.CountBySeverity(fs)
	return Summary{
		Critical: c[finding.SeverityCritical],
		High:     c[finding.SeverityHigh],
		Medium:   c[finding.SeverityMedium],
		Low:      c[finding.SeverityLow],
		Info:     c[finding.SeverityInfo],
		Pass:     c[finding.SeverityPass],
		Problems: len(finding.Problems(fs)),
	}
}

func buildTLSSummary(t *probe.TLSInfo) *TLSSummary {
	s := &TLSSummary{
		Versions:    map[string]bool{},
		TLS13Suite:  t.TLS13Suite,
		Preference:  t.Preference,
		ALPN:        t.ALPN,
		OCSPStapled: t.OCSPStapled,
		ChainLength: t.ChainLength,
	}
	for _, v := range t.Versions {
		s.Versions[v.Version] = v.Supported
	}
	for _, c := range t.Suites {
		s.Suites = append(s.Suites, c.Name)
	}
	if len(t.Chain) > 0 {
		leaf := t.Chain[0]
		na := leaf.NotAfter
		s.CertSubject = leaf.Subject
		s.CertIssuer = leaf.Issuer
		s.CertNotAfter = &na
		s.CertSANs = leaf.DNSNames
		s.CertSignature = leaf.SignatureAlgorithm
		s.CertKey = fmt.Sprintf("%s %d bits", leaf.PublicKeyAlgorithm, leaf.KeyBits)
	}
	return s
}

// FindingsByCategory groups findings for the category cards, preserving the
// canonical category order.
func (r *Report) FindingsByCategory(includePasses bool) []CategoryGroup {
	byCat := map[string][]finding.Finding{}
	for _, f := range r.Findings {
		if !includePasses && !f.Severity.IsProblem() {
			continue
		}
		byCat[f.Category] = append(byCat[f.Category], f)
	}
	var out []CategoryGroup
	for _, cat := range finding.CategoryOrder {
		fs := byCat[cat]
		if len(fs) == 0 {
			continue
		}
		out = append(out, CategoryGroup{
			ID:       cat,
			Title:    finding.CategoryTitles[cat],
			Findings: fs,
			Counts:   finding.CountBySeverity(fs),
		})
	}
	// Any category not in the canonical order still gets shown.
	var extra []string
	for cat := range byCat {
		known := false
		for _, c := range finding.CategoryOrder {
			if c == cat {
				known = true
			}
		}
		if !known {
			extra = append(extra, cat)
		}
	}
	sort.Strings(extra)
	for _, cat := range extra {
		out = append(out, CategoryGroup{ID: cat, Title: cat, Findings: byCat[cat]})
	}
	return out
}

// CategoryGroup is one card of the report.
type CategoryGroup struct {
	ID       string
	Title    string
	Findings []finding.Finding
	Counts   map[finding.Severity]int
}

// RemediationFor returns the snippet for a finding, if any.
func RemediationFor(f finding.Finding) (remediate.Snippet, bool) {
	return remediate.Lookup(f.Remediation)
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644) // #nosec G306 -- a report meant to be read, shared and served
}

// JSON renders the report as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Load reads a JSON report from disk.
func Load(path string) (*Report, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the path is a CLI argument the operator chose
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if r.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s has schema_version %d, this build understands %d", path, r.SchemaVersion, SchemaVersion)
	}
	return &r, nil
}

func buildCookieSummary(r *probe.HTTPResponse) []CookieSummary {
	var out []CookieSummary
	for _, c := range cookies.Parse(r) {
		out = append(out, CookieSummary{
			Name:     c.Name,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			SameSite: c.SameSite,
			Domain:   c.Domain,
			Path:     c.Path,
		})
	}
	return out
}
