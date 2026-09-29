// Package finding defines the vocabulary shared by every analyser: severities,
// the finding catalogue loaded from data/findings.json, and the Finding type
// itself.
//
// It is deliberately a leaf package with no dependencies on the analysers, so
// that internal/analyze can both import the per-family analysers and share
// this type with them without an import cycle.
package finding

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dotMuny/httpsec/data"
)

// Severity ranks a finding. Pass is not a severity in the usual sense; it
// marks a control that was checked and satisfied, which the reports show only
// in verbose mode but which the score always counts.
type Severity string

// The severity ladder, most to least serious.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityPass     Severity = "pass"
)

var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
	SeverityPass:     5,
}

// Rank returns a sort key: lower is more serious.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return len(severityRank)
}

// IsProblem reports whether the severity represents something to fix.
func (s Severity) IsProblem() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

// Category groups findings in the reports.
const (
	CategoryCSP     = "csp"
	CategoryHeaders = "headers"
	CategoryCookies = "cookies"
	CategoryTLS     = "tls"
	CategoryNetwork = "network"
	CategoryInfo    = "info"
)

// CategoryOrder is the order categories appear in every report.
var CategoryOrder = []string{
	CategoryTLS, CategoryHeaders, CategoryCSP, CategoryCookies, CategoryNetwork, CategoryInfo,
}

// CategoryTitles maps a category ID to its human-readable heading.
var CategoryTitles = map[string]string{
	CategoryTLS:     "TLS and certificates",
	CategoryHeaders: "Security headers",
	CategoryCSP:     "Content Security Policy",
	CategoryCookies: "Cookies",
	CategoryNetwork: "Network behaviour",
	CategoryInfo:    "Information disclosure",
}

// Meta is the catalogue entry for a finding ID: everything about a finding
// that does not depend on the target being scanned.
type Meta struct {
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Control     string   `json:"control"`
	Remediation string   `json:"remediation"`
	Why         string   `json:"why"`
	References  []string `json:"references"`
}

type catalogFile struct {
	SchemaVersion int             `json:"schema_version"`
	Findings      map[string]Meta `json:"findings"`
}

var catalog map[string]Meta

func init() {
	var f catalogFile
	if err := json.Unmarshal(data.Findings, &f); err != nil {
		panic("finding: cannot parse embedded findings.json: " + err.Error())
	}
	for id, m := range f.Findings {
		if !m.Severity.Valid() {
			panic(fmt.Sprintf("finding: %s has invalid severity %q", id, m.Severity))
		}
	}
	catalog = f.Findings
}

// Catalog returns every known finding ID with its metadata.
func Catalog() map[string]Meta {
	out := make(map[string]Meta, len(catalog))
	for k, v := range catalog {
		out[k] = v
	}
	return out
}

// CatalogIDs returns every known finding ID, sorted.
func CatalogIDs() []string {
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Lookup returns the catalogue entry for an ID.
func Lookup(id string) (Meta, bool) {
	m, ok := catalog[id]
	return m, ok
}

// Finding is one evaluated control on one target. The immutable parts come
// from the catalogue; Detail and Evidence are what this particular scan saw.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Control     string   `json:"control"`
	Why         string   `json:"why"`
	Detail      string   `json:"detail,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	References  []string `json:"references,omitempty"`
	Remediation string   `json:"remediation_key"`
}

// New builds a Finding from the catalogue. An unknown ID panics, which is
// deliberate: analysers may only emit IDs that are in data/findings.json, and
// a test walks every analyser to make sure of it.
func New(id, detail string) Finding {
	m, ok := Lookup(id)
	if !ok {
		panic("finding: unknown finding ID " + id)
	}
	return Finding{
		ID:          id,
		Title:       m.Title,
		Severity:    m.Severity,
		Category:    m.Category,
		Control:     m.Control,
		Why:         m.Why,
		Detail:      detail,
		References:  m.References,
		Remediation: m.Remediation,
	}
}

// WithEvidence attaches the raw header value or other verbatim observation
// that triggered the finding.
func (f Finding) WithEvidence(ev string) Finding {
	f.Evidence = ev
	return f
}

// WithSubject names the specific thing the finding is about, such as a cookie
// name or a cipher suite, so that repeated findings stay distinguishable.
func (f Finding) WithSubject(s string) Finding {
	f.Subject = s
	return f
}

// Sort orders findings by severity, then category, then ID, then subject, so
// that two scans of the same target produce byte-identical reports.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.Category != b.Category {
			return categoryRank(a.Category) < categoryRank(b.Category)
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Subject < b.Subject
	})
}

func categoryRank(c string) int {
	for i, v := range CategoryOrder {
		if v == c {
			return i
		}
	}
	return len(CategoryOrder)
}

// Problems returns only the findings that represent something to fix.
func Problems(fs []Finding) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if f.Severity.IsProblem() {
			out = append(out, f)
		}
	}
	return out
}

// CountBySeverity tallies findings per severity.
func CountBySeverity(fs []Finding) map[Severity]int {
	m := make(map[Severity]int, len(severityRank))
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}
