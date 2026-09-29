// Package remediate serves the configuration snippets that turn a finding
// into an action.
//
// The snippets live in data/remediation.json, not in this file: adding a
// finding without adding its remediation must be a data change that a test
// can catch, not a Go change that hides in a diff.
package remediate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dotMuny/httpsec/data"
	"github.com/dotMuny/httpsec/internal/finding"
)

// Servers are the targets httpsec can emit configuration for.
var Servers = []string{"nginx", "apache", "caddy", "cdn"}

// ServerTitles maps a server ID to its display name.
var ServerTitles = map[string]string{
	"nginx":  "Nginx",
	"apache": "Apache httpd",
	"caddy":  "Caddy",
	"cdn":    "Cloudflare / generic CDN",
}

// Snippet is the remediation for one key across every supported server.
type Snippet struct {
	Summary string `json:"summary"`
	Nginx   string `json:"nginx"`
	Apache  string `json:"apache"`
	Caddy   string `json:"caddy"`
	CDN     string `json:"cdn"`
	Notes   string `json:"notes,omitempty"`
}

// For returns the snippet for one server ID.
func (s Snippet) For(server string) string {
	switch strings.ToLower(server) {
	case "nginx":
		return s.Nginx
	case "apache":
		return s.Apache
	case "caddy":
		return s.Caddy
	case "cdn", "cloudflare":
		return s.CDN
	default:
		return ""
	}
}

type remediationFile struct {
	SchemaVersion int                `json:"schema_version"`
	Servers       []string           `json:"servers"`
	Remediation   map[string]Snippet `json:"remediation"`
}

var table map[string]Snippet

func init() {
	var f remediationFile
	if err := json.Unmarshal(data.Remediation, &f); err != nil {
		panic("remediate: cannot parse embedded remediation.json: " + err.Error())
	}
	table = f.Remediation
}

// Lookup returns the snippet for a remediation key.
func Lookup(key string) (Snippet, bool) {
	s, ok := table[key]
	return s, ok
}

// Keys lists every remediation key, sorted.
func Keys() []string {
	out := make([]string, 0, len(table))
	for k := range table {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidServer reports whether a server name is supported.
func ValidServer(name string) bool {
	for _, s := range Servers {
		if s == strings.ToLower(name) {
			return true
		}
	}
	return false
}

// Block is a consolidated remediation for one key, carrying the findings that
// asked for it.
type Block struct {
	Key      string
	Summary  string
	Notes    string
	Config   string
	Findings []finding.Finding
}

// Plan groups the problems in a finding set by remediation key, so that
// several findings that need the same configuration change produce one block
// rather than four near-identical ones.
func Plan(findings []finding.Finding, server string) ([]Block, error) {
	if !ValidServer(server) {
		return nil, fmt.Errorf("unknown server %q; supported: %s", server, strings.Join(Servers, ", "))
	}
	order := []string{}
	byKey := map[string][]finding.Finding{}
	for _, f := range findings {
		if !f.Severity.IsProblem() {
			continue
		}
		if _, seen := byKey[f.Remediation]; !seen {
			order = append(order, f.Remediation)
		}
		byKey[f.Remediation] = append(byKey[f.Remediation], f)
	}

	out := make([]Block, 0, len(order))
	for _, key := range order {
		s, ok := Lookup(key)
		if !ok {
			return nil, fmt.Errorf("no remediation for key %q", key)
		}
		out = append(out, Block{
			Key:      key,
			Summary:  s.Summary,
			Notes:    s.Notes,
			Config:   s.For(server),
			Findings: byKey[key],
		})
	}
	return out, nil
}

// Render produces a single configuration block for a server, ready to paste
// into a review.
func Render(findings []finding.Finding, server string) (string, error) {
	blocks, err := Plan(findings, server)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# httpsec remediation for %s\n", ServerTitles[strings.ToLower(server)])
	if len(blocks) == 0 {
		b.WriteString("#\n# No problems were found, so there is nothing to change.\n")
		return b.String(), nil
	}
	fmt.Fprintf(&b, "#\n# %d finding(s) grouped into %d configuration change(s).\n", countFindings(blocks), len(blocks))
	b.WriteString("# Review every line before applying it: the snippets are templates,\n")
	b.WriteString("# and several of them reference hostnames you have to fill in.\n")

	for _, blk := range blocks {
		b.WriteString("\n# ---------------------------------------------------------------\n")
		fmt.Fprintf(&b, "# %s\n", blk.Summary)
		for _, f := range blk.Findings {
			subject := ""
			if f.Subject != "" {
				subject = " [" + f.Subject + "]"
			}
			fmt.Fprintf(&b, "#   - [%s] %s%s\n", f.Severity, f.Title, subject)
		}
		if blk.Notes != "" {
			fmt.Fprintf(&b, "# Note: %s\n", blk.Notes)
		}
		b.WriteString("# ---------------------------------------------------------------\n")
		b.WriteString(blk.Config)
		b.WriteString("\n")
	}
	return b.String(), nil
}

func countFindings(blocks []Block) int {
	n := 0
	for _, b := range blocks {
		n += len(b.Findings)
	}
	return n
}
