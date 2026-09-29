package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/remediate"
)

// MarkdownOptions controls the Markdown renderer.
type MarkdownOptions struct {
	// Verbose includes the controls that passed.
	Verbose bool
	// ExplainScore appends the per-control scoring table.
	ExplainScore bool
	// RemediationServer selects which snippet to inline; empty inlines all
	// four behind a collapsed block.
	RemediationServer string
}

var severityBadge = map[finding.Severity]string{
	finding.SeverityCritical: "🔴 critical",
	finding.SeverityHigh:     "🟠 high",
	finding.SeverityMedium:   "🟡 medium",
	finding.SeverityLow:      "🔵 low",
	finding.SeverityInfo:     "⚪ info",
	finding.SeverityPass:     "🟢 pass",
}

// WriteMarkdown renders the report as Markdown suitable for an issue or a PR
// comment.
func (r *Report) WriteMarkdown(w io.Writer, opts MarkdownOptions) error {
	fmt.Fprintf(w, "# httpsec report: %s\n\n", r.Target.Host)
	fmt.Fprintf(w, "**Grade %s** — score %d/100 (%.1f of %.1f weighted points)\n\n",
		r.Score.Grade, r.Score.Score, r.Score.EarnedWeight, r.Score.TotalWeight)

	if len(r.Score.Caps) > 0 {
		fmt.Fprintf(w, "> The grade is capped at **%s**; without the caps it would be **%s**.\n>\n",
			r.Score.Grade, r.Score.UncappedGrade)
		for _, c := range r.Score.Caps {
			fmt.Fprintf(w, "> - `%s` caps the grade at **%s**: %s\n", c.Finding, c.MaxGrade, c.Reason)
		}
		fmt.Fprintln(w)
	}

	s := r.Summary
	fmt.Fprintln(w, "| critical | high | medium | low | info | pass |")
	fmt.Fprintln(w, "|---:|---:|---:|---:|---:|---:|")
	fmt.Fprintf(w, "| %d | %d | %d | %d | %d | %d |\n\n", s.Critical, s.High, s.Medium, s.Low, s.Info, s.Pass)

	fmt.Fprintf(w, "Scanned `%s` on %s; evidence gathered by %s.\n\n",
		r.Target.Input, r.GeneratedAt.Format("2006-01-02 15:04 MST"), r.Tool)

	for _, g := range r.FindingsByCategory(opts.Verbose) {
		fmt.Fprintf(w, "## %s\n\n", g.Title)
		for _, f := range g.Findings {
			writeMarkdownFinding(w, f, opts)
		}
	}

	if len(r.Notes) > 0 {
		fmt.Fprint(w, "## Notes\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(w, "- %s\n", n)
		}
		fmt.Fprintln(w)
	}
	if len(r.Errors) > 0 {
		fmt.Fprint(w, "## Errors\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "- %s\n", e)
		}
		fmt.Fprintln(w)
	}
	if opts.ExplainScore {
		r.writeMarkdownScore(w)
	}
	return nil
}

func writeMarkdownFinding(w io.Writer, f finding.Finding, opts MarkdownOptions) {
	title := f.Title
	if f.Subject != "" {
		title += " — `" + f.Subject + "`"
	}
	fmt.Fprintf(w, "### %s %s\n\n", severityBadge[f.Severity], title)
	if f.Detail != "" {
		fmt.Fprintf(w, "%s\n\n", f.Detail)
	}
	if f.Severity.IsProblem() && f.Why != "" {
		fmt.Fprintf(w, "**Why it matters.** %s\n\n", f.Why)
	}
	if f.Evidence != "" {
		fmt.Fprintf(w, "<details><summary>Evidence</summary>\n\n```\n%s\n```\n\n</details>\n\n", f.Evidence)
	}
	if f.Severity.IsProblem() {
		writeMarkdownRemediation(w, f, opts.RemediationServer)
	}
	for _, ref := range f.References {
		fmt.Fprintf(w, "- [%s](%s)\n", ref, ref)
	}
	fmt.Fprintf(w, "\n<sub>`%s`</sub>\n\n", f.ID)
}

func writeMarkdownRemediation(w io.Writer, f finding.Finding, server string) {
	snip, ok := RemediationFor(f)
	if !ok {
		return
	}
	fmt.Fprintf(w, "**Fix.** %s\n\n", snip.Summary)
	servers := remediate.Servers
	if server != "" {
		servers = []string{strings.ToLower(server)}
	}
	for _, s := range servers {
		cfg := snip.For(s)
		if cfg == "" {
			continue
		}
		lang := "nginx"
		switch s {
		case "apache":
			lang = "apache"
		case "caddy", "cdn":
			lang = "text"
		}
		fmt.Fprintf(w, "<details><summary>%s</summary>\n\n```%s\n%s\n```\n\n</details>\n\n",
			remediate.ServerTitles[s], lang, cfg)
	}
	if snip.Notes != "" {
		fmt.Fprintf(w, "> %s\n\n", snip.Notes)
	}
}

func (r *Report) writeMarkdownScore(w io.Writer) {
	fmt.Fprintf(w, "## How the grade was calculated\n\nRubric `%s` v%s.\n\n", r.Score.RubricName, r.Score.RubricVersion)
	fmt.Fprintln(w, "| control | weight | earned | lost | why |")
	fmt.Fprintln(w, "|---|---:|---:|---:|---|")
	for _, c := range r.Score.Controls {
		if !c.Applicable {
			fmt.Fprintf(w, "| `%s` | %.1f | — | — | not evaluated, excluded from the total |\n", c.ID, c.Weight)
			continue
		}
		why := "all checks passed"
		switch {
		case len(c.Reasons) > 0:
			why = strings.Join(c.Reasons, "; ")
		case len(c.Findings) > 0 && c.Lost == 0:
			why = "no points lost: `" + strings.Join(c.Findings, "`, `") + "`"
		}
		fmt.Fprintf(w, "| `%s` | %.1f | %.1f | %.1f | %s |\n", c.ID, c.Weight, c.Earned, c.Lost, why)
	}
	fmt.Fprintf(w, "| **total** | **%.1f** | **%.1f** | **%.1f** | %.1f / %.1f = %d%% → **%s** |\n\n",
		r.Score.TotalWeight, r.Score.EarnedWeight, r.Score.TotalWeight-r.Score.EarnedWeight,
		r.Score.EarnedWeight, r.Score.TotalWeight, r.Score.Score, r.Score.UncappedGrade)
}
