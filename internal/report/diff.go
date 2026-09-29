package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/dotMuny/httpsec/internal/finding"
)

// DiffEntry is one finding that appeared, disappeared or changed severity.
type DiffEntry struct {
	ID       string           `json:"id"`
	Subject  string           `json:"subject,omitempty"`
	Title    string           `json:"title"`
	Severity finding.Severity `json:"severity"`
	Was      finding.Severity `json:"was,omitempty"`
}

// Diff compares two reports of the same target.
type Diff struct {
	SchemaVersion int         `json:"schema_version"`
	Before        DiffSide    `json:"before"`
	After         DiffSide    `json:"after"`
	ScoreDelta    int         `json:"score_delta"`
	GradeChanged  bool        `json:"grade_changed"`
	Fixed         []DiffEntry `json:"fixed"`
	Introduced    []DiffEntry `json:"introduced"`
	Changed       []DiffEntry `json:"changed"`
	SameTarget    bool        `json:"same_target"`
}

// DiffSide identifies one of the two reports being compared.
type DiffSide struct {
	Host      string `json:"host"`
	Grade     string `json:"grade"`
	Score     int    `json:"score"`
	Generated string `json:"generated_at"`
}

// Improved reports whether the diff represents a net improvement, which is
// what a CI gate cares about.
func (d Diff) Improved() bool {
	return d.ScoreDelta > 0 || (d.ScoreDelta == 0 && len(d.Introduced) == 0 && len(d.Fixed) > 0)
}

// Regressed reports whether anything got worse.
func (d Diff) Regressed() bool {
	return d.ScoreDelta < 0 || len(d.Introduced) > 0 || len(d.Changed) > 0
}

type findingKey struct{ id, subject string }

// Compare diffs two reports.
func Compare(before, after *Report) Diff {
	d := Diff{
		SchemaVersion: SchemaVersion,
		Before:        side(before),
		After:         side(after),
		ScoreDelta:    after.Score.Score - before.Score.Score,
		GradeChanged:  before.Score.Grade != after.Score.Grade,
		SameTarget:    before.Target.Host == after.Target.Host,
	}

	b := indexProblems(before)
	a := indexProblems(after)

	for k, f := range b {
		switch af, still := a[k]; {
		case !still:
			d.Fixed = append(d.Fixed, entry(f, ""))
		case af.Severity != f.Severity:
			d.Changed = append(d.Changed, entry(af, f.Severity))
		}
	}
	for k, f := range a {
		if _, had := b[k]; !had {
			d.Introduced = append(d.Introduced, entry(f, ""))
		}
	}

	sortEntries(d.Fixed)
	sortEntries(d.Introduced)
	sortEntries(d.Changed)
	return d
}

func side(r *Report) DiffSide {
	return DiffSide{
		Host:      r.Target.Host,
		Grade:     r.Score.Grade,
		Score:     r.Score.Score,
		Generated: r.GeneratedAt.Format("2006-01-02 15:04 MST"),
	}
}

func indexProblems(r *Report) map[findingKey]finding.Finding {
	m := map[findingKey]finding.Finding{}
	for _, f := range r.Findings {
		if f.Severity.IsProblem() {
			m[findingKey{f.ID, f.Subject}] = f
		}
	}
	return m
}

func entry(f finding.Finding, was finding.Severity) DiffEntry {
	return DiffEntry{ID: f.ID, Subject: f.Subject, Title: f.Title, Severity: f.Severity, Was: was}
}

func sortEntries(e []DiffEntry) {
	sort.Slice(e, func(i, j int) bool {
		if e[i].Severity.Rank() != e[j].Severity.Rank() {
			return e[i].Severity.Rank() < e[j].Severity.Rank()
		}
		if e[i].ID != e[j].ID {
			return e[i].ID < e[j].ID
		}
		return e[i].Subject < e[j].Subject
	})
}

// WriteText renders a diff for a terminal.
func (d Diff) WriteText(w io.Writer, force *bool) {
	p := newPalette(w, force)

	fmt.Fprintf(w, "\n%s %s\n", p.wrap(ansiBold, "httpsec diff"), p.wrap(ansiDim, d.Before.Host+" -> "+d.After.Host))
	if !d.SameTarget {
		fmt.Fprintf(w, "%s the two reports are for different hosts\n", p.wrap(ansiYellow, "warning:"))
	}
	delta := fmt.Sprintf("%+d", d.ScoreDelta)
	colour := ansiGrey
	switch {
	case d.ScoreDelta > 0:
		colour = ansiGreen
	case d.ScoreDelta < 0:
		colour = ansiRed
	}
	fmt.Fprintf(w, "%s %s (%d) -> %s (%d)   %s\n\n",
		p.wrap(ansiBold, "grade "),
		p.grade(d.Before.Grade), d.Before.Score,
		p.grade(d.After.Grade), d.After.Score,
		p.wrap(colour, delta+" points"))

	writeDiffSection(w, p, "FIXED", ansiGreen, d.Fixed)
	writeDiffSection(w, p, "INTRODUCED", ansiRed, d.Introduced)
	writeDiffSection(w, p, "SEVERITY CHANGED", ansiYellow, d.Changed)

	if len(d.Fixed) == 0 && len(d.Introduced) == 0 && len(d.Changed) == 0 {
		fmt.Fprintf(w, "%s\n", p.wrap(ansiDim, "No change in findings."))
	}
}

func writeDiffSection(w io.Writer, p palette, title, colour string, entries []DiffEntry) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(w, "%s (%d)\n", p.wrap(ansiBold+colour, title), len(entries))
	for _, e := range entries {
		subject := ""
		if e.Subject != "" {
			subject = " [" + e.Subject + "]"
		}
		if e.Was != "" {
			fmt.Fprintf(w, "  %-22s %s%s  %s\n", p.severity(e.Severity), e.Title, subject,
				p.wrap(ansiDim, fmt.Sprintf("(was %s)", e.Was)))
			continue
		}
		fmt.Fprintf(w, "  %-22s %s%s\n", p.severity(e.Severity), e.Title, subject)
	}
	fmt.Fprintln(w)
}

// WriteMarkdown renders a diff for a pull request comment.
func (d Diff) WriteMarkdown(w io.Writer) {
	fmt.Fprintf(w, "## httpsec diff — %s\n\n", d.After.Host)
	fmt.Fprintf(w, "Grade **%s** (%d) → **%s** (%d), %+d points.\n\n",
		d.Before.Grade, d.Before.Score, d.After.Grade, d.After.Score, d.ScoreDelta)

	section := func(title string, entries []DiffEntry) {
		if len(entries) == 0 {
			return
		}
		fmt.Fprintf(w, "### %s (%d)\n\n", title, len(entries))
		for _, e := range entries {
			subject := ""
			if e.Subject != "" {
				subject = " `" + e.Subject + "`"
			}
			if e.Was != "" {
				fmt.Fprintf(w, "- %s %s%s (was %s) — `%s`\n", severityBadge[e.Severity], e.Title, subject, e.Was, e.ID)
				continue
			}
			fmt.Fprintf(w, "- %s %s%s — `%s`\n", severityBadge[e.Severity], e.Title, subject, e.ID)
		}
		fmt.Fprintln(w)
	}
	section("Fixed", d.Fixed)
	section("Introduced", d.Introduced)
	section("Severity changed", d.Changed)

	if len(d.Fixed) == 0 && len(d.Introduced) == 0 && len(d.Changed) == 0 {
		fmt.Fprintln(w, "No change in findings.")
	}
}
