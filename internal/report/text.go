package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/score"
	"github.com/dotMuny/httpsec/internal/version"
)

// ANSI colours. They are switched off whenever the output is not a terminal,
// or NO_COLOR is set, so piping into a file or a CI log stays readable.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiOrange = "\033[91m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiGreen  = "\033[32m"
	ansiGrey   = "\033[90m"
)

// TextOptions controls the terminal renderer.
type TextOptions struct {
	// Verbose also prints the controls that passed.
	Verbose bool
	// ExplainScore prints the per-control scoring table.
	ExplainScore bool
	// Color forces colour on or off; nil means auto-detect.
	Color *bool
	// ShowRemediation prints the configuration snippet for this server after
	// each finding. Empty means no snippets.
	RemediationServer string
}

type palette struct{ on bool }

func (p palette) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return code + s + ansiReset
}

func newPalette(w io.Writer, force *bool) palette {
	if force != nil {
		return palette{on: *force}
	}
	if os.Getenv("NO_COLOR") != "" {
		return palette{on: false}
	}
	f, ok := w.(*os.File)
	if !ok {
		return palette{on: false}
	}
	st, err := f.Stat()
	if err != nil {
		return palette{on: false}
	}
	return palette{on: st.Mode()&os.ModeCharDevice != 0}
}

func (p palette) severity(s finding.Severity) string {
	label := strings.ToUpper(string(s))
	switch s {
	case finding.SeverityCritical:
		return p.wrap(ansiBold+ansiRed, label)
	case finding.SeverityHigh:
		return p.wrap(ansiOrange, label)
	case finding.SeverityMedium:
		return p.wrap(ansiYellow, label)
	case finding.SeverityLow:
		return p.wrap(ansiBlue, label)
	case finding.SeverityInfo:
		return p.wrap(ansiGrey, label)
	default:
		return p.wrap(ansiGreen, "PASS")
	}
}

func (p palette) grade(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return p.wrap(ansiBold+ansiGreen, g)
	case strings.HasPrefix(g, "B"):
		return p.wrap(ansiBold+ansiGreen, g)
	case strings.HasPrefix(g, "C"):
		return p.wrap(ansiBold+ansiYellow, g)
	case strings.HasPrefix(g, "D"):
		return p.wrap(ansiBold+ansiOrange, g)
	default:
		return p.wrap(ansiBold+ansiRed, g)
	}
}

// WriteText renders the report for a terminal.
func (r *Report) WriteText(w io.Writer, opts TextOptions) error {
	p := newPalette(w, opts.Color)

	// The banner names the binary doing the rendering. r.Tool is the build
	// that gathered the evidence, which is usually the same one but is not
	// when a saved observation is re-analysed later, and the difference is
	// exactly the kind of thing a reader needs to know about a report.
	fmt.Fprintf(w, "\n%s\n", p.wrap(ansiBold, version.String()))
	if r.Tool != "" && r.Tool != version.String() {
		fmt.Fprintf(w, "%s %s\n", p.wrap(ansiDim, "evidence gathered by"), p.wrap(ansiDim, r.Tool))
	}
	fmt.Fprintf(w, "%s %s", p.wrap(ansiBold, "target"), r.Target.Host)
	if r.Target.FinalURL != "" {
		fmt.Fprintf(w, "  %s", p.wrap(ansiDim, r.Target.FinalURL))
	}
	fmt.Fprintf(w, "\n%s %s  %s\n\n",
		p.wrap(ansiBold, "grade "), p.grade(r.Score.Grade),
		p.wrap(ansiDim, fmt.Sprintf("score %d/100 (%.1f of %.1f weighted points)",
			r.Score.Score, r.Score.EarnedWeight, r.Score.TotalWeight)))

	if len(r.Score.Caps) > 0 {
		heading := "Critical findings cap the grade:"
		if r.Score.Grade == r.Score.UncappedGrade {
			heading = "Critical findings that cap the grade (the score is already at or below the cap):"
		}
		fmt.Fprintf(w, "%s\n", p.wrap(ansiBold+ansiRed, heading))
		for _, c := range r.Score.Caps {
			fmt.Fprintf(w, "  %s max %-2s %s\n", p.wrap(ansiRed, "!"), c.MaxGrade, c.Reason)
		}
		if r.Score.Grade != r.Score.UncappedGrade {
			fmt.Fprintf(w, "  %s\n", p.wrap(ansiDim,
				fmt.Sprintf("the score of %d alone would grade %s", r.Score.Score, r.Score.UncappedGrade)))
		}
		fmt.Fprintln(w)
	}

	s := r.Summary
	fmt.Fprintf(w, "%s  %s %d   %s %d   %s %d   %s %d   %s %d   %s %d\n\n",
		p.wrap(ansiBold, "findings"),
		p.severity(finding.SeverityCritical), s.Critical,
		p.severity(finding.SeverityHigh), s.High,
		p.severity(finding.SeverityMedium), s.Medium,
		p.severity(finding.SeverityLow), s.Low,
		p.severity(finding.SeverityInfo), s.Info,
		p.severity(finding.SeverityPass), s.Pass)

	groups := r.FindingsByCategory(opts.Verbose)
	if len(groups) == 0 {
		fmt.Fprintf(w, "%s\n", p.wrap(ansiGreen, "No problems found."))
	}
	for _, g := range groups {
		fmt.Fprintf(w, "%s\n", p.wrap(ansiBold, strings.ToUpper(g.Title)))
		for _, f := range g.Findings {
			writeFinding(w, p, f, opts)
		}
		fmt.Fprintln(w)
	}

	for _, n := range r.Notes {
		fmt.Fprintf(w, "%s %s\n", p.wrap(ansiDim, "note:"), n)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(w, "%s %s\n", p.wrap(ansiYellow, "error:"), e)
	}
	if len(r.Notes) > 0 || len(r.Errors) > 0 {
		fmt.Fprintln(w)
	}

	if opts.ExplainScore {
		r.writeScoreExplanation(w, p)
	}
	if !opts.Verbose {
		fmt.Fprintf(w, "%s\n", p.wrap(ansiDim, fmt.Sprintf("%d passing controls hidden; run with --verbose to see them.", s.Pass)))
	}
	return nil
}

func writeFinding(w io.Writer, p palette, f finding.Finding, opts TextOptions) {
	subject := ""
	if f.Subject != "" {
		subject = p.wrap(ansiDim, " ["+f.Subject+"]")
	}
	fmt.Fprintf(w, "  %-22s %s%s\n", p.severity(f.Severity), f.Title, subject)
	if f.Detail != "" {
		fmt.Fprintf(w, "      %s\n", f.Detail)
	}
	if f.Severity.IsProblem() && f.Why != "" {
		fmt.Fprintf(w, "      %s %s\n", p.wrap(ansiDim, "why:"), p.wrap(ansiDim, f.Why))
	}
	if opts.RemediationServer != "" && f.Severity.IsProblem() {
		if snip, ok := RemediationFor(f); ok {
			if cfg := snip.For(opts.RemediationServer); cfg != "" {
				fmt.Fprintf(w, "      %s\n", p.wrap(ansiDim, "fix:"))
				for _, line := range strings.Split(cfg, "\n") {
					fmt.Fprintf(w, "        %s\n", p.wrap(ansiGreen, line))
				}
			}
		}
	}
	fmt.Fprintf(w, "      %s\n", p.wrap(ansiDim, "id: "+f.ID))
}

func (r *Report) writeScoreExplanation(w io.Writer, p palette) {
	fmt.Fprintf(w, "%s  %s\n", p.wrap(ansiBold, "SCORE EXPLANATION"),
		p.wrap(ansiDim, fmt.Sprintf("rubric %s v%s", r.Score.RubricName, r.Score.RubricVersion)))
	fmt.Fprintf(w, "  %-22s %7s %7s %7s  %s\n", "control", "weight", "earned", "lost", "why")

	for _, c := range r.Score.Controls {
		if !c.Applicable {
			fmt.Fprintf(w, "  %-22s %7.1f %7s %7s  %s\n", c.ID, c.Weight, "-", "-",
				p.wrap(ansiDim, "not evaluated, excluded from the total"))
			continue
		}
		why := p.wrap(ansiGreen, "all checks passed")
		switch {
		case len(c.Reasons) > 0:
			why = strings.Join(c.Reasons, "; ")
		case len(c.Findings) > 0 && c.Lost == 0:
			why = p.wrap(ansiGreen, "no points lost: "+strings.Join(c.Findings, ", "))
		}
		fmt.Fprintf(w, "  %-22s %7.1f %7.1f %7.1f  %s\n", c.ID, c.Weight, c.Earned, c.Lost, why)
	}
	fmt.Fprintf(w, "  %-22s %7.1f %7.1f %7.1f\n", p.wrap(ansiBold, "total"),
		r.Score.TotalWeight, r.Score.EarnedWeight, round1(r.Score.TotalWeight-r.Score.EarnedWeight))
	fmt.Fprintf(w, "\n  %.1f / %.1f = %d%%  ->  grade %s\n",
		r.Score.EarnedWeight, r.Score.TotalWeight, r.Score.Score, p.grade(r.Score.UncappedGrade))
	for _, c := range r.Score.Caps {
		fmt.Fprintf(w, "  %s %s caps the grade at %s: %s\n", p.wrap(ansiRed, "cap"), c.Finding, c.MaxGrade, c.Reason)
	}
	if r.Score.Grade != r.Score.UncappedGrade {
		fmt.Fprintf(w, "  final grade after caps: %s\n", p.grade(r.Score.Grade))
	}
	if len(r.Score.Skipped) > 0 {
		fmt.Fprintf(w, "\n  %s\n", p.wrap(ansiDim, "not evaluated: "+strings.Join(r.Score.Skipped, ", ")))
	}
	fmt.Fprintln(w)
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

// WriteScoreOnly prints just the explanation table, for `--explain-score`
// without a full report.
func (r *Report) WriteScoreOnly(w io.Writer, rubric *score.Rubric, force *bool) {
	p := newPalette(w, force)
	r.writeScoreExplanation(w, p)
}
