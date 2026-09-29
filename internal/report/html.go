package report

import (
	"embed"
	"html/template"
	"io"
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/remediate"
	"github.com/dotMuny/httpsec/internal/score"
)

//go:embed templates/report.html.tmpl
var templateFS embed.FS

var htmlTemplate = template.Must(template.New("report.html.tmpl").Funcs(template.FuncMap{
	"lower": strings.ToLower,
	"pct": func(a, b float64) float64 {
		if b == 0 {
			return 0
		}
		return a / b * 100
	},
}).ParseFS(templateFS, "templates/report.html.tmpl"))

// HTMLOptions controls the HTML renderer.
type HTMLOptions struct {
	// Verbose includes the controls that passed.
	Verbose bool
}

type htmlSnippet struct {
	Server string
	Title  string
	Config string
}

type htmlFinding struct {
	finding.Finding
	SeverityClass string
	Summary       string
	Snippets      []htmlSnippet
	Notes         string
}

type htmlGroup struct {
	ID       string
	Title    string
	Findings []htmlFinding
	Problems int
}

type htmlView struct {
	Report     *Report
	Groups     []htmlGroup
	Controls   []score.ControlScore
	GradeClass string
	Generated  string
	Verbose    bool
}

// WriteHTML renders a single self-contained HTML file: no external
// stylesheets, no fonts, no scripts, so it opens correctly from a laptop with
// no connectivity and survives being emailed as an attachment.
func (r *Report) WriteHTML(w io.Writer, opts HTMLOptions) error {
	v := htmlView{
		Report:     r,
		Controls:   r.Score.Controls,
		GradeClass: gradeClass(r.Score.Grade),
		Generated:  r.GeneratedAt.Format("2006-01-02 15:04 MST"),
		Verbose:    opts.Verbose,
	}
	for _, g := range r.FindingsByCategory(opts.Verbose) {
		hg := htmlGroup{ID: g.ID, Title: g.Title}
		for _, f := range g.Findings {
			hf := htmlFinding{Finding: f, SeverityClass: string(f.Severity)}
			if f.Severity.IsProblem() {
				hg.Problems++
			}
			if snip, ok := RemediationFor(f); ok {
				hf.Summary = snip.Summary
				hf.Notes = snip.Notes
				for _, s := range remediate.Servers {
					if cfg := snip.For(s); cfg != "" {
						hf.Snippets = append(hf.Snippets, htmlSnippet{Server: s, Title: remediate.ServerTitles[s], Config: cfg})
					}
				}
			}
			hg.Findings = append(hg.Findings, hf)
		}
		v.Groups = append(v.Groups, hg)
	}
	return htmlTemplate.Execute(w, v)
}

func gradeClass(g string) string {
	switch {
	case strings.HasPrefix(g, "A"):
		return "a"
	case strings.HasPrefix(g, "B"):
		return "b"
	case strings.HasPrefix(g, "C"):
		return "c"
	case strings.HasPrefix(g, "D"):
		return "d"
	default:
		return "f"
	}
}
