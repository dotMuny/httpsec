package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/remediate"
	"github.com/dotMuny/httpsec/internal/report"
	"github.com/dotMuny/httpsec/internal/score"
)

func newRemediateCommand() *cobra.Command {
	var (
		server   string
		fromRep  string
		fromObs  string
		all      bool
		output   string
		findings []string
	)

	cmd := &cobra.Command{
		Use:   "remediate [target]",
		Short: "Print a configuration block that fixes the findings",
		Long: `Print the configuration needed to fix a set of findings, as one block ready
to paste into a server config.

The findings can come from a live scan of a target, from a JSON report written
earlier, from a recorded observation, from explicit finding IDs, or with --all
from the whole catalogue.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !remediate.ValidServer(server) {
				return fmt.Errorf("unknown server %q; supported: %s", server, strings.Join(remediate.Servers, ", "))
			}

			fs, err := gatherFindings(cmd, args, fromRep, fromObs, findings, all)
			if err != nil {
				return err
			}

			text, err := remediate.Render(fs, server)
			if err != nil {
				return err
			}
			if output != "" {
				// #nosec G306 -- a configuration snippet the operator will read and paste
				if err := os.WriteFile(output, []byte(text), 0o644); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", output)
				return nil
			}
			fmt.Fprint(cmd.OutOrStdout(), text)
			return nil
		},
	}

	cmd.Flags().StringVar(&server, "server", "nginx", "server to generate configuration for: nginx, apache, caddy, cdn")
	cmd.Flags().StringVar(&fromRep, "report", "", "read the findings from a JSON report")
	cmd.Flags().StringVar(&fromObs, "from-observation", "", "read the findings from a recorded observation")
	cmd.Flags().BoolVar(&all, "all", false, "emit every snippet in the catalogue, not just the ones this target needs")
	cmd.Flags().StringSliceVar(&findings, "finding", nil, "emit the snippet for specific finding IDs")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to a file instead of stdout")

	return cmd
}

func gatherFindings(cmd *cobra.Command, args []string, fromRep, fromObs string, ids []string, all bool) ([]finding.Finding, error) {
	switch {
	case all:
		return catalogueFindings(nil)
	case len(ids) > 0:
		return catalogueFindings(ids)
	case fromRep != "":
		r, err := report.Load(fromRep)
		if err != nil {
			return nil, err
		}
		return r.Findings, nil
	case fromObs != "":
		obs, err := LoadObservation(fromObs)
		if err != nil {
			return nil, err
		}
		return buildReport(obs, false).Findings, nil
	case len(args) == 1:
		obs, err := loadOrProbe(cmd.Context(), args[0], scanFlags{port: "443", path: "/"})
		if err != nil {
			return nil, err
		}
		return buildReport(obs, false).Findings, nil
	}
	return nil, fmt.Errorf("give a target, --report, --from-observation, --finding or --all")
}

// catalogueFindings synthesises findings straight from the catalogue, which
// is how --all and --finding work without a scan.
func catalogueFindings(ids []string) ([]finding.Finding, error) {
	if len(ids) == 0 {
		var out []finding.Finding
		for _, id := range finding.CatalogIDs() {
			m, _ := finding.Lookup(id)
			if !m.Severity.IsProblem() {
				continue
			}
			out = append(out, finding.New(id, m.Why))
		}
		return out, nil
	}
	var out []finding.Finding
	for _, id := range ids {
		m, ok := finding.Lookup(id)
		if !ok {
			return nil, fmt.Errorf("unknown finding ID %q", id)
		}
		if !m.Severity.IsProblem() {
			return nil, fmt.Errorf("finding %q is a %s, so there is nothing to remediate", id, m.Severity)
		}
		out = append(out, finding.New(id, m.Why))
	}
	return out, nil
}

func newRubricCommand() *cobra.Command {
	var showCaps bool

	cmd := &cobra.Command{
		Use:   "rubric",
		Short: "Print the scoring rubric",
		Long: `Print the control weights, grade caps and grade bands that produce the score.

The rubric is data, not code: it lives in data/rubric.json and is documented in
full in docs/rubric.md.`,
		Example: `  httpsec rubric
  httpsec rubric --caps`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := score.Default()
			out := cmd.OutOrStdout()

			fmt.Fprintf(out, "\n%s v%s\n%s\n\n", r.Name, r.Version, wrapText(r.Notes, 78))

			fmt.Fprintf(out, "%-24s %-10s %7s  %s\n", "control", "category", "weight", "title")
			controls := append([]score.Control(nil), r.Controls...)
			sort.SliceStable(controls, func(i, j int) bool {
				if controls[i].Category != controls[j].Category {
					return controls[i].Category < controls[j].Category
				}
				return controls[i].Weight > controls[j].Weight
			})
			total := 0.0
			for _, c := range controls {
				total += c.Weight
				fmt.Fprintf(out, "%-24s %-10s %7.0f  %s\n", c.ID, c.Category, c.Weight, c.Title)
			}
			fmt.Fprintf(out, "%-24s %-10s %7.0f\n\n", "total", "", total)

			fmt.Fprintln(out, "severity penalty (fraction of the control weight lost)")
			for _, s := range []finding.Severity{
				finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
				finding.SeverityLow, finding.SeverityInfo,
			} {
				fmt.Fprintf(out, "  %-10s %.2f\n", s, r.Penalty(s))
			}

			fmt.Fprintln(out, "\ngrade bands")
			for _, g := range r.Grades {
				fmt.Fprintf(out, "  %-3s  score >= %d\n", g.Grade, g.MinScore)
			}

			if showCaps {
				fmt.Fprintln(out, "\ngrade caps")
				for _, c := range r.Caps {
					fmt.Fprintf(out, "  %-38s max %-2s  %s\n", c.Finding, c.MaxGrade, c.Reason)
				}
			} else {
				fmt.Fprintf(out, "\n%d findings cap the grade; run with --caps to list them.\n", len(r.Caps))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&showCaps, "caps", false, "list the findings that cap the grade")
	return cmd
}

func wrapText(s string, width int) string {
	var b strings.Builder
	line := 0
	for _, w := range strings.Fields(s) {
		if line > 0 && line+len(w)+1 > width {
			b.WriteByte('\n')
			line = 0
		} else if line > 0 {
			b.WriteByte(' ')
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}
