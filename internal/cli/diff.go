package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dotMuny/httpsec/internal/report"
)

func newDiffCommand() *cobra.Command {
	var (
		format        string
		failOnRegress bool
	)

	cmd := &cobra.Command{
		Use:   "diff [before.json] [after.json]",
		Short: "Compare two JSON reports and show what changed",
		Long: `Compare two JSON reports of the same target.

Intended for CI: keep the report of the last release, generate a new one, and
diff them. With --fail-on-regression the command exits with code 2 whenever a
finding appears or gets worse.`,
		Example: `  # What changed between two scans
  httpsec diff before.json after.json

  # Post the comparison as a PR comment
  httpsec diff before.json after.json --format markdown

  # Fail the build if anything regressed
  httpsec diff baseline.json new.json --fail-on-regression`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			before, err := report.Load(args[0])
			if err != nil {
				return err
			}
			after, err := report.Load(args[1])
			if err != nil {
				return err
			}
			d := report.Compare(before, after)

			out := cmd.OutOrStdout()
			switch format {
			case "text", "":
				d.WriteText(out, colorOverride())
			case "markdown", "md":
				d.WriteMarkdown(out)
			case "json":
				b, err := json.MarshalIndent(d, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(out, string(b))
			default:
				return fmt.Errorf("unknown format %q; use text, markdown or json", format)
			}

			if failOnRegress && d.Regressed() {
				return thresholdError{fmt.Sprintf("%d new and %d worsened findings, score %+d",
					len(d.Introduced), len(d.Changed), d.ScoreDelta)}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format: text, markdown or json")
	cmd.Flags().BoolVar(&failOnRegress, "fail-on-regression", false, "exit with code 2 if anything got worse")
	return cmd
}
