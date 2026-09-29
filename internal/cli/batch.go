package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/dotMuny/httpsec/internal/probe"
	"github.com/dotMuny/httpsec/internal/report"
	"github.com/dotMuny/httpsec/internal/score"
)

type batchResult struct {
	Target string         `json:"target"`
	Host   string         `json:"host"`
	Grade  string         `json:"grade,omitempty"`
	Score  int            `json:"score"`
	Report *report.Report `json:"report,omitempty"`
	Error  string         `json:"error,omitempty"`
}

type batchSummary struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Targets       int           `json:"targets"`
	Failed        int           `json:"failed"`
	Results       []batchResult `json:"results"`
}

// unsafeFilename matches everything that does not belong in a generated file
// name, so a hostile line in the target list cannot escape the output
// directory.
var unsafeFilename = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func newBatchCommand() *cobra.Command {
	var (
		concurrency int
		rate        float64
		timeout     time.Duration
		budget      time.Duration
		format      string
		outputDir   string
		failUnder   string
		headersOnly bool
		tlsOnly     bool
		verbose     bool
		robots      bool
	)

	cmd := &cobra.Command{
		Use:   "batch [file]",
		Short: "Scan many targets and print a comparison",
		Long: `Scan every target in a file, one per line. Blank lines and lines starting
with # are ignored.

Targets are scanned concurrently, but the rate limit is applied per host, so
raising --concurrency spreads the work over more hosts rather than hitting any
one of them harder. robots.txt is consulted before retrieving HTML in batch
mode; see docs/decisions.md for why that is the default here and not for a
single scan.`,
		Example: `  # One target per line; blank lines and # comments are ignored
  httpsec batch domains.txt

  # Ten at a time, still rate limited per host
  httpsec batch domains.txt --concurrency 10

  # A comparison table plus one HTML report per target
  httpsec batch domains.txt --output-dir reports --format html

  # Machine-readable aggregate for a dashboard
  httpsec batch domains.txt --format json > fleet.json

  # Fail if any target in the fleet drops below B
  httpsec batch domains.txt --fail-under B`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := readTargets(args[0])
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				return fmt.Errorf("%s contains no targets", args[0])
			}
			if concurrency < 1 {
				concurrency = 1
			}
			if outputDir != "" {
				if err := os.MkdirAll(outputDir, 0o750); err != nil {
					return err
				}
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			// One shared limiter across all workers: the per-host rate limit
			// has to hold no matter how the targets are distributed.
			limiter := probe.NewLimiter(rate)
			results := make([]batchResult, len(targets))
			sem := make(chan struct{}, concurrency)
			var wg sync.WaitGroup

			for i, t := range targets {
				wg.Add(1)
				go func(i int, t string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					obs, err := probe.Run(ctx, t, probe.Options{
						Timeout:       timeout,
						TotalBudget:   budget,
						HeadersOnly:   headersOnly,
						TLSOnly:       tlsOnly,
						RespectRobots: robots,
						Limiter:       limiter,
					})
					if err != nil {
						results[i] = batchResult{Target: t, Error: err.Error()}
						return
					}
					rep := buildReport(obs, false)
					results[i] = batchResult{
						Target: t, Host: obs.Host,
						Grade: rep.Score.Grade, Score: rep.Score.Score, Report: rep,
					}
				}(i, t)
			}
			wg.Wait()

			if outputDir != "" {
				if err := writeBatchFiles(results, outputDir, format, verbose); err != nil {
					return err
				}
			}

			sum := batchSummary{SchemaVersion: report.SchemaVersion, GeneratedAt: time.Now().UTC(), Targets: len(results)}
			for _, r := range results {
				if r.Error != "" {
					sum.Failed++
				}
			}
			sum.Results = results

			out := cmd.OutOrStdout()
			if format == "json" {
				b, err := json.MarshalIndent(sum, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(out, string(b))
			} else {
				writeBatchTable(out, sum)
			}

			if failUnder == "" {
				return nil
			}
			r := score.Default()
			if !r.ValidGrade(failUnder) {
				return fmt.Errorf("unknown grade %q for --fail-under", failUnder)
			}
			var below []string
			for _, res := range results {
				if res.Report == nil || !res.Report.Score.Passes(r, failUnder) {
					below = append(below, res.Target)
				}
			}
			if len(below) > 0 {
				return thresholdError{fmt.Sprintf("%d of %d targets are below grade %s: %s",
					len(below), len(results), failUnder, strings.Join(below, ", "))}
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "number of targets to scan at once")
	cmd.Flags().Float64Var(&rate, "rate", probe.DefaultRate, "maximum requests per second per host")
	cmd.Flags().DurationVar(&timeout, "timeout", probe.DefaultTimeout, "timeout for each individual network operation")
	cmd.Flags().DurationVar(&budget, "budget", probe.DefaultTotalBudget, "total time budget per target")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "summary format: text or json")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "write a per-target report into this directory")
	cmd.Flags().StringVar(&failUnder, "fail-under", "", "exit with code 2 if any target grades below this letter: A+, A, B+, B, C+, C, D+, D, F")
	cmd.Flags().BoolVar(&headersOnly, "headers-only", false, "skip every TLS handshake probe")
	cmd.Flags().BoolVar(&tlsOnly, "tls-only", false, "skip the HTTP-level probes")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "include passing controls in the per-target reports")
	cmd.Flags().BoolVar(&robots, "respect-robots", true, "consult robots.txt before retrieving HTML")

	return cmd
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- the path is a CLI argument the operator chose
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out, sc.Err()
}

func writeBatchFiles(results []batchResult, dir, format string, verbose bool) error {
	ext := map[string]string{"text": "txt", "json": "json", "html": "html", "markdown": "md", "md": "md"}[format]
	if ext == "" {
		ext = "json"
		format = "json"
	}
	for _, r := range results {
		if r.Report == nil {
			continue
		}
		name := unsafeFilename.ReplaceAllString(r.Host, "_")
		if name == "" {
			name = "target"
		}
		path := filepath.Join(dir, name+"."+ext)
		f, err := os.Create(path) // #nosec G304 -- name is sanitised above
		if err != nil {
			return err
		}
		var werr error
		switch format {
		case "html":
			werr = r.Report.WriteHTML(f, report.HTMLOptions{Verbose: verbose})
		case "markdown", "md":
			werr = r.Report.WriteMarkdown(f, report.MarkdownOptions{Verbose: verbose})
		case "text":
			off := false
			werr = r.Report.WriteText(f, report.TextOptions{Verbose: verbose, Color: &off})
		default:
			b, err := r.Report.JSON()
			if err == nil {
				_, werr = f.Write(b)
			} else {
				werr = err
			}
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
	}
	return nil
}

func writeBatchTable(w io.Writer, sum batchSummary) {
	sorted := append([]batchResult(nil), sum.Results...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Error != "" || sorted[j].Error != "" {
			return sorted[i].Error == "" && sorted[j].Error != ""
		}
		return sorted[i].Score > sorted[j].Score
	})

	width := 6
	for _, r := range sorted {
		if len(r.Target) > width {
			width = len(r.Target)
		}
	}
	fmt.Fprintf(w, "\n%-*s  %-5s %5s  %s\n", width, "target", "grade", "score", "findings (crit/high/med/low)")
	for _, r := range sorted {
		if r.Report == nil {
			fmt.Fprintf(w, "%-*s  %-5s %5s  %s\n", width, r.Target, "-", "-", "error: "+r.Error)
			continue
		}
		s := r.Report.Summary
		fmt.Fprintf(w, "%-*s  %-5s %5d  %d/%d/%d/%d\n", width, r.Target, r.Grade, r.Score,
			s.Critical, s.High, s.Medium, s.Low)
	}
	fmt.Fprintf(w, "\n%d targets, %d failed to scan.\n", sum.Targets, sum.Failed)
}
