package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/dotMuny/httpsec/internal/analyze"
	"github.com/dotMuny/httpsec/internal/probe"
	"github.com/dotMuny/httpsec/internal/remediate"
	"github.com/dotMuny/httpsec/internal/report"
	"github.com/dotMuny/httpsec/internal/score"
)

type scanFlags struct {
	format            string
	output            string
	verbose           bool
	explainScore      bool
	headersOnly       bool
	tlsOnly           bool
	failUnder         string
	timeout           time.Duration
	budget            time.Duration
	rate              float64
	userAgent         string
	path              string
	port              string
	includeObs        bool
	saveObservation   string
	fromObservation   string
	respectRobots     bool
	remediationServer string
	caFile            string
}

func newScanCommand() *cobra.Command {
	var f scanFlags

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Scan one target and report on it",
		Long: `Scan one target.

The target may be a hostname, a host:port pair or a full URL. With
--from-observation, httpsec re-analyses recorded evidence instead and makes no
network requests at all, which is how the analysis is tested and how a report
can be regenerated in a different format later.`,
		Example: `  # Full audit, findings only
  httpsec scan example.com

  # Everything, including the controls that passed
  httpsec scan example.com --verbose

  # Show how the grade was reached, control by control
  httpsec scan example.com --explain-score

  # A single self-contained HTML file that opens offline
  httpsec scan example.com --format html --output report.html

  # A quick partial audit
  httpsec scan example.com --headers-only
  httpsec scan example.com --tls-only

  # Non-standard port, or a specific path
  httpsec scan example.com:8443
  httpsec scan https://example.com/app/login

  # An internal host behind a private CA
  httpsec scan intranet.corp --ca-file /etc/ssl/corp-ca.pem

  # Gate a build: exit code 2 if the grade is below B
  httpsec scan example.com --fail-under B

  # Record the evidence once, then re-render it offline as often as you like
  httpsec scan example.com --save-observation evidence.json
  httpsec scan --from-observation evidence.json --format markdown`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.fromObservation == "" && len(args) == 0 {
				return fmt.Errorf("a target is required unless --from-observation is given")
			}
			if f.headersOnly && f.tlsOnly {
				return fmt.Errorf("--headers-only and --tls-only are mutually exclusive")
			}
			if f.remediationServer != "" && !remediate.ValidServer(f.remediationServer) {
				return fmt.Errorf("unknown --remediate-for %q", f.remediationServer)
			}

			target := ""
			if len(args) > 0 {
				target = args[0]
			}

			obs, err := loadOrProbe(cmd.Context(), target, f)
			if err != nil {
				return err
			}
			if f.saveObservation != "" {
				if err := writeObservation(obs, f.saveObservation); err != nil {
					return err
				}
			}

			rep := buildReport(obs, f.includeObs)
			if err := emit(cmd.OutOrStdout(), rep, f); err != nil {
				return err
			}
			return checkThreshold(rep, f.failUnder)
		},
	}

	cmd.Flags().StringVarP(&f.format, "format", "f", "text", "output format: text, json, html, markdown")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "write the report to a file instead of stdout")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "also show the controls that passed")
	cmd.Flags().BoolVar(&f.explainScore, "explain-score", false, "show how the grade was calculated, control by control")
	cmd.Flags().BoolVar(&f.headersOnly, "headers-only", false, "skip every TLS handshake probe")
	cmd.Flags().BoolVar(&f.tlsOnly, "tls-only", false, "skip the HTTP-level probes")
	cmd.Flags().StringVar(&f.failUnder, "fail-under", "", "exit with code 2 if the grade is below this letter: A+, A, B+, B, C+, C, D+, D, F")
	cmd.Flags().DurationVar(&f.timeout, "timeout", probe.DefaultTimeout, "timeout for each individual network operation")
	cmd.Flags().DurationVar(&f.budget, "budget", probe.DefaultTotalBudget, "total time budget for the whole scan")
	cmd.Flags().Float64Var(&f.rate, "rate", probe.DefaultRate, "maximum requests per second per host")
	cmd.Flags().StringVar(&f.userAgent, "user-agent", "", "override the User-Agent (the default identifies httpsec)")
	cmd.Flags().StringVar(&f.path, "path", "/", "path to request on the target; headers often differ between the front page and the app")
	cmd.Flags().StringVar(&f.port, "port", "443", "HTTPS port")
	cmd.Flags().BoolVar(&f.includeObs, "include-observation", false, "embed the raw evidence in the JSON report")
	cmd.Flags().StringVar(&f.saveObservation, "save-observation", "", "write the raw evidence to a JSON file")
	cmd.Flags().StringVar(&f.fromObservation, "from-observation", "", "re-analyse a saved observation instead of making requests")
	cmd.Flags().BoolVar(&f.respectRobots, "respect-robots", false, "consult robots.txt before retrieving HTML")
	cmd.Flags().StringVar(&f.caFile, "ca-file", "", "verify the certificate chain against this PEM bundle instead of the system trust store")
	cmd.Flags().StringVar(&f.remediationServer, "remediate-for", "", "inline the fix for this server in text output: nginx, apache, caddy, cdn")

	return cmd
}

func loadOrProbe(ctx context.Context, target string, f scanFlags) (*probe.Observation, error) {
	if f.fromObservation != "" {
		return LoadObservation(f.fromObservation)
	}
	roots, err := loadRoots(f.caFile)
	if err != nil {
		return nil, err
	}
	opts := probe.Options{
		RootCAs:       roots,
		Timeout:       f.timeout,
		TotalBudget:   f.budget,
		UserAgent:     f.userAgent,
		Path:          f.path,
		Port:          f.port,
		HeadersOnly:   f.headersOnly,
		TLSOnly:       f.tlsOnly,
		RespectRobots: f.respectRobots,
		Limiter:       probe.NewLimiter(f.rate),
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return probe.Run(ctx, target, opts)
}

// loadRoots reads a PEM bundle to verify chains against, for hosts served by
// an internal CA. An empty path means the system trust store.
func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path) // #nosec G304 -- the path is a CLI argument the operator chose
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s contains no usable PEM certificates", path)
	}
	return pool, nil
}

// LoadObservation reads a recorded Observation from disk.
func LoadObservation(path string) (*probe.Observation, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the path is a CLI argument the operator chose
	if err != nil {
		return nil, err
	}
	var obs probe.Observation
	if err := json.Unmarshal(b, &obs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if obs.SchemaVersion != probe.ObservationSchemaVersion {
		return nil, fmt.Errorf("%s has observation schema_version %d, this build understands %d",
			path, obs.SchemaVersion, probe.ObservationSchemaVersion)
	}
	return &obs, nil
}

func writeObservation(obs *probe.Observation, path string) error {
	b, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		return err
	}
	// #nosec G306 -- a recorded observation meant to be committed as a fixture
	return os.WriteFile(path, append(b, '\n'), 0o644) // #nosec G306 -- a recorded observation meant to be committed as a fixture
}

func buildReport(obs *probe.Observation, includeObs bool) *report.Report {
	res := analyze.Run(obs, time.Now())
	sc := score.Compute(score.Default(), res.Findings)
	return report.Build(obs, res, sc, report.Options{IncludeObservation: includeObs})
}

func emit(stdout io.Writer, rep *report.Report, f scanFlags) error {
	var buf bytes.Buffer
	var w io.Writer = &buf

	switch f.format {
	case "text", "":
		// Colour only makes sense on a terminal, and only when the report is
		// not being redirected to a file.
		colour := colorOverride()
		if f.output != "" {
			off := false
			colour = &off
		}
		dest := stdout
		if f.output != "" {
			dest = &buf
		}
		if err := rep.WriteText(dest, report.TextOptions{
			Verbose:           f.verbose,
			ExplainScore:      f.explainScore,
			Color:             colour,
			RemediationServer: f.remediationServer,
		}); err != nil {
			return err
		}
		if f.output == "" {
			return nil
		}
	case "json":
		b, err := rep.JSON()
		if err != nil {
			return err
		}
		buf.Write(b)
	case "html":
		if err := rep.WriteHTML(w, report.HTMLOptions{Verbose: f.verbose}); err != nil {
			return err
		}
	case "markdown", "md":
		if err := rep.WriteMarkdown(w, report.MarkdownOptions{
			Verbose:           f.verbose,
			ExplainScore:      f.explainScore,
			RemediationServer: f.remediationServer,
		}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q; use text, json, html or markdown", f.format)
	}

	if f.output == "" {
		_, err := stdout.Write(buf.Bytes())
		return err
	}
	// #nosec G306 -- a report meant to be read, shared and served
	if err := os.WriteFile(f.output, buf.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s (%s, grade %s)\n", f.output, f.format, rep.Score.Grade)
	return nil
}

func checkThreshold(rep *report.Report, minGrade string) error {
	if minGrade == "" {
		return nil
	}
	r := score.Default()
	if !r.ValidGrade(minGrade) {
		return fmt.Errorf("unknown grade %q for --fail-under; valid grades: %v", minGrade, r.GradeNames())
	}
	if rep.Score.Passes(r, minGrade) {
		return nil
	}
	return thresholdError{fmt.Sprintf("grade %s is below the required %s (score %d/100)",
		rep.Score.Grade, minGrade, rep.Score.Score)}
}
