// Package cli wires the commands together. It is the only package allowed to
// print to stdout or to decide a process exit code.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/dotMuny/httpsec/internal/version"
)

// ExitCode is returned by Execute so main can exit with it.
const (
	ExitOK        = 0
	ExitError     = 1
	ExitThreshold = 2
)

var globalNoColor bool

// NewRootCommand builds the command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "httpsec",
		Short: "Audit the HTTP security headers and TLS configuration of a website",
		Long: `httpsec audits the security posture a web server exposes in a normal
interaction: its security headers, the quality of its Content-Security-Policy,
its cookies, its TLS configuration and certificate chain, and how it handles
plain HTTP.

It reports what is wrong, why it matters, and the exact configuration line that
fixes it, for Nginx, Apache, Caddy and a generic CDN.

httpsec is not a vulnerability scanner. It does not enumerate subdomains,
brute-force paths or probe for application flaws. Use it on hosts you own or
have written permission to test.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}
	root.PersistentFlags().BoolVar(&globalNoColor, "no-color", false, "disable coloured output")

	root.AddCommand(
		newScanCommand(),
		newBatchCommand(),
		newDiffCommand(),
		newRemediateCommand(),
		newRubricCommand(),
		newVersionCommand(),
	)
	return root
}

// Execute runs the root command and maps errors to exit codes.
func Execute() int {
	root := NewRootCommand()
	if err := root.Execute(); err != nil {
		if te, ok := err.(thresholdError); ok {
			fmt.Fprintln(os.Stderr, te.Error())
			return ExitThreshold
		}
		fmt.Fprintln(os.Stderr, "httpsec: "+err.Error())
		return ExitError
	}
	return ExitOK
}

// thresholdError marks a --fail-under failure, which is not a tool error and
// gets its own exit code so CI can tell the two apart.
type thresholdError struct{ msg string }

func (e thresholdError) Error() string { return e.msg }

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
			return nil
		},
	}
}

func colorOverride() *bool {
	if globalNoColor {
		off := false
		return &off
	}
	return nil
}

// ExecuteWith runs an already-built command tree, so main can attach a context
// that cancels on SIGINT.
func ExecuteWith(root *cobra.Command) int {
	if err := root.Execute(); err != nil {
		if te, ok := err.(thresholdError); ok {
			fmt.Fprintln(os.Stderr, te.Error())
			return ExitThreshold
		}
		fmt.Fprintln(os.Stderr, "httpsec: "+err.Error())
		return ExitError
	}
	return ExitOK
}
