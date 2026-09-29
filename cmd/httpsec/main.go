// Command httpsec audits the HTTP security headers and TLS configuration of a
// website.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/dotMuny/httpsec/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewRootCommand()
	root.SetContext(ctx)
	os.Exit(cli.ExecuteWith(root))
}
