// Package version carries the build identity of the binary.
package version

import "fmt"

// Version is overridden at build time with -ldflags "-X .../version.Version=..".
var (
	Version = "0.1.0-dev"
	Commit  = "none"
	Date    = "unknown"
)

// RepoURL is advertised in the User-Agent so an administrator who finds
// httpsec in their logs can tell what it is.
const RepoURL = "https://github.com/dotMuny/httpsec"

// UserAgent returns the default identifiable User-Agent.
func UserAgent() string {
	return fmt.Sprintf("httpsec/%s (+%s)", Version, RepoURL)
}

// String renders the full version banner.
func String() string {
	return fmt.Sprintf("httpsec %s (commit %s, built %s)", Version, Commit, Date)
}
