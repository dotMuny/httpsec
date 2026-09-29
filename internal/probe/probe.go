package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/dotMuny/httpsec/internal/version"
)

// Default limits. Every one of them is a deadline of some kind: no network
// operation in httpsec runs without one.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultTotalBudget  = 90 * time.Second
	DefaultMaxRedirects = 10
	DefaultMaxBody      = 512 * 1024
	DefaultRate         = 4.0
)

// Options configures a scan.
type Options struct {
	// Timeout bounds each individual network operation.
	Timeout time.Duration
	// TotalBudget bounds the whole scan of one target.
	TotalBudget time.Duration
	// MaxRedirects caps the redirect chain length.
	MaxRedirects int
	// MaxBody caps how much HTML is retrieved for mixed-content analysis.
	MaxBody int
	// UserAgent identifies httpsec in the target's logs.
	UserAgent string
	// Path is the path requested on the target, defaulting to "/".
	Path string
	// Port is the HTTPS port, defaulting to 443.
	Port string
	// HeadersOnly skips every TLS handshake probe.
	HeadersOnly bool
	// TLSOnly skips the HTTP-level probes.
	TLSOnly bool
	// SkipBody avoids downloading the response body.
	SkipBody bool
	// Limiter enforces the per-host request rate.
	Limiter *Limiter
	// RootCAs replaces the system trust store when verifying the chain. It is
	// what makes an internal CA auditable, and what lets the TLS tests verify
	// a chain they generated themselves.
	RootCAs *x509.CertPool
	// RespectRobots makes the HTML retrieval honour robots.txt.
	RespectRobots bool
	// Verbose is used by the caller for diagnostics; probe only passes it on.
	Verbose bool
}

// Normalise fills in the zero values with the defaults.
func (o *Options) Normalise() {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.TotalBudget <= 0 {
		o.TotalBudget = DefaultTotalBudget
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = DefaultMaxRedirects
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	if o.UserAgent == "" {
		o.UserAgent = version.UserAgent()
	}
	if o.Path == "" {
		o.Path = "/"
	}
	if o.Port == "" {
		o.Port = "443"
	}
	if o.Limiter == nil {
		o.Limiter = NewLimiter(DefaultRate)
	}
}

// ParseTarget accepts "example.com", "example.com:8443", "https://example.com"
// or a full URL, and returns the host, port and path to probe.
func ParseTarget(target string) (host, port, path string, err error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", "", "", errors.New("empty target")
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return "", "", "", fmt.Errorf("parse target %q: %w", target, err)
	}
	if u.Host == "" {
		return "", "", "", fmt.Errorf("target %q has no host", target)
	}
	host = u.Hostname()
	port = u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	path = u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	if strings.ContainsAny(host, " \t") {
		return "", "", "", fmt.Errorf("target %q has an invalid host", target)
	}
	return host, port, path, nil
}

// Run probes a target and returns everything it observed. It returns an error
// only when nothing at all could be gathered; individual probe failures are
// recorded in the Observation so the report can explain them.
func Run(ctx context.Context, target string, opts Options) (*Observation, error) {
	opts.Normalise()

	host, port, path, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	if opts.Port != "443" && opts.Port != "" {
		port = opts.Port
	}
	if opts.Path != "/" {
		path = opts.Path
	}

	ctx, cancel := context.WithTimeout(ctx, opts.TotalBudget)
	defer cancel()

	start := time.Now()
	obs := &Observation{
		SchemaVersion: ObservationSchemaVersion,
		Tool:          version.String(),
		Target:        target,
		Host:          host,
		Port:          port,
		StartedAt:     start.UTC(),
	}

	c := newHTTPClient(opts)

	if opts.TLSOnly {
		obs.Skip(GroupHTTP)
		obs.Skip(GroupCORS)
		obs.Skip(GroupMethods)
		obs.Skip(GroupWellKnown)
	} else {
		baseURL := (&url.URL{Scheme: "https", Host: net.JoinHostPort(host, port), Path: "/"}).String()
		if port == "443" {
			baseURL = "https://" + host + "/"
		}
		mainURL := strings.TrimSuffix(baseURL, "/") + path

		obs.HTTPS = c.get(ctx, mainURL, opts, !opts.SkipBody)
		if obs.HTTPS.Error != "" {
			obs.Errors = append(obs.Errors, "https request: "+obs.HTTPS.Error)
		}
		obs.PlainHTTP = c.get(ctx, "http://"+host+path, opts, false)
		obs.CORS = c.probeCORS(ctx, mainURL, opts)
		obs.Options = c.method(ctx, "OPTIONS", mainURL, opts)
		obs.Trace = c.method(ctx, "TRACE", mainURL, opts)
		obs.SecurityTxt = c.securityTxt(ctx, host, port, opts)
		if opts.SkipBody {
			obs.Skip(GroupBody)
		}
	}

	if opts.HeadersOnly {
		obs.Skip(GroupTLS)
	} else {
		obs.TLS = probeTLS(ctx, host, port, opts)
	}

	obs.DurationMs = time.Since(start).Milliseconds()
	return obs, nil
}
