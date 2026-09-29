package cli

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestCAFileVerifiesAgainstAPrivateBundle exercises --ca-file end to end
// against a server using the test CA. Without the flag the same chain must be
// reported as untrusted, which is what proves the flag is wired through rather
// than silently ignored.
func TestCAFileVerifiesAgainstAPrivateBundle(t *testing.T) {
	const certDir = "../../testdata/certs"

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "good.cert.pem"),
		filepath.Join(certDir, "good.key.pem"),
	)
	if err != nil {
		t.Skipf("testdata certificates are unavailable (%v); run scripts/gen-testdata-certs.sh", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	// httpsec deliberately offers suites and protocols the server does not
	// support, in order to find out what it refuses. Those refusals are the
	// measurement, not a problem, so the server's log is discarded.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer srv.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	target := "127.0.0.1:" + port

	certFindings := func(args ...string) map[string]bool {
		t.Helper()
		out, err := run(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var rep struct {
			Findings []struct{ ID string } `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		got := map[string]bool{}
		for _, f := range rep.Findings {
			got[f.ID] = true
		}
		return got
	}

	base := []string{"scan", target, "--format", "json", "--rate", "0",
		"--timeout", "5s", "--budget", "60s", "--port", port}

	without := certFindings(base...)
	if !without["tls.cert.untrusted-chain"] {
		t.Error("without --ca-file the private CA is not in the system store, so the chain must be reported as untrusted")
	}

	with := certFindings(append(append([]string{}, base...), "--ca-file", filepath.Join(certDir, "ca.cert.pem"))...)
	// The chain now verifies. The certificate still draws findings of its own
	// (a locally issued one is valid for ten years and carries no CT SCTs),
	// which is correct and is not what this test is about.
	for _, unwanted := range []string{
		"tls.cert.untrusted-chain", "tls.cert.self-signed", "tls.cert.hostname-mismatch",
		"tls.cert.expired", "tls.cert.not-yet-valid",
	} {
		if with[unwanted] {
			t.Errorf("with --ca-file the chain should verify, but %s was reported", unwanted)
		}
	}
	if !with["tls.version.ok"] {
		t.Errorf("the rest of the TLS analysis should still run; got %v", keys(with))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
