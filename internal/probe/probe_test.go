package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testOptions() Options {
	o := Options{Timeout: 5 * time.Second, Limiter: NewLimiter(0)}
	o.Normalise()
	o.Limiter = NewLimiter(0) // Normalise would install the default rate
	return o
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in               string
		host, port, path string
		wantErr          bool
	}{
		{in: "example.com", host: "example.com", port: "443", path: "/"},
		{in: "example.com:8443", host: "example.com", port: "8443", path: "/"},
		{in: "https://example.com/app", host: "example.com", port: "443", path: "/app"},
		{in: "http://example.com", host: "example.com", port: "80", path: "/"},
		{in: "https://example.com/a?b=c", host: "example.com", port: "443", path: "/a?b=c"},
		{in: "127.0.0.1:9000", host: "127.0.0.1", port: "9000", path: "/"},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
		{in: "https://", wantErr: true},
		{in: "https://not a host/", wantErr: true},
	}
	for _, c := range cases {
		host, port, path, err := ParseTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseTarget(%q) should have failed", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", c.in, err)
			continue
		}
		if host != c.host || port != c.port || path != c.path {
			t.Errorf("ParseTarget(%q) = %q %q %q, want %q %q %q", c.in, host, port, path, c.host, c.port, c.path)
		}
	}
}

func TestOptionsNormalise(t *testing.T) {
	var o Options
	o.Normalise()
	if o.Timeout == 0 || o.TotalBudget == 0 || o.MaxRedirects == 0 || o.MaxBody == 0 {
		t.Errorf("Normalise left a zero limit: %+v", o)
	}
	if !strings.HasPrefix(o.UserAgent, "httpsec/") {
		t.Errorf("UserAgent = %q, want the identifiable default", o.UserAgent)
	}
	if !strings.Contains(o.UserAgent, "https://") {
		t.Error("the User-Agent should carry the project URL so an administrator can look it up")
	}
	if o.Limiter == nil {
		t.Error("rate limiting must be on by default")
	}
}

func TestLimiterSpacesRequests(t *testing.T) {
	l := NewLimiter(50) // 20ms apart
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx, "a.test"); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 35*time.Millisecond {
		t.Errorf("three requests took %v; the limiter did not space them", elapsed)
	}
}

func TestLimiterIsPerHost(t *testing.T) {
	l := NewLimiter(50)
	ctx := context.Background()
	start := time.Now()
	for _, host := range []string{"a.test", "b.test", "c.test"} {
		if err := l.Wait(ctx, host); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed > 15*time.Millisecond {
		t.Errorf("three different hosts took %v; the limit should be per host", elapsed)
	}
}

func TestLimiterZeroRateDoesNotBlock(t *testing.T) {
	l := NewLimiter(0)
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := l.Wait(context.Background(), "a.test"); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Error("a zero rate should disable limiting")
	}
}

func TestLimiterRespectsContextCancellation(t *testing.T) {
	l := NewLimiter(1) // one second apart
	ctx := context.Background()
	if err := l.Wait(ctx, "a.test"); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if err := l.Wait(cancelled, "a.test"); err == nil {
		t.Error("Wait should return the context error rather than block past the deadline")
	}
}

func TestNilLimiterIsSafe(t *testing.T) {
	var l *Limiter
	if err := l.Wait(context.Background(), "a.test"); err != nil {
		t.Errorf("a nil limiter should be a no-op, got %v", err)
	}
}

func TestGetRecordsHeadersAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.Header().Add("Set-Cookie", "a=1; Secure")
		w.Header().Add("Set-Cookie", "b=2")
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer srv.Close()

	c := newHTTPClient(testOptions())
	r := c.get(context.Background(), srv.URL, testOptions(), true)

	if r.Error != "" {
		t.Fatalf("error = %s", r.Error)
	}
	if r.StatusCode != 200 {
		t.Errorf("status = %d", r.StatusCode)
	}
	if r.Header("X-Test") != "yes" {
		t.Errorf("headers = %v", r.Headers)
	}
	if len(r.HeaderValues("Set-Cookie")) != 2 {
		t.Errorf("both Set-Cookie headers should be kept: %v", r.HeaderValues("Set-Cookie"))
	}
	if !strings.Contains(r.Body, "hi") {
		t.Errorf("body = %q", r.Body)
	}
}

func TestGetTruncatesLargeBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 10000)))
	}))
	defer srv.Close()

	opts := testOptions()
	opts.MaxBody = 100
	r := newHTTPClient(opts).get(context.Background(), srv.URL, opts, true)

	if !r.BodyTruncated {
		t.Error("the body should be marked as truncated")
	}
	if len(r.Body) != 100 {
		t.Errorf("body length = %d, want 100", len(r.Body))
	}
}

func TestRedirectChainIsRecorded(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, srv.URL+"/one", http.StatusMovedPermanently)
		case "/one":
			http.Redirect(w, r, srv.URL+"/two", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	r := newHTTPClient(testOptions()).get(context.Background(), srv.URL+"/", testOptions(), false)
	if r.Error != "" {
		t.Fatalf("error = %s", r.Error)
	}
	if len(r.Redirects) != 2 {
		t.Fatalf("recorded %d hops, want 2: %+v", len(r.Redirects), r.Redirects)
	}
	if r.Redirects[0].StatusCode != 301 || r.Redirects[1].StatusCode != 302 {
		t.Errorf("hop status codes = %d, %d", r.Redirects[0].StatusCode, r.Redirects[1].StatusCode)
	}
	if !strings.HasSuffix(r.FinalURL, "/two") {
		t.Errorf("final URL = %s", r.FinalURL)
	}
}

func TestRedirectLoopIsBounded(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/", http.StatusFound)
	}))
	defer srv.Close()

	opts := testOptions()
	opts.MaxRedirects = 3
	r := newHTTPClient(opts).get(context.Background(), srv.URL+"/", opts, false)
	if r.Error == "" {
		t.Fatal("an endless redirect loop should stop with an error")
	}
	if len(r.Redirects) > 4 {
		t.Errorf("followed %d hops with a limit of 3", len(r.Redirects))
	}
}

func TestProbeCORSDetectsReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}))
	defer srv.Close()

	p := newHTTPClient(testOptions()).probeCORS(context.Background(), srv.URL, testOptions())
	if p.AllowOrigin != p.SentOrigin {
		t.Errorf("AllowOrigin = %q, want the reflected probe origin %q", p.AllowOrigin, p.SentOrigin)
	}
	if p.AllowCredentials != "true" {
		t.Errorf("AllowCredentials = %q", p.AllowCredentials)
	}
	if p.NullAllowOrigin != "null" {
		t.Errorf("the null-origin probe should also be reflected, got %q", p.NullAllowOrigin)
	}
}

func TestProbeCORSOnAFailedRequest(t *testing.T) {
	opts := testOptions()
	p := newHTTPClient(opts).probeCORS(context.Background(), "http://127.0.0.1:1/", opts)
	if p.Error == "" {
		t.Error("a failed request should be recorded as an error, not as an absent header")
	}
}

func TestSecurityTxtFallsBackToTheLegacyLocation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/security.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Contact: mailto:a@a.test\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	host, port, _, err := ParseTarget(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := newHTTPClient(testOptions()).securityTxt(context.Background(), host, port, testOptions())
	if r.StatusCode != 200 || !strings.Contains(r.Body, "Contact") {
		t.Errorf("= %d %q", r.StatusCode, r.Body)
	}
}

func TestRunGathersEverything(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		}
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	host, port, _, err := ParseTarget(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	obs, err := Run(context.Background(), host+":"+port, Options{
		Timeout: 5 * time.Second, TotalBudget: 60 * time.Second,
		Limiter: NewLimiter(0), Port: port,
	})
	if err != nil {
		t.Fatal(err)
	}
	if obs.SchemaVersion != ObservationSchemaVersion {
		t.Errorf("schema version = %d", obs.SchemaVersion)
	}
	if obs.HTTPS == nil || obs.HTTPS.Header("Strict-Transport-Security") == "" {
		t.Error("the HTTPS response should have been recorded")
	}
	if obs.Options == nil || obs.Options.Header("Allow") == "" {
		t.Error("the OPTIONS response should have been recorded")
	}
	if obs.TLS == nil || !obs.TLS.Supports("TLS 1.3") {
		t.Errorf("the TLS probe should have run: %+v", obs.TLS)
	}
	if obs.CORS == nil {
		t.Error("the CORS probe should have run")
	}
}

func TestRunHonoursHeadersOnlyAndTLSOnly(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, port, _, _ := ParseTarget(srv.URL)

	headersOnly, err := Run(context.Background(), host+":"+port, Options{
		Limiter: NewLimiter(0), Port: port, HeadersOnly: true, TotalBudget: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if headersOnly.TLS != nil || !headersOnly.WasSkipped(GroupTLS) {
		t.Error("--headers-only should skip the TLS probes")
	}

	tlsOnly, err := Run(context.Background(), host+":"+port, Options{
		Limiter: NewLimiter(0), Port: port, TLSOnly: true, TotalBudget: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tlsOnly.HTTPS != nil || !tlsOnly.WasSkipped(GroupHTTP) {
		t.Error("--tls-only should skip the HTTP probes")
	}
	if tlsOnly.TLS == nil {
		t.Error("--tls-only should still probe TLS")
	}
}

func TestRunRejectsAnInvalidTarget(t *testing.T) {
	if _, err := Run(context.Background(), "", Options{}); err == nil {
		t.Fatal("an empty target should be an error")
	}
}

func TestSkipIsIdempotent(t *testing.T) {
	o := &Observation{}
	o.Skip(GroupTLS)
	o.Skip(GroupTLS)
	if len(o.Skipped) != 1 {
		t.Errorf("Skipped = %v", o.Skipped)
	}
	if !o.WasSkipped(GroupTLS) || o.WasSkipped(GroupHTTP) {
		t.Error("WasSkipped is wrong")
	}
}
