package headers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// resp builds an HTTPResponse with the given headers, which is all most of
// these analysers look at.
func resp(hdr map[string]string) *probe.HTTPResponse {
	r := &probe.HTTPResponse{
		RequestURL: "https://example.test/",
		FinalURL:   "https://example.test/",
		StatusCode: 200,
		Headers:    map[string][]string{},
	}
	for k, v := range hdr {
		r.Headers[http.CanonicalHeaderKey(k)] = []string{v}
	}
	return r
}

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func has(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func mustHave(t *testing.T, fs []finding.Finding, id string) finding.Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("want %s, got %v", id, ids(fs))
	return finding.Finding{}
}

// --- headers response helpers -------------------------------------------

func TestHeaderLookupIsCaseInsensitive(t *testing.T) {
	r := &probe.HTTPResponse{Headers: map[string][]string{"x-weird-CASE": {"v"}}}
	if got := r.Header("X-Weird-Case"); got != "v" {
		t.Errorf("Header = %q, want v", got)
	}
	if !r.HasHeader("x-weird-case") {
		t.Error("HasHeader should match case-insensitively")
	}
	if r.Header("absent") != "" {
		t.Error("an absent header should read as empty")
	}
	var nilResp *probe.HTTPResponse
	if nilResp.Header("anything") != "" {
		t.Error("a nil response should read as empty")
	}
}

// --- HSTS ---------------------------------------------------------------

func TestParseHSTS(t *testing.T) {
	cases := []struct {
		in        string
		maxAge    int64
		subs      bool
		preload   bool
		malformed bool
	}{
		{"max-age=31536000; includeSubDomains; preload", 31536000, true, true, false},
		{"max-age=0", 0, false, false, false},
		{"MAX-AGE=600; INCLUDESUBDOMAINS", 600, true, false, false},
		{`max-age="31536000"`, 31536000, false, false, false},
		{"includeSubDomains", 0, true, false, true},
		{"max-age=abc", 0, false, false, true},
		{"max-age=-1", 0, false, false, true},
		{"", 0, false, false, true},
	}
	for _, c := range cases {
		h := ParseHSTS(c.in)
		if h.MaxAge != c.maxAge || h.IncludeSubDomains != c.subs || h.Preload != c.preload || h.Malformed != c.malformed {
			t.Errorf("ParseHSTS(%q) = %+v, want maxAge=%d subs=%v preload=%v malformed=%v",
				c.in, h, c.maxAge, c.subs, c.preload, c.malformed)
		}
	}
}

func TestAnalyzeHSTS(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		absent bool
		want   []string
		unwant []string
	}{
		{name: "absent", absent: true, want: []string{"hsts.missing"}},
		{name: "good", value: "max-age=31536000; includeSubDomains", want: []string{"hsts.ok", "hsts.no-preload"}},
		{name: "short", value: "max-age=600; includeSubDomains", want: []string{"hsts.max-age-low"}, unwant: []string{"hsts.ok"}},
		{name: "zero", value: "max-age=0", want: []string{"hsts.max-age-zero", "hsts.no-subdomains"}},
		{name: "no subdomains", value: "max-age=31536000", want: []string{"hsts.no-subdomains"}},
		{name: "malformed", value: "includeSubDomains", want: []string{"hsts.malformed"}, unwant: []string{"hsts.ok"}},
		{name: "preload token", value: "max-age=31536000; includeSubDomains; preload", want: []string{"hsts.ok"}, unwant: []string{"hsts.no-preload"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := resp(nil)
			if !c.absent {
				r = resp(map[string]string{"Strict-Transport-Security": c.value})
			}
			fs := AnalyzeHSTS("example.test", r, nil)
			for _, w := range c.want {
				if !has(fs, w) {
					t.Errorf("want %s, got %v", w, ids(fs))
				}
			}
			for _, u := range c.unwant {
				if has(fs, u) {
					t.Errorf("did not want %s, got %v", u, ids(fs))
				}
			}
		})
	}
}

func TestAnalyzeHSTSPreloadedHost(t *testing.T) {
	r := resp(map[string]string{"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"})
	fs := AnalyzeHSTS("github.com", r, nil)
	if !has(fs, "hsts.preloaded") {
		t.Errorf("github.com is in the embedded subset; got %v", ids(fs))
	}
	// A subdomain of an includeSubdomains entry is covered too.
	if !IsPreloaded("gist.github.com") {
		t.Error("subdomains of an includeSubdomains entry should be covered")
	}
	if IsPreloaded("not-a-real-domain.invalid") {
		t.Error("an unlisted domain should not be reported as preloaded")
	}
	if PreloadListUpdated() == "" {
		t.Error("the preload subset should declare when it was updated")
	}
}

func TestAnalyzeHSTSPreloadedButHeaderRemoved(t *testing.T) {
	fs := AnalyzeHSTS("github.com", resp(nil), nil)
	if !has(fs, "hsts.missing") || !has(fs, "hsts.preloaded") {
		t.Errorf("a preloaded host with no header should report both; got %v", ids(fs))
	}
}

func TestAnalyzeHSTSOverPlainHTTP(t *testing.T) {
	plain := resp(map[string]string{"Strict-Transport-Security": "max-age=31536000"})
	plain.FinalURL = "http://example.test/"
	fs := AnalyzeHSTS("example.test", resp(nil), plain)
	if !has(fs, "hsts.over-http") {
		t.Errorf("want hsts.over-http, got %v", ids(fs))
	}
}

// --- framing ------------------------------------------------------------

func TestAnalyzeFraming(t *testing.T) {
	cases := []struct {
		value          string
		absent         bool
		frameAncestors bool
		want           string
	}{
		{absent: true, want: "xfo.missing"},
		{absent: true, frameAncestors: true, want: "xfo.redundant"},
		{value: "DENY", want: "xfo.ok"},
		{value: "sameorigin", want: "xfo.ok"},
		{value: "SAMEORIGIN", frameAncestors: true, want: "xfo.redundant"},
		{value: "ALLOW-FROM https://a.test", want: "xfo.invalid"},
		{value: "ALLOWALL", want: "xfo.allowall"},
		{value: "nonsense", want: "xfo.invalid"},
	}
	for _, c := range cases {
		r := resp(nil)
		if !c.absent {
			r = resp(map[string]string{"X-Frame-Options": c.value})
		}
		fs := AnalyzeFraming(r, c.frameAncestors)
		if !has(fs, c.want) {
			t.Errorf("value=%q absent=%v ancestors=%v: want %s, got %v", c.value, c.absent, c.frameAncestors, c.want, ids(fs))
		}
	}
}

// --- nosniff ------------------------------------------------------------

func TestAnalyzeNoSniff(t *testing.T) {
	if !has(AnalyzeNoSniff(resp(nil)), "nosniff.missing") {
		t.Error("absent nosniff should be reported")
	}
	if !has(AnalyzeNoSniff(resp(map[string]string{"X-Content-Type-Options": "nosniff"})), "nosniff.ok") {
		t.Error("nosniff should pass")
	}
	if !has(AnalyzeNoSniff(resp(map[string]string{"X-Content-Type-Options": "NoSniff"})), "nosniff.ok") {
		t.Error("the value is case-insensitive")
	}
	if !has(AnalyzeNoSniff(resp(map[string]string{"X-Content-Type-Options": "sniff"})), "nosniff.invalid") {
		t.Error("an unexpected value should be reported")
	}
}

// --- Referrer-Policy ----------------------------------------------------

func TestAnalyzeReferrerPolicy(t *testing.T) {
	cases := []struct {
		value  string
		absent bool
		want   string
	}{
		{absent: true, want: "referrer-policy.missing"},
		{value: "no-referrer", want: "referrer-policy.ok"},
		{value: "strict-origin-when-cross-origin", want: "referrer-policy.ok"},
		{value: "same-origin", want: "referrer-policy.ok"},
		{value: "unsafe-url", want: "referrer-policy.leaky"},
		{value: "no-referrer-when-downgrade", want: "referrer-policy.leaky"},
		{value: "made-up", want: "referrer-policy.unknown"},
		// Browsers take the last token they understand, which is how sites
		// ship a new policy with a fallback for old browsers.
		{value: "no-referrer, strict-origin-when-cross-origin", want: "referrer-policy.ok"},
		{value: "strict-origin, unsafe-url", want: "referrer-policy.leaky"},
	}
	for _, c := range cases {
		r := resp(nil)
		if !c.absent {
			r = resp(map[string]string{"Referrer-Policy": c.value})
		}
		if fs := AnalyzeReferrerPolicy(r); !has(fs, c.want) {
			t.Errorf("value=%q: want %s, got %v", c.value, c.want, ids(fs))
		}
	}
}

// --- Permissions-Policy -------------------------------------------------

func TestParsePermissionsPolicy(t *testing.T) {
	p := ParsePermissionsPolicy(`camera=(), geolocation=(self "https://a.test"), payment=*, bogus`)
	if !p.Denied("camera") {
		t.Error("camera=() should be denied")
	}
	if p.Denied("geolocation") {
		t.Error("geolocation has an allowlist, so it is not denied")
	}
	if got, want := len(p.Features["geolocation"]), 2; got != want {
		t.Errorf("geolocation allowlist = %v", p.Features["geolocation"])
	}
	if p.Denied("payment") {
		t.Error("payment=* is not denied")
	}
	if len(p.Invalid) != 1 {
		t.Errorf("invalid = %v, want the bare token", p.Invalid)
	}
}

func TestSplitTopLevelIgnoresSeparatorsInsideParens(t *testing.T) {
	got := splitTopLevel(`a=(self "x,y"), b=()`, ',')
	if len(got) != 2 {
		t.Fatalf("= %q, want 2 items", got)
	}
}

func TestAnalyzePermissionsPolicy(t *testing.T) {
	if !has(AnalyzePermissionsPolicy(resp(nil)), "permissions-policy.missing") {
		t.Error("absent Permissions-Policy should be reported")
	}
	fs := AnalyzePermissionsPolicy(resp(map[string]string{
		"Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
	}))
	if !has(fs, "permissions-policy.ok") {
		t.Errorf("want ok, got %v", ids(fs))
	}
	fs = AnalyzePermissionsPolicy(resp(map[string]string{"Permissions-Policy": "camera=()"}))
	f := mustHave(t, fs, "permissions-policy.open-features")
	if !strings.Contains(f.Detail, "microphone") {
		t.Errorf("the detail should name the features left open: %q", f.Detail)
	}
	fs = AnalyzePermissionsPolicy(resp(map[string]string{"Feature-Policy": "camera 'none'"}))
	if !has(fs, "permissions-policy.legacy-feature-policy") {
		t.Errorf("the legacy header should be reported; got %v", ids(fs))
	}
}

// --- isolation ----------------------------------------------------------

func TestAnalyzeIsolation(t *testing.T) {
	fs := AnalyzeIsolation(resp(nil))
	for _, want := range []string{"coop.missing", "coep.missing", "corp.missing"} {
		if !has(fs, want) {
			t.Errorf("want %s, got %v", want, ids(fs))
		}
	}

	fs = AnalyzeIsolation(resp(map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Cross-Origin-Resource-Policy": "same-origin",
	}))
	for _, want := range []string{"coop.ok", "isolation.enabled", "corp.ok"} {
		if !has(fs, want) {
			t.Errorf("want %s, got %v", want, ids(fs))
		}
	}

	fs = AnalyzeIsolation(resp(map[string]string{"Cross-Origin-Opener-Policy": "unsafe-none"}))
	if !has(fs, "coop.weak") {
		t.Errorf("unsafe-none should be reported; got %v", ids(fs))
	}

	// COOP may carry a reporting parameter, which must not defeat the match.
	fs = AnalyzeIsolation(resp(map[string]string{
		"Cross-Origin-Opener-Policy":   `same-origin; report-to="coop"`,
		"Cross-Origin-Embedder-Policy": "credentialless",
	}))
	if !has(fs, "isolation.enabled") {
		t.Errorf("a report-to parameter should not break parsing; got %v", ids(fs))
	}
}

// --- disclosure and legacy headers --------------------------------------

func TestAnalyzeDisclosure(t *testing.T) {
	if !has(AnalyzeDisclosure(resp(nil)), "info.none") {
		t.Error("no disclosing headers should pass")
	}
	fs := AnalyzeDisclosure(resp(map[string]string{"Server": "nginx/1.25.3"}))
	f := mustHave(t, fs, "info.server-version")
	if !strings.Contains(f.Detail, "1.25.3") {
		t.Errorf("the version should be extracted: %q", f.Detail)
	}
	if !has(AnalyzeDisclosure(resp(map[string]string{"Server": "cloudflare"})), "info.server-present") {
		t.Error("a bare product name is informational")
	}
	fs = AnalyzeDisclosure(resp(map[string]string{
		"X-Powered-By": "PHP/8.2.1", "X-AspNet-Version": "4.0.30319", "X-Generator": "Drupal 10",
	}))
	for _, want := range []string{"info.x-powered-by", "info.aspnet-version", "info.x-generator"} {
		if !has(fs, want) {
			t.Errorf("want %s, got %v", want, ids(fs))
		}
	}
}

func TestAnalyzeLegacyHeaders(t *testing.T) {
	if !has(AnalyzeLegacyHeaders(resp(nil)), "legacy.none") {
		t.Error("no legacy headers should pass")
	}
	if !has(AnalyzeLegacyHeaders(resp(map[string]string{"X-XSS-Protection": "1; mode=block"})), "legacy.x-xss-protection") {
		t.Error("the removed auditor should be reported")
	}
	if has(AnalyzeLegacyHeaders(resp(map[string]string{"X-XSS-Protection": "0"})), "legacy.x-xss-protection") {
		t.Error("X-XSS-Protection: 0 is the recommended value and is not a finding")
	}
	if !has(AnalyzeLegacyHeaders(resp(map[string]string{"Public-Key-Pins": "pin-sha256=\"x\""})), "legacy.public-key-pins") {
		t.Error("HPKP should be reported")
	}
	if !has(AnalyzeLegacyHeaders(resp(map[string]string{"Expect-CT": "max-age=0"})), "legacy.expect-ct") {
		t.Error("Expect-CT should be reported")
	}
}

// --- CORS ---------------------------------------------------------------

func TestAnalyzeCORS(t *testing.T) {
	const origin = "https://httpsec-probe.invalid"

	cases := []struct {
		name   string
		probe  *probe.CORSProbe
		want   []string
		unwant []string
	}{
		{name: "nil probe", probe: nil},
		{name: "probe failed", probe: &probe.CORSProbe{Error: "timeout"}},
		{
			name:  "no CORS at all",
			probe: &probe.CORSProbe{SentOrigin: origin},
			want:  []string{"cors.ok"},
		},
		{
			name:  "wildcard with credentials",
			probe: &probe.CORSProbe{SentOrigin: origin, AllowOrigin: "*", AllowCredentials: "true"},
			want:  []string{"cors.wildcard-with-credentials"},
		},
		{
			name:  "wildcard without credentials",
			probe: &probe.CORSProbe{SentOrigin: origin, AllowOrigin: "*"},
			want:  []string{"cors.wildcard"},
		},
		{
			name:  "reflected with credentials",
			probe: &probe.CORSProbe{SentOrigin: origin, AllowOrigin: origin, AllowCredentials: "true", Vary: "Origin"},
			want:  []string{"cors.reflects-origin-with-credentials"},
		},
		{
			name:  "reflected without credentials and without Vary",
			probe: &probe.CORSProbe{SentOrigin: origin, AllowOrigin: origin},
			want:  []string{"cors.reflects-origin", "cors.missing-vary-origin"},
		},
		{
			name:  "reflected with Vary",
			probe: &probe.CORSProbe{SentOrigin: origin, AllowOrigin: origin, Vary: "Accept-Encoding, Origin"},
			want:  []string{"cors.reflects-origin"}, unwant: []string{"cors.missing-vary-origin"},
		},
		{
			name:  "null origin allowed",
			probe: &probe.CORSProbe{SentOrigin: origin, NullAllowOrigin: "null", NullAllowCreds: "true"},
			want:  []string{"cors.null-origin-allowed"},
		},
		{
			name:  "allowlisted other origin",
			probe: &probe.CORSProbe{SentOrigin: origin, AllowOrigin: "https://app.example.test"},
			want:  []string{"cors.ok"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := AnalyzeCORS(c.probe)
			for _, w := range c.want {
				if !has(fs, w) {
					t.Errorf("want %s, got %v", w, ids(fs))
				}
			}
			for _, u := range c.unwant {
				if has(fs, u) {
					t.Errorf("did not want %s, got %v", u, ids(fs))
				}
			}
			if len(c.want) == 0 && len(fs) != 0 {
				t.Errorf("want no findings, got %v", ids(fs))
			}
		})
	}
}
