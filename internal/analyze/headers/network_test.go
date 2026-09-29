package headers

import (
	"strings"
	"testing"
	"time"

	"github.com/dotMuny/httpsec/internal/probe"
)

func TestAnalyzeRedirect(t *testing.T) {
	cases := []struct {
		name   string
		plain  *probe.HTTPResponse
		want   []string
		unwant []string
		none   bool
	}{
		{name: "nil", plain: nil, none: true},
		{name: "request failed", plain: &probe.HTTPResponse{Error: "connection refused"}, none: true},
		{
			name: "no upgrade",
			plain: &probe.HTTPResponse{
				RequestURL: "http://a.test/", FinalURL: "http://a.test/", StatusCode: 200,
			},
			want: []string{"redirect.no-https"},
		},
		{
			name: "clean 301",
			plain: &probe.HTTPResponse{
				RequestURL: "http://a.test/", FinalURL: "https://a.test/", StatusCode: 200,
				Redirects: []probe.Hop{{URL: "http://a.test/", Scheme: "http", StatusCode: 301, Location: "https://a.test/"}},
			},
			want: []string{"redirect.ok"},
		},
		{
			name: "302 is not cached as an upgrade",
			plain: &probe.HTTPResponse{
				RequestURL: "http://a.test/", FinalURL: "https://a.test/", StatusCode: 200,
				Redirects: []probe.Hop{{URL: "http://a.test/", Scheme: "http", StatusCode: 302, Location: "https://a.test/"}},
			},
			want: []string{"redirect.not-permanent"}, unwant: []string{"redirect.ok"},
		},
		{
			name: "straight to another host",
			plain: &probe.HTTPResponse{
				RequestURL: "http://a.test/", FinalURL: "https://www.a.test/", StatusCode: 200,
				Redirects: []probe.Hop{{URL: "http://a.test/", Scheme: "http", StatusCode: 301, Location: "https://www.a.test/"}},
			},
			want: []string{"redirect.cross-host"},
		},
		{
			name: "back through plain HTTP mid-chain",
			plain: &probe.HTTPResponse{
				RequestURL: "http://a.test/", FinalURL: "https://a.test/final", StatusCode: 200,
				Redirects: []probe.Hop{
					{URL: "http://a.test/", Scheme: "http", StatusCode: 301, Location: "https://a.test/one"},
					{URL: "http://a.test/one", Scheme: "http", StatusCode: 302, Location: "https://a.test/final"},
				},
			},
			want: []string{"redirect.chain-through-http"},
		},
		{
			// apex -> www -> /locale/ is three hops and extremely common, so
			// it must not be reported.
			name: "three hops is normal",
			plain: &probe.HTTPResponse{
				RequestURL: "http://a.test/", FinalURL: "https://www.a.test/en/", StatusCode: 200,
				Redirects: []probe.Hop{
					{URL: "http://a.test/", Scheme: "http", StatusCode: 301, Location: "https://a.test/"},
					{URL: "https://a.test/", Scheme: "https", StatusCode: 301, Location: "https://www.a.test/"},
					{URL: "https://www.a.test/", Scheme: "https", StatusCode: 301, Location: "https://www.a.test/en/"},
				},
			},
			want:   []string{"redirect.ok"},
			unwant: []string{"redirect.long-chain"},
		},
		{
			name: "long chain",
			plain: &probe.HTTPResponse{
				RequestURL: "http://a.test/", FinalURL: "https://a.test/d", StatusCode: 200,
				Redirects: []probe.Hop{
					{URL: "http://a.test/", Scheme: "http", StatusCode: 301, Location: "https://a.test/a"},
					{URL: "https://a.test/a", Scheme: "https", StatusCode: 301, Location: "https://a.test/b"},
					{URL: "https://a.test/b", Scheme: "https", StatusCode: 301, Location: "https://a.test/c"},
					{URL: "https://a.test/c", Scheme: "https", StatusCode: 301, Location: "https://a.test/d"},
				},
			},
			want: []string{"redirect.long-chain"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := AnalyzeRedirect("a.test", c.plain)
			if c.none {
				if len(fs) != 0 {
					t.Fatalf("want no findings, got %v", ids(fs))
				}
				return
			}
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

func TestAnalyzeMixedContent(t *testing.T) {
	body := `<html><head>
		<link rel="stylesheet" href="http://cdn.test/a.css">
		<script src="http://cdn.test/a.js"></script>
	</head><body>
		<img src="http://img.test/a.png">
		<iframe src="http://frame.test/"></iframe>
		<video src="http://media.test/v.mp4"></video>
		<script src="https://secure.test/ok.js"></script>
	</body></html>`

	r := &probe.HTTPResponse{Body: body}
	fs := AnalyzeMixedContent(r)

	active := mustHave(t, fs, "mixed-content.active")
	for _, want := range []string{"script", "iframe", "stylesheet"} {
		if !strings.Contains(active.Detail, want) {
			t.Errorf("active detail %q should mention %s", active.Detail, want)
		}
	}
	passive := mustHave(t, fs, "mixed-content.passive")
	if !strings.Contains(passive.Detail, "image") || !strings.Contains(passive.Detail, "media") {
		t.Errorf("passive detail = %q", passive.Detail)
	}
	if strings.Contains(active.Evidence, "secure.test") {
		t.Error("an https:// reference must not be reported")
	}
}

func TestAnalyzeMixedContentClean(t *testing.T) {
	fs := AnalyzeMixedContent(&probe.HTTPResponse{Body: `<img src="https://a.test/x.png">`})
	if !has(fs, "mixed-content.none") {
		t.Errorf("want mixed-content.none, got %v", ids(fs))
	}
	if len(AnalyzeMixedContent(&probe.HTTPResponse{})) != 0 {
		t.Error("with no body there is nothing to analyse")
	}
	if len(AnalyzeMixedContent(nil)) != 0 {
		t.Error("a nil response should produce nothing")
	}
}

func TestAnalyzeMixedContentMentionsTruncation(t *testing.T) {
	fs := AnalyzeMixedContent(&probe.HTTPResponse{Body: "<html></html>", BodyTruncated: true})
	f := mustHave(t, fs, "mixed-content.none")
	if !strings.Contains(f.Detail, "truncated") {
		t.Errorf("a truncated body should be disclosed: %q", f.Detail)
	}
}

func securityTxtResponse(body string, status int) *probe.HTTPResponse {
	return &probe.HTTPResponse{
		RequestURL: "https://a.test/.well-known/security.txt",
		StatusCode: status,
		Headers:    map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
		Body:       body,
	}
}

func TestAnalyzeSecurityTxt(t *testing.T) {
	future := time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339)
	past := time.Now().AddDate(-1, 0, 0).UTC().Format(time.RFC3339)

	if len(AnalyzeSecurityTxt(nil)) != 0 {
		t.Error("a nil response should produce nothing")
	}
	if !has(AnalyzeSecurityTxt(securityTxtResponse("", 404)), "security-txt.missing") {
		t.Error("404 should be reported as missing")
	}
	ok := AnalyzeSecurityTxt(securityTxtResponse(
		"# comment\nContact: mailto:security@a.test\nExpires: "+future+"\n", 200))
	if !has(ok, "security-txt.ok") {
		t.Errorf("a valid file should pass, got %v", ids(ok))
	}
	if !has(AnalyzeSecurityTxt(securityTxtResponse("Expires: "+future, 200)), "security-txt.invalid") {
		t.Error("a file with no Contact is invalid")
	}
	if !has(AnalyzeSecurityTxt(securityTxtResponse("Contact: mailto:a@a.test", 200)), "security-txt.invalid") {
		t.Error("a file with no Expires is invalid")
	}
	if !has(AnalyzeSecurityTxt(securityTxtResponse("Contact: mailto:a@a.test\nExpires: soon", 200)), "security-txt.invalid") {
		t.Error("a non-RFC3339 Expires is invalid")
	}
	if !has(AnalyzeSecurityTxt(securityTxtResponse("Contact: mailto:a@a.test\nExpires: "+past, 200)), "security-txt.expired") {
		t.Error("a past Expires should be reported as expired")
	}

	html := securityTxtResponse("Contact: mailto:a@a.test\nExpires: "+future, 200)
	html.Headers["Content-Type"] = []string{"text/html"}
	f := mustHave(t, AnalyzeSecurityTxt(html), "security-txt.invalid")
	if !strings.Contains(f.Detail, "text/plain") {
		t.Errorf("the content type problem should be named: %q", f.Detail)
	}
}

func TestParseRFC3339AcceptsLowercaseZ(t *testing.T) {
	// RFC 3339's ABNF inherits case-insensitive literals from RFC 5234, so a
	// lowercase "z" is a valid UTC offset. time.RFC3339 rejects it, and real
	// sites (github.com among them) use it.
	for _, in := range []string{"2026-10-24T10:18:45Z", "2026-10-24T10:18:45z", "2026-10-24T10:18:45+02:00"} {
		if _, err := parseRFC3339(in); err != nil {
			t.Errorf("parseRFC3339(%q) = %v, want it to parse", in, err)
		}
	}
	for _, in := range []string{"", "soon", "2026-13-99T99:99:99Z", "2026-10-24"} {
		if _, err := parseRFC3339(in); err == nil {
			t.Errorf("parseRFC3339(%q) should have failed", in)
		}
	}
}

func TestSecurityTxtAcceptsLowercaseZExpiry(t *testing.T) {
	body := "Contact: https://example.test/report\nExpires: " +
		time.Now().AddDate(1, 0, 0).UTC().Format("2006-01-02T15:04:05") + "z\n"
	fs := AnalyzeSecurityTxt(securityTxtResponse(body, 200))
	if !has(fs, "security-txt.ok") {
		t.Errorf("a lowercase z offset is valid RFC 3339; got %v", ids(fs))
	}
}

func TestAnalyzeMethods(t *testing.T) {
	trace := &probe.HTTPResponse{RequestURL: "https://a.test/", StatusCode: 200}
	if !has(AnalyzeMethods(nil, trace), "methods.trace-enabled") {
		t.Error("TRACE returning 200 should be reported")
	}

	options := resp(map[string]string{"Allow": "GET, HEAD, POST, PUT, DELETE"})
	f := mustHave(t, AnalyzeMethods(options, nil), "methods.dangerous-allowed")
	if !strings.Contains(f.Detail, "PUT") || !strings.Contains(f.Detail, "DELETE") {
		t.Errorf("detail = %q", f.Detail)
	}

	clean := resp(map[string]string{"Allow": "GET, HEAD, OPTIONS"})
	traceRefused := &probe.HTTPResponse{StatusCode: 405}
	if !has(AnalyzeMethods(clean, traceRefused), "methods.ok") {
		t.Error("safe methods with TRACE refused should pass")
	}

	// Some servers answer OPTIONS with Access-Control-Allow-Methods instead.
	cors := resp(map[string]string{"Access-Control-Allow-Methods": "GET, PUT"})
	if !has(AnalyzeMethods(cors, nil), "methods.dangerous-allowed") {
		t.Error("the CORS method list should be read as a fallback")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc..." {
		t.Errorf("= %q", got)
	}
	if got := truncate("ab", 5); got != "ab" {
		t.Errorf("= %q", got)
	}
}
