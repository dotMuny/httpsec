package cookies

import (
	"net/http"
	"testing"
	"time"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

func respWith(setCookies ...string) *probe.HTTPResponse {
	return &probe.HTTPResponse{
		FinalURL: "https://app.example.test/",
		Headers:  map[string][]string{http.CanonicalHeaderKey("Set-Cookie"): setCookies},
	}
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

func hasFor(fs []finding.Finding, id, subject string) bool {
	for _, f := range fs {
		if f.ID == id && f.Subject == subject {
			return true
		}
	}
	return false
}

func TestParseExtractsAttributes(t *testing.T) {
	cs := Parse(respWith("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.test; Max-Age=3600"))
	if len(cs) != 1 {
		t.Fatalf("parsed %d cookies", len(cs))
	}
	c := cs[0]
	if c.Name != "sid" || !c.Secure || !c.HTTPOnly || c.SameSite != "Lax" ||
		c.Domain != "example.test" || c.Path != "/" || c.MaxAge != 3600 {
		t.Errorf("parsed = %+v", c)
	}
	if c.Raw == "" {
		t.Error("the raw header should be kept for evidence")
	}
}

func TestParseNoCookies(t *testing.T) {
	if cs := Parse(&probe.HTTPResponse{}); cs != nil {
		t.Errorf("= %v, want nil", cs)
	}
}

func TestAnalyzeNoCookies(t *testing.T) {
	if !has(Analyze("example.test", &probe.HTTPResponse{}), "cookie.none") {
		t.Error("a response with no cookies should pass")
	}
}

func TestAnalyzeCleanCookie(t *testing.T) {
	fs := Analyze("app.example.test", respWith("__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"))
	if !has(fs, "cookie.ok") {
		t.Errorf("want cookie.ok, got %v", ids(fs))
	}
	for _, f := range fs {
		if f.Severity.IsProblem() {
			t.Errorf("unexpected problem %s: %s", f.ID, f.Detail)
		}
	}
}

func TestAnalyzeMissingFlags(t *testing.T) {
	fs := Analyze("app.example.test", respWith("pref=dark"))
	for _, want := range []string{"cookie.no-secure", "cookie.no-httponly", "cookie.no-samesite"} {
		if !hasFor(fs, want, "pref") {
			t.Errorf("want %s for pref, got %v", want, ids(fs))
		}
	}
	if has(fs, "cookie.ok") {
		t.Error("a cookie with problems must not also pass")
	}
}

func TestSessionLikeNamesEscalateHttpOnly(t *testing.T) {
	for _, name := range []string{"session", "sid", "auth_token", "JSESSIONID", "user.token", "csrf-token", "PHPSESSID"} {
		fs := Analyze("app.example.test", respWith(name+"=x; Secure; SameSite=Lax"))
		if !hasFor(fs, "cookie.session-no-httponly", name) {
			t.Errorf("%s should be treated as a session cookie, got %v", name, ids(fs))
		}
	}
	fs := Analyze("app.example.test", respWith("theme=dark; Secure; SameSite=Lax"))
	if !hasFor(fs, "cookie.no-httponly", "theme") {
		t.Errorf("an ordinary cookie gets the milder finding, got %v", ids(fs))
	}
	if hasFor(fs, "cookie.session-no-httponly", "theme") {
		t.Error("theme should not be treated as a session cookie")
	}
}

func TestSameSiteNoneRequiresSecure(t *testing.T) {
	fs := Analyze("app.example.test", respWith("x=1; HttpOnly; SameSite=None"))
	if !hasFor(fs, "cookie.samesite-none-insecure", "x") {
		t.Errorf("want cookie.samesite-none-insecure, got %v", ids(fs))
	}
	fs = Analyze("app.example.test", respWith("x=1; HttpOnly; Secure; SameSite=None"))
	if has(fs, "cookie.samesite-none-insecure") {
		t.Error("SameSite=None with Secure is fine")
	}
}

func TestHostPrefixViolations(t *testing.T) {
	cases := []struct {
		cookie string
		want   bool
	}{
		{"__Host-a=1; Path=/; Secure; HttpOnly; SameSite=Lax", false},
		{"__Host-a=1; Path=/sub; Secure; HttpOnly; SameSite=Lax", true},
		{"__Host-a=1; Path=/; HttpOnly; SameSite=Lax", true},
		{"__Host-a=1; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.test", true},
		{"__Secure-a=1; Path=/; Secure; HttpOnly; SameSite=Lax", false},
		{"__Secure-a=1; Path=/; HttpOnly; SameSite=Lax", true},
	}
	for _, c := range cases {
		fs := Analyze("app.example.test", respWith(c.cookie))
		if got := has(fs, "cookie.prefix-violation"); got != c.want {
			t.Errorf("%q: prefix violation = %v, want %v (%v)", c.cookie, got, c.want, ids(fs))
		}
	}
}

func TestBroadDomain(t *testing.T) {
	fs := Analyze("app.example.test", respWith("x=1; Secure; HttpOnly; SameSite=Lax; Domain=example.test"))
	if !hasFor(fs, "cookie.broad-domain", "x") {
		t.Errorf("a parent-domain cookie should be reported, got %v", ids(fs))
	}
	fs = Analyze("app.example.test", respWith("x=1; Secure; HttpOnly; SameSite=Lax; Domain=app.example.test"))
	if has(fs, "cookie.broad-domain") {
		t.Error("a cookie scoped to its own host is not broad")
	}
	fs = Analyze("app.example.test", respWith("x=1; Secure; HttpOnly; SameSite=Lax"))
	if has(fs, "cookie.broad-domain") {
		t.Error("a host-only cookie is not broad")
	}
}

func TestLongExpiry(t *testing.T) {
	far := time.Now().AddDate(3, 0, 0).UTC().Format(http.TimeFormat)
	fs := Analyze("app.example.test", respWith("x=1; Secure; HttpOnly; SameSite=Lax; Expires="+far))
	if !hasFor(fs, "cookie.long-expiry", "x") {
		t.Errorf("a three-year cookie should be reported, got %v", ids(fs))
	}

	fs = Analyze("app.example.test", respWith("x=1; Secure; HttpOnly; SameSite=Lax; Max-Age=63072000"))
	if !hasFor(fs, "cookie.long-expiry", "x") {
		t.Errorf("Max-Age should be honoured too, got %v", ids(fs))
	}

	soon := time.Now().AddDate(0, 1, 0).UTC().Format(http.TimeFormat)
	fs = Analyze("app.example.test", respWith("x=1; Secure; HttpOnly; SameSite=Lax; Expires="+soon))
	if has(fs, "cookie.long-expiry") {
		t.Error("a one-month cookie is not long-lived")
	}
}

func TestMultipleCookiesAreReportedIndividually(t *testing.T) {
	fs := Analyze("app.example.test",
		respWith("good=1; Secure; HttpOnly; SameSite=Lax", "bad=2"))
	if !hasFor(fs, "cookie.no-secure", "bad") {
		t.Errorf("the bad cookie should be reported, got %v", ids(fs))
	}
	if hasFor(fs, "cookie.no-secure", "good") {
		t.Error("the good cookie should not be reported")
	}
}

func TestLooksLikeSession(t *testing.T) {
	for _, yes := range []string{"session", "SID", "connect.sid", "my_auth_key", "id_token"} {
		if !LooksLikeSession(yes) {
			t.Errorf("%q should look like a session cookie", yes)
		}
	}
	for _, no := range []string{"theme", "lang", "consent", "utm_source"} {
		if LooksLikeSession(no) {
			t.Errorf("%q should not look like a session cookie", no)
		}
	}
}
