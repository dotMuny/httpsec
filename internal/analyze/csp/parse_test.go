package csp

import (
	"reflect"
	"testing"
)

func TestParseSplitsDirectives(t *testing.T) {
	p := Parse("default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'", false)

	if got, want := len(p.Directives), 3; got != want {
		t.Fatalf("directives = %d, want %d", got, want)
	}
	if got, want := p.Values("script-src"), []string{"'self'", "https://cdn.example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("script-src = %v, want %v", got, want)
	}
	if !p.Has("object-src") {
		t.Error("object-src should be present")
	}
	if p.Has("base-uri") {
		t.Error("base-uri should be absent")
	}
}

func TestParseIsWhitespaceTolerant(t *testing.T) {
	p := Parse("  default-src   'self'  ;;  script-src\t'none' ;", false)
	if got, want := len(p.Directives), 2; got != want {
		t.Fatalf("directives = %d, want %d: %+v", got, want, p.Directives)
	}
	if !IsNone(p.Values("script-src")) {
		t.Errorf("script-src = %v, want 'none'", p.Values("script-src"))
	}
}

func TestParseLowercasesDirectiveNamesAndKeywords(t *testing.T) {
	p := Parse("Default-SRC 'SELF'; SCRIPT-SRC 'Unsafe-Inline'", false)
	if !p.Has("default-src") {
		t.Fatal("directive name should be lowercased")
	}
	if !HasKeyword(p.Values("script-src"), "unsafe-inline") {
		t.Error("keyword matching should be case-insensitive")
	}
}

func TestParsePreservesNonceAndHashCase(t *testing.T) {
	p := Parse("script-src 'nonce-AbCdEf123' 'sha256-XyZ+/abc='", false)
	got := p.Values("script-src")
	if got[0] != "'nonce-AbCdEf123'" {
		t.Errorf("nonce was normalised to %q; base64 is case-sensitive", got[0])
	}
	if got[1] != "'sha256-XyZ+/abc='" {
		t.Errorf("hash was normalised to %q", got[1])
	}
	if !HasNonce(got) {
		t.Error("HasNonce should find the nonce")
	}
	if !HasHash(got) {
		t.Error("HasHash should find the hash")
	}
}

func TestParseFirstDuplicateWins(t *testing.T) {
	p := Parse("script-src 'self'; script-src *", false)
	if got, want := p.Values("script-src"), []string{"'self'"}; !reflect.DeepEqual(got, want) {
		t.Errorf("script-src = %v, want the first declaration %v", got, want)
	}
	if len(p.Duplicates) != 1 || p.Duplicates[0] != "script-src" {
		t.Errorf("duplicates = %v, want [script-src]", p.Duplicates)
	}
}

func TestParseRecordsUnknownDeprecatedAndEmpty(t *testing.T) {
	p := Parse("frobnicate-src 'self'; block-all-mixed-content; img-src", false)
	if len(p.Unknown) != 1 || p.Unknown[0] != "frobnicate-src" {
		t.Errorf("unknown = %v", p.Unknown)
	}
	if len(p.Deprecated) != 1 || p.Deprecated[0] != "block-all-mixed-content" {
		t.Errorf("deprecated = %v", p.Deprecated)
	}
	if len(p.Empty) != 1 || p.Empty[0] != "img-src" {
		t.Errorf("empty = %v", p.Empty)
	}
}

func TestEffectiveFallsBackToDefaultSrc(t *testing.T) {
	p := Parse("default-src 'self'", false)

	v, ok := p.Effective("script-src")
	if !ok || !reflect.DeepEqual(v, []string{"'self'"}) {
		t.Errorf("script-src should fall back to default-src, got %v %v", v, ok)
	}
	if got := p.EffectiveSource("script-src"); got != "default-src" {
		t.Errorf("EffectiveSource = %q, want default-src", got)
	}
	// base-uri and frame-ancestors never fall back.
	if _, ok := p.Effective("base-uri"); ok {
		t.Error("base-uri must not inherit from default-src")
	}
	if _, ok := p.Effective("frame-ancestors"); ok {
		t.Error("frame-ancestors must not inherit from default-src")
	}
	if got := p.EffectiveSource("frame-ancestors"); got != "" {
		t.Errorf("EffectiveSource(frame-ancestors) = %q, want empty", got)
	}
}

func TestEffectivePrefersScriptSrcOverDefaultSrcForElem(t *testing.T) {
	p := Parse("default-src 'none'; script-src 'self'", false)
	v, ok := p.Effective("script-src-elem")
	if !ok || !reflect.DeepEqual(v, []string{"'self'"}) {
		t.Errorf("script-src-elem = %v %v, want script-src", v, ok)
	}
	if got := p.EffectiveSource("script-src-elem"); got != "script-src" {
		t.Errorf("EffectiveSource = %q", got)
	}

	q := Parse("default-src 'none'; style-src 'self'", false)
	if got := q.EffectiveSource("style-src-attr"); got != "style-src" {
		t.Errorf("EffectiveSource(style-src-attr) = %q, want style-src", got)
	}
}

func TestEffectiveWithNoMatchAtAll(t *testing.T) {
	p := Parse("frame-ancestors 'none'", false)
	if _, ok := p.Effective("script-src"); ok {
		t.Error("script-src should not resolve without default-src")
	}
	if got := p.EffectiveSource("script-src-elem"); got != "" {
		t.Errorf("EffectiveSource = %q, want empty", got)
	}
}

func TestWildcards(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"'self' https://a.example", nil},
		{"* 'self'", []string{"*"}},
		{"https: data:", []string{"https:", "data:"}},
		{"'self' blob:", []string{"blob:"}},
		{"*.example.com", nil}, // a subdomain wildcard is not a scheme wildcard
	}
	for _, c := range cases {
		p := Parse("script-src "+c.in, false)
		if got := Wildcards(p.Values("script-src")); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Wildcards(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSubdomainWildcards(t *testing.T) {
	p := Parse("script-src *.example.com https://a.test *", false)
	if got, want := SubdomainWildcards(p.Values("script-src")), []string{"*.example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("= %v, want %v", got, want)
	}
}

func TestHostsStripsSchemePortAndPath(t *testing.T) {
	p := Parse("script-src 'self' https://cdn.example.com:8443/path http://a.test data: 'nonce-x' *", false)
	want := []string{"cdn.example.com", "a.test"}
	if got := Hosts(p.Values("script-src")); !reflect.DeepEqual(got, want) {
		t.Errorf("Hosts = %v, want %v", got, want)
	}
}

func TestIsNone(t *testing.T) {
	if !IsNone([]string{"'none'"}) {
		t.Error("'none' should be none")
	}
	if IsNone([]string{"'none'", "'self'"}) {
		t.Error("a list with more than 'none' is not none")
	}
	if IsNone(nil) {
		t.Error("an empty list is not 'none'")
	}
}

func TestDirectiveNamesIsSorted(t *testing.T) {
	p := Parse("script-src 'self'; base-uri 'none'; default-src 'self'", false)
	want := []string{"base-uri", "default-src", "script-src"}
	if got := p.DirectiveNames(); !reflect.DeepEqual(got, want) {
		t.Errorf("= %v, want %v", got, want)
	}
}

func TestLookupBypass(t *testing.T) {
	if _, ok := LookupBypass("ajax.googleapis.com"); !ok {
		t.Error("ajax.googleapis.com should be a known bypass host")
	}
	if _, ok := LookupBypass("*.googleapis.com"); !ok {
		t.Error("a subdomain wildcard covering a bypass host should match")
	}
	if _, ok := LookupBypass("static.example.com"); ok {
		t.Error("an unrelated host should not match")
	}
	if BypassListUpdated() == "" {
		t.Error("the bypass list should declare when it was updated")
	}
	if len(BypassHosts()) == 0 {
		t.Error("the bypass list should not be empty")
	}
}
