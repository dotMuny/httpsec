package version

import (
	"strings"
	"testing"
)

func TestUserAgentIsIdentifiable(t *testing.T) {
	ua := UserAgent()
	if !strings.HasPrefix(ua, "httpsec/") {
		t.Errorf("= %q, want a httpsec/ prefix", ua)
	}
	// An administrator who finds this in their logs has to be able to look it
	// up without guessing.
	if !strings.Contains(ua, RepoURL) {
		t.Errorf("= %q, want the project URL", ua)
	}
	if strings.ContainsAny(ua, "\r\n") {
		t.Error("the User-Agent must not contain line breaks")
	}
}

func TestStringCarriesBuildIdentity(t *testing.T) {
	s := String()
	for _, want := range []string{"httpsec", Version, Commit, Date} {
		if !strings.Contains(s, want) {
			t.Errorf("%q should contain %q", s, want)
		}
	}
}
