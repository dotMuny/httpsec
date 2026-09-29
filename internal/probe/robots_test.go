package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRobots(t *testing.T) {
	body := `
# a comment
User-agent: *
Disallow: /private
Allow: /private/public

User-agent: httpsec
Disallow: /nope
`
	rules := parseRobots(body)
	if rules.allows("/nope") {
		t.Error("the httpsec-specific group should apply")
	}
	if !rules.allows("/private") {
		t.Error("when a specific group exists the wildcard group is ignored")
	}
}

func TestParseRobotsWildcardGroup(t *testing.T) {
	rules := parseRobots("User-agent: *\nDisallow: /private\nAllow: /private/ok\n")
	if rules.allows("/private/secret") {
		t.Error("/private/secret should be disallowed")
	}
	if !rules.allows("/private/ok") {
		t.Error("the longer Allow rule should win")
	}
	if !rules.allows("/") {
		t.Error("an unmatched path is allowed")
	}
}

func TestParseRobotsEmptyDisallowAllowsEverything(t *testing.T) {
	rules := parseRobots("User-agent: *\nDisallow:\n")
	if !rules.allows("/anything") {
		t.Error("a bare Disallow means allow all")
	}
}

func TestParseRobotsGroupedUserAgents(t *testing.T) {
	rules := parseRobots("User-agent: googlebot\nUser-agent: httpsec\nDisallow: /x\n")
	if rules.allows("/x") {
		t.Error("a shared group should apply to every named agent")
	}
}

func TestParseRobotsJunk(t *testing.T) {
	rules := parseRobots("this is not robots.txt\n\n:::\nSitemap: https://a.test/s.xml\n")
	if !rules.allows("/anything") {
		t.Error("unparseable content should not block anything")
	}
}

func TestRobotsAllowsIsConsultedOnlyWhenAsked(t *testing.T) {
	var robotsHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			robotsHits++
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
			return
		}
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	opts := testOptions()
	c := newHTTPClient(opts)

	// Without --respect-robots the body is retrieved as normal.
	r := c.get(context.Background(), srv.URL+"/", opts, true)
	if r.Body == "" {
		t.Error("robots.txt should not be consulted unless asked for")
	}
	if robotsHits != 0 {
		t.Errorf("robots.txt was fetched %d times without being asked for", robotsHits)
	}

	opts.RespectRobots = true
	r = c.get(context.Background(), srv.URL+"/", opts, true)
	if r.Body != "" {
		t.Error("a disallowed path should not have its body retrieved")
	}
	if !strings.Contains(r.Error, "robots.txt") {
		t.Errorf("the reason should be recorded: %q", r.Error)
	}
	if r.StatusCode != 200 {
		t.Error("the headers should still be recorded: robots.txt governs content retrieval, not the header audit")
	}

	// The result is cached, so a second call does not refetch robots.txt.
	before := robotsHits
	c.get(context.Background(), srv.URL+"/other", opts, true)
	if robotsHits != before {
		t.Error("robots.txt should be fetched once per origin")
	}
}

func TestRobotsMissingFileAllowsEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	opts := testOptions()
	opts.RespectRobots = true
	r := newHTTPClient(opts).get(context.Background(), srv.URL+"/", opts, true)
	if r.Body == "" {
		t.Error("an absent robots.txt allows everything")
	}
}
