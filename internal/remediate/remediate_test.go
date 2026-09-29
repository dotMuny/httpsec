package remediate

import (
	"strings"
	"testing"

	"github.com/dotMuny/httpsec/internal/finding"
)

// TestEveryFindingHasRemediationForEveryServer is the guard the project
// promises: adding a finding without a fix for all four servers must fail the
// build, not ship a report that says "this is broken" and nothing else.
func TestEveryFindingHasRemediationForEveryServer(t *testing.T) {
	for _, id := range finding.CatalogIDs() {
		m, _ := finding.Lookup(id)
		snip, ok := Lookup(m.Remediation)
		if !ok {
			t.Errorf("%s references remediation key %q, which does not exist in data/remediation.json", id, m.Remediation)
			continue
		}
		for _, server := range Servers {
			if strings.TrimSpace(snip.For(server)) == "" {
				t.Errorf("%s (key %q) has no %s configuration", id, m.Remediation, server)
			}
		}
		if strings.TrimSpace(snip.Summary) == "" {
			t.Errorf("remediation key %q has no summary", m.Remediation)
		}
	}
}

func TestNoOrphanRemediationKeys(t *testing.T) {
	used := map[string]bool{}
	for _, id := range finding.CatalogIDs() {
		m, _ := finding.Lookup(id)
		used[m.Remediation] = true
	}
	for _, key := range Keys() {
		if !used[key] {
			t.Errorf("remediation key %q is not referenced by any finding", key)
		}
	}
}

func TestEveryServerHasATitle(t *testing.T) {
	for _, s := range Servers {
		if ServerTitles[s] == "" {
			t.Errorf("server %s has no display title", s)
		}
	}
}

func TestValidServer(t *testing.T) {
	for _, s := range []string{"nginx", "NGINX", "apache", "caddy", "cdn"} {
		if !ValidServer(s) {
			t.Errorf("%s should be a valid server", s)
		}
	}
	if ValidServer("iis") {
		t.Error("iis is not supported and should not validate")
	}
}

func TestSnippetForUnknownServer(t *testing.T) {
	s, ok := Lookup("hsts")
	if !ok {
		t.Fatal("the hsts key should exist")
	}
	if s.For("iis") != "" {
		t.Error("an unsupported server should return nothing")
	}
	if s.For("cloudflare") == "" {
		t.Error("cloudflare should be an alias for cdn")
	}
}

func TestPlanGroupsFindingsByKey(t *testing.T) {
	fs := []finding.Finding{
		finding.New("hsts.missing", ""),
		finding.New("hsts.no-subdomains", ""),
		finding.New("nosniff.missing", ""),
		finding.New("hsts.ok", ""), // a pass must not produce a block
	}
	blocks, err := Plan(fs, "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want 2 (the two HSTS findings share a key)", len(blocks))
	}
	if blocks[0].Key != "hsts" || len(blocks[0].Findings) != 2 {
		t.Errorf("first block = %+v", blocks[0])
	}
	if blocks[1].Key != "nosniff" {
		t.Errorf("second block = %s", blocks[1].Key)
	}
}

func TestPlanRejectsUnknownServer(t *testing.T) {
	if _, err := Plan(nil, "iis"); err == nil {
		t.Fatal("an unknown server should be an error")
	}
}

func TestRender(t *testing.T) {
	out, err := Render([]finding.Finding{finding.New("hsts.missing", "")}, "nginx")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Strict-Transport-Security", "max-age=31536000", "httpsec remediation for Nginx"} {
		if !strings.Contains(out, want) {
			t.Errorf("output should contain %q:\n%s", want, out)
		}
	}
}

func TestRenderWithNothingToFix(t *testing.T) {
	out, err := Render([]finding.Finding{finding.New("hsts.ok", "")}, "caddy")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "nothing to change") {
		t.Errorf("output = %q", out)
	}
}

func TestRenderEveryServerForEveryKey(t *testing.T) {
	var all []finding.Finding
	for _, id := range finding.CatalogIDs() {
		m, _ := finding.Lookup(id)
		if m.Severity.IsProblem() {
			all = append(all, finding.New(id, ""))
		}
	}
	for _, server := range Servers {
		out, err := Render(all, server)
		if err != nil {
			t.Fatalf("%s: %v", server, err)
		}
		if len(out) < 1000 {
			t.Errorf("%s: output is suspiciously short (%d bytes)", server, len(out))
		}
	}
}
