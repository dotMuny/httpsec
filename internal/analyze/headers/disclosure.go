package headers

import (
	"regexp"
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// versionPattern matches a dotted version number inside a header value, which
// is the part that turns a product name into a CVE query.
var versionPattern = regexp.MustCompile(`\d+\.\d+(\.\d+)*`)

// AnalyzeDisclosure reports headers that advertise software and versions.
func AnalyzeDisclosure(r *probe.HTTPResponse) []finding.Finding {
	var out []finding.Finding
	found := false

	if r.HasHeader("Server") {
		v := strings.TrimSpace(r.Header("Server"))
		if m := versionPattern.FindString(v); m != "" {
			found = true
			out = append(out, finding.New("info.server-version",
				"Server advertises version "+m+".").WithSubject("Server").WithEvidence(v))
		} else if v != "" {
			out = append(out, finding.New("info.server-present",
				"Server names the product but not a version.").WithSubject("Server").WithEvidence(v))
		}
	}

	for _, h := range []struct{ name, id string }{
		{"X-Powered-By", "info.x-powered-by"},
		{"X-AspNet-Version", "info.aspnet-version"},
		{"X-AspNetMvc-Version", "info.aspnet-version"},
		{"X-Generator", "info.x-generator"},
	} {
		if !r.HasHeader(h.name) {
			continue
		}
		found = true
		v := strings.TrimSpace(r.Header(h.name))
		out = append(out, finding.New(h.id, h.name+": "+v).WithSubject(h.name).WithEvidence(v))
	}

	if !found {
		out = append(out, finding.New("info.none", "No header advertises a software version."))
	}
	return out
}

// AnalyzeLegacyHeaders reports headers that browsers have withdrawn and that
// are, at best, inert.
func AnalyzeLegacyHeaders(r *probe.HTTPResponse) []finding.Finding {
	var out []finding.Finding

	if r.HasHeader("X-XSS-Protection") {
		v := strings.TrimSpace(r.Header("X-XSS-Protection"))
		// "0" is the modern recommendation: it disables the removed auditor
		// rather than asking for it, so it is not a finding.
		if !strings.HasPrefix(v, "0") {
			out = append(out, finding.New("legacy.x-xss-protection",
				"X-XSS-Protection: "+v+" asks for a filter every major browser has removed. Send 0, or nothing.").
				WithSubject("X-XSS-Protection").WithEvidence(v))
		}
	}
	for _, name := range []string{"Public-Key-Pins", "Public-Key-Pins-Report-Only"} {
		if r.HasHeader(name) {
			out = append(out, finding.New("legacy.public-key-pins",
				name+" is present. HPKP was withdrawn after repeated outages caused by bad pins.").
				WithSubject(name).WithEvidence(strings.TrimSpace(r.Header(name))))
		}
	}
	if r.HasHeader("Expect-CT") {
		out = append(out, finding.New("legacy.expect-ct",
			"Expect-CT is present. Certificate Transparency is now enforced unconditionally and the header is ignored.").
			WithSubject("Expect-CT").WithEvidence(strings.TrimSpace(r.Header("Expect-CT"))))
	}

	if len(out) == 0 {
		out = append(out, finding.New("legacy.none", "No withdrawn security headers are sent."))
	}
	return out
}
