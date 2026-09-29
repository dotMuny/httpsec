package headers

import (
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// AnalyzeFraming evaluates X-Frame-Options in the light of CSP
// frame-ancestors. Reporting a missing X-Frame-Options on a site that already
// sets frame-ancestors would be noise: no browser that understands
// frame-ancestors looks at X-Frame-Options at all.
func AnalyzeFraming(r *probe.HTTPResponse, hasFrameAncestors bool) []finding.Finding {
	raw := strings.TrimSpace(r.Header("X-Frame-Options"))
	present := r.HasHeader("X-Frame-Options")

	if !present {
		if hasFrameAncestors {
			return []finding.Finding{finding.New("xfo.redundant",
				"X-Frame-Options is absent, but CSP frame-ancestors is set and supersedes it in every browser that implements it.")}
		}
		return []finding.Finding{finding.New("xfo.missing",
			"Neither X-Frame-Options nor CSP frame-ancestors restricts who may frame this page.")}
	}

	value := strings.ToUpper(raw)
	switch {
	case value == "DENY", value == "SAMEORIGIN":
		if hasFrameAncestors {
			return []finding.Finding{finding.New("xfo.redundant",
				"X-Frame-Options: "+value+" is set alongside CSP frame-ancestors, which supersedes it. Keeping it only helps pre-CSP2 browsers.").WithEvidence(raw)}
		}
		return []finding.Finding{finding.New("xfo.ok", "X-Frame-Options: "+value).WithEvidence(raw)}
	case strings.HasPrefix(value, "ALLOW-FROM"):
		return []finding.Finding{finding.New("xfo.invalid",
			"ALLOW-FROM was only ever implemented by Firefox and has been removed; browsers ignore it and allow framing. Use CSP frame-ancestors instead.").WithEvidence(raw)}
	case value == "ALLOWALL":
		return []finding.Finding{finding.New("xfo.allowall",
			"ALLOWALL explicitly opts out of framing protection.").WithEvidence(raw)}
	default:
		return []finding.Finding{finding.New("xfo.invalid",
			"Unrecognised value; only DENY and SAMEORIGIN are honoured, and anything else leaves framing unrestricted.").WithEvidence(raw)}
	}
}
