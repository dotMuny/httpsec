package headers

import (
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// AnalyzeIsolation evaluates the three cross-origin isolation headers and
// says whether the document ends up crossOriginIsolated, which is the only
// state in which the strong timing and memory protections apply.
func AnalyzeIsolation(r *probe.HTTPResponse) []finding.Finding {
	var out []finding.Finding

	coop := strings.ToLower(strings.TrimSpace(r.Header("Cross-Origin-Opener-Policy")))
	coep := strings.ToLower(strings.TrimSpace(r.Header("Cross-Origin-Embedder-Policy")))
	corp := strings.ToLower(strings.TrimSpace(r.Header("Cross-Origin-Resource-Policy")))

	// COOP may carry a report-to parameter; only the first token matters.
	coopValue, _, _ := strings.Cut(coop, ";")
	coopValue = strings.TrimSpace(coopValue)
	coepValue, _, _ := strings.Cut(coep, ";")
	coepValue = strings.TrimSpace(coepValue)

	switch {
	case !r.HasHeader("Cross-Origin-Opener-Policy"):
		out = append(out, finding.New("coop.missing",
			"No Cross-Origin-Opener-Policy header, so cross-origin documents can retain a window reference to this page."))
	case coopValue == "unsafe-none":
		out = append(out, finding.New("coop.weak",
			"unsafe-none is the browser default and provides no browsing-context isolation.").WithEvidence(coop))
	default:
		out = append(out, finding.New("coop.ok", "Cross-Origin-Opener-Policy: "+coopValue).WithEvidence(coop))
	}

	isolated := (coopValue == "same-origin") && (coepValue == "require-corp" || coepValue == "credentialless")
	switch {
	case isolated:
		out = append(out, finding.New("isolation.enabled",
			"COOP is same-origin and COEP is "+coepValue+", so the document is cross-origin isolated.").
			WithEvidence("COOP: "+coop+" / COEP: "+coep))
	case r.HasHeader("Cross-Origin-Embedder-Policy"):
		out = append(out, finding.New("coep.ok", "Cross-Origin-Embedder-Policy: "+coepValue).WithEvidence(coep))
	default:
		out = append(out, finding.New("coep.missing",
			"No Cross-Origin-Embedder-Policy header, so the document is not cross-origin isolated."))
	}

	if r.HasHeader("Cross-Origin-Resource-Policy") {
		out = append(out, finding.New("corp.ok", "Cross-Origin-Resource-Policy: "+corp).WithEvidence(corp))
	} else {
		out = append(out, finding.New("corp.missing",
			"No Cross-Origin-Resource-Policy header, so other origins may embed this response."))
	}
	return out
}
