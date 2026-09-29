package headers

import (
	"strings"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// AnalyzeCORS evaluates the CORS response to a synthetic foreign Origin.
//
// Presence of Access-Control-Allow-Origin is not itself a problem. What
// matters is the combination: a reflected origin plus credentials makes every
// authenticated response readable by any site the victim visits.
func AnalyzeCORS(c *probe.CORSProbe) []finding.Finding {
	if c == nil || c.Error != "" {
		return nil
	}

	allow := strings.TrimSpace(c.AllowOrigin)
	creds := strings.EqualFold(strings.TrimSpace(c.AllowCredentials), "true")
	reflected := allow != "" && strings.EqualFold(allow, c.SentOrigin)
	varyOrigin := containsToken(c.Vary, "origin")

	var out []finding.Finding

	switch {
	case allow == "*" && creds:
		out = append(out, finding.New("cors.wildcard-with-credentials",
			"Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true. Browsers reject that combination, which means the CORS layer was configured without testing it, and any variant that echoes the origin instead is fully exploitable.").
			WithEvidence("Access-Control-Allow-Origin: "+allow+" / Access-Control-Allow-Credentials: "+c.AllowCredentials))
	case reflected && creds:
		out = append(out, finding.New("cors.reflects-origin-with-credentials",
			"The server echoed the probe origin "+c.SentOrigin+" and set Access-Control-Allow-Credentials: true.").
			WithEvidence("Access-Control-Allow-Origin: "+allow+" / Access-Control-Allow-Credentials: "+c.AllowCredentials))
	case reflected:
		out = append(out, finding.New("cors.reflects-origin",
			"The server echoed the probe origin "+c.SentOrigin+" back in Access-Control-Allow-Origin.").
			WithEvidence("Access-Control-Allow-Origin: "+allow))
	case allow == "*":
		out = append(out, finding.New("cors.wildcard",
			"Access-Control-Allow-Origin is * without credentials, which is correct for genuinely public resources.").
			WithEvidence("Access-Control-Allow-Origin: *"))
	}

	if strings.EqualFold(strings.TrimSpace(c.NullAllowOrigin), "null") {
		detail := "The server allowed Origin: null."
		if strings.EqualFold(strings.TrimSpace(c.NullAllowCreds), "true") {
			detail += " Credentials are allowed with it, so any sandboxed iframe can read authenticated responses."
		}
		out = append(out, finding.New("cors.null-origin-allowed", detail).
			WithEvidence("Access-Control-Allow-Origin: null"))
	}

	if reflected && !varyOrigin {
		out = append(out, finding.New("cors.missing-vary-origin",
			"Access-Control-Allow-Origin depends on the request but Vary does not include Origin, so a shared cache may serve one origin's allow header to another.").
			WithEvidence("Vary: "+c.Vary))
	}

	if len(out) == 0 {
		detail := "No Access-Control-Allow-Origin was returned for a foreign origin."
		if allow != "" {
			detail = "Access-Control-Allow-Origin is " + allow + ", which does not match the probe origin."
		}
		out = append(out, finding.New("cors.ok", detail))
	}
	return out
}

func containsToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}
