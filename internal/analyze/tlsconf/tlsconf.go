// Package tlsconf turns the raw TLS evidence gathered by internal/probe into
// findings. Like every other analyser it performs no network I/O: everything
// it needs is already in the Observation.
package tlsconf

import (
	"fmt"
	"strings"
	"time"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

// ExpiryWarning is how close to expiry a certificate has to be before
// httpsec reports it.
const ExpiryWarning = 30 * 24 * time.Hour

// MaxValidity is the longest validity period public CAs may issue, so
// anything longer is either a private CA or a very old certificate.
const MaxValidity = 398 * 24 * time.Hour

// weakSignatures are signature algorithms that are forgeable in practice.
var weakSignatures = map[string]string{
	"SHA1-RSA":   "SHA-1 collisions are practical (SHAttered, 2017)",
	"MD5-RSA":    "MD5 collisions have been practical since 2008",
	"DSA-SHA1":   "SHA-1 collisions are practical",
	"ECDSA-SHA1": "SHA-1 collisions are practical",
	"MD2-RSA":    "MD2 is comprehensively broken",
}

// Analyze evaluates everything TLS-related about a target.
func Analyze(host string, t *probe.TLSInfo, now time.Time) []finding.Finding {
	if t == nil {
		return nil
	}
	anySupported := false
	for _, v := range t.Versions {
		if v.Supported {
			anySupported = true
			break
		}
	}
	if !anySupported {
		return []finding.Finding{finding.New("tls.handshake.failed",
			"No TLS version between 1.0 and 1.3 completed a handshake with "+host+".").
			WithEvidence(versionEvidence(t))}
	}

	out := analyzeVersions(t)
	out = append(out, analyzeSuites(t)...)
	out = append(out, analyzeCertificate(host, t, now)...)
	out = append(out, analyzeOCSP(t)...)
	out = append(out, analyzeExtras(t)...)
	return out
}

func versionEvidence(t *probe.TLSInfo) string {
	var b strings.Builder
	for _, v := range t.Versions {
		status := "refused"
		if v.Supported {
			status = "accepted (" + v.Suite + ")"
		}
		fmt.Fprintf(&b, "%s: %s\n", v.Version, status)
	}
	return strings.TrimRight(b.String(), "\n")
}

func analyzeVersions(t *probe.TLSInfo) []finding.Finding {
	var out []finding.Finding
	ev := versionEvidence(t)
	clean := true

	if t.Supports("TLS 1.0") {
		clean = false
		out = append(out, finding.New("tls.version.tls10",
			"The server completed a TLS 1.0 handshake.").WithEvidence(ev))
	}
	if t.Supports("TLS 1.1") {
		clean = false
		out = append(out, finding.New("tls.version.tls11",
			"The server completed a TLS 1.1 handshake.").WithEvidence(ev))
	}
	if t.Tested("TLS 1.2") && !t.Supports("TLS 1.2") {
		clean = false
		out = append(out, finding.New("tls.version.no-tls12",
			"The server refused TLS 1.2.").WithEvidence(ev))
	}
	if t.Tested("TLS 1.3") && !t.Supports("TLS 1.3") {
		clean = false
		out = append(out, finding.New("tls.version.no-tls13",
			"The server refused TLS 1.3.").WithEvidence(ev))
	}
	if clean {
		out = append(out, finding.New("tls.version.ok",
			"TLS 1.2 and 1.3 are accepted; 1.0 and 1.1 are refused.").WithEvidence(ev))
	}
	return out
}

func analyzeSuites(t *probe.TLSInfo) []finding.Finding {
	if len(t.Suites) == 0 {
		if t.TLS13Suite != "" {
			return []finding.Finding{finding.New("tls.cipher.ok",
				"Only TLS 1.3 is offered, and every TLS 1.3 suite is AEAD with forward secrecy. Negotiated: "+t.TLS13Suite+".").
				WithEvidence(t.TLS13Suite)}
		}
		return nil
	}

	var out []finding.Finding
	var names, weakFS, cbc []string
	clean := true

	for _, s := range t.Suites {
		names = append(names, s.Name)
		if s.Insecure {
			clean = false
			out = append(out, finding.New("tls.cipher.insecure",
				s.Name+": "+s.InsecureReason+".").WithSubject(s.Name).WithEvidence(s.Name))
		}
		if !s.ForwardSecrecy {
			weakFS = append(weakFS, s.Name)
		}
		if !s.AEAD && !s.Insecure {
			cbc = append(cbc, s.Name)
		}
	}
	evidence := strings.Join(names, "\n")

	if len(weakFS) > 0 {
		clean = false
		out = append(out, finding.New("tls.cipher.no-forward-secrecy",
			fmt.Sprintf("%d accepted suites use static RSA key exchange: %s.", len(weakFS), strings.Join(weakFS, ", "))).
			WithEvidence(evidence))
	}
	if len(cbc) > 0 {
		clean = false
		out = append(out, finding.New("tls.cipher.cbc",
			fmt.Sprintf("%d accepted suites use CBC mode: %s.", len(cbc), strings.Join(cbc, ", "))).
			WithEvidence(evidence))
	}

	switch t.Preference {
	case "server":
		out = append(out, finding.New("tls.cipher.server-preference",
			"The server selected the same suite regardless of the order the client offered them.").WithEvidence(evidence))
	case "client":
		clean = false
		out = append(out, finding.New("tls.cipher.client-preference",
			"The server selected whichever suite the client listed first, so a weak client steers the connection.").WithEvidence(evidence))
	}

	if clean {
		out = append(out, finding.New("tls.cipher.ok",
			fmt.Sprintf("All %d accepted TLS 1.2 suites are AEAD with forward secrecy.", len(t.Suites))).WithEvidence(evidence))
	}
	return out
}

func analyzeCertificate(host string, t *probe.TLSInfo, now time.Time) []finding.Finding {
	if len(t.Chain) == 0 {
		return nil
	}
	leaf := t.Chain[0]
	ev := certEvidence(leaf)
	var out []finding.Finding
	clean := true

	switch {
	case now.Before(leaf.NotBefore):
		clean = false
		out = append(out, finding.New("tls.cert.not-yet-valid",
			"The certificate is valid from "+leaf.NotBefore.Format(time.RFC3339)+", which is in the future.").WithEvidence(ev))
	case now.After(leaf.NotAfter):
		clean = false
		out = append(out, finding.New("tls.cert.expired",
			"The certificate expired on "+leaf.NotAfter.Format(time.RFC3339)+".").WithEvidence(ev))
	case leaf.NotAfter.Sub(now) < ExpiryWarning:
		clean = false
		out = append(out, finding.New("tls.cert.expiring-soon",
			fmt.Sprintf("The certificate expires on %s, in %.0f days.",
				leaf.NotAfter.Format(time.RFC3339), leaf.NotAfter.Sub(now).Hours()/24)).WithEvidence(ev))
	}

	if !t.HostnameMatch {
		clean = false
		out = append(out, finding.New("tls.cert.hostname-mismatch",
			"No subject alternative name matches "+host+". Present: "+strings.Join(leaf.DNSNames, ", ")+".").WithEvidence(ev))
	}

	switch {
	case t.SelfSigned:
		clean = false
		out = append(out, finding.New("tls.cert.self-signed",
			"The certificate is self-signed: subject and issuer are identical and it verifies against its own key.").WithEvidence(ev))
	case !t.ChainComplete && t.VerifyError == "":
		clean = false
		out = append(out, finding.New("tls.cert.incomplete-chain",
			fmt.Sprintf("The server sent %d certificate(s). The chain only verified after httpsec fetched the issuer over AIA, so clients that do not do that will fail.", t.ChainLength)).
			WithEvidence(chainEvidence(t)))
	case t.VerifyError != "":
		clean = false
		out = append(out, finding.New("tls.cert.untrusted-chain",
			"The chain did not verify against the system trust store: "+t.VerifyError).WithEvidence(chainEvidence(t)))
	}

	if reason, weak := weakSignatures[leaf.SignatureAlgorithm]; weak {
		clean = false
		out = append(out, finding.New("tls.cert.weak-signature",
			leaf.SignatureAlgorithm+": "+reason+".").WithEvidence(ev))
	}
	if bits, weak := weakKey(leaf); weak {
		clean = false
		out = append(out, finding.New("tls.cert.weak-key",
			fmt.Sprintf("%s key of %d bits is below the current public-trust floor.", leaf.PublicKeyAlgorithm, bits)).WithEvidence(ev))
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > MaxValidity {
		clean = false
		out = append(out, finding.New("tls.cert.long-validity",
			fmt.Sprintf("The validity period is %.0f days; public CAs may not issue for more than 398.",
				leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24)).WithEvidence(ev))
	}
	if t.SCTCount == 0 && !t.SelfSigned {
		clean = false
		out = append(out, finding.New("tls.cert.no-sct",
			"No embedded Certificate Transparency SCTs were found, and none were delivered in the handshake.").WithEvidence(ev))
	}
	if t.OCSPStatus == "revoked" {
		clean = false
		out = append(out, finding.New("tls.cert.revoked",
			"The OCSP responder reports this certificate as revoked.").WithEvidence(ev))
	}

	if clean {
		out = append(out, finding.New("tls.cert.ok",
			fmt.Sprintf("Valid until %s, chain of %d verified against the system roots.",
				leaf.NotAfter.Format("2006-01-02"), t.VerifiedChainLength)).WithEvidence(ev))
	}
	return out
}

func weakKey(c probe.CertInfo) (int, bool) {
	switch {
	case strings.Contains(c.PublicKeyAlgorithm, "RSA"):
		return c.KeyBits, c.KeyBits > 0 && c.KeyBits < 2048
	case strings.Contains(c.PublicKeyAlgorithm, "ECDSA"):
		return c.KeyBits, c.KeyBits > 0 && c.KeyBits < 256
	case strings.Contains(c.PublicKeyAlgorithm, "DSA"):
		return c.KeyBits, true
	}
	return c.KeyBits, false
}

func certEvidence(c probe.CertInfo) string {
	return fmt.Sprintf("subject: %s\nissuer: %s\nvalid: %s .. %s\nsans: %s\nsignature: %s\nkey: %s %d bits\nsha256: %s",
		c.Subject, c.Issuer,
		c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339),
		strings.Join(c.DNSNames, ", "), c.SignatureAlgorithm,
		c.PublicKeyAlgorithm, c.KeyBits, c.SHA256Fingerprint)
}

func chainEvidence(t *probe.TLSInfo) string {
	var b strings.Builder
	for i, c := range t.Chain {
		fmt.Fprintf(&b, "%d. %s\n   issued by %s\n", i, c.Subject, c.Issuer)
	}
	if t.VerifyError != "" {
		fmt.Fprintf(&b, "verify error: %s", t.VerifyError)
	}
	return strings.TrimRight(b.String(), "\n")
}

func analyzeOCSP(t *probe.TLSInfo) []finding.Finding {
	if t.OCSPStapled {
		detail := "The handshake carried a stapled OCSP response"
		if t.OCSPStatus != "" {
			detail += " with status " + t.OCSPStatus
		}
		return []finding.Finding{finding.New("tls.ocsp.stapled", detail+".").WithEvidence(t.OCSPStatus)}
	}
	detail := "No stapled OCSP response was returned in the handshake."
	if t.OCSPChecked {
		detail += " A direct OCSP query returned status " + t.OCSPStatus + "."
	} else if len(t.Chain) > 0 && len(t.Chain[0].OCSPServers) == 0 {
		detail += " The certificate publishes no OCSP responder, so there is nothing to staple."
	}
	return []finding.Finding{finding.New("tls.ocsp.no-stapling", detail)}
}

func analyzeExtras(t *probe.TLSInfo) []finding.Finding {
	var out []finding.Finding

	hasH2 := false
	for _, p := range t.ALPN {
		if p == "h2" {
			hasH2 = true
		}
	}
	switch {
	case hasH2:
		out = append(out, finding.New("tls.alpn.ok",
			"ALPN negotiated: "+strings.Join(t.ALPN, ", ")+".").WithEvidence(strings.Join(t.ALPN, ", ")))
	case len(t.ALPN) > 0:
		out = append(out, finding.New("tls.alpn.no-h2",
			"ALPN offers only "+strings.Join(t.ALPN, ", ")+".").WithEvidence(strings.Join(t.ALPN, ", ")))
	default:
		out = append(out, finding.New("tls.alpn.no-h2", "The server negotiated no ALPN protocol."))
	}

	if t.Compression {
		out = append(out, finding.New("tls.compression.enabled",
			"The ServerHello selected a non-null compression method, which is the precondition for CRIME."))
	}
	if !t.SecureRenegotiation {
		out = append(out, finding.New("tls.renegotiation.insecure",
			"The ServerHello did not echo the renegotiation_info extension required by RFC 5746."))
	}

	switch t.Resumption {
	case "none":
		out = append(out, finding.New("tls.resumption.none",
			"A second handshake with the same session cache did not resume."))
	case "ticket", "session-id":
		out = append(out, finding.New("tls.resumption.ok",
			"A second handshake resumed the session via "+t.Resumption+"."))
	}
	return out
}
