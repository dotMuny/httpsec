package tlsconf

import (
	"strings"
	"testing"
	"time"

	"github.com/dotMuny/httpsec/internal/finding"
	"github.com/dotMuny/httpsec/internal/probe"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

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

// modern is a TLSInfo describing a well-configured host, which the tests then
// break one attribute at a time.
func modern() *probe.TLSInfo {
	return &probe.TLSInfo{
		ServerName: "a.test",
		Versions: []probe.VersionResult{
			{Version: "TLS 1.0"},
			{Version: "TLS 1.1"},
			{Version: "TLS 1.2", Supported: true, Suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			{Version: "TLS 1.3", Supported: true, Suite: "TLS_AES_128_GCM_SHA256"},
		},
		Suites: []probe.SuiteResult{
			{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ForwardSecrecy: true, AEAD: true, KeyExchange: "ECDHE", Cipher: "AES-GCM", Bits: 128},
		},
		TLS13Suite:          "TLS_AES_128_GCM_SHA256",
		Preference:          "server",
		ChainLength:         2,
		ChainComplete:       true,
		VerifiedChainLength: 3,
		HostnameMatch:       true,
		SCTCount:            3,
		OCSPStapled:         true,
		OCSPStatus:          "good",
		ALPN:                []string{"h2", "http/1.1"},
		Resumption:          "ticket",
		SecureRenegotiation: true,
		Chain: []probe.CertInfo{{
			Subject:            "CN=a.test",
			Issuer:             "CN=Test CA",
			NotBefore:          now.AddDate(0, -1, 0),
			NotAfter:           now.AddDate(0, 2, 0),
			DNSNames:           []string{"a.test"},
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			KeyBits:            2048,
			SCTCount:           3,
			OCSPServers:        []string{"http://ocsp.test"},
		}},
	}
}

func TestNilInfo(t *testing.T) {
	if fs := Analyze("a.test", nil, now); fs != nil {
		t.Errorf("= %v, want nil", ids(fs))
	}
}

func TestNoVersionSupported(t *testing.T) {
	info := &probe.TLSInfo{Versions: []probe.VersionResult{
		{Version: "TLS 1.2", Error: "connection refused"},
		{Version: "TLS 1.3", Error: "connection refused"},
	}}
	fs := Analyze("a.test", info, now)
	if len(fs) != 1 || fs[0].ID != "tls.handshake.failed" {
		t.Fatalf("= %v, want only tls.handshake.failed", ids(fs))
	}
	if !strings.Contains(fs[0].Evidence, "refused") {
		t.Errorf("evidence should list the per-version errors: %q", fs[0].Evidence)
	}
}

func TestModernHostHasNoProblems(t *testing.T) {
	for _, f := range Analyze("a.test", modern(), now) {
		if f.Severity.IsProblem() {
			t.Errorf("unexpected problem %s: %s", f.ID, f.Detail)
		}
	}
}

func TestDeprecatedVersions(t *testing.T) {
	info := modern()
	info.Versions[0].Supported = true
	info.Versions[1].Supported = true
	fs := Analyze("a.test", info, now)
	for _, want := range []string{"tls.version.tls10", "tls.version.tls11"} {
		if !has(fs, want) {
			t.Errorf("want %s, got %v", want, ids(fs))
		}
	}
	if has(fs, "tls.version.ok") {
		t.Error("the version control must not also pass")
	}
}

func TestMissingModernVersions(t *testing.T) {
	info := modern()
	info.Versions[2].Supported = false
	info.Versions[3].Supported = false
	info.Versions[1].Supported = true
	fs := Analyze("a.test", info, now)
	for _, want := range []string{"tls.version.no-tls12", "tls.version.no-tls13"} {
		if !has(fs, want) {
			t.Errorf("want %s, got %v", want, ids(fs))
		}
	}
}

func TestInsecureSuites(t *testing.T) {
	info := modern()
	info.Suites = append(info.Suites,
		probe.SuiteResult{Name: "TLS_RSA_WITH_RC4_128_SHA", Insecure: true, InsecureReason: "RC4 is broken", Cipher: "RC4"},
		probe.SuiteResult{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", KeyExchange: "RSA", Cipher: "AES-CBC"},
	)
	fs := Analyze("a.test", info, now)
	for _, want := range []string{"tls.cipher.insecure", "tls.cipher.no-forward-secrecy", "tls.cipher.cbc"} {
		if !has(fs, want) {
			t.Errorf("want %s, got %v", want, ids(fs))
		}
	}
	if has(fs, "tls.cipher.ok") {
		t.Error("the cipher control must not also pass")
	}
}

func TestClientCipherPreference(t *testing.T) {
	info := modern()
	info.Preference = "client"
	fs := Analyze("a.test", info, now)
	if !has(fs, "tls.cipher.client-preference") {
		t.Errorf("want tls.cipher.client-preference, got %v", ids(fs))
	}

	info.Preference = "unknown"
	fs = Analyze("a.test", info, now)
	if has(fs, "tls.cipher.client-preference") || has(fs, "tls.cipher.server-preference") {
		t.Errorf("an undetermined preference should produce neither finding: %v", ids(fs))
	}
}

func TestTLS13OnlyServerPassesTheCipherControl(t *testing.T) {
	info := modern()
	info.Suites = nil
	info.Versions[2].Supported = false
	fs := Analyze("a.test", info, now)
	if !has(fs, "tls.cipher.ok") {
		t.Errorf("a 1.3-only server has nothing weak to offer, got %v", ids(fs))
	}
}

func TestCertificateExpiry(t *testing.T) {
	info := modern()
	info.Chain[0].NotAfter = now.AddDate(0, 0, -1)
	if !has(Analyze("a.test", info, now), "tls.cert.expired") {
		t.Error("an expired certificate should be reported")
	}

	info = modern()
	info.Chain[0].NotBefore = now.AddDate(0, 0, 5)
	if !has(Analyze("a.test", info, now), "tls.cert.not-yet-valid") {
		t.Error("a future notBefore should be reported")
	}

	info = modern()
	info.Chain[0].NotAfter = now.AddDate(0, 0, 10)
	if !has(Analyze("a.test", info, now), "tls.cert.expiring-soon") {
		t.Error("a certificate expiring in 10 days should be reported")
	}

	info = modern()
	info.Chain[0].NotAfter = now.AddDate(0, 0, 45)
	if has(Analyze("a.test", info, now), "tls.cert.expiring-soon") {
		t.Error("45 days away is not soon")
	}
}

func TestCertificateTrustProblems(t *testing.T) {
	info := modern()
	info.HostnameMatch = false
	if !has(Analyze("a.test", info, now), "tls.cert.hostname-mismatch") {
		t.Error("a hostname mismatch should be reported")
	}

	info = modern()
	info.SelfSigned = true
	info.ChainComplete = false
	info.VerifyError = "x509: certificate signed by unknown authority"
	fs := Analyze("a.test", info, now)
	if !has(fs, "tls.cert.self-signed") {
		t.Errorf("want tls.cert.self-signed, got %v", ids(fs))
	}
	if has(fs, "tls.cert.untrusted-chain") {
		t.Error("self-signed is the more specific finding and should not double up")
	}

	info = modern()
	info.ChainComplete = false
	info.VerifyError = "x509: certificate signed by unknown authority"
	if !has(Analyze("a.test", info, now), "tls.cert.untrusted-chain") {
		t.Error("an unverifiable chain should be reported")
	}

	// The probe clears VerifyError when the chain only verified after an AIA
	// fetch, which is what distinguishes an incomplete chain from a bad one.
	info = modern()
	info.ChainComplete = false
	info.ChainLength = 1
	if !has(Analyze("a.test", info, now), "tls.cert.incomplete-chain") {
		t.Error("a chain completed via AIA should be reported as incomplete")
	}
}

func TestCertificateCryptographyProblems(t *testing.T) {
	info := modern()
	info.Chain[0].SignatureAlgorithm = "SHA1-RSA"
	if !has(Analyze("a.test", info, now), "tls.cert.weak-signature") {
		t.Error("a SHA-1 signature should be reported")
	}

	info = modern()
	info.Chain[0].KeyBits = 1024
	if !has(Analyze("a.test", info, now), "tls.cert.weak-key") {
		t.Error("a 1024-bit RSA key should be reported")
	}

	info = modern()
	info.Chain[0].PublicKeyAlgorithm = "ECDSA"
	info.Chain[0].KeyBits = 224
	if !has(Analyze("a.test", info, now), "tls.cert.weak-key") {
		t.Error("a 224-bit ECDSA key should be reported")
	}

	info = modern()
	info.Chain[0].PublicKeyAlgorithm = "ECDSA"
	info.Chain[0].KeyBits = 256
	if has(Analyze("a.test", info, now), "tls.cert.weak-key") {
		t.Error("P-256 is fine")
	}

	info = modern()
	info.Chain[0].NotBefore = now.AddDate(-3, 0, 0)
	if !has(Analyze("a.test", info, now), "tls.cert.long-validity") {
		t.Error("a multi-year certificate should be reported")
	}

	info = modern()
	info.SCTCount = 0
	info.Chain[0].SCTCount = 0
	if !has(Analyze("a.test", info, now), "tls.cert.no-sct") {
		t.Error("a certificate with no SCTs should be reported")
	}

	info = modern()
	info.OCSPStatus = "revoked"
	if !has(Analyze("a.test", info, now), "tls.cert.revoked") {
		t.Error("a revoked certificate should be reported")
	}
}

func TestNoChainProducesNoCertificateFindings(t *testing.T) {
	info := modern()
	info.Chain = nil
	fs := Analyze("a.test", info, now)
	for _, f := range fs {
		if strings.HasPrefix(f.ID, "tls.cert.") {
			t.Errorf("unexpected certificate finding with no chain: %s", f.ID)
		}
	}
}

func TestOCSP(t *testing.T) {
	info := modern()
	info.OCSPStapled = false
	info.OCSPChecked = true
	info.OCSPStatus = "good"
	fs := Analyze("a.test", info, now)
	f := mustFind(t, fs, "tls.ocsp.no-stapling")
	if !strings.Contains(f.Detail, "good") {
		t.Errorf("the direct query result should be reported: %q", f.Detail)
	}

	info = modern()
	info.OCSPStapled = false
	info.OCSPChecked = false
	info.Chain[0].OCSPServers = nil
	f = mustFind(t, Analyze("a.test", info, now), "tls.ocsp.no-stapling")
	if !strings.Contains(f.Detail, "no OCSP responder") {
		t.Errorf("a certificate with no responder should say so: %q", f.Detail)
	}
}

func TestExtras(t *testing.T) {
	info := modern()
	info.ALPN = []string{"http/1.1"}
	if !has(Analyze("a.test", info, now), "tls.alpn.no-h2") {
		t.Error("a server without h2 should be reported")
	}

	info = modern()
	info.ALPN = nil
	if !has(Analyze("a.test", info, now), "tls.alpn.no-h2") {
		t.Error("no ALPN at all should be reported")
	}

	info = modern()
	info.Compression = true
	if !has(Analyze("a.test", info, now), "tls.compression.enabled") {
		t.Error("TLS compression should be reported")
	}

	info = modern()
	info.SecureRenegotiation = false
	if !has(Analyze("a.test", info, now), "tls.renegotiation.insecure") {
		t.Error("missing RFC 5746 support should be reported")
	}

	info = modern()
	info.Resumption = "none"
	if !has(Analyze("a.test", info, now), "tls.resumption.none") {
		t.Error("no resumption should be reported")
	}

	info = modern()
	info.Resumption = "unknown"
	fs := Analyze("a.test", info, now)
	if has(fs, "tls.resumption.none") || has(fs, "tls.resumption.ok") {
		t.Errorf("an undetermined resumption state should produce neither finding: %v", ids(fs))
	}
}

func mustFind(t *testing.T, fs []finding.Finding, id string) finding.Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("want %s, got %v", id, ids(fs))
	return finding.Finding{}
}
