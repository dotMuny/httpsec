package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const certDir = "../../testdata/certs"

// tlsServer accepts connections, completes the handshake and closes. That is
// all the TLS probes need: httpsec never sends application data over the
// handshakes it makes.
type tlsServer struct {
	addr string
	ln   net.Listener
	wg   sync.WaitGroup
}

func startTLSServer(t *testing.T, cfg *tls.Config) *tlsServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &tlsServer{addr: ln.Addr().String(), ln: tls.NewListener(ln, cfg)}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if tc, ok := conn.(*tls.Conn); ok {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = tc.HandshakeContext(ctx)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = s.ln.Close()
		s.wg.Wait()
	})
	return s
}

func loadPair(t *testing.T, name string) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, name+".cert.pem"),
		filepath.Join(certDir, name+".key.pem"),
	)
	if err != nil {
		t.Skipf("testdata certificate %q is unavailable (%v); run scripts/gen-testdata-certs.sh", name, err)
	}
	return cert
}

func testRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(certDir, "ca.cert.pem"))
	if err != nil {
		t.Skipf("testdata CA is unavailable (%v); run scripts/gen-testdata-certs.sh", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("testdata CA is not a usable PEM bundle")
	}
	return pool
}

func probeOpts(t *testing.T) Options {
	t.Helper()
	return Options{
		Timeout:     5 * time.Second,
		TotalBudget: 60 * time.Second,
		UserAgent:   "httpsec-test",
		Limiter:     NewLimiter(0),
		RootCAs:     testRoots(t),
	}
}

func hostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestProbeTLSModernServer(t *testing.T) {
	cert := loadPair(t, "good")
	srv := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1"},
	})
	host, port := hostPort(t, srv.addr)

	info := probeTLS(context.Background(), host, port, probeOpts(t))

	if info.Supports("TLS 1.0") || info.Supports("TLS 1.1") {
		t.Error("the server refuses 1.0 and 1.1; the probe should say so")
	}
	if !info.Supports("TLS 1.2") || !info.Supports("TLS 1.3") {
		t.Errorf("1.2 and 1.3 should be accepted: %+v", info.Versions)
	}
	if len(info.Suites) != 3 {
		t.Errorf("enumerated %d suites, want 3: %+v", len(info.Suites), info.Suites)
	}
	for _, s := range info.Suites {
		if !s.AEAD || !s.ForwardSecrecy || s.Insecure {
			t.Errorf("suite %s misclassified: %+v", s.Name, s)
		}
	}
	if info.TLS13Suite == "" {
		t.Error("the negotiated TLS 1.3 suite should be recorded")
	}
	if len(info.Chain) == 0 {
		t.Fatal("the chain should have been captured")
	}
	if !info.HostnameMatch {
		t.Error("the certificate covers 127.0.0.1, so the hostname should match")
	}
	if !info.ChainComplete || info.VerifyError != "" {
		t.Errorf("the chain should verify against the test CA: complete=%v err=%q", info.ChainComplete, info.VerifyError)
	}
	if info.SelfSigned {
		t.Error("this certificate is CA-issued")
	}
	if len(info.ALPN) == 0 {
		t.Errorf("ALPN should have been negotiated, got %v", info.ALPN)
	}
	// Go's TLS implementation supports RFC 5746 and never enables compression.
	if !info.SecureRenegotiation {
		t.Error("the raw ClientHello probe should have seen renegotiation_info")
	}
	if info.Compression {
		t.Error("compression should not be negotiated")
	}
}

func TestProbeTLSLegacyServer(t *testing.T) {
	cert := loadPair(t, "good")
	var suites []uint16
	for _, cs := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		suites = append(suites, cs.ID)
	}
	srv := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: suites,
	})
	host, port := hostPort(t, srv.addr)

	info := probeTLS(context.Background(), host, port, probeOpts(t))

	if !info.Supports("TLS 1.0") || !info.Supports("TLS 1.1") {
		t.Errorf("the deprecated versions should be detected: %+v", info.Versions)
	}
	if info.Supports("TLS 1.3") {
		t.Error("the server caps at 1.2")
	}

	var sawInsecure, sawStaticRSA, sawCBC bool
	for _, s := range info.Suites {
		if s.Insecure {
			sawInsecure = true
		}
		if !s.ForwardSecrecy {
			sawStaticRSA = true
		}
		if strings.Contains(s.Name, "CBC") && !s.AEAD {
			sawCBC = true
		}
	}
	if !sawStaticRSA {
		t.Error("static-RSA suites should have been enumerated")
	}
	if !sawCBC {
		t.Error("CBC suites should have been enumerated")
	}
	if !sawInsecure {
		t.Log("no RC4/3DES suite was negotiated; this Go build may no longer implement them")
	}
	if info.Preference == "unknown" {
		t.Error("with many suites accepted the preference should be determinable")
	}
}

func TestProbeTLSCertificateProblems(t *testing.T) {
	cases := []struct {
		name  string
		cert  string
		check func(t *testing.T, info *TLSInfo)
	}{
		{
			name: "expired",
			cert: "expired",
			check: func(t *testing.T, info *TLSInfo) {
				if !info.Chain[0].NotAfter.Before(time.Now()) {
					t.Errorf("notAfter = %s, want the past", info.Chain[0].NotAfter)
				}
			},
		},
		{
			name: "self-signed",
			cert: "selfsigned",
			check: func(t *testing.T, info *TLSInfo) {
				if !info.SelfSigned {
					t.Error("SelfSigned should be set")
				}
				if info.VerifyError == "" {
					t.Error("a self-signed certificate should not verify")
				}
			},
		},
		{
			name: "wrong hostname",
			cert: "wronghost",
			check: func(t *testing.T, info *TLSInfo) {
				if info.HostnameMatch {
					t.Error("the SAN does not cover 127.0.0.1")
				}
			},
		},
		{
			name: "weak key",
			cert: "weakkey",
			check: func(t *testing.T, info *TLSInfo) {
				if info.Chain[0].KeyBits != 1024 {
					t.Errorf("key bits = %d, want 1024", info.Chain[0].KeyBits)
				}
			},
		},
		{
			name: "sha1 signature",
			cert: "sha1",
			check: func(t *testing.T, info *TLSInfo) {
				if !strings.Contains(strings.ToUpper(info.Chain[0].SignatureAlgorithm), "SHA1") {
					t.Errorf("signature = %s, want a SHA-1 algorithm", info.Chain[0].SignatureAlgorithm)
				}
			},
		},
		{
			name: "expiring soon",
			cert: "expiring",
			check: func(t *testing.T, info *TLSInfo) {
				if d := time.Until(info.Chain[0].NotAfter); d > 31*24*time.Hour {
					t.Errorf("expires in %v, want under 30 days", d)
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := loadPair(t, c.cert)
			// An expired or otherwise unusable certificate is still served;
			// it is the client that objects, which is exactly what is being
			// tested here.
			srv := startTLSServer(t, &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			})
			host, port := hostPort(t, srv.addr)

			info := probeTLS(context.Background(), host, port, probeOpts(t))
			if len(info.Chain) == 0 {
				t.Fatalf("no chain captured: %+v", info.Versions)
			}
			c.check(t, info)
		})
	}
}

func TestProbeTLSUnreachableHost(t *testing.T) {
	opts := probeOpts(t)
	opts.Timeout = 500 * time.Millisecond
	info := probeTLS(context.Background(), "127.0.0.1", "1", opts)
	for _, v := range info.Versions {
		if v.Supported {
			t.Errorf("%s should not have completed a handshake", v.Version)
		}
	}
	if len(info.Errors) == 0 {
		t.Error("the failure should be recorded")
	}
}

func TestClassifySuite(t *testing.T) {
	cases := []struct {
		id       uint16
		fs, aead bool
		kex      string
	}{
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true, true, "ECDHE"},
		{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, true, true, "ECDHE"},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, false, false, "RSA"},
		{tls.TLS_AES_128_GCM_SHA256, true, true, "TLS 1.3"},
	}
	for _, c := range cases {
		got := classifySuite(c.id)
		if got.ForwardSecrecy != c.fs || got.AEAD != c.aead || got.KeyExchange != c.kex {
			t.Errorf("%s = %+v, want fs=%v aead=%v kex=%s", got.Name, got, c.fs, c.aead, c.kex)
		}
	}

	rc4 := classifySuite(tls.TLS_RSA_WITH_RC4_128_SHA)
	if !rc4.Insecure || rc4.InsecureReason == "" {
		t.Errorf("RC4 should be flagged as insecure with a reason: %+v", rc4)
	}
	tripleDES := classifySuite(tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
	if !tripleDES.Insecure || !strings.Contains(tripleDES.InsecureReason, "Sweet32") {
		t.Errorf("3DES should cite Sweet32: %+v", tripleDES)
	}
}

func TestTLSVersionName(t *testing.T) {
	if got := tlsVersionName(tls.VersionTLS13); got != "TLS 1.3" {
		t.Errorf("= %q", got)
	}
	if got := tlsVersionName(0x9999); !strings.Contains(got, "unknown") {
		t.Errorf("= %q", got)
	}
}

func TestBuildClientHelloIsWellFormed(t *testing.T) {
	hello := buildClientHello("example.test")
	if hello[0] != 0x16 {
		t.Error("the record type should be handshake")
	}
	recordLen := int(hello[3])<<8 | int(hello[4])
	if recordLen != len(hello)-5 {
		t.Errorf("record length %d does not match the body length %d", recordLen, len(hello)-5)
	}
	if hello[5] != 0x01 {
		t.Error("the handshake type should be ClientHello")
	}
	// The SCSV signals RFC 5746 support to servers that predate the extension.
	if !containsUint16(hello, 0x00ff) {
		t.Error("the empty-renegotiation-info SCSV should be offered")
	}
}

func TestBuildClientHelloOmitsSNIForIPLiterals(t *testing.T) {
	if len(serverNameExtension("127.0.0.1")) != 0 {
		t.Error("SNI must not carry a literal IP address")
	}
	if len(serverNameExtension("a.test")) == 0 {
		t.Error("SNI should be present for a hostname")
	}
}

func containsUint16(b []byte, v uint16) bool {
	for i := 0; i+1 < len(b); i++ {
		if uint16(b[i])<<8|uint16(b[i+1]) == v {
			return true
		}
	}
	return false
}

func TestCountSCTs(t *testing.T) {
	// A SignedCertificateTimestampList with two 3-byte entries.
	raw := []byte{0x00, 0x0a, 0x00, 0x03, 1, 2, 3, 0x00, 0x03, 4, 5, 6}
	if got := countSCTs(raw); got != 2 {
		t.Errorf("= %d, want 2", got)
	}
	if got := countSCTs([]byte{0x00}); got != 0 {
		t.Errorf("a truncated list should count zero, got %d", got)
	}
	if got := countSCTs(nil); got != 0 {
		t.Errorf("= %d, want 0", got)
	}
}

func TestDetectPreferenceNeedsTwoSuites(t *testing.T) {
	if got := detectPreference(context.Background(), "127.0.0.1:1", "a.test", nil, Options{Limiter: NewLimiter(0)}); got != "unknown" {
		t.Errorf("= %q, want unknown", got)
	}
}
