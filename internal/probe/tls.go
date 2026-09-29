package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// tlsVersions is the set httpsec probes, in ascending order. SSLv3 and below
// are not probed: crypto/tls cannot speak them at all, and a tool that cannot
// test something should not imply that it did. See docs/decisions.md.
var tlsVersions = []struct {
	name string
	id   uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

func tlsVersionName(v uint16) string {
	for _, tv := range tlsVersions {
		if tv.id == v {
			return tv.name
		}
	}
	return fmt.Sprintf("unknown (0x%04x)", v)
}

// ctPoisonOID identifies the embedded Signed Certificate Timestamp list.
var sctExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// probeTLS runs every TLS-level probe against host:port.
func probeTLS(ctx context.Context, host, port string, opts Options) *TLSInfo {
	info := &TLSInfo{ServerName: host, Preference: "unknown", Resumption: "unknown"}
	addr := net.JoinHostPort(host, port)

	// 1. One handshake per protocol version.
	var best *tls.ConnectionState
	for _, v := range tlsVersions {
		res := VersionResult{Version: v.name}
		cfg := baseTLSConfig(host)
		cfg.MinVersion, cfg.MaxVersion = v.id, v.id
		if v.id < tls.VersionTLS13 {
			cfg.CipherSuites = allSuiteIDsFor(v.id)
		}
		st, err := handshake(ctx, addr, cfg, opts)
		if err != nil {
			res.Error = trimError(err)
		} else {
			res.Supported = true
			res.Suite = tls.CipherSuiteName(st.CipherSuite)
			if best == nil || st.Version > best.Version {
				best = st
			}
		}
		info.Versions = append(info.Versions, res)
	}

	if best == nil {
		info.Errors = append(info.Errors, "no TLS version completed a handshake")
		return info
	}

	if best.Version == tls.VersionTLS13 {
		info.TLS13Suite = tls.CipherSuiteName(best.CipherSuite)
	}

	// 2. Enumerate the TLS 1.2 cipher suites the server will accept.
	if info.Supports("TLS 1.2") {
		info.Suites = enumerateSuites(ctx, addr, host, opts)
		info.Preference = detectPreference(ctx, addr, host, info.Suites, opts)
	}

	// 3. Certificate chain, taken from the strongest handshake that succeeded.
	describeChain(ctx, info, best, host, opts)

	// 4. Revocation.
	checkOCSP(ctx, info, best, opts)

	// 5. ALPN, resumption, and the raw-ClientHello probe for renegotiation
	//    and compression, neither of which crypto/tls exposes.
	info.ALPN, info.NegotiatedALPN = probeALPN(ctx, addr, host, opts)
	info.Resumption = probeResumption(ctx, addr, host, opts)
	if reneg, comp, ok := rawHelloProbe(ctx, addr, host, opts); ok {
		info.SecureRenegotiation = reneg
		info.Compression = comp
	} else {
		// Renegotiation does not exist in TLS 1.3, so a 1.3-only server is
		// not vulnerable and the check simply does not apply.
		info.SecureRenegotiation = true
	}
	return info
}

func baseTLSConfig(host string) *tls.Config {
	// The chain is verified explicitly in describeChain. Skipping verification
	// here is what allows httpsec to report on a broken certificate rather
	// than failing to connect to it.
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // G402: verification is performed explicitly, see describeChain
		MinVersion:         tls.VersionTLS10,
	}
}

func handshake(ctx context.Context, addr string, cfg *tls.Config, opts Options) (*tls.ConnectionState, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if err := opts.Limiter.Wait(ctx, host); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: opts.Timeout}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("unexpected connection type %T", conn)
	}
	st := tc.ConnectionState()
	return &st, nil
}

// allSuiteIDsFor returns every suite crypto/tls can offer for a version,
// including the insecure ones: httpsec needs to ask for RC4 and 3DES in order
// to find out whether the server would agree to them.
func allSuiteIDsFor(version uint16) []uint16 {
	var ids []uint16
	for _, cs := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		for _, v := range cs.SupportedVersions {
			if v == version {
				ids = append(ids, cs.ID)
				break
			}
		}
	}
	return ids
}

func enumerateSuites(ctx context.Context, addr, host string, opts Options) []SuiteResult {
	var out []SuiteResult
	for _, id := range allSuiteIDsFor(tls.VersionTLS12) {
		cfg := baseTLSConfig(host)
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		cfg.CipherSuites = []uint16{id}
		st, err := handshake(ctx, addr, cfg, opts)
		if err != nil || st.CipherSuite != id {
			continue
		}
		out = append(out, classifySuite(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// detectPreference offers the same two suites in both orders. A server that
// enforces its own order answers with the same suite twice.
func detectPreference(ctx context.Context, addr, host string, suites []SuiteResult, opts Options) string {
	if len(suites) < 2 {
		return "unknown"
	}
	a, b := suites[0].ID, suites[len(suites)-1].ID

	cfg1 := baseTLSConfig(host)
	cfg1.MinVersion, cfg1.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	cfg1.CipherSuites = []uint16{a, b}
	st1, err1 := handshake(ctx, addr, cfg1, opts)

	cfg2 := baseTLSConfig(host)
	cfg2.MinVersion, cfg2.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	cfg2.CipherSuites = []uint16{b, a}
	st2, err2 := handshake(ctx, addr, cfg2, opts)

	if err1 != nil || err2 != nil {
		return "unknown"
	}
	if st1.CipherSuite == st2.CipherSuite {
		return "server"
	}
	return "client"
}

func classifySuite(id uint16) SuiteResult {
	name := tls.CipherSuiteName(id)
	r := SuiteResult{Name: name, ID: id}

	switch {
	case strings.Contains(name, "ECDHE"):
		r.KeyExchange, r.ForwardSecrecy = "ECDHE", true
	case strings.Contains(name, "DHE"):
		r.KeyExchange, r.ForwardSecrecy = "DHE", true
	case strings.HasPrefix(name, "TLS_AES"), strings.HasPrefix(name, "TLS_CHACHA20"):
		r.KeyExchange, r.ForwardSecrecy = "TLS 1.3", true
	default:
		r.KeyExchange = "RSA"
	}

	switch {
	case strings.Contains(name, "GCM"):
		r.Cipher, r.AEAD = "AES-GCM", true
	case strings.Contains(name, "CHACHA20"):
		r.Cipher, r.AEAD = "ChaCha20-Poly1305", true
	case strings.Contains(name, "CBC"):
		r.Cipher = "AES-CBC"
	case strings.Contains(name, "RC4"):
		r.Cipher = "RC4"
	case strings.Contains(name, "3DES"):
		r.Cipher = "3DES"
	default:
		r.Cipher = "unknown"
	}

	switch {
	case strings.Contains(name, "256"):
		r.Bits = 256
	case strings.Contains(name, "128"):
		r.Bits = 128
	case strings.Contains(name, "3DES"):
		r.Bits = 112
	case strings.Contains(name, "RC4"):
		r.Bits = 128
	}

	switch {
	case strings.Contains(name, "RC4"):
		r.Insecure, r.InsecureReason = true, "RC4 keystream biases allow plaintext recovery (RFC 7465)"
	case strings.Contains(name, "3DES"):
		r.Insecure, r.InsecureReason = true, "64-bit block size allows the Sweet32 birthday attack"
	case strings.Contains(name, "NULL"):
		r.Insecure, r.InsecureReason = true, "no encryption at all"
	case strings.Contains(name, "EXPORT"):
		r.Insecure, r.InsecureReason = true, "deliberately weakened export-grade key sizes"
	case strings.Contains(name, "_anon_"):
		r.Insecure, r.InsecureReason = true, "anonymous key exchange provides no authentication"
	}
	return r
}

func describeChain(ctx context.Context, info *TLSInfo, st *tls.ConnectionState, host string, opts Options) {
	if len(st.PeerCertificates) == 0 {
		info.Errors = append(info.Errors, "server presented no certificate")
		return
	}
	leaf := st.PeerCertificates[0]
	info.ChainLength = len(st.PeerCertificates)

	for _, c := range st.PeerCertificates {
		info.Chain = append(info.Chain, describeCert(c))
	}
	info.SCTCount = info.Chain[0].SCTCount + len(st.SignedCertificateTimestamps)
	info.SelfSigned = info.Chain[0].SelfSigned
	info.HostnameMatch = leaf.VerifyHostname(host) == nil

	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}

	// The hostname and the expiry dates are checked separately and reported
	// as their own findings, so chain verification here asks one question
	// only: does this chain reach a trusted root? Folding the three together
	// would report a valid certificate served on the wrong host as an
	// untrusted chain, which is a different and much more alarming claim.
	verify := func(pool *x509.CertPool) ([][]*x509.Certificate, error) {
		return leaf.Verify(x509.VerifyOptions{
			Intermediates: pool,
			Roots:         opts.RootCAs,
			CurrentTime:   trustCheckTime(leaf),
		})
	}

	chains, err := verify(inter)
	if err == nil {
		info.ChainComplete = true
		if len(chains) > 0 {
			info.VerifiedChainLength = len(chains[0])
		}
		return
	}
	info.VerifyError = err.Error()

	// A chain that fails only because the server did not send the
	// intermediate is a different, much milder problem than an untrusted
	// chain. Fetching the issuer over AIA tells the two apart.
	if fetched := fetchAIAIssuers(ctx, st.PeerCertificates, opts); len(fetched) > 0 {
		for _, c := range fetched {
			inter.AddCert(c)
		}
		if chains, err2 := verify(inter); err2 == nil {
			info.ChainComplete = false
			info.VerifyError = ""
			if len(chains) > 0 {
				info.VerifiedChainLength = len(chains[0])
			}
			return
		}
	}
}

// trustCheckTime returns an instant inside the leaf's validity window, so
// that an expired certificate still gets a meaningful answer to "would this
// chain have been trusted?". Expiry itself is reported by the analyser.
func trustCheckTime(leaf *x509.Certificate) time.Time {
	now := time.Now()
	if now.After(leaf.NotBefore) && now.Before(leaf.NotAfter) {
		return now
	}
	if leaf.NotAfter.After(leaf.NotBefore) {
		return leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	}
	return now
}

func describeCert(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.Raw)
	ci := CertInfo{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialNumber:       c.SerialNumber.String(),
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		DNSNames:           c.DNSNames,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		IsCA:               c.IsCA,
		OCSPServers:        c.OCSPServer,
		SHA256Fingerprint:  hex.EncodeToString(sum[:]),
		SelfSigned:         isSelfSigned(c),
	}
	for _, ip := range c.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.KeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		ci.KeyBits = pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		ci.KeyBits = 256
	}
	for _, ext := range c.Extensions {
		if ext.Id.Equal(sctExtensionOID) {
			ci.SCTCount = countSCTs(ext.Value)
		}
	}
	return ci
}

// isSelfSigned reports whether a certificate signed itself.
//
// x509.Certificate.CheckSignatureFrom is the obvious call and the wrong one:
// it also enforces basic constraints, so a self-signed leaf that is not
// marked as a CA, which is exactly what a hand-rolled certificate looks like,
// comes back as "not self-signed".
func isSelfSigned(c *x509.Certificate) bool {
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// countSCTs walks the SignedCertificateTimestampList structure far enough to
// count its entries without validating them.
func countSCTs(raw []byte) int {
	var inner []byte
	if _, err := asn1.Unmarshal(raw, &inner); err != nil {
		inner = raw
	}
	if len(inner) < 2 {
		return 0
	}
	listLen := int(inner[0])<<8 | int(inner[1])
	body := inner[2:]
	if listLen > len(body) {
		listLen = len(body)
	}
	body = body[:listLen]
	n := 0
	for len(body) >= 2 {
		l := int(body[0])<<8 | int(body[1])
		if l+2 > len(body) {
			break
		}
		body = body[2+l:]
		n++
	}
	return n
}

// fetchAIAIssuers downloads the issuing certificates named in the Authority
// Information Access extension. These requests go to the CA, not to the
// target, and are the only way to tell an incomplete chain from an untrusted
// one.
func fetchAIAIssuers(ctx context.Context, chain []*x509.Certificate, opts Options) []*x509.Certificate {
	var out []*x509.Certificate
	cl := &http.Client{Timeout: opts.Timeout}
	for _, c := range chain {
		for _, u := range c.IssuingCertificateURL {
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				continue
			}
			reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
			if err != nil {
				cancel()
				continue
			}
			req.Header.Set("User-Agent", opts.UserAgent)
			resp, err := cl.Do(req)
			if err != nil {
				cancel()
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
			_ = resp.Body.Close()
			cancel()
			if readErr != nil {
				continue
			}
			if certs, err := x509.ParseCertificates(body); err == nil {
				out = append(out, certs...)
			}
		}
	}
	return out
}

func checkOCSP(ctx context.Context, info *TLSInfo, st *tls.ConnectionState, opts Options) {
	if len(st.OCSPResponse) > 0 {
		info.OCSPStapled = true
		info.OCSPChecked = true
		info.OCSPStatus = parseOCSPStatus(st.OCSPResponse, st.PeerCertificates)
		return
	}
	if len(st.PeerCertificates) < 2 || len(st.PeerCertificates[0].OCSPServer) == 0 {
		return
	}
	leaf, issuer := st.PeerCertificates[0], st.PeerCertificates[1]
	req, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, leaf.OCSPServer[0], strings.NewReader(string(req)))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("User-Agent", opts.UserAgent)

	cl := &http.Client{Timeout: opts.Timeout}
	resp, err := cl.Do(httpReq)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return
	}
	info.OCSPChecked = true
	info.OCSPStatus = parseOCSPStatus(body, st.PeerCertificates)
}

func parseOCSPStatus(raw []byte, chain []*x509.Certificate) string {
	var issuer *x509.Certificate
	if len(chain) > 1 {
		issuer = chain[1]
	}
	r, err := ocsp.ParseResponse(raw, issuer)
	if err != nil {
		return "unparseable"
	}
	switch r.Status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	default:
		return "unknown"
	}
}

func probeALPN(ctx context.Context, addr, host string, opts Options) ([]string, string) {
	var advertised []string
	negotiated := ""
	for _, proto := range []string{"h2", "http/1.1"} {
		cfg := baseTLSConfig(host)
		cfg.NextProtos = []string{proto}
		st, err := handshake(ctx, addr, cfg, opts)
		if err != nil || st.NegotiatedProtocol != proto {
			continue
		}
		advertised = append(advertised, proto)
		if negotiated == "" {
			negotiated = proto
		}
	}
	return advertised, negotiated
}

func probeResumption(ctx context.Context, addr, host string, opts Options) string {
	cfg := baseTLSConfig(host)
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	if _, err := handshake(ctx, addr, cfg, opts); err != nil {
		return "unknown"
	}
	st, err := handshake(ctx, addr, cfg, opts)
	if err != nil {
		return "unknown"
	}
	if st.DidResume {
		return "ticket"
	}
	return "none"
}

// rawHelloProbe writes a TLS 1.2 ClientHello by hand and reads the raw
// ServerHello. crypto/tls exposes neither the renegotiation_info extension
// nor the negotiated compression method, and both are needed here: the first
// for RFC 5746, the second for CRIME.
//
// It reports (secureRenegotiation, compressionEnabled, applicable). A server
// that refuses everything below TLS 1.3 is reported as not applicable, since
// TLS 1.3 has neither renegotiation nor compression.
func rawHelloProbe(ctx context.Context, addr, host string, opts Options) (bool, bool, bool) {
	hostOnly, _, err := net.SplitHostPort(addr)
	if err != nil {
		hostOnly = addr
	}
	if err := opts.Limiter.Wait(ctx, hostOnly); err != nil {
		return false, false, false
	}
	dialCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	d := &net.Dialer{Timeout: opts.Timeout}
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, false, false
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if _, err := conn.Write(buildClientHello(host)); err != nil {
		return false, false, false
	}
	return parseServerHello(conn)
}

func buildClientHello(host string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03) // client_version = TLS 1.2
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i * 7)
	}
	body = append(body, random...)
	body = append(body, 0x00) // empty session id

	suites := []uint16{
		0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9,
		0xc013, 0xc014, 0xc009, 0xc00a,
		0x009c, 0x009d, 0x002f, 0x0035, 0x000a, 0x0005,
	}
	body = appendUint16(body, uint16(len(suites)*2))
	for _, s := range suites {
		body = appendUint16(body, s)
	}
	// Offer both null and DEFLATE compression: a server that answers with
	// DEFLATE is vulnerable to CRIME.
	body = append(body, 0x02, 0x00, 0x01)

	var ext []byte
	ext = append(ext, serverNameExtension(host)...)
	ext = append(ext, supportedGroupsExtension()...)
	ext = append(ext, ecPointFormatsExtension()...)
	ext = append(ext, signatureAlgorithmsExtension()...)
	ext = append(ext, renegotiationInfoExtension()...)
	body = appendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = appendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func appendUint16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

func extension(id uint16, payload []byte) []byte {
	out := appendUint16(nil, id)
	out = appendUint16(out, uint16(len(payload)))
	return append(out, payload...)
}

func serverNameExtension(host string) []byte {
	if net.ParseIP(host) != nil {
		return nil // SNI must not carry a literal address
	}
	name := appendUint16(nil, uint16(len(host)+3))
	name = append(name, 0x00)
	name = appendUint16(name, uint16(len(host)))
	name = append(name, host...)
	return extension(0x0000, name)
}

func supportedGroupsExtension() []byte {
	groups := []uint16{0x001d, 0x0017, 0x0018, 0x0019}
	p := appendUint16(nil, uint16(len(groups)*2))
	for _, g := range groups {
		p = appendUint16(p, g)
	}
	return extension(0x000a, p)
}

func ecPointFormatsExtension() []byte {
	return extension(0x000b, []byte{0x01, 0x00})
}

func signatureAlgorithmsExtension() []byte {
	algs := []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201}
	p := appendUint16(nil, uint16(len(algs)*2))
	for _, a := range algs {
		p = appendUint16(p, a)
	}
	return extension(0x000d, p)
}

func renegotiationInfoExtension() []byte {
	return extension(0xff01, []byte{0x00})
}

// parseServerHello reads one handshake record and extracts the compression
// method and whether renegotiation_info was echoed.
func parseServerHello(conn net.Conn) (secureReneg, compression, applicable bool) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false, false, false
	}
	if hdr[0] != 0x16 { // not a handshake record: alert, or a TLS 1.3-only server
		return false, false, false
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	if length <= 0 || length > 16384 {
		return false, false, false
	}
	rec := make([]byte, length)
	if _, err := io.ReadFull(conn, rec); err != nil {
		return false, false, false
	}
	if len(rec) < 4 || rec[0] != 0x02 { // not a ServerHello
		return false, false, false
	}
	b := rec[4:]
	if len(b) < 35 {
		return false, false, false
	}
	b = b[34:] // server_version (2) + random (32)
	sidLen := int(b[0])
	if len(b) < 1+sidLen+3 {
		return false, false, false
	}
	b = b[1+sidLen:]
	b = b[2:] // cipher_suite
	compression = b[0] != 0x00
	b = b[1:]

	if len(b) < 2 {
		// No extensions at all means no renegotiation_info.
		return false, compression, true
	}
	extLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if extLen > len(b) {
		extLen = len(b)
	}
	b = b[:extLen]
	for len(b) >= 4 {
		id := uint16(b[0])<<8 | uint16(b[1])
		l := int(b[2])<<8 | int(b[3])
		if 4+l > len(b) {
			break
		}
		if id == 0xff01 {
			secureReneg = true
		}
		b = b[4+l:]
	}
	return secureReneg, compression, true
}
