// Package probe performs every network interaction httpsec makes and records
// the result in an Observation.
//
// The rule that shapes this package: probe is the only place that touches the
// network, and internal/analyze never does. Everything an analyser could
// possibly want must end up in the Observation, which is plain JSON-
// serialisable data. That is what makes the whole analysis layer testable
// against recorded fixtures with no network and no flakiness.
package probe

import (
	"net/http"
	"strings"
	"time"
)

// ObservationSchemaVersion is bumped when the Observation layout changes in a
// way that invalidates recorded fixtures.
const ObservationSchemaVersion = 1

// Observation is everything httpsec learned about one target.
type Observation struct {
	SchemaVersion int       `json:"schema_version"`
	Tool          string    `json:"tool"`
	Target        string    `json:"target"`
	Host          string    `json:"host"`
	Port          string    `json:"port"`
	StartedAt     time.Time `json:"started_at"`
	DurationMs    int64     `json:"duration_ms"`

	// HTTPS is the response to the main https:// request.
	HTTPS *HTTPResponse `json:"https,omitempty"`
	// PlainHTTP records what happened when the same path was requested over
	// http://, which is how the redirect analysis gets its evidence.
	PlainHTTP *HTTPResponse `json:"plain_http,omitempty"`
	// CORS is the result of an Origin-reflection probe.
	CORS *CORSProbe `json:"cors,omitempty"`
	// Options is the response to an OPTIONS request.
	Options *HTTPResponse `json:"options,omitempty"`
	// Trace is the response to a TRACE request.
	Trace *HTTPResponse `json:"trace,omitempty"`
	// SecurityTxt is the response to /.well-known/security.txt.
	SecurityTxt *HTTPResponse `json:"security_txt,omitempty"`
	// TLS holds the results of the per-version and per-suite handshakes.
	TLS *TLSInfo `json:"tls,omitempty"`

	// Skipped names the probe groups that were not run, so the analyser can
	// tell "clean" apart from "not looked at".
	Skipped []string `json:"skipped,omitempty"`
	// Errors collects non-fatal failures, one human-readable line each.
	Errors []string `json:"errors,omitempty"`
}

// Skip marks a probe group as not attempted.
func (o *Observation) Skip(what string) {
	for _, s := range o.Skipped {
		if s == what {
			return
		}
	}
	o.Skipped = append(o.Skipped, what)
}

// WasSkipped reports whether a probe group was deliberately not run.
func (o *Observation) WasSkipped(what string) bool {
	for _, s := range o.Skipped {
		if s == what {
			return true
		}
	}
	return false
}

// Probe group names used with Skip.
const (
	GroupHTTP      = "http"
	GroupTLS       = "tls"
	GroupCORS      = "cors"
	GroupMethods   = "methods"
	GroupWellKnown = "well-known"
	GroupBody      = "body"
)

// HTTPResponse is one recorded HTTP exchange, including the redirect chain
// that led to it.
type HTTPResponse struct {
	RequestURL    string              `json:"request_url"`
	FinalURL      string              `json:"final_url"`
	Method        string              `json:"method"`
	StatusCode    int                 `json:"status_code"`
	Proto         string              `json:"proto"`
	Headers       map[string][]string `json:"headers"`
	Body          string              `json:"body,omitempty"`
	BodyTruncated bool                `json:"body_truncated,omitempty"`
	BodyBytes     int                 `json:"body_bytes"`
	Redirects     []Hop               `json:"redirects,omitempty"`
	TLSVersion    string              `json:"tls_version,omitempty"`
	Error         string              `json:"error,omitempty"`
	DurationMs    int64               `json:"duration_ms"`
}

// Hop is one step of a redirect chain.
type Hop struct {
	URL        string `json:"url"`
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location"`
}

// Header returns the first value of a header, or "".
func (r *HTTPResponse) Header(name string) string {
	if r == nil {
		return ""
	}
	v := r.HeaderValues(name)
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// HeaderValues returns every value of a header. Lookup is case-insensitive
// because the fixtures are hand-editable and cannot be trusted to use the
// canonical spelling.
func (r *HTTPResponse) HeaderValues(name string) []string {
	if r == nil || r.Headers == nil {
		return nil
	}
	if v, ok := r.Headers[http.CanonicalHeaderKey(name)]; ok {
		return v
	}
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

// HasHeader reports whether the header was present at all, even if empty.
func (r *HTTPResponse) HasHeader(name string) bool {
	return r.HeaderValues(name) != nil
}

// CORSProbe records what the server answered when sent a foreign Origin.
type CORSProbe struct {
	SentOrigin       string `json:"sent_origin"`
	SentNullOrigin   bool   `json:"sent_null_origin"`
	AllowOrigin      string `json:"allow_origin"`
	AllowCredentials string `json:"allow_credentials"`
	AllowMethods     string `json:"allow_methods"`
	AllowHeaders     string `json:"allow_headers"`
	ExposeHeaders    string `json:"expose_headers"`
	Vary             string `json:"vary"`
	NullAllowOrigin  string `json:"null_allow_origin"`
	NullAllowCreds   string `json:"null_allow_credentials"`
	Error            string `json:"error,omitempty"`
}

// TLSInfo is the union of everything the TLS probes learned.
type TLSInfo struct {
	ServerName          string          `json:"server_name"`
	Versions            []VersionResult `json:"versions"`
	Suites              []SuiteResult   `json:"suites,omitempty"`
	TLS13Suite          string          `json:"tls13_suite,omitempty"`
	Preference          string          `json:"preference"` // server | client | unknown
	Chain               []CertInfo      `json:"chain,omitempty"`
	ChainLength         int             `json:"chain_length"`
	ChainComplete       bool            `json:"chain_complete"`
	VerifiedChainLength int             `json:"verified_chain_length"`
	HostnameMatch       bool            `json:"hostname_match"`
	SelfSigned          bool            `json:"self_signed"`
	VerifyError         string          `json:"verify_error,omitempty"`
	OCSPStapled         bool            `json:"ocsp_stapled"`
	OCSPStatus          string          `json:"ocsp_status,omitempty"`
	OCSPChecked         bool            `json:"ocsp_checked"`
	ALPN                []string        `json:"alpn,omitempty"`
	NegotiatedALPN      string          `json:"negotiated_alpn,omitempty"`
	SCTCount            int             `json:"sct_count"`
	Resumption          string          `json:"resumption"` // ticket | session-id | none | unknown
	Compression         bool            `json:"compression"`
	SecureRenegotiation bool            `json:"secure_renegotiation"`
	Errors              []string        `json:"errors,omitempty"`
}

// VersionResult is the outcome of one per-version handshake attempt.
type VersionResult struct {
	Version   string `json:"version"`
	Supported bool   `json:"supported"`
	Suite     string `json:"suite,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Supports reports whether a named TLS version was accepted.
func (t *TLSInfo) Supports(version string) bool {
	if t == nil {
		return false
	}
	for _, v := range t.Versions {
		if v.Version == version {
			return v.Supported
		}
	}
	return false
}

// Tested reports whether a named TLS version was probed at all.
func (t *TLSInfo) Tested(version string) bool {
	if t == nil {
		return false
	}
	for _, v := range t.Versions {
		if v.Version == version {
			return true
		}
	}
	return false
}

// SuiteResult describes one accepted TLS 1.2 cipher suite.
type SuiteResult struct {
	Name           string `json:"name"`
	ID             uint16 `json:"id"`
	ForwardSecrecy bool   `json:"forward_secrecy"`
	AEAD           bool   `json:"aead"`
	KeyExchange    string `json:"key_exchange"`
	Cipher         string `json:"cipher"`
	Bits           int    `json:"bits"`
	Insecure       bool   `json:"insecure"`
	InsecureReason string `json:"insecure_reason,omitempty"`
}

// CertInfo is one certificate of the chain as the server presented it.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	KeyBits            int       `json:"key_bits"`
	IsCA               bool      `json:"is_ca"`
	SelfSigned         bool      `json:"self_signed"`
	SCTCount           int       `json:"sct_count"`
	OCSPServers        []string  `json:"ocsp_servers,omitempty"`
	SHA256Fingerprint  string    `json:"sha256_fingerprint"`
}
