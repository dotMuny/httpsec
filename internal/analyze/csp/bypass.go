package csp

import (
	"encoding/json"
	"strings"

	"github.com/dotMuny/httpsec/data"
)

// BypassHost is a host that weakens any policy allowlisting it, because it
// serves JavaScript an attacker can influence: JSONP endpoints, arbitrary npm
// or GitHub content, or an AngularJS build that turns HTML injection back
// into script execution.
type BypassHost struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

type bypassFile struct {
	SchemaVersion int          `json:"schema_version"`
	Updated       string       `json:"updated"`
	Source        string       `json:"source"`
	Hosts         []BypassHost `json:"hosts"`
}

var bypassList bypassFile

func init() {
	if err := json.Unmarshal(data.CSPBypass, &bypassList); err != nil {
		panic("csp: cannot parse embedded csp-bypass.json: " + err.Error())
	}
}

// BypassListUpdated is the date the embedded bypass list was last refreshed.
func BypassListUpdated() string { return bypassList.Updated }

// BypassHosts returns the embedded list.
func BypassHosts() []BypassHost { return append([]BypassHost(nil), bypassList.Hosts...) }

// LookupBypass reports whether a CSP host source covers a host known to be
// bypassable. A source of *.googleapis.com counts, because it covers
// www.googleapis.com.
func LookupBypass(source string) (BypassHost, bool) {
	s := strings.ToLower(strings.TrimSuffix(source, "."))
	for _, b := range bypassList.Hosts {
		switch {
		case s == b.Host:
			return b, true
		case strings.HasPrefix(s, "*."):
			suffix := s[1:] // ".googleapis.com"
			if strings.HasSuffix(b.Host, suffix) {
				return b, true
			}
		}
	}
	return BypassHost{}, false
}
