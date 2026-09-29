// Package data holds the embedded data files that drive httpsec: the finding
// catalogue, the scoring rubric, the remediation snippets and the reference
// lists. Keeping them as data rather than as Go literals is deliberate: the
// rubric in particular has to be auditable by someone who does not read Go.
package data

import _ "embed"

// Findings is the catalogue of every finding httpsec can emit, keyed by ID.
//
//go:embed findings.json
var Findings []byte

// Rubric is the scoring rubric: control weights, severity penalties, grade
// caps and grade thresholds.
//
//go:embed rubric.json
var Rubric []byte

// Remediation maps a remediation key to a configuration snippet per server.
//
//go:embed remediation.json
var Remediation []byte

// CSPBypass lists hosts that are known to serve attacker-influenceable
// JavaScript and therefore weaken any CSP that allowlists them.
//
//go:embed csp-bypass.json
var CSPBypass []byte

// HSTSPreload is a curated subset of the Chrome HSTS preload list.
//
//go:embed hsts-preload.json
var HSTSPreload []byte
