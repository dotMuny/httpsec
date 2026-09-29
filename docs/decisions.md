# Design decisions

Where two reasonable designs existed, httpsec takes the simpler one and this
file records what was discarded and why. Entries are append-only: a decision
that is later reversed gets a new entry rather than an edit.

---

## 1. The analysis layer never touches the network

**Decision.** `internal/probe` performs every network interaction and writes
its results into an `Observation`, which is plain JSON. `internal/analyze` and
everything downstream take that struct and nothing else.

**Discarded.** Analysers that fetch what they need on demand, which is shorter
to write and reads more naturally.

**Why.** The whole of the analysis, scoring and reporting layer can then be
tested against `testdata/observations/*.json`, with no network, no flakiness
and no rate limiting, and a report can be regenerated in a different format a
year later from evidence captured once. `httpsec scan --from-observation` is
this property exposed as a flag.

## 2. `Finding` lives in its own leaf package

**Decision.** The `Finding` type and the finding catalogue live in
`internal/finding`, not in `internal/analyze` as the original sketch had it.

**Discarded.** Putting the type in `internal/analyze` and moving the
orchestrator into a separate package.

**Why.** `internal/analyze` imports its per-family sub-packages, and those
sub-packages need the `Finding` type. Either the type or the orchestration had
to move; moving the type keeps the package that a reader opens first
(`internal/analyze/analyze.go`) as the one that shows the whole shape of the
analysis.

## 3. Finding metadata is data, not Go

**Decision.** Titles, severities, categories, control mappings and the "why it
matters" text live in `data/findings.json`. Go code only names IDs.

**Discarded.** A Go map of struct literals, which is less machinery.

**Why.** Three tests depend on it: every ID a finding emits exists in the
catalogue, every catalogue entry has a remediation for all four servers, and
every entry maps to a control the rubric knows about. Keeping it as data makes
those checks a data join rather than reflection over the source, and lets
someone review the wording without reading Go.

## 4. Several enforced CSP headers: evaluate the first, flag the rest

**Decision.** When a server sends more than one `Content-Security-Policy`
header, httpsec parses the first, reports `csp.multiple-policies`, and says so
in the finding.

**Discarded.** Computing the true effective policy, which is the intersection
of all of them.

**Why.** The intersection is strictly at least as strict as each policy, so
evaluating one of them can only over-report, never under-report. Multiple
enforced policies are rare and almost always accidental, and the informational
finding points the reader at the real situation. A correct intersection needs
a model of how every directive combines, which is a large amount of code for a
case that is itself a misconfiguration.

## 5. The HSTS preload list is a curated subset, and absence is never asserted

**Decision.** `data/hsts-preload.json` carries about fifty widely used domains
and declares `"complete": false`. A domain that is not in it is reported as
"not confirmed", never as "not preloaded".

**Discarded.** Embedding Chrome's full `transport_security_state_static.json`,
which has well over 100,000 entries.

**Why.** The full list would dominate the binary and go stale between
releases. A tool that cannot check something must not imply that it did, so
the finding wording and the `--explain-score` output both stay on the right
side of that line. `scripts/update-preload.sh` checks a single domain against
the live list when it matters.

## 6. robots.txt gates HTML retrieval, not the audit

**Decision.** `--respect-robots` (on by default in `batch`, off for a single
`scan`) makes httpsec consult robots.txt before downloading a page body for
mixed-content analysis. Header, TLS, redirect and `security.txt` probes are
never gated on it.

**Discarded.** Honouring robots.txt for every request, or ignoring it
entirely.

**Why.** robots.txt governs crawling. Fetching one page's headers is not
crawling, and a tool that refused to audit a site because its robots.txt
disallows `/` would be useless for exactly the sites that need auditing. But
retrieving and parsing page content is closer to crawling, and in batch mode
httpsec is walking a list of hosts it did not individually choose, so it
defaults to asking. A single scan is an operator acting on one host they
nominated, so the default is off.

## 7. SSL 3.0 and below are not probed

**Decision.** httpsec probes TLS 1.0 through 1.3 and says nothing about
earlier protocols.

**Discarded.** Reporting "SSLv3 not supported", or hand-rolling an SSLv3
handshake.

**Why.** `crypto/tls` cannot speak SSLv3 at all, so httpsec cannot tell a
server that refuses it from one it never asked. Reporting a pass for an
untested control is worse than reporting nothing. Any server still speaking
SSLv3 will fail several other controls loudly enough.

## 8. Secure renegotiation and TLS compression are detected with a hand-built ClientHello

**Decision.** `rawHelloProbe` writes a TLS 1.2 ClientHello byte by byte and
parses the ServerHello directly, to read the `renegotiation_info` extension
and the negotiated compression method.

**Discarded.** Dropping both checks, or pulling in a third-party TLS library.

**Why.** `crypto/tls` exposes neither, and both are in the requirements. The
handshake is about 120 lines and never gets past ServerHello, so it carries no
crypto of its own. A server that refuses everything below TLS 1.3 is reported
as not applicable rather than as failing, since TLS 1.3 has neither
renegotiation nor compression.

## 9. Chain trust, hostname and expiry are three separate questions

**Decision.** Chain verification runs without `DNSName` and at an instant
inside the certificate's validity window. Hostname matching uses
`VerifyHostname`, and expiry is checked by the analyser against the recorded
dates.

**Discarded.** A single `leaf.Verify` with `DNSName` and the current time,
which is the idiomatic call.

**Why.** The single call collapses three very different problems into one
error string. A perfectly good certificate served on the wrong host would be
reported as "chain does not verify against the system trust store", which
sends the reader looking for a CA problem that does not exist. This was caught
by the `wrong.host.badssl.com` and `expired.badssl.com` fixtures, which is
what that corpus is for.

## 10. Verified TLS facts are derived in `probe`, not in `analyze`

**Decision.** `SelfSigned`, `ChainComplete`, `HostnameMatch` and `VerifyError`
are computed while the connection is open and stored in the `Observation`.

**Discarded.** Storing raw DER in the `Observation` and verifying in
`internal/analyze`.

**Why.** Verification needs the system trust store, which is a property of the
machine rather than of the target, so a fixture captured on one machine would
analyse differently on another. Deriving at capture time keeps the fixtures
reproducible. The cost is that re-capturing is needed when the verification
logic changes, which is what happened for decision 9.

## 11. `CheckSignature`, not `CheckSignatureFrom`, for self-signed detection

**Decision.** A certificate is self-signed when its subject equals its issuer
and it verifies against its own public key with `CheckSignature`.

**Discarded.** `CheckSignatureFrom(c)`, which is the obvious call.

**Why.** `CheckSignatureFrom` also enforces basic constraints, so a
self-signed leaf that is not marked as a CA — which is exactly what a
hand-rolled certificate looks like — comes back as not self-signed. The
`self-signed.badssl.com` fixture caught this.

## 12. The score is a weighted fraction; critical findings cap the grade

**Decision.** Each control has a weight. A control loses a fraction of its
weight per finding, by severity, capped at its full weight. The score is
earned weight over applicable weight, out of 100. Separately, a small list of
findings caps the maximum grade regardless of the score.

**Discarded.** Mozilla Observatory's model of a fixed starting score with
absolute point deductions.

**Why.** Absolute deductions do not compose: adding a control changes every
existing score, and the arithmetic stops being explainable once deductions
interact. A weighted fraction answers "what fraction of what we checked did
this site get right", which is the question people actually ask. Caps exist
because some failures are not tradeable: a site that accepts TLS 1.0 should
not be able to buy its way back to an A with a good CSP, however good the CSP.

## 13. Controls that were not evaluated leave the calculation entirely

**Decision.** A control with no finding drops out of both the numerator and
the denominator, and is listed as "not evaluated" in `--explain-score`.

**Discarded.** Counting an unevaluated control as a failure, or as a pass.

**Why.** `--headers-only` would otherwise score every site the same way a
catastrophic TLS configuration does, and `--tls-only` the reverse. Treating
them as passes would be worse: it would invent a result. Making the exclusion
visible in the output keeps the number honest about its own scope.

## 14. Remediation is keyed by fix, not by finding

**Decision.** `data/findings.json` gives each finding a `remediation` key, and
several findings share one key. `httpsec remediate` groups by key.

**Discarded.** One snippet per finding ID.

**Why.** Eight HSTS findings all need the same `add_header` line. One snippet
per finding would mean eight copies to keep in step, and a remediation output
that repeats itself eight times. The test that every finding has a fix for all
four servers works exactly the same either way.

## 15. `X-XSS-Protection: 0` is not a finding

**Decision.** The header is reported only when it asks for the removed XSS
auditor. The value `0`, which disables it, passes silently.

**Discarded.** Reporting the header's presence regardless of value.

**Why.** Sending `0` is current OWASP guidance, and plenty of compliance
checklists still demand the header be present. Flagging the correct value
would train people to ignore the tool.

## 16. Chain completeness is decided by fetching the issuer over AIA

**Decision.** When the presented chain does not verify, httpsec follows the
Authority Information Access URLs, re-verifies, and reports
`tls.cert.incomplete-chain` rather than `tls.cert.untrusted-chain` if that
succeeds.

**Discarded.** Guessing from the chain length, or reporting a single
undifferentiated "chain problem".

**Why.** The two have completely different fixes and completely different
blast radii: a missing intermediate is invisible in browsers and fatal in
`curl`, while an untrusted root is fatal everywhere. The extra request goes to
the certificate authority, not to the target, and is the same request a
browser makes.

## 17. The HTTP transport skips certificate verification

**Decision.** The HTTP client used for header probes sets
`InsecureSkipVerify`, and `gosec`'s G402 is excluded for those two call sites
with a comment at each.

**Discarded.** Refusing to audit hosts with a broken certificate.

**Why.** A site with an expired certificate is exactly the site whose headers
someone needs to see. Verification is not skipped, it is moved: the dedicated
TLS probe performs it explicitly and every certificate problem appears in the
report.

## 18. One `data` package at the repository root

**Decision.** `data/*.json` sits at the root with a `data/data.go` that
`go:embed`s it, as the architecture sketch asked.

**Discarded.** `internal/data/`, which would keep the package unexported.

**Why.** `go:embed` cannot reach outside its own directory, so keeping the
files at `data/` requires a package there. Exporting it is a small cost for a
layout that matches the sketch and puts the auditable files where someone
would look for them.

## 19. README images are SVGs rendered from real output

**Decision.** `scripts/render-examples.sh` captures the actual ANSI bytes
httpsec writes and renders them to SVG with `scripts/ansi-to-svg.py`. The HTML
report is committed as a real file under `docs/examples/`.

**Discarded.** Screenshots, or an animated GIF of the text mode.

**Why.** A screenshot goes stale the moment the output changes and nobody
notices. Regenerating the SVGs is a make target, they are diffable, they stay
sharp, and they are guaranteed to be what the tool prints because they are
produced from its output. The HTML report is better linked than photographed:
the reader can open the real thing and click through it.

## 20. Rate limiting is a minimum interval, not a token bucket

**Decision.** `probe.Limiter` enforces a minimum gap between requests to the
same host.

**Discarded.** A token bucket with a burst allowance.

**Why.** httpsec makes a fixed, small number of requests per target. A burst
allowance would let the whole scan through instantly, which defeats the point,
and would add two more flags to explain. The gap is the behaviour the
responsible-use section promises, expressed directly.
