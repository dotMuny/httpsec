# The httpsec rubric

This document is generated from `data/rubric.json` and `data/findings.json`.
Regenerate it with `make rubric-doc` after changing either file.

Rubric **httpsec default rubric v1.0.0**, schema version 1.

## How the score is calculated

1. Every control carries a **weight**. The weights below add up to
   **142**, but the absolute number does not matter: the score is a ratio.
2. A control starts with its full weight and loses a fraction of it for each
   finding against it, according to the finding's severity:

| severity | fraction of the control's weight lost |
|---|---:|
| critical | 1.00 |
| high | 0.80 |
| medium | 0.50 |
| low | 0.25 |
| info | 0.00 |
| pass | 0.00 |

   Penalties accumulate — three insecure cookies cost more than one — but a
   control can never lose more than its own weight.
3. A control with **no finding at all was not evaluated**. It leaves the
   calculation entirely: out of the numerator and out of the denominator. This
   is what makes `--headers-only` and `--tls-only` score honestly instead of
   punishing a site for what was not looked at.
4. The score is `earned weight / applicable weight × 100`, rounded.
5. The score maps to a letter through the grade bands.
6. Finally, a short list of findings **caps** the grade. A cap never changes
   the score; it limits the letter the score is allowed to buy.

`httpsec scan --explain-score` prints this calculation for a real target,
control by control. `httpsec rubric --caps` prints the table below from the
binary.

## Grade bands

| grade | score |
|---|---:|
| A+ | ≥ 95 |
| A | ≥ 90 |
| B+ | ≥ 85 |
| B | ≥ 80 |
| C+ | ≥ 75 |
| C | ≥ 70 |
| D+ | ≥ 65 |
| D | ≥ 60 |
| F | ≥ 0 |

## Grade caps

Some failures are not tradeable against anything else. A site that accepts
TLS 1.0 should not reach an A on the strength of a good CSP, however good the
CSP is. These findings cap the grade regardless of the score, and the
strictest applicable cap wins.

| finding | caps the grade at | why |
|---|:-:|---|
| `tls.handshake.failed` | **F** | The host does not complete a TLS handshake at all. |
| `tls.cert.expired` | **F** | An expired certificate breaks the site for every visitor. |
| `tls.cert.not-yet-valid` | **F** | A certificate outside its validity window is rejected by clients. |
| `tls.cert.hostname-mismatch` | **F** | A certificate that does not cover the hostname authenticates nothing. |
| `tls.cert.self-signed` | **F** | A self-signed certificate chains to no trusted root. |
| `tls.cert.untrusted-chain` | **F** | The chain does not verify against the system trust store. |
| `tls.cert.revoked` | **F** | A revoked certificate must be replaced immediately. |
| `tls.cert.weak-signature` | **D** | SHA-1 and MD5 signatures are forgeable in practice. |
| `cors.reflects-origin-with-credentials` | **D** | Any website can read this origin's authenticated responses. |
| `cors.wildcard-with-credentials` | **D** | The CORS layer is configured to expose credentialed responses to any origin. |
| `redirect.no-https` | **D** | Content served over plain HTTP can be read and rewritten in transit. |
| `tls.cipher.insecure` | **C** | A cipher suite that is broken in practice is accepted. |
| `tls.compression.enabled` | **C** | TLS compression enables the CRIME attack. |
| `tls.version.tls10` | **C** | TLS 1.0 is deprecated by RFC 8996. |
| `tls.version.tls11` | **B** | TLS 1.1 is deprecated by RFC 8996. |

## Controls

Every control, its weight, and the findings that can move it. A finding marked
*pass* is what the control looks like when it is satisfied.

### TLS and certificates — 37 of 142 points

#### `tls.versions` — weight 12

TLS protocol versions.

| finding | severity | what it means |
|---|---|---|
| `tls.handshake.failed` | critical | No TLS version tested could complete a handshake, so the host offers no usable HTTPS or blocked the probe. |
| `tls.version.no-tls12` | high | TLS 1.2 is the compatibility floor for the current web. |
| `tls.version.no-tls13` | low | TLS 1.3 removes every legacy cipher construction, encrypts more of the handshake and cuts a round trip. |
| `tls.version.ok` | pass | The server speaks TLS 1.2 and/or 1.3 and refuses the deprecated versions. |
| `tls.version.tls10` | critical | TLS 1.0 has been deprecated by RFC 8996 and is disabled in every current browser. |
| `tls.version.tls11` | high | TLS 1.1 is deprecated by RFC 8996 and relies on MD5/SHA-1 in its handshake signatures. |

#### `tls.certificate` — weight 12

Certificate and chain.

| finding | severity | what it means |
|---|---|---|
| `tls.cert.expired` | critical | Every browser shows a full-page interstitial. |
| `tls.cert.expiring-soon` | medium | Renewal automation fails quietly more often than it fails loudly. |
| `tls.cert.hostname-mismatch` | critical | No SAN entry matches the host, so clients cannot verify they are talking to the right server. |
| `tls.cert.incomplete-chain` | medium | Browsers often paper over a missing intermediate with AIA fetching or a cached copy. |
| `tls.cert.long-validity` | low | Long-lived certificates widen the window in which a compromised key stays usable and are no longer issued by public CAs. |
| `tls.cert.no-sct` | low | Chrome requires CT for publicly trusted certificates. |
| `tls.cert.not-yet-valid` | critical | The notBefore date is in the future, so clients reject the certificate. |
| `tls.cert.ok` | pass | The chain verifies, the hostname matches and the certificate is well within its validity window. |
| `tls.cert.revoked` | critical | The issuing CA has withdrawn this certificate, which normally means the key was compromised or mis-issued. |
| `tls.cert.self-signed` | critical | A self-signed certificate chains to no trusted root, so it authenticates nothing to a normal client. |
| `tls.cert.untrusted-chain` | critical | Clients will refuse the connection. |
| `tls.cert.weak-key` | high | RSA below 2048 bits and ECDSA below 256 bits are below the current floor for public trust and are rejected by modern clients. |
| `tls.cert.weak-signature` | critical | SHA-1 and MD5 collisions are practical and have been demonstrated against real certificate issuance. |

#### `tls.ciphers` — weight 8

Cipher suite selection.

| finding | severity | what it means |
|---|---|---|
| `tls.cipher.cbc` | low | CBC with MAC-then-encrypt has produced a decade of padding-oracle and timing attacks (Lucky13 and successors). |
| `tls.cipher.client-preference` | low | When the client picks, a downgraded or hostile client can steer the connection to the weakest mutually supported suite. |
| `tls.cipher.insecure` | critical | RC4, 3DES, NULL, EXPORT and anonymous suites are broken in practice, not just in theory. |
| `tls.cipher.no-forward-secrecy` | high | Static-RSA key exchange means a single future compromise of the private key decrypts every session ever recorded. |
| `tls.cipher.ok` | pass | All accepted TLS 1.2 suites are AEAD with forward secrecy. |
| `tls.cipher.server-preference` | pass | The server, not the client, decides which suite is used. |

#### `tls.extras` — weight 3

TLS protocol hardening.

| finding | severity | what it means |
|---|---|---|
| `tls.alpn.no-h2` | info | HTTP/2 is a performance and connection-management improvement rather than a security control, but its absence usually indicates dated server configuration. |
| `tls.alpn.ok` | pass | ALPN negotiation offers HTTP/2. |
| `tls.compression.enabled` | high | TLS-level compression allows the CRIME attack, which recovers secrets such as session cookies from the compressed ciphertext length. |
| `tls.renegotiation.insecure` | high | Without RFC 5746 the server is open to the TLS renegotiation prefix-injection attack, where an attacker prepends their own request to the victim's authenticated session. |
| `tls.resumption.none` | info | Resumption is a latency optimisation. |
| `tls.resumption.ok` | pass | Returning clients can resume without a full handshake. |

#### `tls.ocsp` — weight 2

OCSP stapling.

| finding | severity | what it means |
|---|---|---|
| `tls.ocsp.no-stapling` | low | Without stapling the client either skips revocation checking or leaks which site it is visiting to the CA, and pays a round trip for it. |
| `tls.ocsp.stapled` | pass | The server provides a fresh revocation proof in the handshake. |

### Security headers — 42 of 142 points

#### `hsts` — weight 10

HTTP Strict Transport Security.

| finding | severity | what it means |
|---|---|---|
| `hsts.malformed` | medium | A header the browser cannot parse (missing or non-numeric max-age) is discarded, so the site behaves as if HSTS were never deployed. |
| `hsts.max-age-low` | medium | A short max-age shrinks the window in which a returning visitor is protected, and 31536000 (one year) is required for the preload list. |
| `hsts.max-age-zero` | high | max-age=0 actively tells browsers to forget the HSTS entry for this host. |
| `hsts.missing` | high | Without HSTS the first request of every session can be downgraded to plain HTTP by an on-path attacker, and the redirect to HTTPS happens too late to protect the cookies already sent. |
| `hsts.no-preload` | info | Preloading removes the trust-on-first-use gap entirely. |
| `hsts.no-subdomains` | low | Without includeSubDomains an attacker can serve plain HTTP on any subdomain and set cookies scoped to the parent domain, which undermines the protected origin. |
| `hsts.ok` | pass | A long max-age with includeSubDomains is enforced. |
| `hsts.over-http` | low | Browsers must ignore HSTS headers received over a non-secure transport. |
| `hsts.preloaded` | pass | Browsers refuse plain HTTP for this host before the first request is ever made. |

#### `cors` — weight 8

CORS configuration.

| finding | severity | what it means |
|---|---|---|
| `cors.missing-vary-origin` | low | When Access-Control-Allow-Origin depends on the request, a cache without Vary: Origin can hand one origin's allow header to another origin's request. |
| `cors.null-origin-allowed` | high | Any sandboxed iframe, including one an attacker embeds in their own page, sends Origin: null. |
| `cors.ok` | pass | The server does not expose credentialed responses to arbitrary origins. |
| `cors.reflects-origin` | medium | Reflecting any origin defeats the point of an allowlist. |
| `cors.reflects-origin-with-credentials` | critical | Any site the victim visits can read authenticated responses from this origin, including CSRF tokens and personal data. |
| `cors.wildcard` | info | A wildcard without credentials is the correct configuration for genuinely public resources. |
| `cors.wildcard-with-credentials` | critical | Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is rejected by browsers, but it is a reliable sign the CORS layer is misconfigured, and any server-side variant that echoes the origin instead makes every authenticated response readable by any website the victim visits. |

#### `nosniff` — weight 4

MIME sniffing is disabled.

| finding | severity | what it means |
|---|---|---|
| `nosniff.invalid` | medium | nosniff is the only defined value. |
| `nosniff.missing` | medium | Without nosniff, browsers may MIME-sniff a user-uploaded file as HTML or JavaScript and execute it in your origin. |
| `nosniff.ok` | pass | MIME sniffing is disabled. |

#### `referrer-policy` — weight 4

Referrer leakage is controlled.

| finding | severity | what it means |
|---|---|---|
| `referrer-policy.leaky` | medium | unsafe-url and no-referrer-when-downgrade send path and query to cross-origin destinations. |
| `referrer-policy.missing` | medium | Browser defaults differ. |
| `referrer-policy.ok` | pass | Third parties receive at most the origin, never the full URL. |
| `referrer-policy.unknown` | low | An unknown token is ignored and the browser default applies, so the header does nothing. |

#### `xfo` — weight 3

Legacy framing protection.

| finding | severity | what it means |
|---|---|---|
| `xfo.allowall` | medium | The page opts out of framing protection, so a hostile site can overlay it and harvest clicks. |
| `xfo.invalid` | low | ALLOW-FROM was never implemented outside Firefox and is now removed; any unrecognised value makes browsers fall back to allowing framing. |
| `xfo.missing` | low | With neither X-Frame-Options nor CSP frame-ancestors the page can be framed by any site, which enables clickjacking. |
| `xfo.ok` | pass | Legacy clients are protected from clickjacking. |
| `xfo.redundant` | info | Every browser that supports frame-ancestors ignores X-Frame-Options when both are present. |

#### `permissions-policy` — weight 3

Powerful features are restricted.

| finding | severity | what it means |
|---|---|---|
| `permissions-policy.legacy-feature-policy` | info | Feature-Policy was renamed to Permissions-Policy and uses a different syntax. |
| `permissions-policy.missing` | low | Powerful features stay available to the document and, in some cases, to embedded third-party frames. |
| `permissions-policy.ok` | pass | Camera, microphone, geolocation and payment are switched off for this document. |
| `permissions-policy.open-features` | low | Features the policy does not name keep their default allowlist. |

#### `coop` — weight 3

Cross-origin opener isolation.

| finding | severity | what it means |
|---|---|---|
| `coop.missing` | low | Without COOP a page you open, or that opens you, keeps a window reference across origins. |
| `coop.ok` | pass | Cross-origin documents cannot hold a usable window reference to this page. |
| `coop.weak` | low | unsafe-none is the default and provides no browsing-context isolation. |

#### `legacy-headers` — weight 3

No withdrawn security headers.

| finding | severity | what it means |
|---|---|---|
| `legacy.expect-ct` | low | Certificate Transparency is now mandatory and enforced unconditionally, so Expect-CT is obsolete and ignored. |
| `legacy.none` | pass | The response carries no withdrawn or counterproductive headers. |
| `legacy.public-key-pins` | medium | HPKP was withdrawn after repeated incidents where a bad pin bricked a domain for the whole max-age. |
| `legacy.x-xss-protection` | low | The XSS auditor was removed from every major browser because its filtering introduced information leaks and could itself be used to disable legitimate scripts. |

#### `coep` — weight 2

Cross-origin embedder policy.

| finding | severity | what it means |
|---|---|---|
| `coep.missing` | info | COEP is only needed if you want crossOriginIsolated (SharedArrayBuffer, precise timers). |
| `coep.ok` | pass | Cross-origin subresources must opt in to being embedded. |
| `isolation.enabled` | pass | COOP same-origin plus COEP require-corp means the strongest browser-side isolation is active. |

#### `corp` — weight 2

Cross-origin resource policy.

| finding | severity | what it means |
|---|---|---|
| `corp.missing` | info | CORP tells the browser who may embed this response. |
| `corp.ok` | pass | Embedding of this response by other origins is restricted. |

### Content Security Policy — 35 of 142 points

#### `csp.present` — weight 10

A Content-Security-Policy is enforced.

| finding | severity | what it means |
|---|---|---|
| `csp.deprecated-directive` | low | Deprecated directives such as block-all-mixed-content or referrer are ignored by current browsers and give a false sense of coverage. |
| `csp.missing` | high | Without a CSP the browser will execute any script the page references or injects, so any HTML injection becomes script execution. |
| `csp.multiple-policies` | info | Multiple policies are intersected by the browser, so the result is at least as strict as each one. |
| `csp.parse-error` | low | Browsers ignore directives they do not understand. |
| `csp.present` | pass | A Content-Security-Policy header is enforced by the browser. |
| `csp.report-only-only` | medium | Report-Only never blocks anything. |
| `csp.report-only-present` | info | Running a stricter policy in report-only mode next to the enforced one is the recommended way to tighten CSP safely. |
| `csp.reporting.uri-without-to` | low | report-uri is deprecated and is being removed from Chromium. |

#### `csp.script-src` — weight 10

Script sources are restricted.

| finding | severity | what it means |
|---|---|---|
| `csp.script-src.bypassable-host` | high | Some popular CDNs host JSONP endpoints, AngularJS or unrestricted user content. |
| `csp.script-src.data-uri` | high | data: in script-src means the attacker supplies the script body inline in the URL. |
| `csp.script-src.missing` | high | Neither script-src nor default-src is present, so script loading is unrestricted. |
| `csp.script-src.ok` | pass | Script sources are limited to an explicit allowlist with no inline execution. |
| `csp.script-src.strict-dynamic` | pass | This is the recommended modern shape: trust propagates from nonced scripts to the scripts they load, and host allowlists (and their bypasses) stop mattering. |
| `csp.script-src.unsafe-eval` | medium | 'unsafe-eval' re-enables eval(), new Function() and string timers, which turns many DOM-based sinks back into script execution even when source restrictions hold. |
| `csp.script-src.unsafe-inline` | high | 'unsafe-inline' with no nonce or hash present lets any injected <script> tag or inline event handler run. |
| `csp.script-src.unsafe-inline-ignored` | info | CSP3 browsers ignore 'unsafe-inline' when a nonce or hash source is present, so it only affects CSP1 browsers. |
| `csp.script-src.wildcard` | high | A source of *, https: or http: lets scripts load from any host on the internet, so an attacker only needs to be able to inject a <script src> tag. |

#### `csp.frame-ancestors` — weight 4

Framing is restricted by CSP.

| finding | severity | what it means |
|---|---|---|
| `csp.frame-ancestors.missing` | medium | frame-ancestors is the modern clickjacking control and does not fall back to default-src. |
| `csp.frame-ancestors.ok` | pass | Framing is limited to an explicit set of origins. |
| `csp.frame-ancestors.permissive` | medium | frame-ancestors * explicitly permits framing from anywhere, which is a clickjacking primitive. |

#### `csp.base-uri` — weight 3

base-uri is restricted.

| finding | severity | what it means |
|---|---|---|
| `csp.base-uri.missing` | medium | base-uri does not fall back to default-src. |
| `csp.base-uri.ok` | pass | Injected <base> tags cannot redirect relative script URLs. |
| `csp.base-uri.permissive` | medium | A wildcard base-uri leaves the injected-<base> bypass open. |

#### `csp.object-src` — weight 3

Plugin content is blocked.

| finding | severity | what it means |
|---|---|---|
| `csp.object-src.missing` | low | Legacy plugin content (<object>, <embed>) can execute script in some browsers. |
| `csp.object-src.ok` | pass | Plugin content is blocked. |
| `csp.object-src.permissive` | medium | An object-src that is not 'none' leaves plugin-based script execution reachable. |

#### `csp.default-src` — weight 3

A restrictive default-src exists.

| finding | severity | what it means |
|---|---|---|
| `csp.default-src.missing` | medium | Fetch directives you did not list fall back to default-src. |
| `csp.default-src.ok` | pass | Directives that are not listed explicitly fall back to a restrictive default. |
| `csp.default-src.permissive` | low | A default-src of * or https: does not restrict anything meaningful for the directives that fall back to it. |

#### `csp.style-src` — weight 2

Style sources are restricted.

| finding | severity | what it means |
|---|---|---|
| `csp.style-src.missing` | low | Neither style-src nor default-src is present, so stylesheet loading and inline styles are unrestricted. |
| `csp.style-src.ok` | pass | Stylesheets are limited to an explicit allowlist with no inline styles. |
| `csp.style-src.unsafe-inline` | low | Inline styles enable CSS-based data exfiltration and UI redressing. |

### Cookies — 8 of 142 points

#### `cookies` — weight 8

Cookie attributes.

| finding | severity | what it means |
|---|---|---|
| `cookie.broad-domain` | low | A cookie set on the registrable domain is sent to every subdomain, so any one of them, including a forgotten marketing host, can read or overwrite it. |
| `cookie.long-expiry` | low | A multi-year persistent cookie is a long-lived bearer credential if it carries any authentication state. |
| `cookie.no-httponly` | medium | Without HttpOnly the cookie is readable from JavaScript, so any XSS turns directly into credential theft. |
| `cookie.no-samesite` | medium | Browser defaults differ and some still send the cookie on cross-site top-level POSTs. |
| `cookie.no-secure` | high | A cookie without Secure is sent over plain HTTP. |
| `cookie.none` | pass | Nothing to misconfigure. |
| `cookie.ok` | pass | Every cookie carries Secure, HttpOnly where appropriate, and an explicit SameSite. |
| `cookie.prefix-violation` | medium | __Host- and __Secure- prefixes are only honoured when the attributes match. |
| `cookie.samesite-none-insecure` | high | SameSite=None requires Secure. |
| `cookie.session-no-httponly` | high | The cookie name suggests it carries a session or token. |

### Network behaviour — 17 of 142 points

#### `redirect` — weight 8

HTTP to HTTPS upgrade.

| finding | severity | what it means |
|---|---|---|
| `redirect.chain-through-http` | high | A single insecure hop in the middle of the chain exposes cookies and allows the attacker to take over the rest of the navigation, even if the final URL is HTTPS. |
| `redirect.cross-host` | low | Redirecting to a different host in the same hop prevents the browser from recording an HSTS entry for the original host. |
| `redirect.long-chain` | low | Each hop is a round trip and another chance to drop out of HTTPS or lose the request. |
| `redirect.no-https` | critical | Anything served over HTTP can be read and rewritten in transit. |
| `redirect.not-permanent` | low | A 302 is not cached as a scheme upgrade, so every new visit starts with a plain-HTTP round trip. |
| `redirect.ok` | pass | Plain HTTP is upgraded immediately and permanently. |

#### `mixed-content` — weight 5

No mixed content.

| finding | severity | what it means |
|---|---|---|
| `mixed-content.active` | high | A script or iframe loaded over HTTP can be replaced in transit and then runs with full access to the HTTPS origin. |
| `mixed-content.none` | pass | The retrieved HTML references no http:// subresources. |
| `mixed-content.passive` | medium | Images and media over HTTP leak the fact of the request and can be swapped by an on-path attacker. |

#### `http-methods` — weight 3

HTTP methods.

| finding | severity | what it means |
|---|---|---|
| `methods.dangerous-allowed` | medium | PUT, DELETE, CONNECT, PATCH or WebDAV verbs advertised on a static endpoint usually mean a module is enabled that nobody intended to expose. |
| `methods.ok` | pass | Only safe methods are advertised and TRACE is refused. |
| `methods.trace-enabled` | medium | TRACE echoes the request, including headers, back in the body. |

#### `security-txt` — weight 1

Disclosure contact published.

| finding | severity | what it means |
|---|---|---|
| `security-txt.expired` | low | RFC 9116 says an expired file must not be used, so the contact details in it are formally stale. |
| `security-txt.invalid` | low | Contact and Expires are mandatory fields. |
| `security-txt.missing` | low | Without a published contact, someone who finds a vulnerability has to guess where to send it, and often gives up or goes public instead. |
| `security-txt.ok` | pass | A reachable, unexpired disclosure contact is published. |

### Information disclosure — 3 of 142 points

#### `info-headers` — weight 3

No version disclosure.

| finding | severity | what it means |
|---|---|---|
| `info.aspnet-version` | low | X-AspNet-Version and X-AspNetMvc-Version pin the exact framework build in use. |
| `info.none` | pass | The response does not advertise software versions. |
| `info.server-present` | info | The product name alone is low-value information. |
| `info.server-version` | low | A precise version turns your host into a match for a CVE feed. |
| `info.x-generator` | low | Naming the CMS and its version points straight at the matching exploit set. |
| `info.x-powered-by` | low | X-Powered-By has no function other than advertising your runtime and its version. |

## How this differs from Mozilla Observatory and SSL Labs

httpsec borrows ideas from both and departs from both deliberately.

### Mozilla Observatory

Observatory scores HTTP headers by starting at 100 and applying absolute
modifiers, some of them positive. httpsec differs in three ways.

* **Ratio, not deductions.** Observatory's modifiers do not compose: adding a
  control changes every existing score, and once several modifiers interact
  the arithmetic stops being explainable in a sentence. httpsec's score is
  "what fraction of what we checked did this site get right", which survives
  new controls being added.
* **No bonus points.** Observatory can push a score above 100 for exemplary
  configuration. httpsec has no bonuses: a control is either satisfied or it
  is not. The `--verbose` output already names everything the site got right.
* **TLS is in the same number.** Observatory scores headers; its TLS
  observations are separate. httpsec puts certificate and protocol controls in
  the same rubric as the headers, because the posture a visitor actually gets
  is the combination.

httpsec's 180-day floor for `max-age` and its treatment of `unsafe-inline` as
the single most expensive CSP mistake both follow Observatory's lead.

### Qualys SSL Labs

SSL Labs grades TLS alone, using category subscores and a well-known set of
grade caps. httpsec differs in three ways.

* **Scope.** SSL Labs is a TLS grader. httpsec covers TLS as one of six
  categories and will never match its depth: no client-simulation matrix, no
  DH parameter analysis, no protocol-specific attack replication, no
  certificate-transparency log verification.
* **Caps, not subscores.** SSL Labs computes weighted category subscores and
  then applies caps. httpsec uses caps alone for the non-tradeable failures,
  which is the part of the SSL Labs model that carries most of the meaning,
  and skips the subscore machinery.
* **Grade letters.** The letters look the same and are not comparable. An
  httpsec B and an SSL Labs B measure different things over different scopes.
  Do not put them in the same column of a spreadsheet.

The specific caps httpsec applies for deprecated protocol versions, broken
cipher suites and invalid certificates follow SSL Labs' reasoning closely.

### What neither of them does, and httpsec does

Parse the policy and judge its quality. A CSP with `unsafe-inline`, a wildcard
`script-src` and an allowlisted JSONP endpoint is scored as what it is —
barely better than no policy at all — rather than as "CSP present". That
judgement is the reason this tool exists.

## Changing the rubric

The rubric is data. To change it:

1. Edit `data/rubric.json`.
2. Run `make test`. Several tests will tell you if you have broken the
   invariants: every control must be reachable from at least one finding,
   every finding must point at a control that exists, every cap must name a
   real problem finding and a real grade, and the severity penalties must stay
   monotonic.
3. Run `make rubric-doc` to regenerate this file.
4. Bump `version` in `data/rubric.json`. It appears in every report, so a
   score can always be traced back to the rubric that produced it.
