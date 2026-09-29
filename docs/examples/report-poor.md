# httpsec report: example.com

**Grade F** — score 50/100 (71.2 of 142.0 weighted points)

> The grade is capped at **F**; without the caps it would be **F**.
>
> - `redirect.no-https` caps the grade at **D**: Content served over plain HTTP can be read and rewritten in transit.
> - `tls.version.tls10` caps the grade at **C**: TLS 1.0 is deprecated by RFC 8996.
> - `tls.version.tls11` caps the grade at **B**: TLS 1.1 is deprecated by RFC 8996.

| critical | high | medium | low | info | pass |
|---:|---:|---:|---:|---:|---:|
| 2 | 5 | 6 | 7 | 4 | 9 |

Scanned `example.com` on 2026-09-29 18:04 UTC; evidence gathered by httpsec 0.1.0-dev (commit none, built unknown).

## TLS and certificates

### 🔴 critical TLS 1.0 is accepted

The server completed a TLS 1.0 handshake.

**Why it matters.** TLS 1.0 has been deprecated by RFC 8996 and is disabled in every current browser. It is vulnerable to BEAST and to downgrade attacks, and it fails PCI DSS.

<details><summary>Evidence</summary>

```
TLS 1.0: accepted (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
TLS 1.1: accepted (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
TLS 1.2: accepted (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
TLS 1.3: accepted (TLS_AES_128_GCM_SHA256)
```

</details>

**Fix.** Offer only TLS 1.2 and TLS 1.3.

<details><summary>Nginx</summary>

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

</details>

<details><summary>Apache httpd</summary>

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

</details>

<details><summary>Caddy</summary>

```text
tls {
    protocols tls1.2 tls1.3
}
# Caddy defaults to TLS 1.2+ already; this block is only needed to pin it.
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare: SSL/TLS -> Edge Certificates -> Minimum TLS Version -> TLS 1.2
```

</details>

> Check your client population before dropping TLS 1.0/1.1: it mostly affects Android 4.x and Windows XP era clients.

- [https://www.rfc-editor.org/rfc/rfc8996](https://www.rfc-editor.org/rfc/rfc8996)

<sub>`tls.version.tls10`</sub>

### 🟠 high Server accepts cipher suites without forward secrecy

5 accepted suites use static RSA key exchange: TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384.

**Why it matters.** Static-RSA key exchange means a single future compromise of the private key decrypts every session ever recorded. ECDHE removes that risk.

<details><summary>Evidence</summary>

```
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_256_GCM_SHA384
```

</details>

**Fix.** Restrict TLS 1.2 to AEAD suites with forward secrecy and let the server pick the order.

<details><summary>Nginx</summary>

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
```

</details>

<details><summary>Apache httpd</summary>

```apache
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder on
SSLOpenSSLConfCmd Curves X25519:prime256v1:secp384r1
```

</details>

<details><summary>Caddy</summary>

```text
tls {
    ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    curves x25519 secp256r1 secp384r1
}
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare manages cipher selection at the edge; set Minimum TLS Version to 1.2 and leave the rest to the platform.
```

</details>

> The list above is the Mozilla "intermediate" profile minus the CBC suites.


<sub>`tls.cipher.no-forward-secrecy`</sub>

### 🟠 high TLS 1.1 is accepted

The server completed a TLS 1.1 handshake.

**Why it matters.** TLS 1.1 is deprecated by RFC 8996 and relies on MD5/SHA-1 in its handshake signatures. No current client needs it.

<details><summary>Evidence</summary>

```
TLS 1.0: accepted (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
TLS 1.1: accepted (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
TLS 1.2: accepted (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
TLS 1.3: accepted (TLS_AES_128_GCM_SHA256)
```

</details>

**Fix.** Offer only TLS 1.2 and TLS 1.3.

<details><summary>Nginx</summary>

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

</details>

<details><summary>Apache httpd</summary>

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

</details>

<details><summary>Caddy</summary>

```text
tls {
    protocols tls1.2 tls1.3
}
# Caddy defaults to TLS 1.2+ already; this block is only needed to pin it.
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare: SSL/TLS -> Edge Certificates -> Minimum TLS Version -> TLS 1.2
```

</details>

> Check your client population before dropping TLS 1.0/1.1: it mostly affects Android 4.x and Windows XP era clients.

- [https://www.rfc-editor.org/rfc/rfc8996](https://www.rfc-editor.org/rfc/rfc8996)

<sub>`tls.version.tls11`</sub>

### 🟡 medium Certificate expires in less than 30 days

The certificate expires on 2026-10-27T22:17:21Z, in 28 days.

**Why it matters.** Renewal automation fails quietly more often than it fails loudly. Thirty days is the last point at which a failure is still comfortable to fix.

<details><summary>Evidence</summary>

```
subject: CN=example.com
issuer: CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
valid: 2026-07-29T22:10:08Z .. 2026-10-27T22:17:21Z
sans: example.com, *.example.com
signature: ECDSA-SHA256
key: ECDSA 256 bits
sha256: 6153a96fd1a6ab7f4d438fc34932484299d0729d9140b3a126bb2f9c07b02200
```

</details>

**Fix.** Serve a certificate from a publicly trusted CA that covers the hostname, with the full intermediate chain, and automate renewal.

<details><summary>Nginx</summary>

```nginx
ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;   # leaf + intermediates
ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
# fullchain.pem, not cert.pem: cert.pem alone leaves the chain incomplete.
```

</details>

<details><summary>Apache httpd</summary>

```apache
SSLCertificateFile      /etc/letsencrypt/live/example.com/fullchain.pem
SSLCertificateKeyFile   /etc/letsencrypt/live/example.com/privkey.pem
# Apache < 2.4.8 also needs SSLCertificateChainFile.
```

</details>

<details><summary>Caddy</summary>

```text
# Caddy obtains and renews certificates automatically:
example.com {
    # nothing to configure; or, for your own certificate:
    # tls /etc/ssl/fullchain.pem /etc/ssl/privkey.pem
}
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare: SSL/TLS -> Edge Certificates covers the edge.
# Use an Origin CA certificate on the origin and set the mode to Full (strict).
```

</details>

> Verify the deployed chain with: openssl s_client -connect example.com:443 -servername example.com -showcerts


<sub>`tls.cert.expiring-soon`</sub>

### 🔵 low Server accepts CBC-mode cipher suites

9 accepted suites use CBC mode: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA.

**Why it matters.** CBC with MAC-then-encrypt has produced a decade of padding-oracle and timing attacks (Lucky13 and successors). AEAD suites have no equivalent history.

<details><summary>Evidence</summary>

```
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_256_GCM_SHA384
```

</details>

**Fix.** Restrict TLS 1.2 to AEAD suites with forward secrecy and let the server pick the order.

<details><summary>Nginx</summary>

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
```

</details>

<details><summary>Apache httpd</summary>

```apache
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder on
SSLOpenSSLConfCmd Curves X25519:prime256v1:secp384r1
```

</details>

<details><summary>Caddy</summary>

```text
tls {
    ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    curves x25519 secp256r1 secp384r1
}
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare manages cipher selection at the edge; set Minimum TLS Version to 1.2 and leave the rest to the platform.
```

</details>

> The list above is the Mozilla "intermediate" profile minus the CBC suites.


<sub>`tls.cipher.cbc`</sub>

## Security headers

### 🟠 high No Strict-Transport-Security header

No Strict-Transport-Security header on the HTTPS response.

**Why it matters.** Without HSTS the first request of every session can be downgraded to plain HTTP by an on-path attacker, and the redirect to HTTPS happens too late to protect the cookies already sent.

**Fix.** Send Strict-Transport-Security with a one-year max-age and includeSubDomains from the TLS vhost.

<details><summary>Nginx</summary>

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" 
```

</details>

<details><summary>Caddy</summary>

```text
header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare: SSL/TLS -> Edge Certificates -> HTTP Strict Transport Security (HSTS) -> Enable
#   Max Age: 12 months, Apply to subdomains: On, Preload: On
```

</details>

> Only add `preload` once every subdomain is HTTPS-only: submission to hstspreload.org is slow to reverse.

- [https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security](https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security)

<sub>`hsts.missing`</sub>

### 🟡 medium No X-Content-Type-Options: nosniff

No X-Content-Type-Options header, so browsers may MIME-sniff responses whose declared type they distrust.

**Why it matters.** Without nosniff, browsers may MIME-sniff a user-uploaded file as HTML or JavaScript and execute it in your origin. It also enables cross-origin script inclusion of JSON endpoints.

**Fix.** Send X-Content-Type-Options: nosniff on every response.

<details><summary>Nginx</summary>

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set X-Content-Type-Options "nosniff" 
```

</details>

<details><summary>Caddy</summary>

```text
header X-Content-Type-Options "nosniff"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Transform Rule -> Set static -> X-Content-Type-Options: nosniff
```

</details>

> Make sure Content-Type is correct for every response first, since nosniff makes the declared type binding.

- [https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options](https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options)

<sub>`nosniff.missing`</sub>

### 🟡 medium No Referrer-Policy header

No Referrer-Policy header, so the browser default applies and it is not the same in every browser.

**Why it matters.** Browser defaults differ. Where the default is still no-referrer-when-downgrade, the full URL of your page, including any tokens in the path or query, is sent to every third-party host you reference.

**Fix.** Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer.

<details><summary>Nginx</summary>

```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Referrer-Policy "strict-origin-when-cross-origin" 
```

</details>

<details><summary>Caddy</summary>

```text
header Referrer-Policy "strict-origin-when-cross-origin"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Transform Rule -> Set static -> Referrer-Policy: strict-origin-when-cross-origin
```

</details>

> strict-origin-when-cross-origin keeps the full URL for same-origin navigation and sends only the origin elsewhere.

- [https://www.w3.org/TR/referrer-policy/](https://www.w3.org/TR/referrer-policy/)

<sub>`referrer-policy.missing`</sub>

### 🔵 low No Cross-Origin-Opener-Policy header

No Cross-Origin-Opener-Policy header, so cross-origin documents can retain a window reference to this page.

**Why it matters.** Without COOP a page you open, or that opens you, keeps a window reference across origins. That reference is the basis of tabnabbing and of several XS-Leaks.

**Fix.** Send Cross-Origin-Opener-Policy: same-origin to isolate the browsing context group.

<details><summary>Nginx</summary>

```nginx
add_header Cross-Origin-Opener-Policy "same-origin" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Cross-Origin-Opener-Policy "same-origin" 
```

</details>

<details><summary>Caddy</summary>

```text
header Cross-Origin-Opener-Policy "same-origin"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Transform Rule -> Set static -> Cross-Origin-Opener-Policy: same-origin
```

</details>

> Use same-origin-allow-popups if the site opens OAuth popups that need window.opener.

- [https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy](https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)

<sub>`coop.missing`</sub>

### 🔵 low No Permissions-Policy header

No Permissions-Policy header, so camera, microphone, geolocation and payment keep their default availability.

**Why it matters.** Powerful features stay available to the document and, in some cases, to embedded third-party frames. Denying what you do not use limits what injected or embedded code can reach.

**Fix.** Send Permissions-Policy denying the features the site does not use.

<details><summary>Nginx</summary>

```nginx
add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" 
```

</details>

<details><summary>Caddy</summary>

```text
header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Transform Rule -> Set static -> Permissions-Policy: camera=(), geolocation=(), microphone=(), payment=()
```

</details>

> An empty allowlist `()` denies the feature to the document and to every frame it embeds.

- [https://www.w3.org/TR/permissions-policy-1/](https://www.w3.org/TR/permissions-policy-1/)

<sub>`permissions-policy.missing`</sub>

### 🔵 low No X-Frame-Options header

Neither X-Frame-Options nor CSP frame-ancestors restricts who may frame this page.

**Why it matters.** With neither X-Frame-Options nor CSP frame-ancestors the page can be framed by any site, which enables clickjacking.

**Fix.** Send X-Frame-Options: DENY for legacy clients, and rely on CSP frame-ancestors for modern ones.

<details><summary>Nginx</summary>

```nginx
add_header X-Frame-Options "DENY" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set X-Frame-Options "DENY" 
```

</details>

<details><summary>Caddy</summary>

```text
header X-Frame-Options "DENY"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Transform Rule -> Set static -> X-Frame-Options: DENY
```

</details>

> ALLOW-FROM is not supported anywhere; use CSP frame-ancestors when you need to allow specific origins.

- [https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options](https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options)

<sub>`xfo.missing`</sub>

## Content Security Policy

### 🟠 high No Content-Security-Policy header

No Content-Security-Policy or Content-Security-Policy-Report-Only header was returned.

**Why it matters.** Without a CSP the browser will execute any script the page references or injects, so any HTML injection becomes script execution. CSP is the only defence-in-depth layer that survives a templating mistake.

**Fix.** Deploy an enforced Content-Security-Policy. Start from a nonce-based policy and roll it out with Report-Only first.

<details><summary>Nginx</summary>

```nginx
# Replace $csp_nonce with a per-request nonce (ngx_http_sub_module or your app).
add_header Content-Security-Policy "default-src 'self'; script-src 'nonce-$csp_nonce' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
# mod_headers; generate the nonce in your application and expose it as %{CSP_NONCE}e
Header always set Content-Security-Policy "default-src 'self'; script-src 'nonce-%{CSP_NONCE}e' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
```

</details>

<details><summary>Caddy</summary>

```text
header {
    Content-Security-Policy "default-src 'self'; script-src 'nonce-{http.vars.csp_nonce}' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
}
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare Transform Rule (Modify Response Header) -> Set static
# Header name:  Content-Security-Policy
# Value:        default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
# A nonce-based policy needs a Worker, since the value must change per request.
```

</details>

> Deploy as Content-Security-Policy-Report-Only first, collect violations for a release cycle, then switch the header name.

- [https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy](https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy)

<sub>`csp.missing`</sub>

### 🟠 high CSP restricts nothing for scripts

No enforced Content-Security-Policy applies, so this control has nothing to restrict it.

**Why it matters.** Neither script-src nor default-src is present, so script loading is unrestricted.

**Fix.** Remove 'unsafe-inline' from script-src and adopt per-request nonces with 'strict-dynamic'.

<details><summary>Nginx</summary>

```nginx
# 1. Generate a nonce per request and place it on every <script> tag.
# 2. Then drop 'unsafe-inline' (keep it only as the CSP1 fallback shown here):
add_header Content-Security-Policy "script-src 'nonce-$csp_nonce' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Content-Security-Policy "script-src 'nonce-%{CSP_NONCE}e' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'"
```

</details>

<details><summary>Caddy</summary>

```text
header Content-Security-Policy "script-src 'nonce-{http.vars.csp_nonce}' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Nonces cannot be produced by a static header rule. Use a Cloudflare Worker:
#   const nonce = crypto.randomUUID().replace(/-/g,'');
#   res.headers.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'strict-dynamic' https: 'unsafe-inline'`)
# and inject the same nonce into the HTML with HTMLRewriter.
```

</details>

> 'unsafe-inline' is ignored by CSP3 browsers when a nonce is present, so keeping it is safe and helps old clients.


<sub>`csp.script-src.missing`</sub>

### 🟡 medium CSP does not set base-uri

No enforced Content-Security-Policy applies, so this control has nothing to restrict it.

**Why it matters.** base-uri does not fall back to default-src. Without it an injected <base> tag rewrites every relative script URL on the page, which bypasses a host allowlist entirely.

**Fix.** Set base-uri 'none' (or 'self') so an injected <base> tag cannot rewrite relative script URLs.

<details><summary>Nginx</summary>

```nginx
add_header Content-Security-Policy "...; base-uri 'none'" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Content-Security-Policy "...; base-uri 'none'" 
```

</details>

<details><summary>Caddy</summary>

```text
header Content-Security-Policy "...; base-uri 'none'"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Append `base-uri 'none';` to the CSP value.
```

</details>

> base-uri does not fall back to default-src, so it must be listed explicitly.

- [https://www.w3.org/TR/CSP3/#directive-base-uri](https://www.w3.org/TR/CSP3/#directive-base-uri)

<sub>`csp.base-uri.missing`</sub>

### 🟡 medium CSP has no default-src fallback

No enforced Content-Security-Policy applies, so this control has nothing to restrict it.

**Why it matters.** Fetch directives you did not list fall back to default-src. Without it, connect-src, font-src, frame-src, worker-src and friends are completely unrestricted.

**Fix.** Add a restrictive default-src so unlisted fetch directives inherit a safe fallback.

<details><summary>Nginx</summary>

```nginx
add_header Content-Security-Policy "default-src 'self'; ..." always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Content-Security-Policy "default-src 'self'; ..." 
```

</details>

<details><summary>Caddy</summary>

```text
header Content-Security-Policy "default-src 'self'; ..."
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Add `default-src 'self';` to the start of the CSP value in your Transform Rule.
```

</details>

- [https://www.w3.org/TR/CSP3/#directive-default-src](https://www.w3.org/TR/CSP3/#directive-default-src)

<sub>`csp.default-src.missing`</sub>

### 🟡 medium CSP does not set frame-ancestors

No enforced Content-Security-Policy applies, so this control has nothing to restrict it.

**Why it matters.** frame-ancestors is the modern clickjacking control and does not fall back to default-src. Without it (and without X-Frame-Options) the page can be framed by anyone.

**Fix.** Set frame-ancestors to 'none', or to the exact origins allowed to frame the page.

<details><summary>Nginx</summary>

```nginx
add_header Content-Security-Policy "...; frame-ancestors 'none'" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Content-Security-Policy "...; frame-ancestors 'none'" 
```

</details>

<details><summary>Caddy</summary>

```text
header Content-Security-Policy "...; frame-ancestors 'none'"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Append `frame-ancestors 'none';` to the CSP value.
```

</details>

> frame-ancestors supersedes X-Frame-Options and supports multiple origins, which X-Frame-Options never did.

- [https://www.w3.org/TR/CSP3/#directive-frame-ancestors](https://www.w3.org/TR/CSP3/#directive-frame-ancestors)

<sub>`csp.frame-ancestors.missing`</sub>

### 🔵 low CSP does not set object-src 'none'

No enforced Content-Security-Policy applies, so this control has nothing to restrict it.

**Why it matters.** Legacy plugin content (<object>, <embed>) can execute script in some browsers. object-src 'none' is free to deploy and closes that path.

**Fix.** Set object-src 'none' to block plugin-based script execution.

<details><summary>Nginx</summary>

```nginx
add_header Content-Security-Policy "...; object-src 'none'" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Content-Security-Policy "...; object-src 'none'" 
```

</details>

<details><summary>Caddy</summary>

```text
header Content-Security-Policy "...; object-src 'none'"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Append `object-src 'none';` to the CSP value.
```

</details>

- [https://csp.withgoogle.com/docs/strict-csp.html](https://csp.withgoogle.com/docs/strict-csp.html)

<sub>`csp.object-src.missing`</sub>

### 🔵 low CSP restricts nothing for stylesheets

No enforced Content-Security-Policy applies, so this control has nothing to restrict it.

**Why it matters.** Neither style-src nor default-src is present, so stylesheet loading and inline styles are unrestricted.

**Fix.** Remove 'unsafe-inline' from script-src and adopt per-request nonces with 'strict-dynamic'.

<details><summary>Nginx</summary>

```nginx
# 1. Generate a nonce per request and place it on every <script> tag.
# 2. Then drop 'unsafe-inline' (keep it only as the CSP1 fallback shown here):
add_header Content-Security-Policy "script-src 'nonce-$csp_nonce' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'" always;
```

</details>

<details><summary>Apache httpd</summary>

```apache
Header always set Content-Security-Policy "script-src 'nonce-%{CSP_NONCE}e' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'"
```

</details>

<details><summary>Caddy</summary>

```text
header Content-Security-Policy "script-src 'nonce-{http.vars.csp_nonce}' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'"
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Nonces cannot be produced by a static header rule. Use a Cloudflare Worker:
#   const nonce = crypto.randomUUID().replace(/-/g,'');
#   res.headers.set('Content-Security-Policy', `script-src 'nonce-${nonce}' 'strict-dynamic' https: 'unsafe-inline'`)
# and inject the same nonce into the HTML with HTMLRewriter.
```

</details>

> 'unsafe-inline' is ignored by CSP3 browsers when a nonce is present, so keeping it is safe and helps old clients.


<sub>`csp.style-src.missing`</sub>

## Network behaviour

### 🔴 critical Plain HTTP is served without redirecting to HTTPS

http://example.com returned 200 and ended at http://example.com/ without upgrading to HTTPS.

**Why it matters.** Anything served over HTTP can be read and rewritten in transit. If the same content is reachable over both schemes, an on-path attacker simply keeps the user on the insecure one.

<details><summary>Evidence</summary>

```
200 http://example.com/
```

</details>

**Fix.** Redirect every plain-HTTP request to the same host over HTTPS with a single permanent redirect.

<details><summary>Nginx</summary>

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}
```

</details>

<details><summary>Apache httpd</summary>

```apache
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>
# Or with mod_rewrite:
#   RewriteEngine On
#   RewriteCond %{HTTPS} off
#   RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
```

</details>

<details><summary>Caddy</summary>

```text
# Caddy redirects HTTP to HTTPS automatically for any site with a hostname.
example.com {
    # automatic HTTP -> HTTPS redirect
}
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare: SSL/TLS -> Edge Certificates -> Always Use HTTPS -> On
```

</details>

> Redirect to the same host first and let that host redirect to the canonical name, otherwise the browser never records an HSTS entry for the original host.


<sub>`redirect.no-https`</sub>

### 🔵 low No /.well-known/security.txt

https://example.com/.well-known/security.txt returned 404.

**Why it matters.** Without a published contact, someone who finds a vulnerability has to guess where to send it, and often gives up or goes public instead.

**Fix.** Publish /.well-known/security.txt with at least Contact and Expires, served over HTTPS as text/plain.

<details><summary>Nginx</summary>

```nginx
location = /.well-known/security.txt {
    default_type text/plain;
    return 200 "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00.000Z\nPreferred-Languages: en, es\nCanonical: https://example.com/.well-known/security.txt\n";
}
```

</details>

<details><summary>Apache httpd</summary>

```apache
# Place the file at DOCUMENT_ROOT/.well-known/security.txt and force its type:
<Files "security.txt">
    ForceType text/plain
</Files>
```

</details>

<details><summary>Caddy</summary>

```text
handle /.well-known/security.txt {
    header Content-Type text/plain
    respond "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00.000Z\n" 200
}
```

</details>

<details><summary>Cloudflare / generic CDN</summary>

```text
# Cloudflare Pages/Workers: serve a static /.well-known/security.txt with Content-Type: text/plain,
# or use a Worker that returns the file contents for that path.
```

</details>

> Sign the file with PGP and link the signature from the Canonical field if you publish a key.

- [https://www.rfc-editor.org/rfc/rfc9116](https://www.rfc-editor.org/rfc/rfc9116)

<sub>`security-txt.missing`</sub>

