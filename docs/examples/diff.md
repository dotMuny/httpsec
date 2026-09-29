## httpsec diff — github.com

Grade **F** (50) → **A** (90), +40 points.

### Fixed (16)

- 🔴 critical Plain HTTP is served without redirecting to HTTPS — `redirect.no-https`
- 🔴 critical TLS 1.0 is accepted — `tls.version.tls10`
- 🟠 high No Content-Security-Policy header — `csp.missing`
- 🟠 high CSP restricts nothing for scripts — `csp.script-src.missing`
- 🟠 high No Strict-Transport-Security header — `hsts.missing`
- 🟠 high TLS 1.1 is accepted — `tls.version.tls11`
- 🟡 medium CSP does not set base-uri — `csp.base-uri.missing`
- 🟡 medium CSP has no default-src fallback — `csp.default-src.missing`
- 🟡 medium CSP does not set frame-ancestors — `csp.frame-ancestors.missing`
- 🟡 medium No X-Content-Type-Options: nosniff — `nosniff.missing`
- 🟡 medium No Referrer-Policy header — `referrer-policy.missing`
- 🟡 medium Certificate expires in less than 30 days — `tls.cert.expiring-soon`
- 🔵 low CSP does not set object-src 'none' — `csp.object-src.missing`
- 🔵 low CSP restricts nothing for stylesheets — `csp.style-src.missing`
- 🔵 low No /.well-known/security.txt — `security-txt.missing`
- 🔵 low No X-Frame-Options header — `xfo.missing`

### Introduced (3)

- 🟡 medium Cookie is missing the HttpOnly flag `_octo` — `cookie.no-httponly`
- 🔵 low style-src allows 'unsafe-inline' — `csp.style-src.unsafe-inline`
- 🔵 low OCSP stapling is not enabled — `tls.ocsp.no-stapling`

