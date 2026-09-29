# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's **Report a
vulnerability** button under this repository's *Security* tab. That opens a
private advisory only the maintainer can see.

Please do not open a public issue for a security problem.

If you prefer another channel, or you get no acknowledgement within a
reasonable time, add a contact here:

<!-- Optional: replace the line below with an address you are happy to publish,
     or delete it and rely on GitHub's private reporting alone. -->
- Alternative contact: _not published — use GitHub's private reporting_

Expect an acknowledgement within a week. httpsec is maintained by one person in
their own time, so please be patient; if the issue is being fixed you will hear
about it before the fix is public.

## Supported versions

Only the latest release is supported. There are no long-term support branches.

## What counts as a vulnerability in httpsec

httpsec is a command-line auditing tool. It parses untrusted input — HTTP
headers, HTML, TLS certificates and handshakes from servers it does not
control — and writes reports that people open in a browser. The interesting
attack surface is therefore a **hostile server attacking the person running the
scan**. In scope:

- A crafted response header, certificate, `security.txt` or HTML body that
  causes a crash, an unbounded allocation, or a hang that outlives the
  configured timeouts.
- Any content from a scanned host that escapes escaping and executes in the
  HTML report, or that is written outside the intended output path.
- A scanned host being able to make httpsec issue requests it was not asked to
  make, beyond the documented probes and the AIA and OCSP fetches described in
  the README.
- Disclosure of local files, environment variables or credentials into a
  report or a request.
- A path in a batch target list or a fixture that escapes the output
  directory.

Out of scope:

- **The findings themselves.** A false positive or a missed check is a bug,
  not a vulnerability; please open a normal issue. The one exception is a
  finding that would lead someone to deploy a configuration that is *less*
  safe than what they had, which is worth reporting privately.
- The grade a site receives, and any disagreement with the rubric. It is
  documented in `docs/rubric.md` and it is data you can change.
- Anything requiring an attacker to already control the machine httpsec runs
  on, or to modify its configuration files.
- Behaviour of the sites httpsec scans. If httpsec reports a real problem on
  someone's site, that is between you and them.

## Using httpsec responsibly

httpsec makes requests to servers you point it at. It is built for auditing
hosts you own or have written permission to test, and it deliberately stops
short of being a vulnerability scanner: no subdomain enumeration, no
path brute-forcing, no exploitation. See the *Responsible use* section of the
README.

Reporting a problem you found **on someone else's site** by running httpsec
against it without permission is not something this policy covers, and
scanning without authorisation may be unlawful where you are.
