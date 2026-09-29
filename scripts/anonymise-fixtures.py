#!/usr/bin/env python3
"""Scrub captured Observation fixtures before they are committed.

What is removed and why:

* Set-Cookie values. The attributes are what httpsec analyses; the value is a
  live session token for whoever ran the capture. Names and attributes stay,
  the value becomes a placeholder.
* Response bodies are truncated. Only the subresource URLs matter for the
  mixed-content analysis, and a full homepage makes the diff unreadable.
* Volatile headers (Date, Age, Set-Cookie expiry noise, request IDs, cache
  keys) are normalised so a re-capture produces a reviewable diff instead of a
  wall of churn.
"""
import json
import pathlib
import re
import sys

VOLATILE = {
    "date", "age", "expires", "last-modified", "etag", "x-request-id",
    "x-amz-cf-id", "x-amz-request-id", "cf-ray", "x-served-by", "x-cache",
    "x-cache-hits", "x-timer", "x-github-request-id", "report-to",
    "nel", "x-client-ip", "x-trace-id", "traceparent", "x-runtime",
}
COOKIE_VALUE = re.compile(r"^([^=]+)=[^;]*")
MAX_BODY = 8000


def scrub_headers(headers):
    if not headers:
        return headers
    out = {}
    for name, values in headers.items():
        low = name.lower()
        if low == "set-cookie":
            out[name] = [COOKIE_VALUE.sub(r"\1=REDACTED", v, count=1) for v in values]
        elif low in VOLATILE:
            out[name] = ["REDACTED"]
        else:
            out[name] = values
    return out


def scrub_response(resp):
    if not resp:
        return resp
    resp["headers"] = scrub_headers(resp.get("headers"))
    body = resp.get("body")
    if body and len(body) > MAX_BODY:
        resp["body"] = body[:MAX_BODY]
        resp["body_truncated"] = True
    resp["duration_ms"] = 0
    return resp


def scrub(obs):
    for key in ("https", "plain_http", "options", "trace", "security_txt"):
        if obs.get(key):
            obs[key] = scrub_response(obs[key])
    obs["duration_ms"] = 0
    return obs


def main(directory):
    for path in sorted(pathlib.Path(directory).glob("*.json")):
        obs = json.loads(path.read_text())
        path.write_text(json.dumps(scrub(obs), indent=2, sort_keys=False) + "\n")
        print(f"scrubbed {path.name}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "testdata/observations")
