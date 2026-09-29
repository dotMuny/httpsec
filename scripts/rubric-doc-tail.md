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
