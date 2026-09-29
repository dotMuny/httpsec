#!/usr/bin/env python3
"""Regenerate docs/rubric.md from the rubric and the finding catalogue.

The rubric has to be documented, and a rubric documented by hand drifts from
the one the binary actually uses. This reads the same two data files the
binary embeds, and appends the hand-written commentary from
scripts/rubric-doc-tail.md.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

CATEGORY_TITLES = {
    "tls": "TLS and certificates",
    "headers": "Security headers",
    "csp": "Content Security Policy",
    "cookies": "Cookies",
    "network": "Network behaviour",
    "info": "Information disclosure",
}
CATEGORY_ORDER = ["tls", "headers", "csp", "cookies", "network", "info"]


def main():
    rub = json.loads((ROOT / "data" / "rubric.json").read_text())
    find = json.loads((ROOT / "data" / "findings.json").read_text())["findings"]

    by_control = {}
    for fid, m in sorted(find.items()):
        by_control.setdefault(m["control"], []).append((fid, m))

    total = sum(c["weight"] for c in rub["controls"])
    out = []
    w = out.append

    w("# The httpsec rubric\n")
    w("This document is generated from `data/rubric.json` and `data/findings.json`.")
    w("Regenerate it with `make rubric-doc` after changing either file.\n")
    w(f"Rubric **{rub['name']} v{rub['version']}**, schema version {rub['schema_version']}.\n")

    w("## How the score is calculated\n")
    w("1. Every control carries a **weight**. The weights below add up to")
    w(f"   **{total}**, but the absolute number does not matter: the score is a ratio.")
    w("2. A control starts with its full weight and loses a fraction of it for each")
    w("   finding against it, according to the finding's severity:\n")
    w("| severity | fraction of the control's weight lost |")
    w("|---|---:|")
    for sev in ["critical", "high", "medium", "low", "info", "pass"]:
        w(f"| {sev} | {rub['severity_penalty'][sev]:.2f} |")
    w("")
    w("   Penalties accumulate — three insecure cookies cost more than one — but a")
    w("   control can never lose more than its own weight.")
    w("3. A control with **no finding at all was not evaluated**. It leaves the")
    w("   calculation entirely: out of the numerator and out of the denominator. This")
    w("   is what makes `--headers-only` and `--tls-only` score honestly instead of")
    w("   punishing a site for what was not looked at.")
    w("4. The score is `earned weight / applicable weight × 100`, rounded.")
    w("5. The score maps to a letter through the grade bands.")
    w("6. Finally, a short list of findings **caps** the grade. A cap never changes")
    w("   the score; it limits the letter the score is allowed to buy.\n")
    w("`httpsec scan --explain-score` prints this calculation for a real target,")
    w("control by control. `httpsec rubric --caps` prints the table below from the")
    w("binary.\n")

    w("## Grade bands\n")
    w("| grade | score |")
    w("|---|---:|")
    for g in rub["grades"]:
        w(f"| {g['grade']} | ≥ {g['min_score']} |")
    w("")

    w("## Grade caps\n")
    w("Some failures are not tradeable against anything else. A site that accepts")
    w("TLS 1.0 should not reach an A on the strength of a good CSP, however good the")
    w("CSP is. These findings cap the grade regardless of the score, and the")
    w("strictest applicable cap wins.\n")
    w("| finding | caps the grade at | why |")
    w("|---|:-:|---|")
    for c in rub["caps"]:
        w(f"| `{c['finding']}` | **{c['max_grade']}** | {c['reason']} |")
    w("")

    w("## Controls\n")
    w("Every control, its weight, and the findings that can move it. A finding marked")
    w("*pass* is what the control looks like when it is satisfied.\n")

    cats = {}
    for c in rub["controls"]:
        cats.setdefault(c["category"], []).append(c)

    for cat in CATEGORY_ORDER:
        if cat not in cats:
            continue
        sub = sum(c["weight"] for c in cats[cat])
        w(f"### {CATEGORY_TITLES[cat]} — {sub} of {total} points\n")
        for c in sorted(cats[cat], key=lambda x: -x["weight"]):
            w(f"#### `{c['id']}` — weight {c['weight']}\n")
            w(f"{c['title']}.\n")
            w("| finding | severity | what it means |")
            w("|---|---|---|")
            for fid, m in by_control.get(c["id"], []):
                why = m["why"].split(". ")[0].rstrip(".") + "."
                w(f"| `{fid}` | {m['severity']} | {why} |")
            w("")

    tail = (ROOT / "scripts" / "rubric-doc-tail.md").read_text()
    body = "\n".join(out) + "\n" + tail

    target = ROOT / "docs" / "rubric.md"
    target.write_text(body)
    print(f"wrote {target.relative_to(ROOT)}", file=sys.stderr)


if __name__ == "__main__":
    main()
