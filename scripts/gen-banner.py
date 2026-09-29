#!/usr/bin/env python3
"""Generate the README banner in a light and a dark variant.

Both variants come from one description so they cannot drift, and the README
picks between them with <picture media="(prefers-color-scheme: dark)">.

Only generic font families are used. GitHub serves repository SVGs through a
proxy and web fonts never load, so the banner is laid out with enough slack to
survive whatever the reader's machine substitutes.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"

W, H = 900, 240

THEMES = {
    "dark": {
        "bg": "#12141a",
        "panel": "#1b1e26",
        "line": "#2b303b",
        "ink": "#eef1f6",
        "muted": "#98a1b0",
        "accent": "#5dd39e",
        "critical": "#ff6b6b",
        "high": "#ff9f5a",
        "medium": "#e8c34a",
        "low": "#7aa7ff",
    },
    "light": {
        "bg": "#ffffff",
        "panel": "#f4f5f7",
        "line": "#e1e3e8",
        "ink": "#16181d",
        "muted": "#5b616e",
        "accent": "#15803d",
        "critical": "#b3261e",
        "high": "#c2410c",
        "medium": "#a16207",
        "low": "#1d4ed8",
    },
}

MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
SANS = "system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"

# The severity ladder, drawn as a legend strip along the bottom.
LADDER = [
    ("critical", "critical"),
    ("high", "high"),
    ("medium", "medium"),
    ("low", "low"),
    ("accent", "pass"),
]


def banner(t):
    p = []
    a = p.append

    a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
      f'viewBox="0 0 {W} {H}" role="img" aria-label="httpsec — audit HTTP security headers and TLS configuration">')

    a('<defs>')
    a(f'<clipPath id="round"><rect width="{W}" height="{H}" rx="16"/></clipPath>')
    a('</defs>')

    a('<g clip-path="url(#round)">')
    a(f'<rect width="{W}" height="{H}" fill="{t["bg"]}"/>')

    # A hairline grid, faint, to suggest a report rather than a poster.
    for x in range(0, W, 30):
        a(f'<line x1="{x}" y1="0" x2="{x}" y2="{H}" stroke="{t["line"]}" stroke-width="0.5" opacity="0.35"/>')

    # The grade chip: the thing the tool actually hands you.
    cx, cy, cs = 56, 54, 96
    a(f'<rect x="{cx}" y="{cy}" width="{cs}" height="{cs}" rx="14" '
      f'fill="{t["panel"]}" stroke="{t["accent"]}" stroke-width="3"/>')
    a(f'<text x="{cx + cs/2}" y="{cy + 68}" text-anchor="middle" '
      f'font-family="{SANS}" font-size="46" font-weight="700" fill="{t["accent"]}">A+</text>')

    # Wordmark and tagline.
    tx = cx + cs + 40
    a(f'<text x="{tx}" y="{cy + 34}" font-family="{MONO}" font-size="44" '
      f'font-weight="700" fill="{t["ink"]}">httpsec</text>')
    a(f'<text x="{tx}" y="{cy + 68}" font-family="{SANS}" font-size="17" fill="{t["muted"]}">'
      f'Audit HTTP security headers and TLS configuration.</text>')
    a(f'<text x="{tx}" y="{cy + 92}" font-family="{SANS}" font-size="17" fill="{t["ink"]}">'
      f'Get back the exact config line that fixes each problem.</text>')

    # Severity legend.
    ly = H - 42
    a(f'<line x1="{cx}" y1="{ly - 26}" x2="{W - cx}" y2="{ly - 26}" stroke="{t["line"]}" stroke-width="1"/>')
    x = cx
    for key, label in LADDER:
        a(f'<circle cx="{x + 6}" cy="{ly}" r="5.5" fill="{t[key]}"/>')
        a(f'<text x="{x + 20}" y="{ly + 5}" font-family="{MONO}" font-size="13" '
          f'fill="{t["muted"]}">{label}</text>')
        x += 24 + len(label) * 8 + 26

    # Right-hand strapline, the one-line pitch.
    a(f'<text x="{W - cx}" y="{ly + 5}" text-anchor="end" font-family="{MONO}" font-size="13" '
      f'fill="{t["muted"]}">nginx · apache · caddy · cdn</text>')

    a('</g>')
    a(f'<rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="16" fill="none" '
      f'stroke="{t["line"]}" stroke-width="1"/>')
    a('</svg>')
    return "\n".join(p) + "\n"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, theme in THEMES.items():
        path = OUT / f"banner-{name}.svg"
        path.write_text(banner(theme))
        print(f"wrote {path.relative_to(ROOT)}", file=sys.stderr)


if __name__ == "__main__":
    main()
