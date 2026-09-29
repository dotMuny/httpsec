#!/usr/bin/env python3
"""Render real ANSI terminal output as an SVG.

The README needs a picture of the text report. A screenshot would need a
terminal and a camera in CI; this reads the actual bytes httpsec writes and
draws them, so what the README shows is what the tool prints.

    httpsec scan example.com | python3 scripts/ansi-to-svg.py out.svg --title "httpsec scan"
"""
import argparse
import re
import sys
from html import escape

ANSI = re.compile(r"\033\[([0-9;]*)m")

# The palette is the one the HTML report uses, so the two read as one project.
COLOURS = {
    30: "#3b4048", 31: "#ff6b6b", 32: "#5dd39e", 33: "#e8c34a",
    34: "#7aa7ff", 35: "#c792ea", 36: "#6fd3e0", 37: "#c8ccd4",
    90: "#7c8494", 91: "#ff9f5a", 92: "#7ee0b4", 93: "#f0d878",
    94: "#9dbcff", 95: "#d9aef0", 96: "#93e3ee", 97: "#eef1f6",
}
DEFAULT_FG = "#dfe3ea"

CHAR_W = 8.05
LINE_H = 19
PAD_X = 18
PAD_Y = 16
TITLE_H = 34


class Style:
    def __init__(self):
        self.reset()

    def reset(self):
        self.fg = None
        self.bold = False
        self.dim = False

    def apply(self, codes):
        for raw in codes.split(";"):
            if raw == "":
                raw = "0"
            code = int(raw)
            if code == 0:
                self.reset()
            elif code == 1:
                self.bold = True
            elif code == 2:
                self.dim = True
            elif code == 22:
                self.bold = self.dim = False
            elif code == 39:
                self.fg = None
            elif code in COLOURS:
                self.fg = COLOURS[code]

    def attrs(self):
        out = []
        if self.fg:
            out.append(f'fill="{self.fg}"')
        if self.bold:
            out.append('font-weight="600"')
        if self.dim:
            out.append('opacity="0.62"')
        return " ".join(out)


def spans(line):
    """Split one line into (text, style) runs."""
    style = Style()
    pos = 0
    out = []
    for m in ANSI.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], style.attrs()))
        style.apply(m.group(1))
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], style.attrs()))
    return out


def render(text, title):
    lines = text.replace("\t", "    ").rstrip("\n").split("\n")
    width = max((len(ANSI.sub("", l)) for l in lines), default=80)
    width = max(width, len(title) + 10)

    w = int(PAD_X * 2 + width * CHAR_W)
    h = int(PAD_Y * 2 + TITLE_H + len(lines) * LINE_H)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" '
        f'font-size="13">',
        '<defs><clipPath id="r"><rect width="%d" height="%d" rx="9"/></clipPath></defs>' % (w, h),
        f'<g clip-path="url(#r)">',
        f'<rect width="{w}" height="{h}" fill="#12141a"/>',
        f'<rect width="{w}" height="{TITLE_H}" fill="#1b1e26"/>',
        '<circle cx="18" cy="17" r="5.5" fill="#ff5f57"/>',
        '<circle cx="36" cy="17" r="5.5" fill="#febc2e"/>',
        '<circle cx="54" cy="17" r="5.5" fill="#28c840"/>',
        f'<text x="{w/2}" y="22" fill="#8b93a1" font-size="12" text-anchor="middle">{escape(title)}</text>',
        '</g>',
    ]

    y = TITLE_H + PAD_Y + 12
    for line in lines:
        runs = spans(line)
        if runs:
            parts.append(f'<text x="{PAD_X}" y="{y}" fill="{DEFAULT_FG}" xml:space="preserve">')
            for text_run, attrs in runs:
                if not text_run:
                    continue
                parts.append(f"<tspan {attrs}>{escape(text_run)}</tspan>")
            parts.append("</text>")
        y += LINE_H

    parts.append("</svg>")
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output")
    ap.add_argument("--title", default="httpsec")
    args = ap.parse_args()

    svg = render(sys.stdin.read(), args.title)
    with open(args.output, "w") as fh:
        fh.write(svg + "\n")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
