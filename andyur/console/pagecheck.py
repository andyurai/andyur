"""The rule that lets the console's CSP be `script-src 'self'; style-src
'self'` with nothing inline: the served page carries no inline script, no
inline style and no on* handler attributes. One parser-based check, used by
the unit test and by the live gate on the bytes the running binary served
(a regex misses `<button/onclick=` and `href="x"onclick=`; the HTML parser
sees them the way a browser does).

    python -m andyur.console.pagecheck < page.html   # exit 1 on a violation
"""
from __future__ import annotations

import sys
from html.parser import HTMLParser


class _Inline(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.violations: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "style":
            self.violations.append("<style> element")
        if tag == "script" and not any(k == "src" and v for k, v in attrs):
            self.violations.append("<script> without src")
        for k, _ in attrs:
            if k.startswith("on"):
                self.violations.append(f"<{tag} {k}=> inline handler")
            if k == "style":
                self.violations.append(f"<{tag} style=> inline style")


def inline_violations(html: str) -> list[str]:
    """Everything in `html` the strict CSP would block. Empty means clean."""
    parser = _Inline()
    parser.feed(html)
    parser.close()
    return parser.violations


def main() -> int:
    found = inline_violations(sys.stdin.read())
    for item in found:
        print(item)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
