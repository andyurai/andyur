"""A JS scanner that hands the console page's OWN markup to `pagecheck`.

`app.js` builds every page as template literals, so the strict CSP's rule (no
inline style, no on* handler, no inline script) has to be checked against what
the script BUILDS, not only against the static index.html. A regex over the
source is not enough and is not safe: `esc()` contains a regex literal whose
character class holds a double quote, a single quote and a backtick. A scanner
that cannot tell a regex literal from a string starts reading the rest of the
file inside an imaginary string, and reports nothing for the rest of the page.

So this is a real (small) tokenizer. It walks the source once, skipping
comments and regex literals, and returns every string and template literal it
finds -- including those nested inside a template's `${...}` holes, which is
where a page's conditional markup lives.
"""
from __future__ import annotations

# The last significant character before a `/` decides whether the `/` opens a
# regex literal or is a division. After a value (identifier, number, `)`, `]`)
# it is division; after an operator or an opening bracket it is a regex.
_BEFORE_REGEX = set("(,=:[!&|?{};+-*%<>~^") | {"\n"}
_HOLE = ""          # stands in for a ${...} hole inside a template


def js_literals(js: str) -> list[str]:
    """Every string and template literal in `js`, in source order.

    A template literal is returned with each `${...}` hole replaced by a
    placeholder, so a partly-interpolated attribute still reads as a complete
    quoted attribute to an HTML parser. The expressions inside those holes are
    scanned too, so a string of markup built in a conditional is returned on
    its own.
    """
    out: list[str] = []
    _scan(js, 0, len(js), out)
    return out


def _scan(js: str, i: int, end: int, out: list[str], stop_at_brace: bool = False) -> int:
    """Scan js[i:end], appending literals to `out`. Returns where it stopped.

    With `stop_at_brace`, returns at the `}` that closes the current template
    hole; nested braces are matched, so an object literal inside a hole does
    not end it early.
    """
    depth = 0
    prev = "\n"
    while i < end:
        c = js[i]
        if c == "/" and i + 1 < end and js[i + 1] == "/":
            nl = js.find("\n", i)
            if nl < 0:
                return end
            i = nl
            continue
        if c == "/" and i + 1 < end and js[i + 1] == "*":
            i = js.find("*/", i) + 2
            continue
        if c == "/" and prev in _BEFORE_REGEX:
            i = _skip_regex(js, i, end)
            prev = "/"
            continue
        if c in "'\"":
            i, text = _read_quoted(js, i, end, c)
            out.append(text)
            prev = c
            continue
        if c == "`":
            i = _read_template(js, i, end, out)
            prev = "`"
            continue
        if stop_at_brace:
            if c == "{":
                depth += 1
            elif c == "}":
                if depth == 0:
                    return i
                depth -= 1
        if c == "\n":
            prev = "\n"
        elif not c.isspace():
            prev = c
        i += 1
    return end


def _skip_regex(js: str, i: int, end: int) -> int:
    i += 1                                   # the opening slash
    in_class = False
    while i < end:
        c = js[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            return i + 1
        elif c == "\n":
            return i                         # unterminated: not a regex after all
        i += 1
    return end


def _read_quoted(js: str, i: int, end: int, quote: str) -> tuple[int, str]:
    i += 1
    buf: list[str] = []
    while i < end and js[i] != quote:
        if js[i] == "\\":
            buf.append(js[i + 1:i + 2])
            i += 2
            continue
        if js[i] == "\n":                    # unterminated: stop at the line
            break
        buf.append(js[i])
        i += 1
    return i + 1, "".join(buf)


def _read_template(js: str, i: int, end: int, out: list[str]) -> int:
    i += 1                                   # the opening backtick
    buf: list[str] = []
    while i < end:
        c = js[i]
        if c == "\\":
            buf.append(js[i + 1:i + 2])
            i += 2
            continue
        if c == "`":
            out.append("".join(buf))
            return i + 1
        if c == "$" and i + 1 < end and js[i + 1] == "{":
            buf.append(_HOLE)
            i = _scan(js, i + 2, end, out, stop_at_brace=True) + 1
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return end
