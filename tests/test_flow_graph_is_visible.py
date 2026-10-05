"""The flow graph's shapes must be visible against the card they are drawn on.

Found by the operator looking at it: in dark mode the workflow graph rendered as
floating text with no boxes and no edges. Measured rather than eyeballed --
`.flow .box` was `fill:var(--panel)` drawn inside a `.card` whose background is
also `var(--panel)`, so the node rectangles were the SAME COLOUR as their own
ground (1.00:1), and `--line` strokes came in at 1.34:1 where WCAG 1.4.11 asks
3:1 for the boundary of a UI component.

The console's own light palette carries a comment measuring status colours to
WCAG 1.4.3 for TEXT. Nothing measured the non-text shapes, which is how a graph
of coloured rectangles ended up invisible on one of two themes.

This reads the real stylesheet. A test asserting the token strings would pass
after someone changed a hex to another invisible one; a contrast computation
fails on the property that actually matters.
"""
import re
from pathlib import Path

import pytest

CSS = Path(__file__).resolve().parents[1] / "andyur/console/static/app.css"
MIN_BOUNDARY = 3.0     # WCAG 1.4.11, non-text contrast


def _lin(c):
    c /= 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _luminance(hex_colour):
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(a, b):
    la, lb = _luminance(a), _luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _tokens():
    """(dark, light) token maps, read from the stylesheet as it ships.

    Light is the dark map updated by the `prefers-color-scheme: light` block,
    which is how the cascade actually resolves it -- light overrides only some
    tokens and inherits the rest.
    """
    css = CSS.read_text()
    light_block = re.search(
        r"@media \(prefers-color-scheme: light\)\{(.*?)\n\}", css, re.S).group(1)
    dark_block = css[:css.index("@media (prefers-color-scheme: light)")]

    def grab(block):
        return dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*(#[0-9A-Fa-f]{6})", block))

    dark = grab(dark_block)
    light = {**dark, **grab(light_block)}
    return dark, light


def test_the_stylesheet_defines_the_flow_tokens_in_both_themes():
    """Fixture guard: if these vanish, every assertion below reads an empty map
    and would pass while measuring nothing."""
    dark, light = _tokens()
    for name in ("--flow-node", "--flow-node2", "--flow-stroke", "--panel"):
        assert name in dark, f"{name} missing from the dark palette"
        assert name in light, f"{name} missing from the light palette"
    assert dark["--flow-stroke"] != light["--flow-stroke"], (
        "one stroke for both themes cannot be right; the check below would be "
        "measuring the same value twice")


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_graphs_strokes_meet_the_non_text_contrast_floor(theme):
    """Edges, node borders and badge outlines carry the graph's meaning."""
    dark, light = _tokens()
    t = dark if theme == "dark" else light
    card = t["--panel"]              # .card background: the graph's ground
    got = contrast(t["--flow-stroke"], card)
    assert got >= MIN_BOUNDARY, (
        f"{theme}: flow strokes are {got:.2f}:1 against the card "
        f"({t['--flow-stroke']} on {card}); WCAG 1.4.11 asks {MIN_BOUNDARY}:1. "
        "Edges and node borders are what make this a graph rather than a list.")


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_a_node_is_not_the_same_colour_as_the_card_it_sits_on(theme):
    """The original defect, stated directly. A filled shape indistinguishable
    from its own ground is not a shape."""
    dark, light = _tokens()
    t = dark if theme == "dark" else light
    card = t["--panel"]
    for token in ("--flow-node", "--flow-node2"):
        assert t[token] != card, (
            f"{theme}: {token} is exactly --panel, so the node is the same "
            "colour as the card it is drawn on")


def test_the_measurement_itself_is_not_broken():
    """Positive and negative controls on the contrast function, because every
    assertion above is only as good as this."""
    assert contrast("#FFFFFF", "#000000") == pytest.approx(21.0, abs=0.01)
    assert contrast("#121A33", "#121A33") == pytest.approx(1.0, abs=0.001)
    # and it would have caught the defect this file exists for
    assert contrast("#243059", "#121A33") < MIN_BOUNDARY
