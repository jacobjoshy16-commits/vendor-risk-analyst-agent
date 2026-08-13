"""HTML/text normalization and volatile-content stripping.

Phase 2.3: strip volatile content before hashing, or every run reports a false
change. This module is the difference between a tool and a noise generator, so
the rules are explicit, named, and unit-tested rather than one clever regex.

Each rule replaces volatile text with a stable placeholder rather than deleting
it, so the diff still shows *where* content lived without showing churn.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

# --------------------------------------------------------------------------
# Volatile content rules. (name, pattern, replacement)
# --------------------------------------------------------------------------
VOLATILE_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "iso_timestamp",
        re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"),
        "<TIMESTAMP>",
    ),
    (
        "session_token",
        re.compile(
            r"\b(session|sessionid|session_id|sid|csrf|nonce|request-id|requestid|trace-id)"
            r"\s*[=:]\s*[\"']?[0-9a-fA-F-]{6,}[\"']?",
            re.IGNORECASE,
        ),
        r"\1=<VOLATILE>",
    ),
    (
        "bare_guid",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<GUID>",
    ),
    (
        "build_number",
        re.compile(r"\bbuild\s+#?\d+\b", re.IGNORECASE),
        "build <BUILD>",
    ),
    (
        "render_time",
        re.compile(
            r"\b(?:rendered\s+in|render|page\s+render|generated\s+in|took)\s+\d+(?:\.\d+)?\s*(?:ms|s)\b",
            re.IGNORECASE,
        ),
        "render <DURATION>",
    ),
    (
        "cache_buster",
        re.compile(r"[?&](?:v|ver|cb|_|t)=\d{6,}"),
        "?v=<CACHEBUST>",
    ),
    (
        "copyright_year",
        re.compile(r"(©|&copy;|Copyright)\s*\d{4}", re.IGNORECASE),
        r"\1 <YEAR>",
    ),
    (
        "visitor_count",
        re.compile(r"\b\d{1,3}(?:,\d{3})+\s+(?:visitors|customers|users)\s+online\b", re.IGNORECASE),
        "<COUNTER> online",
    ),
]

# Elements whose entire contents are dropped: script/style are not prose, and
# rotating promo banners are marketing churn that changes on every fetch.
DROP_ELEMENTS = {"script", "style", "noscript", "svg"}
DROP_CLASS_TOKENS = {
    "promo-banner",
    "promo",
    "announcement-bar",
    "cookie-banner",
    "cookie-notice",
    "newsletter",
    "carousel",
    "ticker",
    "live-chat",
}


class _TextExtractor(HTMLParser):
    """Minimal HTML-to-text conversion with volatile-block dropping.

    Deliberately stdlib-only: this tool is meant to run on a locked-down
    workstation without a dependency tree to justify to security review.
    """

    BLOCK_TAGS = {
        "p", "div", "li", "tr", "br", "h1", "h2", "h3", "h4", "h5", "h6",
        "section", "article", "header", "footer", "table", "ul", "ol", "hr",
    }
    CELL_TAGS = {"td", "th"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._drop_depth = 0
        self._drop_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        classes = set((attr.get("class") or "").lower().split())
        drop = tag in DROP_ELEMENTS or bool(classes & DROP_CLASS_TOKENS)
        if drop:
            self._drop_depth += 1
            self._drop_stack.append(tag)
            return
        if self._drop_depth:
            self._drop_stack.append(tag)
            return
        if tag in self.BLOCK_TAGS:
            self._parts.append("\n")
        elif tag in self.CELL_TAGS:
            self._parts.append(" | ")

    def handle_endtag(self, tag: str) -> None:
        if self._drop_depth:
            if self._drop_stack:
                opened = self._drop_stack.pop()
                # Closing the tag that opened the dropped region ends it.
                if opened == tag and len(self._drop_stack) < self._drop_depth:
                    self._drop_depth -= 1
            return
        if tag in self.BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._drop_depth:
            return
        self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def html_to_text(raw: str) -> str:
    parser = _TextExtractor()
    parser.feed(raw)
    parser.close()
    return parser.text()


def strip_volatile(text: str) -> tuple[str, list[str]]:
    """Replace volatile substrings with placeholders.

    Returns the cleaned text and the names of rules that actually fired, so a
    run can explain *why* two fetches with different bytes hashed the same.
    """
    fired: list[str] = []
    for name, pattern, replacement in VOLATILE_RULES:
        text, count = pattern.subn(replacement, text)
        if count:
            fired.append(name)
    return text, fired


def collapse_whitespace(text: str) -> str:
    lines = [re.sub(r"[ \t\xa0]+", " ", line).strip() for line in text.splitlines()]
    out: list[str] = []
    for line in lines:
        if line or (out and out[-1]):
            out.append(line)
    while out and not out[-1]:
        out.pop()
    return "\n".join(out)


def normalize(raw: str, *, is_html: bool | None = None) -> tuple[str, list[str]]:
    """Full pipeline: markup to text, strip volatile content, tidy whitespace."""
    if is_html is None:
        is_html = bool(re.search(r"<\s*(html|body|div|p|table|ul)\b", raw, re.IGNORECASE))
    text = html_to_text(raw) if is_html else raw
    text, fired = strip_volatile(text)
    return collapse_whitespace(text), fired
