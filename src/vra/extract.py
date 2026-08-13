"""Structured extraction from real-world trust-center artifacts.

The sandbox fixtures are tidy HTML tables, and the normalizer turns them into
pipe-delimited text. Real trust centers are not tidy: subprocessors appear as
nested HTML tables, PDFs, or behind SafeBase / Whistic / Vanta portals with a
click-through NDA. AIV-03 (every model provider named as a subprocessor and
BAA-covered) depends entirely on this parse, so this module is where the tool
refuses to guess: it parses the actual structure where it can, detects the
platform where it cannot, and says so explicitly instead of silently passing.

Everything here is stdlib except PDF text extraction, which optionally uses
``pypdf`` (pure-Python) and reports a precise error when it is missing — a PDF
that cannot be read is a marked gap, never a silent pass.
"""

from __future__ import annotations

import html as _html
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any

# ---------------------------------------------------------------------------
# HTML table extraction — tolerant of real-world markup (nested tags inside
# cells, links, entities, multi-table pages, headers outside <thead>, etc.)
# ---------------------------------------------------------------------------


class _TableExtractor(HTMLParser):
    """Collect every <table> as a list of rows of cell texts.

    Deliberately simple and lossy in the right places: cell content is flattened
    to text, rowspan/colspan are ignored (a cell that spans columns is
    duplicated), and tables with no <tr> but bare <td>s are recovered as a
    single row. The point is rows of text we can match headers against — not a
    DOM.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._table = []
        elif tag in ("tr", "thead", "tbody", "tfoot"):
            if self._table is not None:
                self._row = []
        elif tag in ("td", "th"):
            self._cell = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._cell is not None:
            text = "".join(self._cell)
            text = re.sub(r"\s+", " ", text).strip()
            if self._row is not None:
                self._row.append(text)
            elif self._table is not None:
                # A cell with no enclosing <tr> (some sloppy pages) becomes a row.
                self._table.append([text])
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row and self._table is not None:
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            # Drop tables with zero or one row — usually layout scaffolding,
            # not data. Keep at least the header row even if cells are empty.
            if len(self._table) > 1 or (self._table and any(c for row in self._table for c in row)):
                self.tables.append(self._table)
            self._table = None

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)


def extract_html_tables(raw: str) -> list[list[list[str]]]:
    """Return all data tables in an HTML document as row-major cell text."""
    parser = _TableExtractor()
    try:
        parser.feed(raw)
        parser.close()
    except Exception:  # pragma: no cover - malformed markup must not kill a run
        return []
    return parser.tables


# ---------------------------------------------------------------------------
# Trust-platform detection — SafeBase / Whistic / Vanta and generic NDA walls
# ---------------------------------------------------------------------------

PORTAL_PLATFORMS = ("safebase", "whistic", "vanta")

# (platform, signatures) — any signature match names the platform.
PLATFORM_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "safebase",
        (
            "safebase",
            "sb-assets",
            "safebase.io",
            "app.safebase.io",
            # SafeBase interstitial: "You're leaving … to continue to SafeBase"
            "continue to safebase",
        ),
    ),
    (
        "whistic",
        (
            "whistic",
            "whistic.com",
            "whistic-profile",
            "profile.whistic.com",
        ),
    ),
    (
        "vanta",
        (
            "vanta",
            "vanta.com",
            "trust.vanta.com",
            "vanta-portal",
            "vanta__",
        ),
    ),
)

# Signs a page is a click-through / access-gated gate rather than the content.
NDA_WALL_TERMS = (
    "non-disclosure",
    "nda",
    "click to accept",
    "accept and continue",
    "accept & continue",
    "i agree",
    "i accept",
    "agree to the terms",
    "you are about to be redirected",
    "you're about to be redirected",
    "continue to the site",
    "continue to site",
    "request access",
    "request access to",
    "sign in to continue",
    "please sign in",
    "this content is available under",
)


def detect_trust_platform(
    raw: str, *, page_url: str | None = None
) -> tuple[str | None, bool, str]:
    """Detect which trust-center platform hosts a page.

    Returns ``(platform, click_through_required, evidence)``:

    * platform — ``"safebase"``, ``"whistic"``, ``"vanta"``, ``"generic"``, or None.
    * click_through_required — True when the page is an access gate / NDA
      interstitial or a branded portal we cannot scrape without credentials.
    * evidence — verbatim text (or URL) that triggered the verdict, for the
      audit trail and the drafted outreach.
    """
    low = raw.lower()
    url_low = (page_url or "").lower()

    platform: str | None = None
    sig_hit: str | None = None
    for name, sigs in PLATFORM_SIGNATURES:
        for sig in sigs:
            if sig in low or sig in url_low:
                platform = name
                sig_hit = sig
                break
        if platform:
            break

    # A branded portal host alone (safebase.io etc.) is enough to name it even
    # when the page body gives no brand name (JS-rendered shell).
    if platform is None and page_url:
        for name, domain in (("safebase", "safebase.io"),
                             ("whistic", "whistic.com"),
                             ("vanta", "vanta.com")):
            host = urllib.parse.urlparse(page_url).netloc.lower()
            if domain in host:
                platform, sig_hit = name, host

    # Is this the content, or a wall in front of it?
    wall_hits = [t for t in NDA_WALL_TERMS if t in low]
    click_through = bool(wall_hits)
    if platform and not wall_hits:
        # A branded portal page without an explicit wall still cannot be
        # scraped deterministically — treat it as gated unless it demonstrably
        # contains a data table (the caller decides by attempting the parse).
        click_through = True

    if platform:
        evidence = f"platform signature: {sig_hit!r}" + (
            f"; wall terms: {wall_hits[:3]}" if wall_hits else ""
        )
        return platform, click_through, evidence

    if wall_hits:
        return "generic", True, f"access-gate terms present: {wall_hits[:3]}"

    return None, False, ""


# ---------------------------------------------------------------------------
# PDF text extraction — optional pypdf, explicit failure otherwise
# ---------------------------------------------------------------------------


def extract_pdf_text(data: bytes) -> tuple[str, str | None]:
    """Return (text, error). Requires pypdf; the error is precise when absent."""
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except ImportError:
        return (
            "",
            "PDF artifact requires the pypdf package (pip install pypdf); "
            "AIV-03 cannot be evaluated from this source until it is installed.",
        )
    try:
        from io import BytesIO

        reader = PdfReader(BytesIO(data))
        pages = []
        for page in reader.pages:
            try:
                pages.append(page.extract_text() or "")
            except Exception as exc:  # pragma: no cover - malformed page
                pages.append(f"[page text extraction failed: {exc}]")
        return "\n".join(pages), None
    except Exception as exc:
        return "", f"PDF parse failed: {exc}"


# ---------------------------------------------------------------------------
# Link discovery — used by onboarding to find changelog / subprocessor / DPA
# pages from a trust-center entry point.
# ---------------------------------------------------------------------------

_ATTR_RE = re.compile(r'<a\b[^>]*\bhref=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)


# Base used to resolve relative hrefs when the page came from a local file path
# (a saved trust-center snapshot). The host is a placeholder: the analyst
# should replace it with the real host in the register watch block, but the
# path structure of every discovered link is preserved.
LOCAL_FILE_BASE = "https://vendor.trust-center.local/"


def discover_links(raw: str, page_url: str) -> dict[str, str]:
    """Best-effort discovery of watchable artifact pages from a trust center.

    Returns a map of source kind -> absolute URL. Preference goes to visible
    link text (e.g. "Subprocessors", "Release notes", "Data Processing
    Addendum"), then URL path components. Returns only http(s) URLs. When
    ``page_url`` is a local file path, relative links resolve against a
    placeholder host so their paths survive for the analyst to fix up.
    """
    base = page_url if re.match(r"^https?://", page_url or "") else LOCAL_FILE_BASE
    links: list[tuple[str, str]] = []
    for href, text in _ATTR_RE.findall(raw):
        text_clean = re.sub(r"<[^>]+>", "", text)
        text_clean = re.sub(r"\s+", " ", _html.unescape(text_clean)).strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        abs_url = urllib.parse.urljoin(base, href)
        if not abs_url.startswith(("http://", "https://")):
            continue
        links.append((text_clean, abs_url))

    def score(link_text: str, url: str) -> tuple[int, str]:
        low_t, low_u = link_text.lower(), url.lower()
        for kind, patterns in (
            ("subprocessors", ("sub-processor", "subprocessor", "sub processor")),
            ("changelog", ("release notes", "release-note", "changelog", "what's new", "whats new", "updates")),
            ("dpa", ("data processing", "data-processing", "data protection", " dpa", "business associate", "baa")),
            ("trust_center", ("trust center", "trust-center", "security", "compliance")),
        ):
            for pat in patterns:
                if pat in low_t:
                    return (2, kind)
                if pat in low_u:
                    return (1, kind)
        return (0, "")

    found: dict[str, str] = {}
    for text, url in links:
        rank, kind = score(text, url)
        if rank and kind not in found:
            found[kind] = url
        elif rank and kind in found and rank == 2:
            found[kind] = url
    return found


def looks_like_html(raw: bytes) -> bool:
    head = raw[:4096].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html") or b"<table" in head


def looks_like_pdf(raw: bytes, url: str = "", content_type: str | None = None) -> bool:
    if content_type and "pdf" in content_type.lower():
        return True
    if raw[:5] == b"%PDF-":
        return True
    path = urllib.parse.urlparse(url).path.lower()
    return path.endswith(".pdf")


def decode_bytes(raw: bytes) -> str:
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")
