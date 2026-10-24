"""URL normalization and defanging. Nothing in this module opens a connection."""

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.services.parsed import LinkPair, NormalizedUrl

_URL_RE = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9@])
    (
        (?:https?|hxxps?)://[^\s<>'"\]]+
        |
        www\.[^\s<>'"\]]+
    )
    """
)
_HREF_RE = re.compile(r"""(?i)href\s*=\s*["']([^"']+)["']""")
_DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}
_TRAILING = ".,;:)>\"']"


def defang(value: str) -> str:
    """Make a URL or host visibly non-clickable. This does not change stored values."""
    if value[:8].lower() == "https://":
        value = "hxxps://" + value[8:]
    elif value[:7].lower() == "http://":
        value = "hxxp://" + value[7:]
    else:
        # A javascript: or data: string is still pasteable if the colon stays.
        for scheme in ("javascript:", "vbscript:", "data:", "file:"):
            if value.lower().startswith(scheme):
                value = value[: len(scheme) - 1] + "[colon]" + value[len(scheme) :]
                break
    return value.replace(".", "[.]")


def defang_host(value: str) -> str:
    return value.replace(".", "[.]")


def _refang(value: str) -> str:
    value = value.strip().strip("<>")
    value = re.sub(r"(?i)^hxxps://", "https://", value)
    value = re.sub(r"(?i)^hxxp://", "http://", value)
    value = value.replace("[.]", ".").replace("(.)", ".")
    while value and value[-1] in _TRAILING:
        value = value[:-1]
    return value


def _strip_userinfo(raw: str) -> str:
    return re.sub(r"(?i)^((?:https?|hxxps?)://)[^/\s@]+@", r"\1", raw)


def normalize_url(raw: str, source: str) -> NormalizedUrl | None:
    """Return a normalized URL, or None when the string is not a URL we understand.

    Userinfo is removed before the value is stored. Callers must not fetch the result.
    """
    if not raw or not raw.strip():
        return None
    cleaned = _refang(raw)
    if not cleaned or len(cleaned) > 2048:
        cleaned = cleaned[:2048]
    had_userinfo = bool(re.search(r"(?i)^(?:https?|hxxps?)://[^/\s@]+@", cleaned))
    safe_original = _strip_userinfo(raw.strip())[:2048]
    scheme_match = re.match(r"(?i)^([a-z][a-z0-9+\-.]*):", cleaned)
    if scheme_match and scheme_match.group(1).lower() in _DANGEROUS_SCHEMES:
        scheme = scheme_match.group(1).lower()
        normalized = cleaned[:2048]
        # Trailing punctuation is stripped from the normalized form. The defanged
        # display keeps the original characters, with the scheme colon broken.
        display_source = safe_original if safe_original.lower().startswith(scheme + ":") else normalized
        return NormalizedUrl(
            original=safe_original,
            normalized=normalized,
            defanged=defang(display_source)[:2048],
            scheme=scheme,
            host=None,
            is_ip_literal=False,
            source=source,
            had_userinfo=had_userinfo,
        )
    parse_target = cleaned
    if parse_target.lower().startswith("www."):
        parse_target = "http://" + parse_target
    if "://" not in parse_target:
        return None
    parts = urlsplit(parse_target)
    scheme = (parts.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    netloc = f"[{host}]" if is_ip and ":" in host else host
    try:
        port = parts.port
    except ValueError:
        port = None
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = parts.path or ""
    query = f"?{parts.query}" if parts.query else ""
    normalized = f"{scheme}://{netloc}{path}{query}"[:2048]
    return NormalizedUrl(
        original=safe_original[:2048],
        normalized=normalized,
        defanged=defang(normalized)[:2048],
        scheme=scheme,
        host=host,
        is_ip_literal=is_ip,
        source=source,
        had_userinfo=had_userinfo,
    )


def extract_urls_from_text(text: str, source: str) -> list[NormalizedUrl]:
    found: list[NormalizedUrl] = []
    seen: set[str] = set()
    for match in _URL_RE.findall(text or ""):
        url = normalize_url(match, source)
        if url is None or url.normalized in seen:
            continue
        seen.add(url.normalized)
        found.append(url)
        if len(found) >= 50:
            break
    return found


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.texts: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = tag.lower()
        if name in {"script", "style"}:
            self._skip += 1
        if name == "a" and self._skip == 0:
            mapping = {key.lower(): (value or "") for key, value in attrs}
            self._href = mapping.get("href")
            self._buf = []

    def handle_endtag(self, tag: str) -> None:
        name = tag.lower()
        if name in {"script", "style"} and self._skip:
            self._skip -= 1
        if name == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.texts.append(data)
        if self._href is not None:
            self._buf.append(data)


def html_to_text_and_links(html: str) -> tuple[str, list[LinkPair]]:
    """Extract visible text and anchors. Scripts are skipped and never executed."""
    parser = _LinkParser()
    try:
        parser.feed(html or "")
        parser.close()
        raw_links = parser.links
        text = " ".join(part.strip() for part in parser.texts if part.strip())
    except Exception:
        raw_links = [(href, "") for href in _HREF_RE.findall(html or "")]
        text = re.sub(r"(?is)<(script|style)\b.*?>.*?</\1>", " ", html or "")
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
    links: list[LinkPair] = []
    for href, anchor_text in raw_links[:50]:
        href_url = normalize_url(href, "html_href")
        text_url = None
        candidate = anchor_text.strip()
        if candidate and " " not in candidate:
            text_url = normalize_url(candidate, "html_text")
            if text_url is None and re.match(r"(?i)^[a-z0-9.-]+\.[a-z]{2,}(/|$)", candidate):
                text_url = normalize_url("http://" + candidate, "html_text")
        links.append(
            LinkPair(href_raw=href[:2048], text=anchor_text[:500], href=href_url, text_url=text_url)
        )
    return text[:20_000], links
