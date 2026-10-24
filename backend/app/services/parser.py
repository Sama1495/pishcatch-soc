"""Parse a .eml payload into headers, text, URL strings, and attachment metadata.

The parser never executes a part and never resolves a URL. Attachment bytes are
hashed and dropped.
"""

import hashlib
import re
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from app.services.exceptions import ParseRejection
from app.services.parsed import AttachmentMeta, NormalizedUrl, ParsedEmail
from app.services.urls import extract_urls_from_text, html_to_text_and_links

MAX_BODY_CHARS = 20_000
MAX_HEADER_CHARS = 500
MAX_RECEIVED = 10
MAX_PARTS = 100

_STRONG_HEADERS = {
    "from",
    "sender",
    "reply-to",
    "return-path",
    "subject",
    "date",
    "received",
    "to",
    "cc",
    "message-id",
    "authentication-results",
    "received-spf",
    "dkim-signature",
}
_AUTH_RE = re.compile(
    r"(?i)\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|none|neutral|temperror|permerror|bestguesspass)\b"
)
_WORST_FIRST = (
    "fail",
    "softfail",
    "permerror",
    "temperror",
    "neutral",
    "none",
    "bestguesspass",
    "pass",
)


def parse_eml(raw: bytes) -> ParsedEmail:
    """Parse ``raw`` or raise ``ParseRejection`` with a generic message."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if not raw.strip():
        raise ParseRejection("empty_file", "The uploaded file is empty.")
    if raw.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        raise ParseRejection(
            "invalid_content",
            "The file is a zip archive, not an email. It was not opened.",
        )
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise ParseRejection(
            "invalid_content",
            "The file could not be parsed as an email message.",
        ) from exc
    header_names = {name.lower() for name in message.keys()}
    if not header_names.intersection(_STRONG_HEADERS):
        raise ParseRejection(
            "invalid_content",
            "The file does not contain a recognizable email header section.",
        )

    parsed = ParsedEmail()
    parsed.sender_raw = _header(message, "from")
    parsed.sender_display, parsed.sender_address, parsed.sender_domain = _split_mailbox(
        parsed.sender_raw
    )
    parsed.reply_to_raw = _header(message, "reply-to")
    for _display, address in getaddresses(message.get_all("reply-to", [])):
        _name, addr, domain = _split_mailbox(address)
        if addr:
            parsed.reply_to_addresses.append(addr)
        if domain:
            parsed.reply_to_domains.append(domain)
    parsed.return_path_raw = _header(message, "return-path")
    _name, parsed.return_path_address, parsed.return_path_domain = _split_mailbox(
        parsed.return_path_raw
    )
    parsed.subject = _header(message, "subject")
    parsed.date = _header(message, "date")
    parsed.message_id = _header(message, "message-id")
    parsed.to = _address_list(message, "to")
    parsed.cc = _address_list(message, "cc")
    parsed.received = [_clip(item) for item in (message.get_all("received") or [])[:MAX_RECEIVED]]
    parsed.authentication_results = [
        _clip(item) for item in (message.get_all("authentication-results") or [])[:5]
    ]
    parsed.received_spf = _header(message, "received-spf")
    parsed.mailing_list = _mailing_list(message)
    _apply_auth(parsed, message)

    body_parts: list[str] = []
    url_seen: set[str] = set()
    part_count = 0
    for part in message.walk():
        part_count += 1
        if part_count > MAX_PARTS:
            parsed.warnings.append("Additional MIME parts were ignored after the safety cap.")
            break
        if part.is_multipart():
            continue
        filename = _safe_filename(part.get_filename())
        disposition = (part.get_content_disposition() or "").lower()
        if filename or disposition == "attachment":
            parsed.attachments.append(_attachment_meta(part, filename))
            if len(parsed.attachments) >= 30:
                break
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        text = _part_text(part)
        if not text:
            continue
        if content_type == "text/html":
            visible, links = html_to_text_and_links(text)
            parsed.links.extend(links)
            if visible:
                body_parts.append(visible)
                for url in extract_urls_from_text(visible, "html_text"):
                    _add_url(parsed, url_seen, url)
            for link in links:
                if link.href is not None:
                    _add_url(parsed, url_seen, link.href)
        else:
            body_parts.append(text)
            for url in extract_urls_from_text(text, "body_text"):
                _add_url(parsed, url_seen, url)

    for url in extract_urls_from_text(parsed.subject or "", "subject"):
        _add_url(parsed, url_seen, url)

    body = "\n".join(part.strip() for part in body_parts if part.strip())
    if len(body) > MAX_BODY_CHARS:
        parsed.body_truncated = True
        body = body[:MAX_BODY_CHARS]
    parsed.body_text = body
    return parsed


def _add_url(parsed: ParsedEmail, seen: set[str], url: NormalizedUrl) -> None:
    if url.normalized in seen or len(parsed.urls) >= 50:
        return
    seen.add(url.normalized)
    parsed.urls.append(url)


def _attachment_meta(part, filename: str | None) -> AttachmentMeta:
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:
        payload = b""
    if not isinstance(payload, (bytes, bytearray)):
        payload = b""
    extension = None
    if filename:
        suffixes = Path(filename).suffixes
        extension = suffixes[-1].lower() if suffixes else None
    return AttachmentMeta(
        filename=filename,
        content_type=(part.get_content_type() or "application/octet-stream")[:200],
        size_bytes=len(payload),
        extension=extension,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _part_text(part) -> str:
    try:
        content = part.get_content()
    except Exception:
        raw = part.get_payload(decode=True) or b""
        if not isinstance(raw, (bytes, bytearray)):
            return ""
        content = bytes(raw).decode("utf-8", errors="replace")
    if not isinstance(content, str):
        return ""
    return content


def _apply_auth(parsed: ParsedEmail, message) -> None:
    """Score Authentication-Results only for a configured authserv-id.

    Received-SPF is stored and not scored. An uploaded message can forge both
    headers, so an unlisted authserv-id leaves SPF, DKIM, and DMARC unset.
    """
    del message
    if not parsed.authentication_results:
        parsed.auth_trust = "absent"
        parsed.spf = None
        parsed.dkim = None
        parsed.dmarc = None
        return
    from app.core.config import get_settings

    trusted = get_settings().trusted_authserv_set
    blobs = [blob for blob in parsed.authentication_results if _authserv(blob) in trusted]
    if not blobs:
        parsed.auth_trust = "untrusted"
        parsed.spf = None
        parsed.dkim = None
        parsed.dmarc = None
        return
    parsed.auth_trust = "trusted"
    results: dict[str, str] = {}
    for blob in blobs:
        for mechanism, value in _AUTH_RE.findall(blob):
            key = mechanism.lower()
            results[key] = _worse(results.get(key), value.lower())
    parsed.spf = results.get("spf")
    parsed.dkim = results.get("dkim")
    parsed.dmarc = results.get("dmarc")


def _authserv(header: str) -> str:
    head = header.split(";", 1)[0]
    head = re.sub(r"\([^)]*\)", "", head).strip()
    parts = head.split()
    if not parts:
        return ""
    return parts[0].lower().rstrip(".")


def _mailing_list(message) -> bool:
    """True when list markers are present. The header values are not stored."""
    if message.get("list-id") or message.get("mailing-list") or message.get("list-unsubscribe"):
        return True
    precedence = str(message.get("precedence") or "")
    token = precedence.split(";", 1)[0].strip().lower()
    return token in {"list", "bulk"}


def _worse(current: str | None, new: str) -> str:
    if current is None:
        return new
    if _WORST_FIRST.index(new) < _WORST_FIRST.index(current):
        return new
    return current


def _header(message, name: str) -> str | None:
    value = message.get(name)
    if value is None:
        return None
    return _clip(_decode(str(value)))


def _clip(value: str | None) -> str:
    if not value:
        return ""
    compact = " ".join(value.replace("\x00", " ").split())
    return compact[:MAX_HEADER_CHARS]


def _decode(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _address_list(message, name: str) -> list[str]:
    values = []
    for _display, address in getaddresses(message.get_all(name, [])):
        if address:
            values.append(_clip(address))
    return values[:20]


def _split_mailbox(raw: str | None) -> tuple[str | None, str | None, str | None]:
    if not raw:
        return None, None, None
    display, address = parseaddr(raw)
    display = _decode(display).replace("\x00", "").strip() or None
    address = (address or "").strip().lower()
    if "@" not in address:
        match = re.search(r"(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", raw)
        address = match.group(0).lower() if match else ""
    if "@" not in address:
        return display, None, None
    domain = address.rsplit("@", 1)[1].strip().rstrip(".").lower()
    return display, address, domain or None


def _safe_filename(filename: str | None) -> str | None:
    if not filename:
        return None
    cleaned = Path(str(filename)).name.replace("\x00", "")
    cleaned = cleaned.strip()
    return cleaned[:255] or None
