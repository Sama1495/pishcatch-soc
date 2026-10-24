"""Turn a parsed message into normalized indicators."""

from dataclasses import dataclass

from app.services.parsed import ParsedEmail
from app.services.urls import defang, defang_host


@dataclass
class IndicatorDraft:
    type: str
    value: str
    display_value: str
    context: str | None = None


def build_indicators(parsed: ParsedEmail) -> list[IndicatorDraft]:
    items: list[IndicatorDraft] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str | None, display: str | None, context: str | None) -> None:
        if not value:
            return
        stored = value.strip()[:2048]
        key = (kind, stored.casefold())
        if not stored or key in seen:
            return
        seen.add(key)
        items.append(
            IndicatorDraft(
                type=kind,
                value=stored,
                display_value=(display or stored)[:2048],
                context=context,
            )
        )

    add("email", _lower(parsed.sender_address), defang(parsed.sender_address or ""), "from")
    add("domain", _lower(parsed.sender_domain), defang_host(parsed.sender_domain or ""), "from")
    for address, domain in zip(parsed.reply_to_addresses, parsed.reply_to_domains, strict=False):
        add("email", address.lower(), defang(address), "reply-to")
        add("domain", domain.lower(), defang_host(domain), "reply-to")
    add(
        "email",
        _lower(parsed.return_path_address),
        defang(parsed.return_path_address or ""),
        "return-path",
    )
    add(
        "domain",
        _lower(parsed.return_path_domain),
        defang_host(parsed.return_path_domain or ""),
        "return-path",
    )
    for url in parsed.urls:
        add("url", url.normalized, url.defanged, url.source)
        if url.host and url.is_ip_literal:
            add("ip", url.host, url.host, url.source)
        elif url.host:
            add("domain", url.host.lower(), defang_host(url.host), "url_host")
    for attachment in parsed.attachments:
        label = attachment.filename or attachment.content_type
        add("attachment", label, label, attachment.extension)
    for name, result in (("spf", parsed.spf), ("dkim", parsed.dkim), ("dmarc", parsed.dmarc)):
        if result:
            add("header", f"{name}:{result}", f"{name}={result}", "authentication")
    return items


def _lower(value: str | None) -> str | None:
    return value.lower() if value else None
