"""Internal parse model. Not the API schema."""

from dataclasses import dataclass, field


@dataclass
class NormalizedUrl:
    original: str
    normalized: str
    defanged: str
    scheme: str
    host: str | None
    is_ip_literal: bool
    source: str
    had_userinfo: bool = False


@dataclass
class LinkPair:
    href_raw: str
    text: str
    href: NormalizedUrl | None
    text_url: NormalizedUrl | None


@dataclass
class AttachmentMeta:
    filename: str | None
    content_type: str
    size_bytes: int
    extension: str | None
    sha256: str


@dataclass
class ParsedEmail:
    sender_display: str | None = None
    sender_address: str | None = None
    sender_domain: str | None = None
    sender_raw: str | None = None
    reply_to_raw: str | None = None
    reply_to_addresses: list[str] = field(default_factory=list)
    reply_to_domains: list[str] = field(default_factory=list)
    return_path_raw: str | None = None
    return_path_address: str | None = None
    return_path_domain: str | None = None
    subject: str | None = None
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    date: str | None = None
    message_id: str | None = None
    received: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    received_spf: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    # absent: no Authentication-Results. untrusted: present, authserv-id not trusted.
    # trusted: at least one Authentication-Results header was scored.
    auth_trust: str = "absent"
    mailing_list: bool = False
    body_text: str = ""
    body_truncated: bool = False
    urls: list[NormalizedUrl] = field(default_factory=list)
    links: list[LinkPair] = field(default_factory=list)
    attachments: list[AttachmentMeta] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def sender(self) -> str | None:
        # Keep the original From header. Rebuilding it would nest the display
        # name when that name itself contains an address, which is a common lure.
        if self.sender_raw:
            return self.sender_raw
        if self.sender_display and self.sender_address:
            return f"{self.sender_display} <{self.sender_address}>"
        return self.sender_address or self.sender_display
