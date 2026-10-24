"""Fields extracted from a message and returned with an incident."""

from pydantic import BaseModel, Field


class UrlOut(BaseModel):
    original: str
    normalized: str
    defanged: str
    host: str | None = None
    scheme: str
    is_ip_literal: bool = False
    source: str


class AttachmentOut(BaseModel):
    """Metadata only. Bytes are hashed for identity and then discarded."""

    filename: str | None = None
    content_type: str
    size_bytes: int
    extension: str | None = None
    sha256: str


class KeyHeaderSet(BaseModel):
    from_header: str | None = None
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    reply_to: str | None = None
    return_path: str | None = None
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    received: list[str] = Field(default_factory=list)
    authentication_results: list[str] = Field(default_factory=list)
    received_spf: str | None = None
    auth_trust: str | None = None
