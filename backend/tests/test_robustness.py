import pytest
from email.message import EmailMessage

from app.services.exceptions import ParseRejection
from app.services.parser import parse_eml
from app.services.rules import evaluate


def test_binary_garbage_is_rejected():
    with pytest.raises(ParseRejection) as caught:
        parse_eml(b"\x00\x01\x02\xff\xfe not an email")
    assert caught.value.code == "invalid_content"


def test_missing_from_still_parses():
    raw = b"Subject: hello\r\nDate: Tue, 20 Oct 2026 15:00:00 +0000\r\n\r\nBody\r\n"
    parsed = parse_eml(raw)
    assert parsed.sender_address is None
    assert parsed.subject == "hello"
    evaluate(parsed)


def test_non_utf8_body_does_not_crash():
    raw = (
        b"From: a@example.test\r\n"
        b"Subject: cafe\r\n"
        b"Content-Type: text/plain; charset=iso-8859-1\r\n"
        b"\r\n"
        b"Caf\xe9 para ma\xf1ana\r\n"
    )
    parsed = parse_eml(raw)
    assert parsed.body_text
    evaluate(parsed)


def test_nested_multipart_and_long_url():
    message = EmailMessage()
    message["From"] = "a@example.test"
    message["Subject"] = "nested"
    message.set_content("plain side")
    inner = EmailMessage()
    inner["Subject"] = "inner"
    long_url = "https://example.test/" + ("a" * 3000)
    inner.set_content(f"see {long_url}")
    related = EmailMessage()
    related.make_related()
    related.attach(inner)
    message.make_alternative()
    message.attach(related)
    parsed = parse_eml(message.as_bytes())
    evaluate(parsed)
    assert all(len(url.normalized) <= 2048 for url in parsed.urls)


def test_huge_header_is_clipped_or_rejected():
    raw = b"From: a@example.test\r\nSubject: " + (b"A" * 400_000) + b"\r\n\r\nHi\r\n"
    try:
        parsed = parse_eml(raw)
    except ParseRejection as exc:
        assert exc.code in {"invalid_content", "empty_file"}
        return
    assert parsed.subject is not None
    assert len(parsed.subject) <= 500
    evaluate(parsed)
