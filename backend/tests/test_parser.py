import pytest

from app.services.exceptions import ParseRejection
from app.services.parser import parse_eml
from tests.paths import SAMPLES


def test_parses_phishing_sample():
    parsed = parse_eml((SAMPLES / "clearly_phishing.eml").read_bytes())
    assert parsed.sender_address == "billing@paypa1-secure.example"
    assert parsed.sender_domain == "paypa1-secure.example"
    assert "paypal.com" in (parsed.sender_display or "")
    assert parsed.reply_to_domains == ["evil-collect.example"]
    assert parsed.return_path_domain == "evil-collect.example"
    assert parsed.subject == "Urgent action required: verify your account"
    assert parsed.auth_trust == "untrusted"
    assert parsed.spf is None
    assert parsed.dkim is None
    assert parsed.dmarc is None
    assert len(parsed.received) == 2
    assert parsed.authentication_results
    hosts = {url.host for url in parsed.urls}
    assert "paypa1-secure.example" in hosts
    assert "203.0.113.50" in hosts
    assert any(url.is_ip_literal for url in parsed.urls)
    assert all("[.]" in url.defanged for url in parsed.urls)
    assert all(not url.defanged.lower().startswith("http") for url in parsed.urls)
    assert any(item.filename == "invoice.html" for item in parsed.attachments)
    attachment = next(item for item in parsed.attachments if item.filename == "invoice.html")
    assert attachment.extension == ".html"
    assert attachment.size_bytes > 0
    assert len(attachment.sha256) == 64
    assert "not executed" not in parsed.body_text
    assert "verify your account" in parsed.body_text.lower()


def test_parses_benign_sample():
    parsed = parse_eml((SAMPLES / "clearly_benign.eml").read_bytes())
    assert parsed.sender_address == "alex.rivera@contoso.example"
    assert parsed.auth_trust == "untrusted"
    assert parsed.spf is None
    assert parsed.dkim is None
    assert parsed.dmarc is None
    assert parsed.reply_to_domains == ["contoso.example"]
    assert any(url.host == "intranet.contoso.example" for url in parsed.urls)
    assert parsed.attachments == []


def test_malformed_sample_is_rejected():
    with pytest.raises(ParseRejection) as caught:
        parse_eml((SAMPLES / "malformed.eml").read_bytes())
    assert caught.value.code == "invalid_content"


def test_trusted_authserv_scores_authentication_results(monkeypatch):
    monkeypatch.setenv("PHISHCATCH_TRUSTED_AUTHSERV_IDS", "mx.contoso.example")
    from app.core.config import get_settings

    get_settings.cache_clear()
    parsed = parse_eml((SAMPLES / "clearly_phishing.eml").read_bytes())
    assert parsed.auth_trust == "trusted"
    assert parsed.spf == "fail"
    assert parsed.dkim == "fail"
    assert parsed.dmarc == "fail"
    benign = parse_eml((SAMPLES / "clearly_benign.eml").read_bytes())
    assert benign.spf == "pass"
    assert benign.dkim == "pass"
    assert benign.dmarc == "pass"
    get_settings.cache_clear()


def test_zip_renamed_as_eml_is_not_opened():
    with pytest.raises(ParseRejection) as caught:
        parse_eml(b"PK\x03\x04" + b"not-really-a-zip-body")
    assert caught.value.code == "invalid_content"
    assert "zip" in caught.value.message


def test_empty_sample_is_rejected():
    with pytest.raises(ParseRejection) as caught:
        parse_eml((SAMPLES / "empty.eml").read_bytes())
    assert caught.value.code == "empty_file"
