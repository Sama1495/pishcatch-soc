from datetime import datetime, timedelta, timezone

from app.services.parser import parse_eml
from app.services.risk import classify
from app.services.rules import evaluate
from tests.paths import SAMPLES


def test_clean_auth_lure_is_malicious_without_trusting_spf():
    parsed = parse_eml((SAMPLES / "certification_lure_clean_auth.eml").read_bytes())
    assert parsed.subject == (
        "Daniel, your AWS Certified Machine Learning badge is waiting for verification"
    )
    assert parsed.auth_trust == "untrusted"
    assert parsed.spf is None
    hits = evaluate(parsed)
    ids = {hit.rule_id for hit in hits}
    assert "spf_pass" not in ids
    assert "credential_or_sso_request" in ids
    assert "payment_for_credential_or_job" in ids
    assert "certification_badge_lure" in ids
    assert "brand_in_body_unaligned" in ids
    assert "osint_personalization" in ids
    assert "deadline_pressure" in ids
    assert classify(hits).label == "likely_malicious"
    assert classify(hits).score >= 55


def test_multipart_certification_lure_is_malicious():
    parsed = parse_eml((SAMPLES / "certification_lure.eml").read_bytes())
    assert parsed.subject == (
        "Daniel, action required: claim your AWS Certified Machine Learning badge within 24 hours"
    )
    hits = evaluate(parsed)
    ids = {hit.rule_id for hit in hits}
    assert "display_name_domain_mismatch" in ids
    assert "url_text_href_mismatch" in ids
    assert "credential_or_sso_request" in ids
    assert "payment_for_credential_or_job" in ids
    assert "freemail_corporate_claim" in ids
    assert classify(hits).label == "likely_malicious"


def test_linkedin_learning_notice_does_not_fire_payment_or_badge():
    parsed = parse_eml((SAMPLES / "certification_benign.eml").read_bytes())
    assert parsed.subject == "Your certificate of completion is ready"
    hits = evaluate(parsed)
    ids = {hit.rule_id for hit in hits}
    assert "payment_for_credential_or_job" not in ids
    assert "credential_or_sso_request" not in ids
    assert "certification_badge_lure" not in ids
    assert not any(hit.polarity == "suspicious" for hit in hits)


def test_spanish_badge_payment_phrases_still_match():
    from app.services.parsed import ParsedEmail

    parsed = ParsedEmail(
        sender_address="a@news.example",
        sender_domain="news.example",
        subject="Tu insignia",
        body_text="Paga la tarifa de verificacion y reclama tu insignia de certificacion.",
    )
    hits = evaluate(parsed)
    ids = {hit.rule_id for hit in hits}
    assert "payment_for_credential_or_job" in ids
    assert "certification_badge_lure" in ids
    assert classify(hits).label == "suspicious"


def test_currency_token_without_a_pay_request_is_not_malicious():
    from app.services.parsed import ParsedEmail

    parsed = ParsedEmail(
        sender_address="news@newsletter.example",
        sender_domain="newsletter.example",
        subject="AWS certification notes",
        body_text="The AWS certification exam listed on the site is USD 49.",
    )
    hits = evaluate(parsed)
    ids = {hit.rule_id for hit in hits}
    assert "payment_for_credential_or_job" not in ids
    assert "certification_badge_lure" not in ids
    assert classify(hits).label not in {"likely_malicious", "suspicious"}


def test_mailing_list_skips_envelope_mismatches():
    from app.services.parsed import ParsedEmail

    parsed = ParsedEmail(
        sender_domain="lists.example",
        sender_address="owner@lists.example",
        reply_to_domains=["users.example"],
        return_path_domain=["bounces.example"][0],
        mailing_list=True,
        subject="digest",
        body_text="Monthly notes.",
    )
    ids = {hit.rule_id for hit in evaluate(parsed)}
    assert "reply_to_mismatch" not in ids
    assert "return_path_mismatch" not in ids


def test_rdap_hit_is_opt_in(monkeypatch):
    from app.core.config import get_settings
    from app.integrations import rdap
    from app.services.parsed import ParsedEmail

    monkeypatch.setenv("PHISHCATCH_RDAP_ENABLED", "true")
    get_settings.cache_clear()
    rdap.set_lookup(lambda domain, timeout: datetime.now(timezone.utc) - timedelta(days=3))
    try:
        parsed = ParsedEmail(sender_domain="new-brand.com", sender_address="a@new-brand.com")
        ids = {hit.rule_id for hit in evaluate(parsed)}
        assert "newly_registered_domain" in ids
    finally:
        rdap.set_lookup(None)
        get_settings.cache_clear()
