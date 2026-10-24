from app.services.parser import parse_eml
from app.services.risk import CAVEAT_BENIGN, CAVEAT_INCONCLUSIVE, classify
from app.services.rules import CATALOG, evaluate
from tests.paths import SAMPLES

PHISHING_RULES = {
    "display_name_domain_mismatch",
    "reply_to_mismatch",
    "return_path_mismatch",
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "lookalike_domain",
    "url_text_href_mismatch",
    "ip_literal_url",
    "urgency_credential_lure",
    "risky_attachment_extension",
}


def test_catalog_is_documented():
    assert CATALOG
    for spec in CATALOG.values():
        assert spec.title
        assert len(spec.description) > 20
        assert spec.severity in {"info", "low", "medium", "high"}
        assert spec.polarity in {"suspicious", "benign_support", "info"}


def _trust(monkeypatch, ids: str) -> None:
    monkeypatch.setenv("PHISHCATCH_TRUSTED_AUTHSERV_IDS", ids)
    from app.core.config import get_settings

    get_settings.cache_clear()


def test_phishing_sample_hits_expected_rules(monkeypatch):
    _trust(monkeypatch, "mx.contoso.example")
    hits = evaluate(parse_eml((SAMPLES / "clearly_phishing.eml").read_bytes()))
    ids = {hit.rule_id for hit in hits}
    missing = PHISHING_RULES - ids
    assert not missing, missing
    for hit in hits:
        assert hit.rule_id in CATALOG
        assert hit.reason
        assert hit.observed_fields or hit.rule_id == "no_suspicious_signals"
    classification = classify(hits)
    assert classification.label == "likely_malicious"
    assert classification.score >= 55


def test_untrusted_auth_does_not_score_forged_results():
    hits = evaluate(parse_eml((SAMPLES / "clearly_phishing.eml").read_bytes()))
    ids = {hit.rule_id for hit in hits}
    assert "spf_fail" not in ids
    assert "dkim_fail" not in ids
    assert "dmarc_fail" not in ids
    classification = classify(hits)
    assert classification.label == "likely_malicious"


def test_benign_sample_without_trusted_auth_is_not_cleared():
    parsed = parse_eml((SAMPLES / "clearly_benign.eml").read_bytes())
    hits = evaluate(parsed)
    assert parsed.auth_trust == "untrusted"
    assert not any(hit.polarity == "suspicious" for hit in hits)
    assert "spf_pass" not in {hit.rule_id for hit in hits}
    classification = classify(hits)
    assert classification.label == "inconclusive"
    assert classification.caveat == CAVEAT_INCONCLUSIVE


def test_benign_sample_has_no_suspicious_hits(monkeypatch):
    _trust(monkeypatch, "mx.contoso.example")
    hits = evaluate(parse_eml((SAMPLES / "clearly_benign.eml").read_bytes()))
    assert not any(hit.polarity == "suspicious" for hit in hits)
    assert {"spf_pass", "dkim_pass", "dmarc_pass"}.issubset({hit.rule_id for hit in hits})
    classification = classify(hits)
    assert classification.label == "likely_benign"
    assert classification.caveat == CAVEAT_BENIGN
    assert "not proof" in classification.caveat


def test_no_signals_are_not_declared_safe():
    hits = evaluate(parse_eml((SAMPLES / "no_signals.eml").read_bytes()))
    assert not any(hit.polarity == "suspicious" for hit in hits)
    classification = classify(hits)
    assert classification.label == "inconclusive"
    assert classification.label != "likely_benign"
    assert classification.caveat == CAVEAT_INCONCLUSIVE
    assert "not declared safe" in classification.caveat
    assert "safe to" not in classification.caveat.lower()


def test_ambiguous_sample_is_suspicious_not_malicious():
    hits = evaluate(parse_eml((SAMPLES / "ambiguous.eml").read_bytes()))
    ids = {hit.rule_id for hit in hits}
    assert "url_shortener" in ids
    classification = classify(hits)
    assert classification.label == "suspicious"


def test_spanish_lure_phrase():
    from app.services.parsed import ParsedEmail

    parsed = ParsedEmail(
        sender_address="alerts@contoso.example",
        sender_domain="contoso.example",
        subject="Aviso",
        body_text="Se requiere acción inmediata: verifique su cuenta.",
    )
    ids = {hit.rule_id for hit in evaluate(parsed)}
    assert "urgency_credential_lure" in ids


def test_punycode_and_dangerous_scheme_and_credentials():
    from app.services.parsed import NormalizedUrl, ParsedEmail

    parsed = ParsedEmail(
        sender_domain="contoso.example",
        urls=[
            NormalizedUrl(
                original="http://xn--pple-43d.example/a",
                normalized="http://xn--pple-43d.example/a",
                defanged="hxxp://xn--pple-43d[.]example/a",
                scheme="http",
                host="xn--pple-43d.example",
                is_ip_literal=False,
                source="body_text",
            ),
            NormalizedUrl(
                original="javascript:alert(1)",
                normalized="javascript:alert(1)",
                defanged="javascript[colon]alert(1)",
                scheme="javascript",
                host=None,
                is_ip_literal=False,
                source="html_href",
            ),
            NormalizedUrl(
                original="http://user:secret@evil.example/a",
                normalized="http://evil.example/a",
                defanged="hxxp://evil[.]example/a",
                scheme="http",
                host="evil.example",
                is_ip_literal=False,
                source="body_text",
                had_userinfo=True,
            ),
        ],
    )
    ids = {hit.rule_id for hit in evaluate(parsed)}
    assert "punycode_domain" in ids
    assert "dangerous_url_scheme" in ids
    assert "url_embedded_credentials" in ids
    reasons = " ".join(hit.reason for hit in evaluate(parsed))
    assert "secret" not in reasons
