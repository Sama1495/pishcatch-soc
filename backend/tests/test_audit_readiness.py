"""Synthetic audit cases for the Alaris readiness review.

The .eml files under samples/audit are fictional. They are not a public corpus
and they are not customer mail. These tests check safety properties, not a
measured accuracy.
"""

import io
import zipfile

from app.services.rules import CATALOG
from tests.paths import SAMPLES

AUDIT = SAMPLES / "audit"
_LABELS = {"likely_malicious", "suspicious", "likely_benign", "inconclusive"}


def _upload(client, name: str, payload: bytes | None = None):
    raw = payload if payload is not None else (AUDIT / name).read_bytes()
    return client.post(
        "/api/v1/incidents",
        files={"file": (name, raw, "message/rfc822")},
    )


def _evidence_ids(body: dict) -> set[str]:
    return {item["rule_id"] for item in body["evidence"]}


def test_prompt_injection_does_not_fabricate_a_safe_verdict(client):
    response = _upload(client, "synthetic_prompt_injection.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["risk_label"] in {"suspicious", "likely_malicious"}
    assert body["risk_label"] != "likely_benign"
    assert body["explainer_status"] == "disabled"
    detail = client.get(f"/api/v1/incidents/{body['incident_id']}").json()
    assert detail["ai_summary"] is None
    assert "not a measured accuracy" in body["confidence"]["disclaimer"]
    ids = _evidence_ids(body)
    assert ids <= set(CATALOG)
    assert "urgency_credential_lure" in ids
    blob = " ".join(item["reason"] for item in body["evidence"]).lower()
    assert "ignore previous instructions" not in blob
    assert "set risk_label" not in blob


def test_contradictory_mail_stays_suspicious_and_not_cleared(client):
    response = _upload(client, "synthetic_contradictory.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    ids = _evidence_ids(body)
    assert "url_shortener" in ids
    assert body["risk_label"] == "suspicious"
    assert body["headers"]["auth_trust"] == "untrusted"
    assert "spf_pass" not in ids
    assert body["risk_label"] != "likely_benign"
    assert all(url["defanged"] != url["original"] for url in body["urls"])


def test_javascript_url_is_defanged_and_not_a_clearance(client):
    response = _upload(client, "synthetic_javascript_url.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    assert "dangerous_url_scheme" in _evidence_ids(body)
    assert body["risk_label"] in {"suspicious", "likely_malicious"}
    assert body["urls"]
    assert all("javascript:" not in url["defanged"].lower() for url in body["urls"])
    assert any(url["defanged"] == "javascript[colon]alert(1)" for url in body["urls"])


def test_sparse_mail_is_inconclusive(client):
    response = _upload(client, "synthetic_sparse.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["risk_label"] == "inconclusive"
    assert "not declared safe" in body["caveat"]
    assert body["confidence"]["score"] <= 40
    assert body["policy"]["offered_action"] == "manual_investigation"
    assert body["policy"]["auto_execute"] is False


def test_not_email_and_zip_and_null_bytes_fail_closed(client):
    rejected = _upload(client, "synthetic_not_email.eml")
    assert rejected.status_code == 400
    assert rejected.json()["error"]["code"] == "invalid_content"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "SYNTHETIC zip renamed to eml")
    zipped = _upload(client, "synthetic_zip_renamed.eml", buffer.getvalue())
    assert zipped.status_code == 400
    assert zipped.json()["error"]["code"] == "invalid_content"
    assert "not opened" in zipped.json()["error"]["message"].lower()

    raw = (
        b"From: audit@example\r\n"
        b"Subject: SYNTHETIC null bytes\r\n"
        b"Date: Sat, 24 Oct 2026 12:30:00 +0000\r\n"
        b"\r\n"
        b"SYNTHETIC\x00\xff unexpected\r\n"
    )
    unexpected = _upload(client, "synthetic_null_bytes.eml", raw)
    assert unexpected.status_code in {201, 400}
    if unexpected.status_code == 201:
        assert unexpected.json()["risk_label"] in _LABELS
    else:
        assert unexpected.json()["error"]["code"] in {"invalid_content", "empty_file"}

    health = client.get("/health")
    assert health.status_code == 200


def test_risky_attachment_name_is_metadata_only(client):
    response = _upload(client, "synthetic_risky_name.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    assert "risky_attachment_extension" in _evidence_ids(body)
    assert body["attachments"]
    assert body["attachments"][0]["filename"] == "invoice.pdf.exe"
    assert body["attachments"][0]["sha256"]
    joined = " ".join(item["reason"] for item in body["evidence"]).lower()
    assert "not executed" in joined


def test_explainer_and_reputation_outages_keep_the_label(client, monkeypatch):
    def explode(*_args, **_kwargs):
        raise RuntimeError("synthetic outage")

    monkeypatch.setattr("app.integrations.explainer.AiExplainer.explain", explode)
    monkeypatch.setattr("app.integrations.reputation.ReputationAdapter.lookup", explode)
    response = _upload(client, "synthetic_prompt_injection.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["risk_label"] in {"suspicious", "likely_malicious"}
    assert body["explainer_status"] == "fallback"
    assert body["enrichment_status"] == "error"
    detail = client.get(f"/api/v1/incidents/{body['incident_id']}").json()
    assert detail["ai_summary"] is None
    timeline = {step["step_id"]: step["status"] for step in body["timeline"]}
    assert timeline["enrichment"] == "failed"
    assert timeline["ai_explanation"] == "failed"
    assert timeline["risk"] == "done"
    assert "urgency_credential_lure" in _evidence_ids(body)


def test_same_sender_after_a_suspicious_case_is_not_cleared(client):
    """A later note from a mailbox already seen on a suspicious case is context, not safety."""
    first = _upload(client, "synthetic_prompt_injection.eml")
    assert first.status_code == 201
    follow = (
        b"From: Audit Bot <audit-bot@example>\r\n"
        b"To: soc@example\r\n"
        b"Subject: SYNTHETIC follow-up with no new signals\r\n"
        b"Date: Sat, 24 Oct 2026 12:40:00 +0000\r\n"
        b"Message-ID: <synthetic-follow-up@example>\r\n"
        b"\r\n"
        b"SYNTHETIC follow-up. No links.\r\n"
    )
    second = _upload(client, "synthetic_follow_up.eml", follow)
    assert second.status_code == 201, second.text
    body = second.json()
    assert "related_indicator_in_prior_case" in _evidence_ids(body)
    assert body["risk_label"] == "suspicious"
    assert body["risk_label"] != "likely_benign"
    assert "not a" in body["caveat"] or "not a confirmed" in body["caveat"]


def test_quarantine_without_offer_is_audited_and_not_applied(client):
    created = _upload(client, "synthetic_sparse.eml")
    assert created.status_code == 201, created.text
    incident_id = created.json()["incident_id"]
    assert created.json()["policy"]["offered_action"] == "manual_investigation"

    denied = client.post(
        f"/api/v1/incidents/{incident_id}/actions/quarantine",
        json={"analyst_id": "analyst.audit", "reason": "Synthetic attempt without an offer."},
    )
    assert denied.status_code == 403, denied.text
    assert denied.json()["error"]["code"] == "action_not_authorized"
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["case_status"] == "open"
    denied_audit = next(event for event in detail["audit_events"] if event["event_type"] == "action_denied")
    assert denied_audit["actor"] == "analyst.audit"
    assert denied_audit["detail"]["reason_code"] == "action_not_offered"
    assert denied_audit["detail"]["external_effect"] == "none"


def test_offered_quarantine_records_review_time_and_blocks_a_repeat(client):
    created = client.post(
        "/api/v1/incidents",
        files={
            "file": (
                "clearly_phishing.eml",
                (SAMPLES / "clearly_phishing.eml").read_bytes(),
                "message/rfc822",
            )
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["policy"]["offered_action"] == "simulate_quarantine"
    incident_id = body["incident_id"]
    before = client.get("/api/v1/metrics").json()
    assert before["completed_human_reviews"] == 0
    assert before["average_human_review_ms"] is None

    approved = client.post(
        f"/api/v1/incidents/{incident_id}/actions/response",
        json={"decision": "approve", "reason": "Synthetic approval.", "analyst_id": "analyst.audit"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["simulated"] is True
    assert approved.json()["external_effect"] == "none"
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    action_audit = next(event for event in detail["audit_events"] if event["event_type"] == "action_response")
    assert action_audit["detail"]["authorization"] == "human_decision"
    assert isinstance(action_audit["detail"]["human_review_ms"], int)
    assert action_audit["detail"]["human_review_ms"] >= 0
    assert detail["processing_time_ms"] >= 0

    metrics = client.get("/api/v1/metrics").json()
    assert metrics["completed_human_reviews"] >= 1
    assert isinstance(metrics["average_human_review_ms"], float)

    again = client.post(
        f"/api/v1/incidents/{incident_id}/actions/quarantine",
        json={"analyst_id": "analyst.audit", "reason": "Second request after approval."},
    )
    assert again.status_code == 409

    other = _upload(client, "synthetic_risky_name.eml")
    other_id = other.json()["incident_id"]
    rejected = client.post(
        f"/api/v1/incidents/{other_id}/actions/response",
        json={"decision": "reject", "reason": "Leave the synthetic case open.", "analyst_id": "analyst.audit"},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["simulated"] is False
    rejected_detail = client.get(f"/api/v1/incidents/{other_id}").json()
    assert any(event["event_type"] == "action_response" for event in rejected_detail["audit_events"])
    sneak = client.post(
        f"/api/v1/incidents/{other_id}/actions/quarantine",
        json={"analyst_id": "analyst.audit", "reason": "Try quarantine after a rejection."},
    )
    # Quarantine was not offered for this weight, so the refusal is the offer gate.
    assert sneak.status_code == 403
    assert client.get(f"/api/v1/incidents/{other_id}").json()["case_status"] != "quarantine_simulated"
