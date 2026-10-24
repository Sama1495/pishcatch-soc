import logging

from app.agent.tools import ALLOWED_TOOLS
from tests.paths import SAMPLES


def upload(client, name: str):
    payload = (SAMPLES / name).read_bytes()
    return client.post(
        "/api/v1/incidents",
        files={"file": (name, payload, "message/rfc822")},
    )


def test_tool_allowlist_has_no_fetch_or_shell():
    assert "simulate_quarantine" in ALLOWED_TOOLS
    assert "parse_email" in ALLOWED_TOOLS
    blob = " ".join(ALLOWED_TOOLS)
    assert "shell" not in blob
    assert "fetch" not in blob
    assert "urlopen" not in blob


def test_end_to_end_phishing_flow(client, caplog):
    caplog.set_level(logging.INFO, logger="phishcatch")
    created = upload(client, "clearly_phishing.eml")
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["sender_address"] == "billing@paypa1-secure.example"
    assert body["subject"].startswith("Urgent action required")
    assert body["risk_label"] == "likely_malicious"
    assert body["machine_risk_label"] == "likely_malicious"
    assert body["label_source"] == "deterministic_rules"
    assert body["urls"]
    assert all("hxxp" in url["defanged"] for url in body["urls"])
    assert any(url["is_ip_literal"] for url in body["urls"])
    assert body["evidence"]
    assert all(item["reason"] and item["provenance"]["producer"] for item in body["evidence"])
    assert body["recommended_actions"]
    assert any("quarantine" in action.lower() for action in body["recommended_actions"])
    assert body["brief"]["summary"]
    assert body["brief"]["assessment"]["risk_label"] == "likely_malicious"
    assert body["brief"]["sources_consulted"]
    assert body["brief"]["limitations"]
    assert body["enrichment_status"] == "disabled"
    assert body["explainer_status"] == "disabled"
    assert body["processing_time_ms"] >= 0
    assert body["case_status"] == "open"
    assert body["headers"]["received"]
    assert "not executed" not in body["body_excerpt"]
    rule_ids = {item["rule_id"] for item in body["evidence"]}
    assert "url_text_href_mismatch" in rule_ids
    assert "risky_attachment_extension" in rule_ids

    log_text = caplog.text.lower()
    assert "verify your account" not in log_text
    assert "service@paypal.com" not in log_text
    assert "203.0.113.50" not in log_text
    assert "not executed" not in log_text

    listed = client.get("/api/v1/incidents")
    assert listed.status_code == 200
    queue = listed.json()
    assert queue["total"] == 1
    item = queue["items"][0]
    assert item["incident_id"] == body["incident_id"]
    assert "body_text" not in item
    assert "body_excerpt" not in item
    assert item["url_count"] >= 1
    assert item["attachment_count"] >= 1
    assert item["auth_trust"] in {"absent", "untrusted", "trusted"}
    assert item["sender_domain"]
    assert item["verdict"] is None
    assert item["action_decision"] is None

    detail = client.get(f"/api/v1/incidents/{body['incident_id']}")
    assert detail.status_code == 200
    case = detail.json()
    assert "verify your account" in case["body_text"].lower()
    assert any(event["event_type"] == "analysis_completed" for event in case["audit_events"])
    assert case["audit_events"][0]["actor"]
    assert case["audit_events"][0]["created_at"]
    assert case["processing_time_ms"] == body["processing_time_ms"]

    decision = client.post(
        f"/api/v1/incidents/{body['incident_id']}/decisions",
        json={
            "action": "correct",
            "corrected_label": "suspicious",
            "reason": "Links were part of a sanctioned exercise.",
            "analyst_id": "analyst.1",
        },
    )
    assert decision.status_code == 200, decision.text
    recorded = decision.json()
    assert recorded["action"] == "correct"
    assert recorded["analyst_id"] == "analyst.1"
    assert recorded["previous_label"] == "likely_malicious"

    updated = client.get(f"/api/v1/incidents/{body['incident_id']}").json()
    assert updated["risk_label"] == "suspicious"
    assert updated["machine_risk_label"] == "likely_malicious"
    assert updated["label_source"] == "analyst_corrected"
    assert updated["case_status"] == "closed"
    assert updated["brief"]["assessment"]["risk_label"] == "likely_malicious"
    assert any(event["event_type"] == "analyst_decision" for event in updated["audit_events"])
    decision_audit = next(
        event for event in updated["audit_events"] if event["event_type"] == "analyst_decision"
    )
    assert decision_audit["actor"] == "analyst.1"
    assert decision_audit["detail"]["rules_updated"] is False
    assert "sanctioned exercise" not in str(decision_audit["detail"])

    again = upload(client, "clearly_phishing.eml")
    assert again.status_code == 201
    second = again.json()
    assert second["machine_risk_label"] == "likely_malicious"
    assert "related_indicator_in_prior_case" in {item["rule_id"] for item in second["evidence"]}

    quarantine = client.post(
        f"/api/v1/incidents/{body['incident_id']}/actions/quarantine",
        json={"analyst_id": "analyst.1", "reason": "Contain the reported lure during the exercise."},
    )
    assert quarantine.status_code == 200, quarantine.text
    simulated = quarantine.json()
    assert simulated["simulated"] is True
    assert simulated["external_effect"] == "none"
    assert "no mailbox" in simulated["message"].lower()
    final = client.get(f"/api/v1/incidents/{body['incident_id']}").json()
    assert final["case_status"] == "quarantine_simulated"
    assert any(event["event_type"] == "quarantine_simulated" for event in final["audit_events"])


def test_no_signal_upload_is_not_safe(client):
    response = upload(client, "no_signals.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["risk_label"] == "inconclusive"
    assert "not declared safe" in body["caveat"]
    assert not any(item["polarity"] == "suspicious" for item in body["evidence"])
    assert any(item["rule_id"] == "no_suspicious_signals" for item in body["evidence"])
    assert any("not" in action.lower() and "safe" in action.lower() for action in body["recommended_actions"])
    assert body["explainer_status"] == "disabled"
    assert body["enrichment_status"] == "disabled"


def test_benign_upload_keeps_the_caveat(client):
    response = upload(client, "clearly_benign.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["risk_label"] == "inconclusive"
    assert "not declared safe" in body["caveat"]
    assert "trusted list" in body["caveat"]
    assert body["headers"]["auth_trust"] == "untrusted"
    assert any("safe" in action.lower() for action in body["recommended_actions"])


def test_ambiguous_upload(client):
    response = upload(client, "ambiguous.eml")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["risk_label"] == "suspicious"
    assert "url_shortener" in {item["rule_id"] for item in body["evidence"]}


def test_uppercase_extension_is_accepted(client):
    payload = (SAMPLES / "no_signals.eml").read_bytes()
    response = client.post(
        "/api/v1/incidents",
        files={"file": ("Notes.EML", payload, "message/rfc822")},
    )
    assert response.status_code == 201


def test_confirm_decision_and_invalid_decision(client):
    created = upload(client, "ambiguous.eml")
    incident_id = created.json()["incident_id"]
    bad = client.post(
        f"/api/v1/incidents/{incident_id}/decisions",
        json={"action": "correct", "reason": "Missing the replacement label."},
    )
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "invalid_decision"

    confirmed = client.post(
        f"/api/v1/incidents/{incident_id}/decisions",
        json={"action": "confirm", "reason": "The shortener is enough to keep the case suspicious."},
    )
    assert confirmed.status_code == 200, confirmed.text
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["label_source"] == "analyst_confirmed"
    assert detail["risk_label"] == "suspicious"
    assert detail["case_status"] == "closed"


def test_unknown_incident_is_a_controlled_404(client):
    missing = client.get("/api/v1/incidents/not-a-case")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "incident_not_found"


def test_queue_filter(client):
    upload(client, "clearly_phishing.eml")
    upload(client, "no_signals.eml")
    filtered = client.get("/api/v1/incidents", params={"risk_label": "inconclusive"})
    assert filtered.status_code == 200
    body = filtered.json()
    assert body["total"] == 1
    assert body["items"][0]["risk_label"] == "inconclusive"
