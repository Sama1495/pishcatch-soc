"""Timeline, confidence, and the human yes/no plus correct/wrong loop."""

import json
import logging

from tests.test_analyze_flow import upload


def _step(body: dict, step_id: str) -> dict:
    return next(step for step in body["timeline"] if step["step_id"] == step_id)


def test_phishing_timeline_confidence_and_policy(client):
    created = upload(client, "clearly_phishing.eml")
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["confidence"]["band"] == "high"
    assert body["confidence"]["score"] > body["risk_score"] or body["confidence"]["score"] <= 100
    assert "not a measured accuracy" in body["confidence"]["disclaimer"]
    assert body["policy"]["offered_action"] == "simulate_quarantine"
    assert body["policy"]["auto_execute"] is False
    assert body["policy"]["requires_human_approval"] is True
    assert _step(body, "enrichment")["status"] == "skipped"
    assert _step(body, "ai_explanation")["status"] == "skipped"
    assert _step(body, "awaiting_human_decision")["status"] == "waiting"
    assert _step(body, "simulated_action")["status"] == "waiting"
    assert _step(body, "reception")["provenance"]["byte_count"] > 0
    blob = json.dumps(body["timeline"]).lower()
    assert "verify your account" not in blob
    assert "billing@paypa1-secure.example" not in blob
    assert body["subject"].lower() not in blob

    listed = client.get("/api/v1/incidents", params={"confidence_band": "high"})
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["confidence_band"] == "high"


def test_no_signals_skips_simulated_action_and_caps_confidence(client):
    created = upload(client, "no_signals.eml")
    body = created.json()
    assert body["risk_label"] == "inconclusive"
    assert body["confidence"]["score"] <= 40
    assert body["policy"]["offered_action"] == "manual_investigation"
    assert _step(body, "simulated_action")["status"] == "skipped"


def test_queue_is_ordered_by_risk_rank_times_confidence(client):
    upload(client, "clearly_benign.eml")
    upload(client, "clearly_phishing.eml")
    upload(client, "no_signals.eml")
    items = client.get("/api/v1/incidents").json()["items"]
    assert items[0]["risk_label"] == "likely_malicious"
    assert [item["risk_label"] for item in items[1:]] == ["inconclusive", "inconclusive"]


def test_metrics_before_feedback_has_no_raw_rate(client):
    upload(client, "clearly_phishing.eml")
    metrics = client.get("/api/v1/metrics")
    assert metrics.status_code == 200, metrics.text
    body = metrics.json()
    assert body["raw_agreement_rate"] is None
    assert body["feedback_total"] == 0
    assert set(body["cases_by_label"]) == {
        "likely_malicious",
        "suspicious",
        "likely_benign",
        "inconclusive",
    }
    assert body["cases_by_label"]["likely_malicious"] == 1
    assert body["average_processing_time_ms"] is not None
    assert "not a measured accuracy" in body["disclaimer"]
    assert body["shrunk_agreement_percent"] == 50


def test_verdict_and_action_are_audited_and_do_not_change_rules(client, caplog):
    caplog.set_level(logging.INFO, logger="phishcatch")
    reason = "zz-reason-token-not-for-logs"
    created = upload(client, "clearly_phishing.eml")
    incident_id = created.json()["incident_id"]

    wrong = client.post(
        f"/api/v1/incidents/{incident_id}/feedback",
        json={
            "verdict": "wrong",
            "reason": reason,
            "analyst_id": "analyst.1",
        },
    )
    assert wrong.status_code == 200, wrong.text
    assert wrong.json()["rules_updated"] is False
    assert wrong.json()["verdict"] == "wrong"

    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["risk_label"] == "likely_malicious"
    assert detail["machine_risk_label"] == "likely_malicious"
    feedback_audit = next(event for event in detail["audit_events"] if event["event_type"] == "verdict_feedback")
    assert feedback_audit["actor"] == "analyst.1"
    assert reason not in json.dumps(feedback_audit["detail"])
    assert _step(detail, "human_decision")["status"] == "done"

    again = upload(client, "clearly_phishing.eml")
    assert again.status_code == 201
    second = again.json()
    assert second["machine_risk_label"] == "likely_malicious"
    history = next(
        item for item in second["confidence"]["components"] if item["key"] == "historical_agreement"
    )
    assert history["score"] < 50

    approved = client.post(
        f"/api/v1/incidents/{incident_id}/actions/response",
        json={"decision": "approve", "reason": reason, "analyst_id": "analyst.1"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["simulated"] is True
    assert approved.json()["external_effect"] == "none"
    assert approved.json()["case_status"] == "quarantine_simulated"
    final = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert final["case_status"] == "quarantine_simulated"
    assert _step(final, "simulated_action")["status"] == "done"
    assert _step(final, "awaiting_human_decision")["status"] == "done"
    action_audit = next(event for event in final["audit_events"] if event["event_type"] == "action_response")
    assert action_audit["actor"] == "analyst.1"
    assert reason not in json.dumps(action_audit["detail"])

    duplicate_feedback = client.post(
        f"/api/v1/incidents/{incident_id}/feedback",
        json={"verdict": "correct", "reason": "second try", "analyst_id": "analyst.1"},
    )
    assert duplicate_feedback.status_code == 409
    assert duplicate_feedback.json()["error"]["code"] == "already_recorded"
    duplicate_action = client.post(
        f"/api/v1/incidents/{incident_id}/actions/response",
        json={"decision": "reject", "reason": "second try", "analyst_id": "analyst.1"},
    )
    assert duplicate_action.status_code == 409

    other = upload(client, "ambiguous.eml")
    other_id = other.json()["incident_id"]
    rejected = client.post(
        f"/api/v1/incidents/{other_id}/actions/response",
        json={"decision": "reject", "reason": "leave it open", "analyst_id": "analyst.2"},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["simulated"] is False
    assert rejected.json()["case_status"] == "open"
    rejected_detail = client.get(f"/api/v1/incidents/{other_id}").json()
    assert rejected_detail["case_status"] == "open"

    log_text = caplog.text.lower()
    assert "zz-reason-token-not-for-logs" not in log_text
    assert "verify your account" not in log_text
