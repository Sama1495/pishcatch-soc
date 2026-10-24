"""The policy engine, not the model, chooses the offered action."""

from app.policy.engine import decide


def test_high_confidence_malicious_offers_quarantine_with_approval():
    decision = decide("likely_malicious", "high")
    assert decision.offered_action == "simulate_quarantine"
    assert decision.autonomy == "approve_recommended_action"
    assert decision.requires_human_approval is True
    assert decision.auto_execute is False
    assert decision.forced_auto_execute_off is False


def test_inconclusive_is_manual_at_every_band():
    for band in ("high", "medium", "low"):
        decision = decide("inconclusive", band)
        assert decision.offered_action == "manual_investigation"
        assert decision.auto_execute is False
        assert decision.requires_human_approval is True


def test_a_file_that_asks_to_auto_execute_is_forced_off():
    document = {
        "version": "test",
        "auto_execute": True,
        "calibration_note": "test only",
        "action_labels": {"simulate_quarantine": "Simulate quarantine"},
        "rules": [
            {
                "id": "would-auto",
                "risk_label": "*",
                "confidence_band": "*",
                "autonomy": "auto",
                "offered_action": "simulate_quarantine",
                "auto_execute": True,
                "requires_human_approval": False,
                "summary": "This file asked to skip the human. The engine must not.",
            }
        ],
    }
    decision = decide("likely_malicious", "high", document=document)
    assert decision.auto_execute is False
    assert decision.requires_human_approval is True
    assert decision.forced_auto_execute_off is True
    assert decision.offered_action == "simulate_quarantine"
