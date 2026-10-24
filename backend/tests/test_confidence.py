"""The confidence formula is deterministic and is not an accuracy claim."""

from app.policy.engine import load_policy
from app.services.confidence import DISCLAIMER, compute_confidence
from app.services.rules import make_hit

_DONE = {
    "local_parser": "done",
    "deterministic_rules": "done",
    "local_correlation": "done",
    "reputation": "done",
    "ai_explainer": "done",
}


def test_weights_sum_to_one():
    weights = load_policy()["confidence_formula"]["weights"]
    assert abs(sum(weights.values()) - 1.0) < 1e-9


def test_score_is_the_capped_half_up_round_and_not_accuracy():
    report = compute_confidence(
        label="suspicious",
        risk_score=30,
        hits=[make_hit("lookalike_domain", "Host resembles a protected brand.")],
        source_statuses=_DONE,
        agreements=0,
        disagreements=0,
    )
    expected = int(min(report.raw_score, report.cap) + 0.5)
    assert report.score == max(0, min(100, expected))
    assert "not a measured accuracy" in report.disclaimer
    assert report.disclaimer == DISCLAIMER


def test_no_history_uses_the_uninformed_prior():
    report = compute_confidence(
        label="suspicious",
        risk_score=30,
        hits=[make_hit("lookalike_domain", "Host resembles a protected brand.")],
        source_statuses=_DONE,
        agreements=0,
        disagreements=0,
    )
    history = next(item for item in report.components if item.key == "historical_agreement")
    assert history.score == 50
    assert "prior" in history.explanation.lower()
    assert "not a measured accuracy" in history.explanation


def test_conflicting_signals_lower_the_score():
    suspicious = [make_hit("lookalike_domain", "Host resembles a protected brand.")]
    mixed = [
        *suspicious,
        make_hit("spf_pass", "SPF passed."),
        make_hit("dkim_pass", "DKIM passed."),
    ]
    only = compute_confidence(
        label="suspicious",
        risk_score=30,
        hits=suspicious,
        source_statuses=_DONE,
        agreements=0,
        disagreements=0,
    )
    conflicted = compute_confidence(
        label="suspicious",
        risk_score=30,
        hits=mixed,
        source_statuses=_DONE,
        agreements=0,
        disagreements=0,
    )
    assert conflicted.score < only.score


def test_inconclusive_and_benign_are_capped():
    inconclusive = compute_confidence(
        label="inconclusive",
        risk_score=0,
        hits=[],
        source_statuses=_DONE,
        agreements=0,
        disagreements=0,
    )
    assert inconclusive.score <= 40
    assert inconclusive.cap == 40

    benign = compute_confidence(
        label="likely_benign",
        risk_score=0,
        hits=[
            make_hit("spf_pass", "SPF passed."),
            make_hit("dkim_pass", "DKIM passed."),
            make_hit("dmarc_pass", "DMARC passed."),
            make_hit("reply_to_aligned", "Reply-To aligns."),
        ],
        source_statuses=_DONE,
        agreements=0,
        disagreements=0,
    )
    assert benign.score <= 70
    assert benign.cap == 70
    assert benign.cap_applied is True
