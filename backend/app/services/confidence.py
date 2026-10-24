"""Deterministic confidence in the agent's own verdict.

Confidence is not the risk score and it is not a measured accuracy.
The weights, caps, and prior live in ``trust_policy.json`` so the same file
the policy engine reads is the formula the score uses.
"""

from dataclasses import dataclass

from app.policy.engine import load_policy
from app.services.rules import RULESET_VERSION, RuleHit

DISCLAIMER = (
    "Confidence is a deterministic score for how strongly this ruleset supports its own verdict. "
    "It is not a measured accuracy and it is not a probability that the label is correct."
)


@dataclass(frozen=True)
class ConfidenceComponent:
    key: str
    label: str
    score: int
    weight: float
    weighted_points: float
    explanation: str

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "score": self.score,
            "weight": self.weight,
            "weighted_points": round(self.weighted_points, 2),
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class ConfidenceReport:
    score: int
    band: str
    formula_version: str
    ruleset: str
    raw_score: float
    cap: int
    cap_applied: bool
    disclaimer: str
    components: list[ConfidenceComponent]

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "band": self.band,
            "formula_version": self.formula_version,
            "ruleset": self.ruleset,
            "raw_score": round(self.raw_score, 2),
            "cap": self.cap,
            "cap_applied": self.cap_applied,
            "disclaimer": self.disclaimer,
            "components": [item.as_dict() for item in self.components],
        }


def compute_confidence(
    *,
    label: str,
    risk_score: int,
    hits: list[RuleHit],
    source_statuses: dict[str, str],
    agreements: int,
    disagreements: int,
    formula: dict | None = None,
) -> ConfidenceReport:
    formula = formula or load_policy()["confidence_formula"]
    weights = formula["weights"]
    agreement, agreement_why = _evidence_agreement(label, risk_score, hits, formula)
    clarity, clarity_why = _conflict_clarity(hits)
    coverage, coverage_why = _coverage(source_statuses, formula["coverage_weights"])
    history, history_why = _historical(
        agreements,
        disagreements,
        int(formula["historical_prior"]["pseudo_count"]),
        float(formula["historical_prior"]["rate"]),
    )
    components = [
        _component("evidence_agreement", "Evidence agreement", agreement, weights["evidence_agreement"], agreement_why),
        _component("coverage", "Source coverage", coverage, weights["coverage"], coverage_why),
        _component("conflict_clarity", "Conflicting signals", clarity, weights["conflict_clarity"], clarity_why),
        _component(
            "historical_agreement",
            "Historical agreement",
            history,
            weights["historical_agreement"],
            history_why,
        ),
    ]
    raw = sum(item.weighted_points for item in components)
    cap = int(formula["label_caps"].get(label, 100))
    capped = min(raw, float(cap))
    score = _round_half_up(capped)
    score = max(0, min(100, score))
    return ConfidenceReport(
        score=score,
        band=_band(score, formula["bands"]),
        formula_version=str(formula.get("version") or "1.0.0"),
        ruleset=RULESET_VERSION,
        raw_score=raw,
        cap=cap,
        cap_applied=raw > cap,
        disclaimer=DISCLAIMER,
        components=components,
    )


def _component(key: str, label: str, score: int, weight: float, explanation: str) -> ConfidenceComponent:
    return ConfidenceComponent(
        key=key,
        label=label,
        score=score,
        weight=float(weight),
        weighted_points=score * float(weight),
        explanation=explanation,
    )


def _evidence_agreement(label: str, risk_score: int, hits: list[RuleHit], formula: dict) -> tuple[int, str]:
    suspicious = {hit.rule_id for hit in hits if hit.polarity == "suspicious"}
    benign = {hit.rule_id for hit in hits if hit.polarity == "benign_support"}
    if label in {"likely_malicious", "suspicious"}:
        score = max(0, min(100, risk_score))
        why = (
            f"Suspicious evidence totals {score} risk points across {len(suspicious)} rule(s)."
        )
        if len(suspicious) <= 1:
            cap = int(formula["single_rule_agreement_cap"])
            score = min(score, cap)
            why += f" A single rule is capped at {cap} in this component."
        elif len(suspicious) == 2:
            cap = int(formula["two_rule_agreement_cap"])
            score = min(score, cap)
            why += f" Two rules are capped at {cap} in this component."
        return score, why
    if label == "likely_benign":
        per_signal = int(formula["benign_agreement_per_signal"])
        cap = int(formula["benign_agreement_cap"])
        score = min(cap, per_signal * len(benign))
        return score, (
            f"{len(benign)} aligning signal(s) contribute {per_signal} points each, "
            f"capped at {cap}. Aligning signals are not proof of safety."
        )
    if benign:
        score = min(35, 12 * len(benign))
        return score, "A few aligning signals exist, but not enough for a firm verdict."
    return 10, "No suspicious or aligning evidence supports a firm verdict."


def _conflict_clarity(hits: list[RuleHit]) -> tuple[int, str]:
    suspicious = {hit.rule_id for hit in hits if hit.polarity == "suspicious"}
    benign = {hit.rule_id for hit in hits if hit.polarity == "benign_support"}
    if suspicious and benign:
        score = max(15, 100 - 18 * len(benign) - 4 * len(suspicious))
        return score, (
            f"Suspicious rules ({len(suspicious)}) and aligning signals ({len(benign)}) "
            "point in different directions."
        )
    if not suspicious and not benign:
        return 40, "There is no conflict because there is also little evidence."
    if suspicious:
        return 100, "No aligning signal contradicts the suspicious rules."
    return 100, "No suspicious signal contradicts the aligning signals."


def _coverage(statuses: dict[str, str], weights: dict[str, int]) -> tuple[int, str]:
    earned = 0
    notes: list[str] = []
    for key, weight in weights.items():
        status = statuses.get(key, "skipped")
        if status == "done":
            earned += int(weight)
            notes.append(f"{key} ran ({weight})")
        elif status == "failed":
            notes.append(f"{key} failed (0 of {weight})")
        else:
            notes.append(f"{key} did not run (0 of {weight})")
    total = sum(int(value) for value in weights.values()) or 1
    score = _round_half_up(earned / total * 100)
    return max(0, min(100, score)), "; ".join(notes) + "."


def _historical(agreements: int, disagreements: int, pseudo_count: int, rate: float) -> tuple[int, str]:
    total = agreements + disagreements
    shrunk = (agreements + pseudo_count * rate) / (total + pseudo_count)
    score = max(0, min(100, _round_half_up(shrunk * 100)))
    if total == 0:
        why = (
            "No analyst verdicts are stored for this ruleset. "
            f"The formula uses an uninformed prior of {int(rate * 100)} "
            f"from {pseudo_count} pseudo-cases. This is not a measured accuracy."
        )
    else:
        why = (
            f"{agreements} agreement(s) and {disagreements} disagreement(s) "
            f"are shrunk toward {int(rate * 100)} with {pseudo_count} pseudo-cases. "
            "This is not a measured accuracy."
        )
    return score, why


def shrunk_agreement_percent(agreements: int, disagreements: int) -> int:
    """Same prior the confidence formula uses. Not a measured accuracy."""
    prior = load_policy()["confidence_formula"]["historical_prior"]
    score, _why = _historical(
        agreements,
        disagreements,
        int(prior["pseudo_count"]),
        float(prior["rate"]),
    )
    return score


def _band(score: int, bands: dict) -> str:
    if score >= int(bands["high_min"]):
        return "high"
    if score >= int(bands["medium_min"]):
        return "medium"
    return "low"


def _round_half_up(value: float) -> int:
    return int(value + 0.5) if value >= 0 else int(value - 0.5)
