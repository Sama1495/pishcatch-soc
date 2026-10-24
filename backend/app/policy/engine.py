"""Apply the trust policy. This module never calls a model and never executes an action."""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

POLICY_PATH = Path(__file__).with_name("trust_policy.json")


@dataclass(frozen=True)
class PolicyDecision:
    policy_version: str
    rule_id: str
    autonomy: str
    offered_action: str
    offered_action_label: str
    requires_human_approval: bool
    auto_execute: bool
    summary: str
    calibration_note: str
    forced_auto_execute_off: bool

    def as_dict(self) -> dict:
        return {
            "policy_version": self.policy_version,
            "rule_id": self.rule_id,
            "autonomy": self.autonomy,
            "offered_action": self.offered_action,
            "offered_action_label": self.offered_action_label,
            "requires_human_approval": self.requires_human_approval,
            "auto_execute": self.auto_execute,
            "summary": self.summary,
            "calibration_note": self.calibration_note,
            "forced_auto_execute_off": self.forced_auto_execute_off,
        }


@lru_cache
def load_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def decide(risk_label: str, confidence_band: str, document: dict | None = None) -> PolicyDecision:
    """Pick the offered action from the policy file.

    ``auto_execute`` is forced off. A file that asks for automatic execution
    still returns a human-approval decision. The MVP does not grow autonomy
    by itself.
    """
    document = document if document is not None else load_policy()
    labels = document.get("action_labels") or {}
    chosen = None
    for rule in document.get("rules") or []:
        label_ok = rule.get("risk_label") in {risk_label, "*"}
        band = rule.get("confidence_band")
        band_ok = band in {confidence_band, "*"}
        if label_ok and band_ok:
            chosen = rule
            break
    if chosen is None:
        chosen = {
            "id": "fallback-manual",
            "autonomy": "manual_investigation",
            "offered_action": "manual_investigation",
            "requires_human_approval": True,
            "summary": "No policy rule matched. Investigate manually.",
        }
    requested_auto = bool(document.get("auto_execute")) or bool(chosen.get("auto_execute"))
    action = chosen.get("offered_action") or "manual_investigation"
    return PolicyDecision(
        policy_version=str(document.get("version") or "unknown"),
        rule_id=str(chosen.get("id") or "unspecified"),
        autonomy=str(chosen.get("autonomy") or "manual_investigation"),
        offered_action=action,
        offered_action_label=str(labels.get(action) or action.replace("_", " ")),
        requires_human_approval=True,
        auto_execute=False,
        summary=str(chosen.get("summary") or ""),
        calibration_note=str(document.get("calibration_note") or ""),
        forced_auto_execute_off=requested_auto,
    )
