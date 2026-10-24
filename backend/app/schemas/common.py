"""Shared literals for the analysis contract."""

from typing import Literal

RiskLabel = Literal["likely_malicious", "suspicious", "likely_benign", "inconclusive"]
CaseStatus = Literal["open", "in_review", "closed", "quarantine_simulated"]
ConfidenceBand = Literal["high", "medium", "low"]
StepStatus = Literal["done", "skipped", "failed", "waiting"]
LabelSource = Literal["deterministic_rules", "analyst_confirmed", "analyst_corrected"]
IndicatorType = Literal["email", "domain", "url", "ip", "attachment", "header"]
Severity = Literal["info", "low", "medium", "high"]
Polarity = Literal["suspicious", "benign_support", "info"]
