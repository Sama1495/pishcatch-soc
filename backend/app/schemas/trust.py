"""Confidence, policy decision, timeline, and human-loop contracts."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ConfidenceBand, StepStatus


class ConfidenceComponentOut(BaseModel):
    key: str
    label: str
    score: int
    weight: float
    weighted_points: float
    explanation: str


class ConfidenceOut(BaseModel):
    score: int = Field(ge=0, le=100)
    band: ConfidenceBand
    formula_version: str
    ruleset: str
    raw_score: float
    cap: int
    cap_applied: bool
    disclaimer: str
    components: list[ConfidenceComponentOut]


class PolicyDecisionOut(BaseModel):
    policy_version: str
    rule_id: str
    autonomy: str
    offered_action: str
    offered_action_label: str
    requires_human_approval: bool
    auto_execute: bool
    summary: str
    calibration_note: str
    forced_auto_execute_off: bool = False


class TimelineStepOut(BaseModel):
    step_id: str
    title: str
    status: StepStatus
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int = Field(ge=0)
    provenance: dict


class VerdictFeedbackCreate(BaseModel):
    verdict: str = Field(description="correct or wrong")
    reason: str = Field(min_length=3, max_length=2000)
    analyst_id: str = Field(default="local-analyst", min_length=1, max_length=120)
    corrected_label: str | None = None


class VerdictFeedbackOut(BaseModel):
    id: str
    incident_id: str
    verdict: str
    previous_label: str
    corrected_label: str | None = None
    reason: str
    analyst_id: str
    ruleset_version: str
    rules_updated: bool = False
    created_at: datetime


class ActionResponseCreate(BaseModel):
    decision: str = Field(description="approve or reject")
    reason: str = Field(min_length=3, max_length=2000)
    analyst_id: str = Field(default="local-analyst", min_length=1, max_length=120)


class ActionResponseOut(BaseModel):
    id: str
    incident_id: str
    decision: str
    offered_action: str
    reason: str
    analyst_id: str
    case_status: str
    simulated: bool
    external_effect: str
    message: str
    created_at: datetime


class MetricsOut(BaseModel):
    ruleset: str
    case_count: int
    cases_by_label: dict[str, int]
    average_processing_time_ms: float | None
    completed_human_reviews: int = 0
    average_human_review_ms: float | None = None
    agreements: int
    disagreements: int
    feedback_total: int
    raw_agreement_rate: float | None
    shrunk_agreement_percent: int
    disclaimer: str
