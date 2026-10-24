"""Analysis result returned by upload, plus the stored incident views."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.brief import IncidentBrief
from app.schemas.common import CaseStatus, ConfidenceBand, LabelSource, RiskLabel
from app.schemas.decision import AnalystDecision
from app.schemas.evidence import Evidence
from app.schemas.incident import AttachmentOut, KeyHeaderSet, UrlOut
from app.schemas.indicator import Indicator
from app.schemas.trust import (
    ActionResponseOut,
    ConfidenceOut,
    PolicyDecisionOut,
    TimelineStepOut,
    VerdictFeedbackOut,
)


class AuditEventOut(BaseModel):
    id: str
    event_type: str
    actor: str
    created_at: datetime
    detail: dict


class AnalysisResult(BaseModel):
    """What the upload endpoint returns. The risk label is from the rules engine."""

    incident_id: str
    created_at: datetime
    filename: str
    sender: str | None = None
    sender_address: str | None = None
    sender_domain: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    subject: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    headers: KeyHeaderSet
    body_excerpt: str = ""
    urls: list[UrlOut]
    attachments: list[AttachmentOut]
    indicators: list[Indicator]
    evidence: list[Evidence]
    risk_label: RiskLabel
    machine_risk_label: RiskLabel
    risk_score: int
    label_source: LabelSource
    caveat: str
    recommended_actions: list[str]
    brief: IncidentBrief
    case_status: CaseStatus
    processing_time_ms: int = Field(ge=0)
    enrichment_status: str
    explainer_status: str
    confidence: ConfidenceOut
    policy: PolicyDecisionOut
    timeline: list[TimelineStepOut]


class IncidentSummary(BaseModel):
    """Queue row. The body is intentionally absent."""

    incident_id: str
    created_at: datetime
    filename: str
    sender: str | None = None
    sender_address: str | None = None
    subject: str | None = None
    risk_label: RiskLabel
    machine_risk_label: RiskLabel
    risk_score: int
    label_source: LabelSource
    case_status: CaseStatus
    processing_time_ms: int
    enrichment_status: str
    explainer_status: str
    confidence_score: int = 0
    confidence_band: ConfidenceBand = "low"
    offered_action: str | None = None
    autonomy: str | None = None
    sender_domain: str | None = None
    url_count: int = 0
    attachment_count: int = 0
    auth_trust: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    verdict: str | None = None
    action_decision: str | None = None


class IncidentList(BaseModel):
    items: list[IncidentSummary]
    total: int


class BatchItem(BaseModel):
    filename: str
    incident_id: str | None = None
    risk_label: str | None = None
    error_code: str | None = None
    error_message: str | None = None


class BatchResult(BaseModel):
    accepted: int
    failed: int
    items: list[BatchItem]


class IncidentDetail(AnalysisResult):
    body_text: str = ""
    ai_summary: str | None = None
    decisions: list[AnalystDecision] = Field(default_factory=list)
    audit_events: list[AuditEventOut] = Field(default_factory=list)
    verdict_feedback: list[VerdictFeedbackOut] = Field(default_factory=list)
    action_response: ActionResponseOut | None = None
