"""Analyst decisions and the simulated quarantine action."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import RiskLabel


class DecisionCreate(BaseModel):
    action: str = Field(description="confirm or correct")
    reason: str = Field(min_length=3, max_length=2000)
    corrected_label: RiskLabel | None = None
    analyst_id: str = Field(default="local-analyst", min_length=1, max_length=120)


class AnalystDecision(BaseModel):
    id: str
    incident_id: str
    action: str
    previous_label: RiskLabel
    corrected_label: RiskLabel | None = None
    reason: str
    analyst_id: str
    created_at: datetime


class QuarantineRequest(BaseModel):
    analyst_id: str = Field(default="local-analyst", min_length=1, max_length=120)
    reason: str = Field(min_length=3, max_length=2000)


class QuarantineResult(BaseModel):
    incident_id: str
    simulated: bool = True
    external_effect: str = "none"
    case_status: str
    message: str
    audit_event_id: str
