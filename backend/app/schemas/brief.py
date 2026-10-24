"""Incident Brief. Produced from evidence the engine actually observed."""

from pydantic import BaseModel, Field

from app.schemas.common import RiskLabel
from app.schemas.evidence import Evidence
from app.schemas.indicator import Indicator


class Assessment(BaseModel):
    risk_label: RiskLabel
    risk_score: int
    origin: str = "deterministic_rules"
    rationale: str
    caveat: str


class SourceConsulted(BaseModel):
    name: str
    status: str
    detail: str


class IncidentBrief(BaseModel):
    summary: str
    indicators: list[Indicator]
    evidence: list[Evidence]
    assessment: Assessment
    recommended_actions: list[str]
    sources_consulted: list[SourceConsulted]
    limitations: list[str] = Field(default_factory=list)
