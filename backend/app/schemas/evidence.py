"""Evidence items. Every hit names the rule, the reason, and its provenance."""

from pydantic import BaseModel, Field

from app.schemas.common import Severity


class Provenance(BaseModel):
    """Where an evidence item came from. Required so a hit is explainable later."""

    producer: str
    version: str
    method: str
    observed_fields: list[str] = Field(default_factory=list)
    notes: str | None = None


class Evidence(BaseModel):
    id: str
    rule_id: str
    title: str
    reason: str
    severity: Severity
    source: str
    polarity: str
    weight: int
    indicator_value: str | None = None
    provenance: Provenance
