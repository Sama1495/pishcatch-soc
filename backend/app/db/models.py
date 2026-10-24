"""Local case store. Message bodies stay in this database and out of the logs."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sender: Mapped[str | None] = mapped_column(String(500))
    sender_address: Mapped[str | None] = mapped_column(String(320))
    sender_domain: Mapped[str | None] = mapped_column(String(255))
    reply_to: Mapped[str | None] = mapped_column(String(500))
    return_path: Mapped[str | None] = mapped_column(String(500))
    subject: Mapped[str | None] = mapped_column(String(998))
    body_text: Mapped[str | None] = mapped_column(Text)
    spf_result: Mapped[str | None] = mapped_column(String(32))
    dkim_result: Mapped[str | None] = mapped_column(String(32))
    dmarc_result: Mapped[str | None] = mapped_column(String(32))
    headers_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    urls_json: Mapped[list] = mapped_column(JSON, nullable=False)
    attachments_json: Mapped[list] = mapped_column(JSON, nullable=False)
    risk_label: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    machine_risk_label: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    label_source: Mapped[str] = mapped_column(String(32), nullable=False)
    caveat: Mapped[str] = mapped_column(Text, nullable=False)
    case_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    processing_time_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    brief_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    enrichment_status: Mapped[str] = mapped_column(String(32), nullable=False)
    explainer_status: Mapped[str] = mapped_column(String(32), nullable=False)
    ai_summary: Mapped[str | None] = mapped_column(Text)
    confidence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence_band: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    confidence_json: Mapped[dict | None] = mapped_column(JSON)
    policy_json: Mapped[dict | None] = mapped_column(JSON)

    indicators: Mapped[list["IndicatorRow"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IndicatorRow.position",
    )
    evidence: Mapped[list["EvidenceRow"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="EvidenceRow.position",
    )
    decisions: Mapped[list["DecisionRow"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="DecisionRow.created_at",
    )
    audit_events: Mapped[list["AuditEventRow"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="AuditEventRow.created_at",
    )
    operation_steps: Mapped[list["OperationStepRow"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="OperationStepRow.position",
    )
    verdict_feedback: Mapped[list["VerdictFeedbackRow"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="VerdictFeedbackRow.created_at",
    )
    action_responses: Mapped[list["ActionResponseRow"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="ActionResponseRow.created_at",
    )


class IndicatorRow(Base):
    __tablename__ = "indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    indicator_type: Mapped[str] = mapped_column("type", String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    display_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    context: Mapped[str | None] = mapped_column(String(255))

    incident: Mapped[Incident] = relationship(back_populates="indicators")


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rule_id: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    polarity: Mapped[str] = mapped_column(String(32), nullable=False)
    weight: Mapped[int] = mapped_column(Integer, nullable=False)
    indicator_value: Mapped[str | None] = mapped_column(String(2048))
    provenance_json: Mapped[dict] = mapped_column(JSON, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="evidence")


class DecisionRow(Base):
    __tablename__ = "analyst_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_label: Mapped[str] = mapped_column(String(32), nullable=False)
    corrected_label: Mapped[str | None] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    analyst_id: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")

    incident: Mapped[Incident] = relationship(back_populates="decisions")


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detail_json: Mapped[dict] = mapped_column(JSON, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="audit_events")


class OperationStepRow(Base):
    __tablename__ = "operation_steps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    step_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    provenance_json: Mapped[dict] = mapped_column(JSON, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="operation_steps")


class VerdictFeedbackRow(Base):
    __tablename__ = "verdict_feedback"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_label: Mapped[str] = mapped_column(String(32), nullable=False)
    corrected_label: Mapped[str | None] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    analyst_id: Mapped[str] = mapped_column(String(120), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="verdict_feedback")


class ActionResponseRow(Base):
    __tablename__ = "action_responses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    offered_action: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    analyst_id: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="action_responses")
