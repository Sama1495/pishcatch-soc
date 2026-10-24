"""Map stored incidents to API schemas without going back through the rules."""

from app.core.time import ensure_utc
from app.db.models import Incident
from app.schemas.analysis import AnalysisResult, AuditEventOut, IncidentDetail, IncidentSummary
from app.schemas.brief import IncidentBrief
from app.schemas.decision import AnalystDecision
from app.schemas.evidence import Evidence, Provenance
from app.schemas.incident import AttachmentOut, KeyHeaderSet, UrlOut
from app.schemas.indicator import Indicator
from app.schemas.trust import (
    ActionResponseOut,
    ConfidenceOut,
    PolicyDecisionOut,
    TimelineStepOut,
    VerdictFeedbackOut,
)
from app.services.actions import describe_action
from app.services.confidence import DISCLAIMER
from app.services.rules import RULESET_VERSION


def analysis_from_incident(incident: Incident) -> AnalysisResult:
    brief = IncidentBrief.model_validate(incident.brief_json)
    body = incident.body_text or ""
    return AnalysisResult(
        incident_id=incident.id,
        created_at=ensure_utc(incident.created_at),
        filename=incident.filename,
        sender=incident.sender,
        sender_address=incident.sender_address,
        sender_domain=incident.sender_domain,
        reply_to=incident.reply_to,
        return_path=incident.return_path,
        subject=incident.subject,
        spf=incident.spf_result,
        dkim=incident.dkim_result,
        dmarc=incident.dmarc_result,
        headers=_headers(incident.headers_json or {}),
        body_excerpt=body[:1500],
        urls=[UrlOut.model_validate(item) for item in incident.urls_json or []],
        attachments=[AttachmentOut.model_validate(item) for item in incident.attachments_json or []],
        indicators=[_indicator(row) for row in incident.indicators],
        evidence=[_evidence(row) for row in incident.evidence],
        risk_label=incident.risk_label,  # type: ignore[arg-type]
        machine_risk_label=incident.machine_risk_label,  # type: ignore[arg-type]
        risk_score=incident.risk_score,
        label_source=incident.label_source,  # type: ignore[arg-type]
        caveat=incident.caveat,
        recommended_actions=list(brief.recommended_actions),
        brief=brief,
        case_status=incident.case_status,  # type: ignore[arg-type]
        processing_time_ms=incident.processing_time_ms,
        enrichment_status=incident.enrichment_status,
        explainer_status=incident.explainer_status,
        confidence=_confidence(incident),
        policy=_policy(incident),
        timeline=_timeline(incident),
    )


def detail_from_incident(incident: Incident) -> IncidentDetail:
    base = analysis_from_incident(incident)
    return IncidentDetail(
        **base.model_dump(),
        body_text=incident.body_text or "",
        ai_summary=incident.ai_summary,
        decisions=[
            AnalystDecision(
                id=row.id,
                incident_id=row.incident_id,
                action=row.action,
                previous_label=row.previous_label,  # type: ignore[arg-type]
                corrected_label=row.corrected_label,  # type: ignore[arg-type]
                reason=row.reason,
                analyst_id=row.analyst_id,
                created_at=ensure_utc(row.created_at),
            )
            for row in incident.decisions
        ],
        audit_events=[
            AuditEventOut(
                id=row.id,
                event_type=row.event_type,
                actor=row.actor,
                created_at=ensure_utc(row.created_at),
                detail=row.detail_json or {},
            )
            for row in incident.audit_events
        ],
        verdict_feedback=[
            VerdictFeedbackOut(
                id=row.id,
                incident_id=row.incident_id,
                verdict=row.verdict,
                previous_label=row.previous_label,
                corrected_label=row.corrected_label,
                reason=row.reason,
                analyst_id=row.analyst_id,
                ruleset_version=row.ruleset_version,
                rules_updated=False,
                created_at=ensure_utc(row.created_at),
            )
            for row in incident.verdict_feedback
        ],
        action_response=_action_response(incident),
    )


def summary_from_incident(incident: Incident) -> IncidentSummary:
    return IncidentSummary(
        incident_id=incident.id,
        created_at=ensure_utc(incident.created_at),
        filename=incident.filename,
        sender=incident.sender,
        sender_address=incident.sender_address,
        subject=incident.subject,
        risk_label=incident.risk_label,  # type: ignore[arg-type]
        machine_risk_label=incident.machine_risk_label,  # type: ignore[arg-type]
        risk_score=incident.risk_score,
        label_source=incident.label_source,  # type: ignore[arg-type]
        case_status=incident.case_status,  # type: ignore[arg-type]
        processing_time_ms=incident.processing_time_ms,
        enrichment_status=incident.enrichment_status,
        explainer_status=incident.explainer_status,
        confidence_score=incident.confidence_score or 0,
        confidence_band=_band(incident.confidence_band),
        offered_action=(incident.policy_json or {}).get("offered_action"),
        autonomy=(incident.policy_json or {}).get("autonomy"),
    )


def _confidence(incident: Incident) -> ConfidenceOut:
    if incident.confidence_json:
        return ConfidenceOut.model_validate(incident.confidence_json)
    score = int(incident.confidence_score or 0)
    return ConfidenceOut(
        score=score,
        band=_band(incident.confidence_band),
        formula_version="unknown",
        ruleset=RULESET_VERSION,
        raw_score=float(score),
        cap=100,
        cap_applied=False,
        disclaimer=DISCLAIMER,
        components=[],
    )


def _policy(incident: Incident) -> PolicyDecisionOut:
    if incident.policy_json:
        return PolicyDecisionOut.model_validate(incident.policy_json)
    return PolicyDecisionOut(
        policy_version="unknown",
        rule_id="unavailable",
        autonomy="manual_investigation",
        offered_action="manual_investigation",
        offered_action_label="Mark for manual investigation",
        requires_human_approval=True,
        auto_execute=False,
        summary="This case was stored before a policy decision was recorded.",
        calibration_note="",
        forced_auto_execute_off=False,
    )


def _timeline(incident: Incident) -> list[TimelineStepOut]:
    return [
        TimelineStepOut(
            step_id=row.step_id,
            title=row.title,
            status=row.status,  # type: ignore[arg-type]
            started_at=ensure_utc(row.started_at),
            finished_at=ensure_utc(row.finished_at) if row.finished_at else None,
            duration_ms=row.duration_ms,
            provenance=row.provenance_json or {},
        )
        for row in incident.operation_steps
    ]


def _action_response(incident: Incident) -> ActionResponseOut | None:
    if not incident.action_responses:
        return None
    row = incident.action_responses[-1]
    simulated, message = describe_action(row.decision, row.offered_action)
    return ActionResponseOut(
        id=row.id,
        incident_id=row.incident_id,
        decision=row.decision,
        offered_action=row.offered_action,
        reason=row.reason,
        analyst_id=row.analyst_id,
        case_status=incident.case_status,
        simulated=simulated,
        external_effect="none",
        message=message,
        created_at=ensure_utc(row.created_at),
    )


def _band(value: str | None) -> str:
    if value in {"high", "medium", "low"}:
        return value
    return "low"


def _indicator(row) -> Indicator:
    return Indicator(
        id=row.id,
        type=row.indicator_type,
        value=row.value,
        display_value=row.display_value,
        context=row.context,
    )


def _evidence(row) -> Evidence:
    return Evidence(
        id=row.id,
        rule_id=row.rule_id,
        title=row.title,
        reason=row.reason,
        severity=row.severity,
        source=row.source,
        polarity=row.polarity,
        weight=row.weight,
        indicator_value=row.indicator_value,
        provenance=Provenance.model_validate(row.provenance_json),
    )


def _headers(payload: dict) -> KeyHeaderSet:
    return KeyHeaderSet(
        from_header=payload.get("from"),
        to=list(payload.get("to") or []),
        cc=list(payload.get("cc") or []),
        reply_to=payload.get("reply_to"),
        return_path=payload.get("return_path"),
        subject=payload.get("subject"),
        date=payload.get("date"),
        message_id=payload.get("message_id"),
        received=list(payload.get("received") or []),
        authentication_results=list(payload.get("authentication_results") or []),
        received_spf=payload.get("received_spf"),
        auth_trust=payload.get("auth_trust"),
    )
