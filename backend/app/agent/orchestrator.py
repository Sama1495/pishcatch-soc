"""Run the controlled triage flow and persist the case.

Tool order is fixed. Email content is data for the parser and the rules, not
instructions to the agent. Reputation and the explainer are optional and cannot
override a failure: the deterministic result is always stored.
"""

import re
import time
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.tools import ALLOWED_TOOLS
from app.core.errors import AppError
from app.core.logging import get_logger
from app.core.time import utcnow
from app.db.models import (
    ActionResponseRow,
    AuditEventRow,
    DecisionRow,
    EvidenceRow,
    Incident,
    IndicatorRow,
    OperationStepRow,
    VerdictFeedbackRow,
)
from app.db.repository import find_prior_indicators, verdict_tally
from app.integrations.explainer import AiExplainer, ExplainerOutcome
from app.integrations.reputation import ReputationAdapter, ReputationBatch
from app.policy.engine import decide
from app.schemas.analysis import AnalysisResult
from app.schemas.decision import AnalystDecision, DecisionCreate, QuarantineRequest, QuarantineResult
from app.schemas.evidence import Evidence, Provenance
from app.schemas.indicator import Indicator
from app.schemas.trust import ActionResponseCreate, ActionResponseOut, VerdictFeedbackCreate, VerdictFeedbackOut
from app.services.actions import describe_action
from app.services.brief import build_brief, recommended_actions
from app.services.confidence import compute_confidence
from app.services.exceptions import ParseRejection
from app.services.indicators import IndicatorDraft, build_indicators
from app.services.parser import parse_eml
from app.services.parsed import ParsedEmail
from app.services.present import analysis_from_incident
from app.services.risk import classify
from app.services.rules import RULESET_VERSION, RuleHit, evaluate, make_hit
from app.services.steps import complete_step
from app.services.urls import defang

logger = get_logger()
_ANALYST_RE = re.compile(r"^[A-Za-z0-9_.:@ -]+$")
_LABELS = {"likely_malicious", "suspicious", "likely_benign", "inconclusive"}


class TriageOrchestrator:
    def __init__(
        self,
        reputation: ReputationAdapter | None = None,
        explainer: AiExplainer | None = None,
    ) -> None:
        self.reputation = reputation or ReputationAdapter.from_settings()
        self.explainer = explainer or AiExplainer.from_settings()

    def analyze(self, session: Session, raw: bytes, filename: str) -> AnalysisResult:
        started = time.perf_counter()
        incident_id = str(uuid.uuid4())
        marks: list[tuple[str, str, str, object, object, int, dict]] = []

        def lap(origin: float) -> tuple[float, int]:
            now = time.perf_counter()
            return now, max(0, int((now - origin) * 1000))

        wall = utcnow()
        marks.append(
            (
                "reception",
                "Reception",
                "done",
                wall,
                wall,
                0,
                {"component": "upload", "tool": "read_eml_upload", "byte_count": len(raw)},
            )
        )

        # parse_email
        phase = time.perf_counter()
        phase_wall = utcnow()
        try:
            parsed = parse_eml(raw)
        except ParseRejection as exc:
            logger.warning("upload_rejected code=%s", exc.code)
            raise AppError(exc.code, exc.message, 400) from exc
        phase, duration = lap(phase)
        marks.append(
            (
                "validation_extraction",
                "Validation and extraction",
                "done",
                phase_wall,
                utcnow(),
                duration,
                {
                    "component": "parser",
                    "tool": "parse_email",
                    "url_count": len(parsed.urls),
                    "attachment_count": len(parsed.attachments),
                    "warning_count": len(parsed.warnings),
                },
            )
        )

        # extract_indicators, evaluate_rules
        phase_wall = utcnow()
        drafts = build_indicators(parsed)
        hits = evaluate(parsed)
        phase, duration = lap(phase)
        marks.append(
            (
                "deterministic_rules",
                "Deterministic rules",
                "done",
                phase_wall,
                utcnow(),
                duration,
                {
                    "component": "deterministic_rules",
                    "tool": "evaluate_rules",
                    "ruleset": RULESET_VERSION,
                    "hit_count": len(hits),
                    "rule_ids": [hit.rule_id for hit in hits],
                },
            )
        )

        # lookup_reputation — stub, off by default, never required
        phase_wall = utcnow()
        try:
            reputation = self.reputation.lookup(drafts)
        except Exception:
            logger.warning("enrichment_failed incident_pending=%s", incident_id)
            reputation = ReputationBatch(status="error", results=[], provider_statuses={})
        enrichment_state = _source_state(reputation.status, "reputation")
        phase, duration = lap(phase)
        marks.append(
            (
                "enrichment",
                "Enrichment",
                enrichment_state,
                phase_wall,
                utcnow(),
                duration,
                {
                    "component": "reputation_adapter",
                    "tool": "lookup_reputation",
                    "provider_status": reputation.status,
                    "providers": reputation.provider_statuses,
                },
            )
        )

        # correlate_indicators against cases already stored
        phase_wall = utcnow()
        related = _correlate(session, drafts)
        hits.extend(related)
        phase, duration = lap(phase)
        marks.append(
            (
                "correlation",
                "Correlation",
                "done",
                phase_wall,
                utcnow(),
                duration,
                {
                    "component": "local_correlation",
                    "tool": "correlate_indicators",
                    "prior_hit_count": len(related),
                    "rule_ids": [hit.rule_id for hit in related],
                },
            )
        )

        # classify_risk, then an informational marker when nothing suspicious fired
        phase_wall = utcnow()
        classification = classify(hits)
        if classification.label == "inconclusive" and not any(
            hit.polarity == "suspicious" for hit in hits
        ):
            hits.append(make_hit("no_suspicious_signals", classification.caveat))
        phase, duration = lap(phase)
        marks.append(
            (
                "risk",
                "Risk",
                "done",
                phase_wall,
                utcnow(),
                duration,
                {
                    "component": "risk_engine",
                    "tool": "classify_risk",
                    "risk_label": classification.label,
                    "risk_score": classification.score,
                },
            )
        )

        suspicious_ids = [hit.rule_id for hit in hits if hit.polarity == "suspicious"]
        titles = [hit.title for hit in hits if hit.polarity == "suspicious"]
        # explain — structured indicators only; a failure keeps the template
        phase_wall = utcnow()
        try:
            explanation = self.explainer.explain(
                suspicious_ids,
                titles,
                classification.label,
                _explainer_indicators(drafts),
            )
        except Exception:
            logger.warning("explainer_failed incident_pending=%s", incident_id)
            explanation = ExplainerOutcome(status="fallback")
        explainer_state = _source_state(explanation.status, "explainer")
        phase, duration = lap(phase)
        marks.append(
            (
                "ai_explanation",
                "AI explanation",
                explainer_state,
                phase_wall,
                utcnow(),
                duration,
                {
                    "component": "ai_explainer",
                    "tool": "explain",
                    "explainer_status": explanation.status,
                    "provider": self.explainer.provider,
                    **(
                        {"reason_code": "deterministic_template"}
                        if explanation.status == "fallback"
                        else {}
                    ),
                },
            )
        )

        phase_wall = utcnow()
        indicators = _indicator_models(drafts)
        evidence = _evidence_models(hits)
        actions = recommended_actions(classification.label)
        brief = build_brief(
            sender=parsed.sender,
            subject=parsed.subject,
            classification=classification,
            indicators=indicators,
            evidence=evidence,
            enrichment_status=reputation.status,
            provider_statuses=reputation.provider_statuses,
            explainer_status=explanation.status,
            body_truncated=parsed.body_truncated,
            parser_warnings=parsed.warnings,
        )
        if explanation.status == "validated" and explanation.summary:
            brief.limitations.append(
                "A schema-valid explainer note was stored separately and did not change the risk label."
            )
        _phase_end, duration = lap(phase)
        marks.append(
            (
                "incident_brief",
                "Incident Brief",
                "done",
                phase_wall,
                utcnow(),
                duration,
                {
                    "component": "incident_brief",
                    "tool": "build_brief",
                    "source_count": len(brief.sources_consulted),
                    "limitation_count": len(brief.limitations),
                    "action_count": len(actions),
                },
            )
        )

        agreements, disagreements = verdict_tally(session, RULESET_VERSION)
        report = compute_confidence(
            label=classification.label,
            risk_score=classification.score,
            hits=hits,
            source_statuses={
                "local_parser": "done",
                "deterministic_rules": "done",
                "local_correlation": "done",
                "reputation": enrichment_state,
                "ai_explainer": explainer_state,
            },
            agreements=agreements,
            disagreements=disagreements,
        )
        policy = decide(classification.label, report.band)
        waiting_at = utcnow()
        marks.append(
            (
                "awaiting_human_decision",
                "Awaiting human decision",
                "waiting",
                waiting_at,
                None,
                0,
                {
                    "component": "policy_engine",
                    "offered_action": policy.offered_action,
                    "requires_human_approval": True,
                    "auto_execute": False,
                },
            )
        )
        marks.append(
            (
                "human_decision",
                "Human decision",
                "waiting",
                waiting_at,
                None,
                0,
                {"component": "analyst", "awaiting": "verdict_or_action"},
            )
        )
        if policy.offered_action == "simulate_quarantine":
            marks.append(
                (
                    "simulated_action",
                    "Simulated action",
                    "waiting",
                    waiting_at,
                    None,
                    0,
                    {
                        "component": "policy_engine",
                        "offered_action": policy.offered_action,
                        "auto_execute": False,
                    },
                )
            )
        else:
            marks.append(
                (
                    "simulated_action",
                    "Simulated action",
                    "skipped",
                    waiting_at,
                    waiting_at,
                    0,
                    {
                        "component": "policy_engine",
                        "offered_action": policy.offered_action,
                        "reason_code": "action_not_offered",
                    },
                )
            )

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        created_at = utcnow()
        incident = Incident(
            id=incident_id,
            created_at=created_at,
            filename=_safe_filename(filename),
            sender=parsed.sender,
            sender_address=parsed.sender_address,
            sender_domain=parsed.sender_domain,
            reply_to=parsed.reply_to_raw,
            return_path=parsed.return_path_raw,
            subject=parsed.subject,
            body_text=parsed.body_text,
            spf_result=parsed.spf,
            dkim_result=parsed.dkim,
            dmarc_result=parsed.dmarc,
            headers_json=_headers(parsed),
            urls_json=[_url_dict(url) for url in parsed.urls],
            attachments_json=[_attachment_dict(item) for item in parsed.attachments],
            risk_label=classification.label,
            machine_risk_label=classification.label,
            risk_score=classification.score,
            label_source="deterministic_rules",
            caveat=_caveat(classification.caveat, parsed),
            case_status="open",
            processing_time_ms=max(elapsed_ms, 0),
            brief_json=brief.model_dump(mode="json"),
            enrichment_status=reputation.status,
            explainer_status=explanation.status,
            ai_summary=explanation.summary if explanation.status == "validated" else None,
            confidence_score=report.score,
            confidence_band=report.band,
            confidence_json=report.as_dict(),
            policy_json=policy.as_dict(),
        )
        incident.indicators = [
            IndicatorRow(
                id=item.id,
                incident_id=incident_id,
                position=index,
                indicator_type=item.type,
                value=item.value,
                display_value=item.display_value,
                context=item.context,
            )
            for index, item in enumerate(indicators)
        ]
        incident.evidence = [
            EvidenceRow(
                id=item.id,
                incident_id=incident_id,
                position=index,
                rule_id=item.rule_id,
                title=item.title,
                reason=item.reason,
                severity=item.severity,
                source=item.source,
                polarity=item.polarity,
                weight=item.weight,
                indicator_value=item.indicator_value,
                provenance_json=item.provenance.model_dump(mode="json"),
            )
            for index, item in enumerate(evidence)
        ]
        incident.audit_events.append(
            AuditEventRow(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                event_type="analysis_completed",
                actor="phishcatch-agent",
                created_at=created_at,
                detail_json={
                    "risk_label": classification.label,
                    "risk_score": classification.score,
                    "evidence_count": len(evidence),
                    "enrichment_status": reputation.status,
                    "explainer_status": explanation.status,
                    "processing_time_ms": incident.processing_time_ms,
                    "tools": list(ALLOWED_TOOLS),
                    "ruleset": RULESET_VERSION,
                    "confidence_score": report.score,
                    "confidence_band": report.band,
                    "offered_action": policy.offered_action,
                    "auto_execute": False,
                },
            )
        )
        incident.operation_steps = [
            OperationStepRow(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                position=index,
                step_id=step_id,
                title=title,
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=duration_ms,
                provenance_json=provenance,
            )
            for index, (step_id, title, status, started_at, finished_at, duration_ms, provenance) in enumerate(
                marks
            )
        ]
        session.add(incident)
        session.commit()
        logger.info(
            "analysis_completed incident_id=%s risk_label=%s confidence=%s band=%s offered_action=%s evidence_count=%s duration_ms=%s enrichment=%s explainer=%s",
            incident_id,
            classification.label,
            report.score,
            report.band,
            policy.offered_action,
            len(evidence),
            incident.processing_time_ms,
            reputation.status,
            explanation.status,
        )
        return analysis_from_incident(incident)

    def record_decision(
        self, session: Session, incident_id: str, payload: DecisionCreate
    ) -> AnalystDecision:
        _check_analyst(payload.analyst_id)
        action = payload.action.strip().lower()
        if action not in {"confirm", "correct"}:
            raise AppError("invalid_decision", "Action must be confirm or correct.", 422)
        if action == "correct" and payload.corrected_label is None:
            raise AppError(
                "invalid_decision",
                "A corrected label is required when the action is correct.",
                422,
            )
        if action == "confirm" and payload.corrected_label is not None:
            raise AppError(
                "invalid_decision",
                "Confirm does not take a corrected label.",
                422,
            )
        if payload.corrected_label is not None and payload.corrected_label not in _LABELS:
            raise AppError("invalid_decision", "The corrected label is not recognized.", 422)
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise AppError("incident_not_found", "The incident was not found.", 404)
        previous = incident.risk_label
        if action == "correct":
            incident.risk_label = payload.corrected_label or previous
            incident.label_source = "analyst_corrected"
        else:
            incident.label_source = "analyst_confirmed"
        incident.case_status = "closed"
        decision = DecisionRow(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            action=action,
            previous_label=previous,
            corrected_label=payload.corrected_label,
            reason=payload.reason.strip(),
            analyst_id=payload.analyst_id.strip(),
            created_at=utcnow(),
            ruleset_version=RULESET_VERSION,
        )
        audit = AuditEventRow(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="analyst_decision",
            actor=decision.analyst_id,
            created_at=decision.created_at,
            detail_json={
                "decision_id": decision.id,
                "action": action,
                "previous_label": previous,
                "new_label": incident.risk_label,
                "rules_updated": False,
            },
        )
        session.add(decision)
        session.add(audit)
        _note_human(
            session,
            incident.id,
            {
                "component": "analyst",
                "kind": "label_decision",
                "action": action,
                "analyst_id": decision.analyst_id,
                "rules_updated": False,
            },
        )
        complete_step(
            session,
            incident.id,
            "awaiting_human_decision",
            "done",
            {"component": "analyst", "closed_by": action, "analyst_id": decision.analyst_id},
        )
        session.commit()
        logger.info(
            "analyst_decision incident_id=%s action=%s actor=%s",
            incident.id,
            action,
            decision.analyst_id,
        )
        return AnalystDecision(
            id=decision.id,
            incident_id=decision.incident_id,
            action=decision.action,
            previous_label=decision.previous_label,  # type: ignore[arg-type]
            corrected_label=decision.corrected_label,  # type: ignore[arg-type]
            reason=decision.reason,
            analyst_id=decision.analyst_id,
            created_at=decision.created_at,
        )

    def simulate_quarantine(
        self, session: Session, incident_id: str, payload: QuarantineRequest
    ) -> QuarantineResult:
        """Record a quarantine mark. This method has no mail-system client."""
        _check_analyst(payload.analyst_id)
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise AppError("incident_not_found", "The incident was not found.", 404)
        incident.case_status = "quarantine_simulated"
        audit = AuditEventRow(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="quarantine_simulated",
            actor=payload.analyst_id.strip(),
            created_at=utcnow(),
            detail_json={
                "simulated": True,
                "external_effect": "none",
                "reason_recorded": True,
            },
        )
        session.add(audit)
        actor = payload.analyst_id.strip()
        complete_step(
            session,
            incident.id,
            "simulated_action",
            "done",
            {
                "component": "quarantine_simulator",
                "simulated": True,
                "external_effect": "none",
                "analyst_id": actor,
            },
        )
        complete_step(
            session,
            incident.id,
            "awaiting_human_decision",
            "done",
            {"component": "quarantine_simulator", "closed_by": "simulate_quarantine", "analyst_id": actor},
        )
        session.commit()
        logger.info(
            "quarantine_simulated incident_id=%s actor=%s external_effect=none",
            incident.id,
            payload.analyst_id.strip(),
        )
        return QuarantineResult(
            incident_id=incident.id,
            simulated=True,
            external_effect="none",
            case_status="quarantine_simulated",
            message="Quarantine was simulated. No mailbox or message was modified.",
            audit_event_id=audit.id,
        )

    def record_verdict(
        self, session: Session, incident_id: str, payload: VerdictFeedbackCreate
    ) -> VerdictFeedbackOut:
        """Record whether the agent verdict was right. Does not close the case or edit rules."""
        _check_analyst(payload.analyst_id)
        verdict = payload.verdict.strip().lower()
        if verdict not in {"correct", "wrong"}:
            raise AppError("invalid_decision", "Verdict must be correct or wrong.", 422)
        corrected = payload.corrected_label
        if verdict == "correct" and corrected is not None:
            raise AppError("invalid_decision", "A correct verdict does not take a replacement label.", 422)
        if corrected is not None and corrected not in _LABELS:
            raise AppError("invalid_decision", "The corrected label is not recognized.", 422)
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise AppError("incident_not_found", "The incident was not found.", 404)
        existing = session.scalar(
            select(VerdictFeedbackRow.id).where(VerdictFeedbackRow.incident_id == incident.id)
        )
        if existing is not None:
            raise AppError("already_recorded", "A verdict is already recorded for this incident.", 409)
        previous = incident.risk_label
        if verdict == "wrong" and corrected is not None:
            incident.risk_label = corrected
            incident.label_source = "analyst_corrected"
        actor = payload.analyst_id.strip()
        row = VerdictFeedbackRow(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            verdict=verdict,
            previous_label=previous,
            corrected_label=corrected if verdict == "wrong" else None,
            reason=payload.reason.strip(),
            analyst_id=actor,
            ruleset_version=RULESET_VERSION,
            created_at=utcnow(),
        )
        audit = AuditEventRow(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="verdict_feedback",
            actor=actor,
            created_at=row.created_at,
            detail_json={
                "feedback_id": row.id,
                "verdict": verdict,
                "previous_label": previous,
                "corrected_label": row.corrected_label,
                "rules_updated": False,
                "ruleset": RULESET_VERSION,
            },
        )
        session.add(row)
        session.add(audit)
        _note_human(
            session,
            incident.id,
            {
                "component": "analyst",
                "kind": "verdict_feedback",
                "verdict": verdict,
                "analyst_id": actor,
                "rules_updated": False,
            },
        )
        session.commit()
        logger.info(
            "verdict_feedback incident_id=%s verdict=%s actor=%s rules_updated=false",
            incident.id,
            verdict,
            actor,
        )
        return VerdictFeedbackOut(
            id=row.id,
            incident_id=row.incident_id,
            verdict=row.verdict,
            previous_label=row.previous_label,
            corrected_label=row.corrected_label,
            reason=row.reason,
            analyst_id=row.analyst_id,
            ruleset_version=row.ruleset_version,
            rules_updated=False,
            created_at=row.created_at,
        )

    def respond_to_action(
        self, session: Session, incident_id: str, payload: ActionResponseCreate
    ) -> ActionResponseOut:
        """Yes or no on the action the policy already offered. Never calls out to a mailbox."""
        _check_analyst(payload.analyst_id)
        decision = payload.decision.strip().lower()
        if decision not in {"approve", "reject"}:
            raise AppError("invalid_decision", "Decision must be approve or reject.", 422)
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise AppError("incident_not_found", "The incident was not found.", 404)
        existing = session.scalar(
            select(ActionResponseRow.id).where(ActionResponseRow.incident_id == incident.id)
        )
        if existing is not None:
            raise AppError("already_recorded", "An action response is already recorded for this incident.", 409)
        offered = str((incident.policy_json or {}).get("offered_action") or "manual_investigation")
        actor = payload.analyst_id.strip()
        if decision == "approve" and offered == "simulate_quarantine":
            incident.case_status = "quarantine_simulated"
            complete_step(
                session,
                incident.id,
                "simulated_action",
                "done",
                {
                    "component": "quarantine_simulator",
                    "simulated": True,
                    "external_effect": "none",
                    "analyst_id": actor,
                },
            )
        elif decision == "reject" and offered == "simulate_quarantine":
            complete_step(
                session,
                incident.id,
                "simulated_action",
                "skipped",
                {
                    "component": "policy_engine",
                    "offered_action": offered,
                    "reason_code": "human_rejected",
                    "analyst_id": actor,
                },
            )
        elif decision == "approve" and offered == "close_no_containment":
            incident.case_status = "closed"
        elif decision == "approve":
            incident.case_status = "in_review"
        row = ActionResponseRow(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            decision=decision,
            offered_action=offered,
            reason=payload.reason.strip(),
            analyst_id=actor,
            created_at=utcnow(),
        )
        simulated, message = describe_action(decision, offered)
        audit = AuditEventRow(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="action_response",
            actor=actor,
            created_at=row.created_at,
            detail_json={
                "response_id": row.id,
                "decision": decision,
                "offered_action": offered,
                "case_status": incident.case_status,
                "simulated": simulated,
                "external_effect": "none",
            },
        )
        session.add(row)
        session.add(audit)
        complete_step(
            session,
            incident.id,
            "awaiting_human_decision",
            "done",
            {
                "component": "analyst",
                "decision": decision,
                "offered_action": offered,
                "analyst_id": actor,
            },
        )
        _note_human(
            session,
            incident.id,
            {
                "component": "analyst",
                "kind": "action_response",
                "decision": decision,
                "offered_action": offered,
                "analyst_id": actor,
            },
        )
        session.commit()
        logger.info(
            "action_response incident_id=%s decision=%s offered_action=%s actor=%s external_effect=none",
            incident.id,
            decision,
            offered,
            actor,
        )
        return ActionResponseOut(
            id=row.id,
            incident_id=incident.id,
            decision=decision,
            offered_action=offered,
            reason=row.reason,
            analyst_id=actor,
            case_status=incident.case_status,
            simulated=simulated,
            external_effect="none",
            message=message,
            created_at=row.created_at,
        )


def _check_analyst(analyst_id: str) -> None:
    if not _ANALYST_RE.fullmatch(analyst_id.strip()):
        raise AppError("invalid_decision", "analyst_id contains unsupported characters.", 422)


def _note_human(session: Session, incident_id: str, provenance: dict) -> None:
    row = session.scalar(
        select(OperationStepRow).where(
            OperationStepRow.incident_id == incident_id,
            OperationStepRow.step_id == "human_decision",
        )
    )
    merged: dict = {}
    if row is not None and isinstance(row.provenance_json, dict):
        merged.update(row.provenance_json)
    merged.pop("awaiting", None)
    merged.update(provenance)
    complete_step(session, incident_id, "human_decision", "done", merged)


def _caveat(caveat: str, parsed: ParsedEmail) -> str:
    if parsed.auth_trust != "untrusted":
        return caveat
    return (
        caveat
        + " Authentication-Results were present but their authserv-id is not in the trusted list,"
        + " so SPF, DKIM, and DMARC were not scored."
    )


def _explainer_indicators(drafts: list[IndicatorDraft]) -> list[dict]:
    """Defanged non-personal indicators. Mailbox addresses are omitted."""
    items: list[dict] = []
    for item in drafts:
        if item.type == "url":
            items.append({"type": "url", "defanged": item.display_value[:300]})
        elif item.type == "domain":
            items.append({"type": "domain", "defanged": item.display_value[:200]})
        elif item.type == "ip":
            items.append({"type": "ip", "defanged": item.display_value[:80]})
        elif item.type == "attachment":
            items.append({"type": "attachment", "defanged": "hashed-attachment"})
    return items[:20]


def _source_state(status: str, kind: str) -> str:
    if kind == "explainer":
        if status == "validated":
            return "done"
        if status == "fallback":
            return "failed"
        return "skipped"
    if status in {"timeout", "error"}:
        return "failed"
    if status == "ok":
        return "done"
    return "skipped"


def _correlate(session: Session, drafts: list[IndicatorDraft]) -> list[RuleHit]:
    values = [item.value for item in drafts if item.type in {"url", "domain", "ip", "email"}]
    priors = find_prior_indicators(session, values)
    suspicious: list[str] = []
    seen_info: list[str] = []
    for value, _incident_id, label in priors:
        defanged = defang(value)
        if label in {"likely_malicious", "suspicious"}:
            if defanged not in suspicious:
                suspicious.append(defanged)
        elif defanged not in seen_info and defanged not in suspicious:
            seen_info.append(defanged)
    hits: list[RuleHit] = []
    if suspicious:
        hits.append(
            make_hit(
                "related_indicator_in_prior_case",
                "Previously stored suspicious or malicious case shares: " + ", ".join(suspicious[:5]) + ".",
                suspicious[0],
            )
        )
    elif seen_info:
        hits.append(
            make_hit(
                "related_indicator_seen_before",
                "Previously stored case shares: " + ", ".join(seen_info[:5]) + ".",
                seen_info[0],
            )
        )
    return hits


def _indicator_models(drafts: list[IndicatorDraft]) -> list[Indicator]:
    return [
        Indicator(
            id=str(uuid.uuid4()),
            type=item.type,  # type: ignore[arg-type]
            value=item.value,
            display_value=item.display_value,
            context=item.context,
        )
        for item in drafts
    ]


def _evidence_models(hits: list[RuleHit]) -> list[Evidence]:
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    ordered = sorted(hits, key=lambda hit: (severity_order.get(hit.severity, 9), hit.rule_id))
    models: list[Evidence] = []
    for hit in ordered:
        source = "deterministic_rules"
        if hit.rule_id.startswith("related_indicator"):
            source = "local_correlation"
        models.append(
            Evidence(
                id=str(uuid.uuid4()),
                rule_id=hit.rule_id,
                title=hit.title,
                reason=hit.reason,
                severity=hit.severity,  # type: ignore[arg-type]
                source=source,
                polarity=hit.polarity,
                weight=hit.weight,
                indicator_value=hit.indicator_value,
                provenance=Provenance(
                    producer="phishcatch-rules" if source == "deterministic_rules" else "phishcatch-correlation",
                    version=RULESET_VERSION,
                    method="static_rule" if source == "deterministic_rules" else "local_lookup",
                    observed_fields=hit.observed_fields,
                ),
            )
        )
    return models


def _headers(parsed: ParsedEmail) -> dict:
    return {
        "from": parsed.sender_raw,
        "to": parsed.to,
        "cc": parsed.cc,
        "reply_to": parsed.reply_to_raw,
        "return_path": parsed.return_path_raw,
        "subject": parsed.subject,
        "date": parsed.date,
        "message_id": parsed.message_id,
        "received": parsed.received,
        "authentication_results": parsed.authentication_results,
        "received_spf": parsed.received_spf,
        "auth_trust": parsed.auth_trust,
    }


def _url_dict(url) -> dict:
    return {
        "original": url.original,
        "normalized": url.normalized,
        "defanged": url.defanged,
        "host": url.host,
        "scheme": url.scheme,
        "is_ip_literal": url.is_ip_literal,
        "source": url.source,
    }


def _attachment_dict(item) -> dict:
    return {
        "filename": item.filename,
        "content_type": item.content_type,
        "size_bytes": item.size_bytes,
        "extension": item.extension,
        "sha256": item.sha256,
    }


def _safe_filename(name: str) -> str:
    base = Path(name or "message.eml").name
    cleaned = re.sub(r"[^\w.\- ()]", "_", base, flags=re.UNICODE).strip()
    return (cleaned or "message.eml")[:255]
