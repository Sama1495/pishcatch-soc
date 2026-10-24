"""Queries for incidents and prior indicators."""

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import ActionResponseRow, DecisionRow, Incident, IndicatorRow, VerdictFeedbackRow

CORRELATABLE = {"url", "domain", "ip", "email"}


def find_prior_indicators(session: Session, values: list[str]) -> list[tuple[str, str, str]]:
    """Return (value, incident_id, risk_label) for indicators already stored."""
    cleaned = [value for value in values if value and len(value) >= 3][:100]
    if not cleaned:
        return []
    statement = (
        select(IndicatorRow.value, Incident.id, Incident.machine_risk_label)
        .join(Incident, IndicatorRow.incident_id == Incident.id)
        .where(IndicatorRow.value.in_(cleaned))
        .where(IndicatorRow.indicator_type.in_(CORRELATABLE))
    )
    return [(row[0], row[1], row[2]) for row in session.execute(statement).all()]


def list_incidents(
    session: Session,
    *,
    risk_label: str | None,
    case_status: str | None,
    confidence_band: str | None,
    limit: int,
    offset: int,
) -> tuple[list[Incident], int]:
    statement = select(Incident)
    count_statement = select(func.count()).select_from(Incident)
    if risk_label:
        statement = statement.where(Incident.risk_label == risk_label)
        count_statement = count_statement.where(Incident.risk_label == risk_label)
    if case_status:
        statement = statement.where(Incident.case_status == case_status)
        count_statement = count_statement.where(Incident.case_status == case_status)
    if confidence_band:
        statement = statement.where(Incident.confidence_band == confidence_band)
        count_statement = count_statement.where(Incident.confidence_band == confidence_band)
    total = session.scalar(count_statement) or 0
    # Priority is risk rank times confidence, so a high-confidence malicious case
    # stays above a low-confidence one. This is a queue order, not a new score.
    rank = case(
        (Incident.risk_label == "likely_malicious", 4),
        (Incident.risk_label == "suspicious", 3),
        (Incident.risk_label == "inconclusive", 2),
        else_=1,
    )
    rows = (
        session.scalars(
            statement.order_by(
                (rank * Incident.confidence_score).desc(),
                Incident.created_at.desc(),
            )
            .limit(limit)
            .offset(offset)
        )
        .all()
    )
    return list(rows), int(total)


def get_incident(session: Session, incident_id: str) -> Incident | None:
    statement = (
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            selectinload(Incident.indicators),
            selectinload(Incident.evidence),
            selectinload(Incident.decisions),
            selectinload(Incident.audit_events),
            selectinload(Incident.operation_steps),
            selectinload(Incident.verdict_feedback),
            selectinload(Incident.action_responses),
        )
    )
    return session.scalars(statement).one_or_none()


def verdict_tally(session: Session, ruleset: str) -> tuple[int, int]:
    """Return (agreements, disagreements) for one ruleset. Not an accuracy claim."""
    agreements = 0
    disagreements = 0
    decisions = session.execute(
        select(DecisionRow.action).where(DecisionRow.ruleset_version == ruleset)
    ).all()
    for (action,) in decisions:
        if action == "confirm":
            agreements += 1
        elif action == "correct":
            disagreements += 1
    feedback = session.execute(
        select(VerdictFeedbackRow.verdict).where(VerdictFeedbackRow.ruleset_version == ruleset)
    ).all()
    for (verdict,) in feedback:
        if verdict == "correct":
            agreements += 1
        elif verdict == "wrong":
            disagreements += 1
    return agreements, disagreements


def metrics_snapshot(session: Session, ruleset: str) -> dict:
    agreements, disagreements = verdict_tally(session, ruleset)
    total_feedback = agreements + disagreements
    counts = dict(
        session.execute(
            select(Incident.machine_risk_label, func.count()).group_by(Incident.machine_risk_label)
        ).all()
    )
    case_count = session.scalar(select(func.count()).select_from(Incident)) or 0
    average = session.scalar(select(func.avg(Incident.processing_time_ms)))
    raw_rate = (agreements / total_feedback) if total_feedback else None
    return {
        "case_count": int(case_count),
        "cases_by_label": {label: int(counts.get(label, 0)) for label in (
            "likely_malicious",
            "suspicious",
            "likely_benign",
            "inconclusive",
        )},
        "average_processing_time_ms": None if average is None or case_count == 0 else round(float(average), 1),
        "agreements": agreements,
        "disagreements": disagreements,
        "feedback_total": total_feedback,
        "raw_agreement_rate": None if raw_rate is None else round(raw_rate, 4),
    }


def latest_action_response(session: Session, incident_id: str) -> ActionResponseRow | None:
    return session.scalar(
        select(ActionResponseRow)
        .where(ActionResponseRow.incident_id == incident_id)
        .order_by(ActionResponseRow.created_at.desc())
    )
