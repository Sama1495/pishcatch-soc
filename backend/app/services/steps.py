"""Update a persisted orchestrator step after a later human action."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.time import ensure_utc, utcnow
from app.db.models import OperationStepRow


def complete_step(
    session: Session,
    incident_id: str,
    step_id: str,
    status: str,
    provenance: dict,
) -> None:
    row = session.scalar(
        select(OperationStepRow).where(
            OperationStepRow.incident_id == incident_id,
            OperationStepRow.step_id == step_id,
        )
    )
    if row is None:
        return
    finished = utcnow()
    row.status = status
    row.finished_at = finished
    started = ensure_utc(row.started_at)
    row.duration_ms = max(0, int((finished - started).total_seconds() * 1000))
    row.provenance_json = provenance
