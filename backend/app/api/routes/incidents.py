"""Incident queue, analysis, analyst decisions, and simulated quarantine."""

import json
from pathlib import Path

from fastapi import APIRouter, Depends, File, Query, UploadFile
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.agent.orchestrator import TriageOrchestrator
from app.api.uploads import read_bounded_upload, read_eml_upload
from app.core.errors import AppError
from app.core.logging import get_logger
from app.db.repository import get_incident, list_incidents, metrics_snapshot
from app.db.session import get_db
from app.schemas.analysis import AnalysisResult, BatchItem, BatchResult, IncidentDetail, IncidentList
from app.services.batch import MAX_BATCH_MESSAGES, split_upload
from app.services.demo_pack import available as demo_available
from app.services.demo_pack import load as load_demo

logger = get_logger()
_EVALUATION = Path(__file__).resolve().parents[2] / "evaluation" / "latest.json"
from app.schemas.decision import AnalystDecision, DecisionCreate, QuarantineRequest, QuarantineResult
from app.schemas.trust import ActionResponseCreate, ActionResponseOut, MetricsOut, VerdictFeedbackCreate, VerdictFeedbackOut
from app.services.confidence import DISCLAIMER, shrunk_agreement_percent
from app.services.present import detail_from_incident, summary_from_incident
from app.services.report import build_docx, build_xlsx, case_code, is_decided
from app.services.rules import RULESET_VERSION

router = APIRouter(prefix="/api/v1", tags=["incidents"])

_LABELS = {"likely_malicious", "suspicious", "likely_benign", "inconclusive"}
_STATUSES = {"open", "in_review", "closed", "quarantine_simulated"}
_BANDS = {"high", "medium", "low"}
_METRICS_NOTE = (
    DISCLAIMER
    + " The raw agreement rate counts recorded verdicts only. "
    + "The shrunk percent is the prior this formula uses when a new case is scored. "
    + "It is not a measured accuracy."
)


def get_orchestrator() -> TriageOrchestrator:
    return TriageOrchestrator()


@router.post("/incidents", response_model=AnalysisResult, status_code=201)
async def create_incident(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    orchestrator: TriageOrchestrator = Depends(get_orchestrator),
) -> AnalysisResult:
    raw = await read_eml_upload(file)
    return orchestrator.analyze(db, raw, file.filename or "message.eml")


@router.post("/incidents/batch", response_model=BatchResult, status_code=200)
async def create_batch(
    files: list[UploadFile] = File(...),
    db: Session = Depends(get_db),
    orchestrator: TriageOrchestrator = Depends(get_orchestrator),
) -> BatchResult:
    """Analyze several .eml files or one .mbox. One bad message does not stop the rest."""
    items: list[BatchItem] = []
    remaining = MAX_BATCH_MESSAGES
    for upload in files:
        if remaining <= 0:
            items.append(
                BatchItem(
                    filename=Path(upload.filename or "message").name,
                    error_code="batch_limit",
                    error_message="The batch stopped at 50 messages.",
                )
            )
            continue
        try:
            raw = await read_bounded_upload(upload, {".eml", ".mbox"})
        except AppError as exc:
            items.append(
                BatchItem(
                    filename=Path(upload.filename or "message").name,
                    error_code=exc.code,
                    error_message=exc.message,
                )
            )
            continue
        parts = split_upload(upload.filename or "message.eml", raw)
        for filename, part in parts:
            if remaining <= 0:
                items.append(
                    BatchItem(
                        filename=filename,
                        error_code="batch_limit",
                        error_message="The batch stopped at 50 messages.",
                    )
                )
                break
            remaining -= 1
            try:
                created = orchestrator.analyze(db, part, filename)
            except AppError as exc:
                items.append(
                    BatchItem(filename=filename, error_code=exc.code, error_message=exc.message)
                )
                continue
            except Exception as exc:
                logger.error("batch_item_failed type=%s", type(exc).__name__)
                items.append(
                    BatchItem(
                        filename=filename,
                        error_code="internal_error",
                        error_message="This message could not be processed.",
                    )
                )
                continue
            items.append(
                BatchItem(
                    filename=filename,
                    incident_id=created.incident_id,
                    risk_label=created.risk_label,
                )
            )
    accepted = sum(1 for item in items if item.incident_id)
    return BatchResult(accepted=accepted, failed=len(items) - accepted, items=items)


@router.get("/demo-pack")
def list_demo_pack() -> dict:
    return {"items": demo_available()}


@router.post("/demo-pack/{name}/analyze", response_model=AnalysisResult, status_code=201)
def analyze_demo(
    name: str,
    db: Session = Depends(get_db),
    orchestrator: TriageOrchestrator = Depends(get_orchestrator),
) -> AnalysisResult:
    filename, raw = load_demo(name)
    return orchestrator.analyze(db, raw, filename)


@router.get("/evaluation")
def evaluation_report():
    if not _EVALUATION.is_file():
        raise AppError(
            "evaluation_not_run",
            "No measured evaluation file is stored. Run python -m app.evaluate.",
            404,
        )
    try:
        payload = json.loads(_EVALUATION.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AppError("evaluation_not_run", "The evaluation file could not be read.", 404) from exc
    return JSONResponse(payload)


@router.get("/incidents", response_model=IncidentList)
def list_incident_queue(
    risk_label: str | None = Query(default=None),
    case_status: str | None = Query(default=None),
    confidence_band: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> IncidentList:
    if risk_label is not None and risk_label not in _LABELS:
        raise AppError("validation_error", "risk_label is not recognized.", 422)
    if case_status is not None and case_status not in _STATUSES:
        raise AppError("validation_error", "case_status is not recognized.", 422)
    if confidence_band is not None and confidence_band not in _BANDS:
        raise AppError("validation_error", "confidence_band is not recognized.", 422)
    rows, total = list_incidents(
        db,
        risk_label=risk_label,
        case_status=case_status,
        confidence_band=confidence_band,
        limit=limit,
        offset=offset,
    )
    return IncidentList(items=[summary_from_incident(row) for row in rows], total=total)


@router.get("/metrics", response_model=MetricsOut)
def metrics(db: Session = Depends(get_db)) -> MetricsOut:
    snapshot = metrics_snapshot(db, RULESET_VERSION)
    return MetricsOut(
        ruleset=RULESET_VERSION,
        shrunk_agreement_percent=shrunk_agreement_percent(
            snapshot["agreements"], snapshot["disagreements"]
        ),
        disclaimer=_METRICS_NOTE,
        **snapshot,
    )


def _decided_incident(incident_id: str, db: Session):
    incident = get_incident(db, incident_id)
    if incident is None:
        raise AppError("incident_not_found", "The incident was not found.", 404)
    if not is_decided(incident):
        raise AppError(
            "report_not_ready",
            "Record a yes/no or a correct/wrong verdict before downloading the report.",
            409,
        )
    return incident


@router.get("/incidents/{incident_id}/report.docx")
def download_docx(incident_id: str, db: Session = Depends(get_db)) -> Response:
    incident = _decided_incident(incident_id, db)
    payload = build_docx(incident)
    name = f"{case_code(incident.id)}-incident-report.docx"
    return Response(
        content=payload,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/incidents/{incident_id}/report.xlsx")
def download_xlsx(incident_id: str, db: Session = Depends(get_db)) -> Response:
    incident = _decided_incident(incident_id, db)
    payload = build_xlsx(incident)
    name = f"{case_code(incident.id)}-incident-report.xlsx"
    return Response(
        content=payload,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident_detail(incident_id: str, db: Session = Depends(get_db)) -> IncidentDetail:
    incident = get_incident(db, incident_id)
    if incident is None:
        raise AppError("incident_not_found", "The incident was not found.", 404)
    return detail_from_incident(incident)


@router.post("/incidents/{incident_id}/decisions", response_model=AnalystDecision)
def record_decision(
    incident_id: str,
    payload: DecisionCreate,
    db: Session = Depends(get_db),
    orchestrator: TriageOrchestrator = Depends(get_orchestrator),
) -> AnalystDecision:
    return orchestrator.record_decision(db, incident_id, payload)


@router.post("/incidents/{incident_id}/feedback", response_model=VerdictFeedbackOut)
def record_verdict(
    incident_id: str,
    payload: VerdictFeedbackCreate,
    db: Session = Depends(get_db),
    orchestrator: TriageOrchestrator = Depends(get_orchestrator),
) -> VerdictFeedbackOut:
    return orchestrator.record_verdict(db, incident_id, payload)


@router.post("/incidents/{incident_id}/actions/response", response_model=ActionResponseOut)
def respond_to_action(
    incident_id: str,
    payload: ActionResponseCreate,
    db: Session = Depends(get_db),
    orchestrator: TriageOrchestrator = Depends(get_orchestrator),
) -> ActionResponseOut:
    return orchestrator.respond_to_action(db, incident_id, payload)


@router.post("/incidents/{incident_id}/actions/quarantine", response_model=QuarantineResult)
def quarantine(
    incident_id: str,
    payload: QuarantineRequest,
    db: Session = Depends(get_db),
    orchestrator: TriageOrchestrator = Depends(get_orchestrator),
) -> QuarantineResult:
    return orchestrator.simulate_quarantine(db, incident_id, payload)
