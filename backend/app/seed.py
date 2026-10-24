"""Load the synthetic samples when the local database has no cases."""

from pathlib import Path

from sqlalchemy import func, select

from app.agent.orchestrator import TriageOrchestrator
from app.db.models import Incident
from app.db.session import get_session_factory, init_db

SAMPLES = (
    "clearly_benign.eml",
    "no_signals.eml",
    "ambiguous.eml",
    "clearly_phishing.eml",
)


def seed_if_empty() -> int:
    init_db()
    session = get_session_factory()()
    try:
        count = session.scalar(select(func.count()).select_from(Incident)) or 0
        if count:
            print(f"seed_skipped existing_cases={count}")
            return 0
        root = Path(__file__).resolve().parents[2] / "samples"
        orchestrator = TriageOrchestrator()
        for name in SAMPLES:
            orchestrator.analyze(session, (root / name).read_bytes(), name)
            print(name)
        return len(SAMPLES)
    finally:
        session.close()


if __name__ == "__main__":
    seed_if_empty()
