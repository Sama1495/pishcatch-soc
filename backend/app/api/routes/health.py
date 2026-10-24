"""Liveness for the local API. It does not touch the case database."""

from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings
from app.integrations.explainer import AiExplainer
from app.services.rules import RULESET_VERSION

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "service": "phishcatch-soc",
        "version": __version__,
        "engine": "deterministic",
        "ruleset": RULESET_VERSION,
        "reputation_enabled": settings.reputation_enabled,
        "ai_enabled": settings.ai_enabled,
        "explainer_provider": AiExplainer.from_settings(settings).provider,
    }
