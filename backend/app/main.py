"""PhishCatch SOC API entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.errors import install_exception_handlers
from app.api.routes.health import router as health_router
from app.api.routes.incidents import router as incidents_router
from app.core.config import get_settings
from app.core.logging import get_logger, setup_logging
from app.db.session import init_db

logger = get_logger()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    setup_logging()
    init_db()
    settings = get_settings()
    logger.info(
        "service_started version=%s reputation_enabled=%s ai_enabled=%s",
        __version__,
        settings.reputation_enabled,
        settings.ai_enabled,
    )
    yield


def create_app() -> FastAPI:
    setup_logging()
    settings = get_settings()
    application = FastAPI(
        title="PhishCatch SOC",
        summary="Deterministic phishing triage for SOC analysts, with optional reputation and AI stubs.",
        version=__version__,
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    install_exception_handlers(application)
    application.include_router(health_router)
    application.include_router(incidents_router)
    return application


app = create_app()
