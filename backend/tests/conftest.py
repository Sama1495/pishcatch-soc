"""API client bound to a throwaway SQLite file."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    from app.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    database = tmp_path / "phishcatch.db"
    monkeypatch.setenv("PHISHCATCH_DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("PHISHCATCH_REPUTATION_ENABLED", "false")
    monkeypatch.setenv("PHISHCATCH_AI_ENABLED", "false")
    monkeypatch.setenv("PHISHCATCH_VT_API_KEY", "")
    monkeypatch.setenv("PHISHCATCH_URLHAUS_AUTH_KEY", "")
    monkeypatch.setenv("PHISHCATCH_AI_API_KEY", "")
    monkeypatch.setenv("PHISHCATCH_MAX_UPLOAD_BYTES", "1048576")
    monkeypatch.setenv("PHISHCATCH_TRUSTED_AUTHSERV_IDS", "")
    monkeypatch.setenv("PHISHCATCH_RDAP_ENABLED", "false")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("GEMINI_MODEL", "")
    monkeypatch.setenv("AI_EXPLAINER_PROVIDER", "")
    monkeypatch.setenv("PHISHCATCH_AI_EXPLAINER_PROVIDER", "")
    monkeypatch.setenv("PHISHCATCH_LOG_LEVEL", "INFO")

    from app.core.config import get_settings
    from app.db.session import reset_db_state

    get_settings.cache_clear()
    reset_db_state()
    from app.main import create_app

    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    reset_db_state()
    get_settings.cache_clear()
