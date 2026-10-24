"""Environment-backed settings. Secrets stay in the environment, never in code."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _discover_env_file() -> str | None:
    """Load a gitignored .env from the repo root or the current directory."""
    root_env = Path(__file__).resolve().parents[3] / ".env"
    if root_env.is_file():
        return str(root_env)
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        return str(cwd_env)
    return None


class Settings(BaseSettings):
    """Runtime settings.

    Boolean flags default to the safe position: reputation and the AI
    explainer are disabled, so the deterministic engine is the whole product
    until an operator turns them on.
    """

    model_config = SettingsConfigDict(
        env_file=_discover_env_file(),
        env_file_encoding="utf-8",
        env_prefix="PHISHCATCH_",
        extra="ignore",
    )

    max_upload_bytes: int = 1_048_576
    database_url: str = "sqlite:///./data/phishcatch.db"
    cors_origins: str = "http://127.0.0.1:8742,http://localhost:8742"
    reputation_enabled: bool = False
    reputation_timeout_seconds: float = 3.0
    vt_api_key: str = ""
    urlhaus_auth_key: str = ""
    ai_enabled: bool = False
    ai_timeout_seconds: float = 5.0
    ai_api_key: str = ""
    ai_model: str = ""
    # Comma-separated Authentication-Results authserv-ids. Empty means none are scored.
    trusted_authserv_ids: str = ""
    # Opt-in RDAP age check. Off by default; it never fetches a URL from the mail.
    rdap_enabled: bool = False
    log_level: str = "INFO"

    @property
    def trusted_authserv_set(self) -> set[str]:
        return {
            item.strip().lower().rstrip(".")
            for item in self.trusted_authserv_ids.split(",")
            if item.strip()
        }

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
