"""Engine and session factory. The URL comes from the environment."""

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.models import Base

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def sqlite_file_path(url: str) -> Path | None:
    if not url.startswith("sqlite:"):
        return None
    raw = url.split("sqlite:///", 1)[-1]
    if not raw or raw.startswith(":memory:"):
        return None
    return Path(raw)


def _ensure_sqlite_parent(url: str) -> None:
    path = sqlite_file_path(url)
    if path is not None and str(path.parent) not in {"", "."}:
        path.parent.mkdir(parents=True, exist_ok=True)


def get_engine() -> Engine:
    global _engine, _session_factory
    if _engine is None:
        url = get_settings().database_url
        _ensure_sqlite_parent(url)
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args, pool_pre_ping=not url.startswith("sqlite"))
        if url.startswith("sqlite"):

            @event.listens_for(_engine, "connect")
            def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        _session_factory = sessionmaker(bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    get_engine()
    assert _session_factory is not None
    return _session_factory


def init_db() -> None:
    Base.metadata.create_all(get_engine())
    _migrate_sqlite()


def _migrate_sqlite() -> None:
    """Add columns introduced after the first local database file."""
    engine = get_engine()
    if not str(engine.url).startswith("sqlite"):
        return
    with engine.begin() as connection:
        tables = {
            row[0]
            for row in connection.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        }
        if "incidents" in tables:
            _add_columns(
                connection,
                "incidents",
                {
                    "confidence_score": "INTEGER NOT NULL DEFAULT 0",
                    "confidence_band": "VARCHAR(16) NOT NULL DEFAULT 'low'",
                    "confidence_json": "TEXT",
                    "policy_json": "TEXT",
                },
            )
        if "analyst_decisions" in tables:
            _add_columns(
                connection,
                "analyst_decisions",
                {"ruleset_version": "VARCHAR(32) NOT NULL DEFAULT '1.0.0'"},
            )


def _add_columns(connection, table: str, columns: dict[str, str]) -> None:
    existing = {row[1] for row in connection.execute(text(f"PRAGMA table_info({table})"))}
    for name, ddl in columns.items():
        if name not in existing:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def reset_db_state() -> None:
    """Drop the cached engine so tests can point at a fresh file."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def get_db() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
