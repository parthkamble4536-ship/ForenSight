"""
Database engine and session management for ForenSight.

Configures SQLite with Write-Ahead Logging (WAL) and foreign key constraints.
"""

from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from forensight.core.config import settings
from forensight.database.models import Base

# Ensure data directory exists
settings.ensure_directories()

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    echo=settings.debug,
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable SQLite WAL mode and enforce foreign keys for performance and data integrity."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _ensure_column(inspector, table_name: str, column_name: str, ddl_type: str) -> None:
    if inspector.has_table(table_name):
        cols = {col["name"] for col in inspector.get_columns(table_name)}
        if column_name not in cols:
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl_type}"))


def init_db() -> None:
    """Create all database tables and apply safe additive schema migrations if needed."""
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    _ensure_column(inspector, "custody_events", "sequence_index", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(inspector, "findings", "rule_version", "VARCHAR(20) NOT NULL DEFAULT '1.0.0'")
    _ensure_column(inspector, "findings", "analyzer_name", "VARCHAR(120)")
    _ensure_column(inspector, "findings", "analyzer_version", "VARCHAR(20)")
    _ensure_column(inspector, "findings", "evidence_reference", "VARCHAR(255)")
    _ensure_column(inspector, "findings", "offset", "INTEGER")
    _ensure_column(inspector, "findings", "detected_at", "DATETIME")
    _ensure_column(inspector, "iocs", "offset", "INTEGER")
    _ensure_column(inspector, "iocs", "occurrences", "INTEGER NOT NULL DEFAULT 1")


def get_db() -> Generator[Session, None, None]:
    """Dependency helper yielding an active database session with automatic cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

