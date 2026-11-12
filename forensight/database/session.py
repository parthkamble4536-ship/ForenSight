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
    # Custody ledger ordering
    _ensure_column(inspector, "custody_events", "sequence_index", "INTEGER NOT NULL DEFAULT 0")
    # Detection provenance & IOC offsets (Phase 2)
    _ensure_column(inspector, "findings", "rule_version", "VARCHAR(20) NOT NULL DEFAULT '1.0.0'")
    _ensure_column(inspector, "findings", "analyzer_name", "VARCHAR(120)")
    _ensure_column(inspector, "findings", "analyzer_version", "VARCHAR(20)")
    _ensure_column(inspector, "findings", "evidence_reference", "VARCHAR(255)")
    _ensure_column(inspector, "findings", "offset", "INTEGER")
    _ensure_column(inspector, "findings", "detected_at", "DATETIME")
    _ensure_column(inspector, "iocs", "offset", "INTEGER")
    _ensure_column(inspector, "iocs", "occurrences", "INTEGER NOT NULL DEFAULT 1")
    # Findings investigation workflow (Phase 3)
    _ensure_column(inspector, "findings", "review_status", "VARCHAR(30) NOT NULL DEFAULT 'OPEN'")
    _ensure_column(inspector, "findings", "is_false_positive", "BOOLEAN NOT NULL DEFAULT 0")
    _ensure_column(inspector, "findings", "analyst_notes", "TEXT")
    _ensure_column(inspector, "findings", "reviewed_by", "VARCHAR(100)")
    _ensure_column(inspector, "findings", "reviewed_at", "DATETIME")
    _ensure_column(inspector, "findings", "review_history_json", "TEXT")
    # Evidence verification telemetry & tags (Phase 3)
    _ensure_column(inspector, "evidence_items", "manifest_id", "VARCHAR(36)")
    _ensure_column(inspector, "evidence_items", "last_verified_at", "DATETIME")
    _ensure_column(inspector, "evidence_items", "last_verification_status", "VARCHAR(50)")
    _ensure_column(inspector, "evidence_items", "last_verification_details", "TEXT")
    _ensure_column(inspector, "evidence_items", "tags_json", "TEXT")
    # Case analyst workflow & closure (Phase 3)
    _ensure_column(inspector, "cases", "updated_at", "DATETIME")
    _ensure_column(inspector, "cases", "investigator_notes", "TEXT")
    _ensure_column(inspector, "cases", "case_summary", "TEXT")
    _ensure_column(inspector, "cases", "tags_json", "TEXT")
    _ensure_column(inspector, "cases", "closed_by", "VARCHAR(100)")
    _ensure_column(inspector, "cases", "closed_at", "DATETIME")
    _ensure_column(inspector, "cases", "closure_notes", "TEXT")


def get_db() -> Generator[Session, None, None]:
    """Dependency helper yielding an active database session with automatic cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

