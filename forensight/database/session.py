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


def init_db() -> None:
    """Create all database tables and apply safe additive schema migrations if needed."""
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    if inspector.has_table("custody_events"):
        cols = {col["name"] for col in inspector.get_columns("custody_events")}
        if "sequence_index" not in cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE custody_events ADD COLUMN sequence_index INTEGER NOT NULL DEFAULT 0")
                )


def get_db() -> Generator[Session, None, None]:
    """Dependency helper yielding an active database session with automatic cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

