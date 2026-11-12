"""
Database models, session management, and CRUD helpers for ForenSight.
"""

from forensight.database.crud import (
    create_case,
    create_evidence,
    get_case,
    get_dashboard_summary,
    get_evidence,
    get_evidence_by_hash,
    get_latest_analysis_run,
    list_cases,
    list_custody_events,
    list_evidence,
    list_timeline_events,
    record_analysis_run,
    save_custody_event,
    save_timeline_events,
)
from forensight.database.models import (
    AnalysisRunModel,
    Base,
    CaseModel,
    CustodyEventModel,
    EvidenceModel,
    FindingModel,
    IOCModel,
    TimelineEventModel,
)
from forensight.database.session import SessionLocal, engine, get_db, init_db

__all__ = [
    "Base",
    "CaseModel",
    "EvidenceModel",
    "AnalysisRunModel",
    "FindingModel",
    "IOCModel",
    "CustodyEventModel",
    "TimelineEventModel",
    "engine",
    "SessionLocal",
    "init_db",
    "get_db",
    "create_case",
    "get_case",
    "list_cases",
    "create_evidence",
    "get_evidence",
    "get_evidence_by_hash",
    "list_evidence",
    "record_analysis_run",
    "get_latest_analysis_run",
    "save_custody_event",
    "list_custody_events",
    "save_timeline_events",
    "list_timeline_events",
    "get_dashboard_summary",
]

