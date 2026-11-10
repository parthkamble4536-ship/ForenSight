"""
Unit tests for SQLite persistence, SQLAlchemy models, and CRUD operations.
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from forensight.core.types import (
    ConfidenceLevel,
    EvidenceMetadata,
    EvidenceRecord,
    Finding,
    FindingSeverity,
    HashResult,
    IOCRecord,
    IOCType,
    RiskScore,
)
from forensight.database.crud import (
    create_case,
    create_evidence,
    get_case,
    get_dashboard_summary,
    get_evidence,
    get_latest_analysis_run,
    list_cases,
    list_evidence,
    record_analysis_run,
)
from forensight.database.models import Base


@pytest.fixture
def test_db_session():
    """Create an in-memory SQLite database session for isolated testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


class TestDatabaseCRUD:
    """Tests for database operations and relational integrity."""

    def test_create_and_retrieve_case(self, test_db_session) -> None:
        """Verify creating and fetching an investigation case."""
        case = create_case(test_db_session, title="Project Chimera", description="APT Triage", investigator="Agent Mulder")
        assert case.case_id is not None
        assert case.title == "Project Chimera"

        fetched = get_case(test_db_session, case.case_id)
        assert fetched is not None
        assert fetched.investigator == "Agent Mulder"

    def test_create_evidence_and_analysis_run(self, test_db_session) -> None:
        """Verify persisting evidence and attaching an immutable analysis run with findings."""
        case = create_case(test_db_session, title="Case Delta")

        record = EvidenceRecord(
            evidence_id="ev-999",
            case_id=case.case_id,
            original_filename="dropper.exe",
            sanitized_filename="dropper.exe",
            storage_path="/data/evidence/ev-999.bin",
            hashes=HashResult(
                sha256="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
                sha1="2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
                md5="9e107d9d372bb6826bd81d3542a419d6",
                size_bytes=4096,
            ),
        )
        meta = EvidenceMetadata(
            file_size_bytes=4096,
            identified_type="PE",
            mime_type="application/vnd.microsoft.portable-executable",
            declared_extension=".exe",
            entropy=6.8,
        )

        ev_model = create_evidence(test_db_session, record, meta)
        assert ev_model.evidence_id == "ev-999"

        finding = Finding(
            rule_id="PE-PACKING-001",
            category="PACKING",
            title="UPX Packed",
            description="High entropy section detected",
            severity=FindingSeverity.HIGH,
            confidence=ConfidenceLevel.CONFIRMED,
            score_impact=30,
        )
        ioc = IOCRecord(ioc_type=IOCType.IPV4, value="198.51.100.1", defanged_value="198[.]51[.]100[.]1")

        run = record_analysis_run(
            test_db_session,
            evidence_id="ev-999",
            risk=RiskScore(score=75, verdict="HIGH RISK", summary="Suspicious packed binary"),
            findings=[finding],
            iocs=[ioc],
            details={"machine": "AMD64"},
        )

        assert run.run_id is not None
        assert run.risk_score == 75

        latest = get_latest_analysis_run(test_db_session, "ev-999")
        assert latest is not None
        assert len(latest.findings) == 1
        assert latest.findings[0].rule_id == "PE-PACKING-001"
        assert len(latest.iocs) == 1

        summary = get_dashboard_summary(test_db_session)
        assert summary["total_cases"] == 1
        assert summary["total_evidence"] == 1
        assert summary["suspicious_evidence"] == 1
