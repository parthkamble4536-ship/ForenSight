"""
Comprehensive integration tests for API routes, triage handlers, and report exports.
"""

import io
import json
from pathlib import Path
import pytest
from starlette.datastructures import Headers, UploadFile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from forensight.api.routes import (
    dashboard_stats,
    get_cases,
    health_check,
    new_case,
    upload_evidence,
    verify_integrity,
)
from forensight.core.config import settings
from forensight.crypto.keys import key_manager
from forensight.dashboard.routes import export_html, export_json, export_pdf
from forensight.database.models import Base


@pytest.fixture
def test_db():
    """Create an isolated SQLite database session for API testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def setup_environment():
    """Initialize necessary directories and cryptographic keys."""
    settings.ensure_directories()
    key_manager.load_or_create_keypair()


class TestAPIEndpointsDirect:
    """Direct functional integration testing of API and triage pipeline handlers."""

    def test_health_check(self) -> None:
        """Verify API health check response."""
        res = health_check()
        assert res["status"] == "HEALTHY"
        assert res["app"] == "ForenSight"

    def test_dashboard_summary(self, test_db) -> None:
        """Verify dashboard statistics computation."""
        stats = dashboard_stats(db=test_db)
        assert "total_cases" in stats
        assert "total_evidence" in stats
        assert stats["total_cases"] == 0

    def test_case_lifecycle(self, test_db) -> None:
        """Verify creating a case and listing cases."""
        case = new_case(
            title="APT Triage Operation",
            description="Investigating suspicious dropper",
            investigator="Lead Analyst",
            db=test_db,
        )
        assert case.case_id is not None
        assert case.title == "APT Triage Operation"

        cases_list = get_cases(db=test_db)
        assert len(cases_list) == 1
        assert cases_list[0].case_id == case.case_id

    def test_evidence_upload_triage_verify_and_export(self, test_db) -> None:
        """
        Verify end-to-end evidence upload, automatic static analysis, manifest signing,
        live integrity verification, and HTML/JSON/PDF report exports.
        """
        # 1. Create a Case
        case = new_case(title="Malware Triage Case", db=test_db)

        # 2. Upload and Ingest a synthetic log artifact
        log_bytes = b"2026-11-10 14:00:00 [ALERT] Connecting to http://malicious-c2-portal.org/beacon\n"
        upload_file = UploadFile(
            file=io.BytesIO(log_bytes),
            filename="network_capture.log",
            headers=Headers({"content-type": "text/plain"}),
        )

        upload_result = upload_evidence(
            file=upload_file,
            case_id=case.case_id,
            db=test_db,
        )

        assert "evidence_id" in upload_result
        evidence_id = upload_result["evidence_id"]
        assert upload_result["filename"] == "network_capture.log"
        assert upload_result["identified_type"] == "TXT"

        # 3. Live Cryptographic Integrity Verification
        audit = verify_integrity(evidence_id=evidence_id, db=test_db)
        assert audit["is_valid"] is True
        assert audit["is_path_safe"] is True
        assert audit["computed_size_bytes"] == len(log_bytes)

        # 4. Standalone HTML Report Export
        html_resp = export_html(evidence_id=evidence_id, db=test_db)
        assert html_resp.status_code == 200
        html_text = html_resp.body.decode("utf-8")
        assert "<!DOCTYPE html>" in html_text
        assert "network_capture.log" in html_text
        assert "hxxp://malicious-c2-portal[.]org/beacon" in html_text

        # 5. JSON Report Export
        json_resp = export_json(evidence_id=evidence_id, db=test_db)
        assert json_resp.status_code == 200
        json_data = json.loads(json_resp.body.decode("utf-8"))
        assert json_data["evidence"]["evidence_id"] == evidence_id
        assert json_data["evidence"]["hashes"]["sha256"] is not None

        # 6. PDF Report Export
        pdf_resp = export_pdf(evidence_id=evidence_id, db=test_db)
        assert pdf_resp.status_code == 200
        assert pdf_resp.media_type == "application/pdf"
        assert Path(pdf_resp.path).exists()
        pdf_bytes = Path(pdf_resp.path).read_bytes()
        assert pdf_bytes.startswith(b"%PDF-")
