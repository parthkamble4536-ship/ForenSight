"""
Phase 1 P0 regression tests:
- Persistent duplicate detection across application/pipeline restarts & concurrency
- Persistent Chain of Custody restoration, cross-restart continuation, and tamper detection
- HTML & PDF report XSS / XML injection escaping
- Persistent SQLite timeline storage without GET-time re-analysis
- Dependency completeness check against forensight imports
"""

import ast
import concurrent.futures
import io
import uuid
from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import Headers, UploadFile
from starlette.requests import Request

from forensight.api.routes import upload_evidence
from forensight.core.exceptions import DuplicateEvidenceError, IntegrityCompromisedError
from forensight.core.types import (
    AnalysisResult,
    EvidenceMetadata,
    EvidenceRecord,
    Finding,
    FindingSeverity,
    HashResult,
    IOCRecord,
    IOCType,
    RiskScore,
)
from forensight.crypto.keys import key_manager
from forensight.dashboard.routes import evidence_detail_page
from forensight.database.crud import create_evidence, list_timeline_events
from forensight.database.models import Base, CustodyEventModel, TimelineEventModel
from forensight.evidence.custody import CustodyLedger
from forensight.ingestion.pipeline import IngestionPipeline
from forensight.reports.generator import ReportGenerator
from forensight.storage.manager import EvidenceStorageManager, evidence_vault


@pytest.fixture
def sqlite_file_db(tmp_path: Path):
    """Provide a real file-backed SQLite engine + sessionmaker for cross-restart and concurrency tests."""
    db_path = tmp_path / "phase1_test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionFactory


class TestPhase1P0Fixes:
    """Regression suite validating all six Phase 1 P0 critical engineering fixes."""

    def test_requirements_txt_covers_third_party_imports(self) -> None:
        """Every third-party package imported in forensight/ must appear in requirements.txt."""
        import sys

        req_lines = Path("requirements.txt").read_text(encoding="utf-8").splitlines()
        declared = {
            line.strip().split(">=")[0].split("==")[0].split("[")[0].strip().lower()
            for line in req_lines
            if line.strip() and not line.strip().startswith("#")
        }

        import_map = {
            "pil": "pillow",
            "pydantic_settings": "pydantic-settings",
            "docx": "python-docx",
        }
        third_party = set()
        for py_file in Path("forensight").rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0].lower()
                        if top != "forensight" and top not in sys.stdlib_module_names:
                            third_party.add(import_map.get(top, top))
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top = node.module.split(".")[0].lower()
                    if top != "forensight" and top not in sys.stdlib_module_names:
                        third_party.add(import_map.get(top, top))

        missing = third_party - declared
        assert not missing, f"Missing dependencies in requirements.txt: {sorted(missing)}"

    def test_persistent_duplicate_detection_survives_restart(
        self,
        sqlite_file_db,
        storage_manager: EvidenceStorageManager,
    ) -> None:
        """Uploading identical bytes after a simulated restart must detect the DB-persisted duplicate."""
        payload = b"ForenSight Phase 1 restart duplicate test artifact\n"

        # Process 1: ingest and persist in SQLite
        pipeline1 = IngestionPipeline(vault_manager=storage_manager)
        with sqlite_file_db() as db1:
            res1 = pipeline1.ingest_bytes(payload, "first_run.txt", db=db1)
            create_evidence(db1, res1.evidence, res1.metadata, res1.manifest)
            pipeline1.release_inflight_hash(db1, res1.evidence.hashes.sha256)

        # Simulated restart: brand new IngestionPipeline instance (empty in-memory dict)
        pipeline2 = IngestionPipeline(vault_manager=storage_manager)
        with sqlite_file_db() as db2:
            with pytest.raises(DuplicateEvidenceError) as exc_info:
                pipeline2.ingest_bytes(payload, "second_run.txt", db=db2)

        assert exc_info.value.existing_evidence_id == res1.evidence.evidence_id
        assert exc_info.value.sha256 == res1.evidence.hashes.sha256

    def test_concurrent_duplicate_uploads_reject_race(
        self,
        sqlite_file_db,
        storage_manager: EvidenceStorageManager,
    ) -> None:
        """Concurrent uploads of identical content must allow only one writer and reject the duplicate."""
        payload = b"Concurrent duplicate upload race payload " + uuid.uuid4().hex.encode()
        pipeline = IngestionPipeline(vault_manager=storage_manager)

        def worker(idx: int):
            with sqlite_file_db() as db:
                res = pipeline.ingest_bytes(payload, f"concurrent_{idx}.txt", db=db)
                try:
                    create_evidence(db, res.evidence, res.metadata, res.manifest)
                finally:
                    pipeline.release_inflight_hash(db, res.evidence.hashes.sha256)
                return res.evidence.evidence_id

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(worker, 1)
            f2 = pool.submit(worker, 2)
            outcomes = []
            for fut in (f1, f2):
                try:
                    outcomes.append(("ok", fut.result()))
                except DuplicateEvidenceError as err:
                    outcomes.append(("dup", err.existing_evidence_id))

        assert sorted(o[0] for o in outcomes) == ["dup", "ok"]

    def test_custody_chain_persists_across_restart_and_detects_tampering(
        self,
        sqlite_file_db,
    ) -> None:
        """Custody ledger must resume from DB tail across restarts and fail loudly if historical row altered."""
        # Process 1: write two custody events
        ledger1 = CustodyLedger()
        with sqlite_file_db() as db1:
            e1 = ledger1.record_event("ev-p1", "ACQUISITION", "Acquired artifact", db=db1)
            e2 = ledger1.record_event("ev-p1", "ANALYSIS_RUN", "Analyzed artifact", db=db1)
            assert e1.previous_event_hash == CustodyLedger.GENESIS_HASH
            assert e2.previous_event_hash == e1.event_hash

        # Simulated restart: brand new CustodyLedger instance
        ledger2 = CustodyLedger()
        with sqlite_file_db() as db2:
            e3 = ledger2.record_event("ev-p1", "INTEGRITY_AUDIT", "Verified artifact", db=db2)
            assert e3.previous_event_hash == e2.event_hash
            is_valid, err = ledger2.verify_ledger_integrity(db=db2)
            assert is_valid is True, err

        # Tamper historical DB event directly
        with sqlite_file_db() as db3:
            row = db3.query(CustodyEventModel).filter(CustodyEventModel.event_id == e2.event_id).first()
            assert row is not None
            row.details = "TAMPERED AUDIT DETAILS"
            db3.commit()

        # New ledger instance MUST refuse to append or silently start a new chain
        ledger3 = CustodyLedger()
        with sqlite_file_db() as db4:
            is_valid, err = ledger3.verify_ledger_integrity(db=db4)
            assert is_valid is False
            assert "altered" in (err or "")
            with pytest.raises(IntegrityCompromisedError):
                ledger3.record_event("ev-p1", "REPORT_EXPORT", "Attempted append over tampered chain", db=db4)

    def test_html_and_pdf_reports_escape_xss_and_xml_payloads(self, tmp_path: Path) -> None:
        """Malicious HTML/JS/XML characters in untrusted metadata must be escaped in HTML & PDF exports."""
        xss_filename = '"><script>alert("xss")</script>.pdf'
        xss_title = '<img src=x onerror="alert(1)"> & Finding'
        result = AnalysisResult(
            evidence=EvidenceRecord(
                evidence_id="ev-xss-1",
                original_filename=xss_filename,
                sanitized_filename='script_alert.pdf',
                storage_path="/vault/ev-xss-1.bin",
                hashes=HashResult(sha256="a" * 64, sha1="b" * 40, md5="c" * 32, size_bytes=128),
            ),
            metadata=EvidenceMetadata(
                file_size_bytes=128,
                identified_type="PDF",
                mime_type="application/pdf<script>bad()</script>",
                declared_extension=".pdf",
                entropy=3.1,
            ),
            risk=RiskScore(score=50, verdict="SUSPICIOUS", summary='Summary with <script>bad()</script> & chars'),
            findings=[
                Finding(
                    rule_id="PDF-XSS-1",
                    category="TEST",
                    title=xss_title,
                    description='Desc <script>evil()</script> & more',
                    severity=FindingSeverity.HIGH,
                    score_impact=35,
                    explanation='Explain <b>bold</b> & <script>x</script>',
                )
            ],
            iocs=[
                IOCRecord(
                    ioc_type=IOCType.URL,
                    value="http://evil.example/a?x=<script>",
                    defanged_value="hxxp://evil[.]example/a?x=<script>",
                    context='PDF <script>alert(2)</script>',
                )
            ],
        )

        gen = ReportGenerator()
        html_out = gen.generate_html_report(result)
        assert "<script>" not in html_out
        assert "&lt;script&gt;" in html_out
        assert "&lt;img src=x onerror=" in html_out

        # Must also safely build ReportLab PDF without XML parser crash
        pdf_path = gen.generate_pdf_report(result, tmp_path / "escaped.pdf")
        assert pdf_path.exists()
        assert pdf_path.read_bytes().startswith(b"%PDF-")

    def test_timeline_persisted_in_sqlite_without_get_reanalysis(
        self,
        sqlite_file_db,
        monkeypatch,
    ) -> None:
        """Timeline events must be persisted during upload and read from DB without re-analyzing on GET."""
        key_manager.load_or_create_keypair()

        # Simple synthetic PDF with CreationDate metadata + unique marker for clean DB test
        unique_marker = uuid.uuid4().hex.encode()
        pdf_bytes = (
            b"%PDF-1.7\n% " + unique_marker + b"\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        upload = UploadFile(
            file=io.BytesIO(pdf_bytes),
            filename="timeline_test.pdf",
            headers=Headers({"content-type": "application/pdf"}),
        )

        with sqlite_file_db() as db:
            up_res = upload_evidence(file=upload, case_id="  ", db=db)
            ev_id = up_res["evidence_id"]
            try:
                # Verify timeline events exist in SQLite (INGESTION + ANALYSIS at minimum)
                persisted = list_timeline_events(db, evidence_id=ev_id)
                assert len(persisted) >= 2
                types_seen = {t.timestamp_type.value for t in persisted}
                assert "INGESTION" in types_seen
                assert "ANALYSIS" in types_seen

                # Verify api/routes.py sanitized whitespace case_id to None in custody rows
                custody_rows = db.query(CustodyEventModel).filter(CustodyEventModel.evidence_id == ev_id).all()
                assert all(r.case_id is None for r in custody_rows)

                # Force analyzer lookup to fail if evidence_detail_page attempts GET-time re-analysis
                import forensight.dashboard.routes as dash_routes
                monkeypatch.setattr(
                    dash_routes,
                    "get_analyzer_for_type",
                    lambda *_args, **_kwargs: pytest.fail("evidence_detail_page re-ran analyzer on GET!"),
                )

                scope = {
                    "type": "http",
                    "method": "GET",
                    "path": f"/evidence/{ev_id}",
                    "headers": [],
                    "query_string": b"",
                }
                req = Request(scope)
                resp = evidence_detail_page(evidence_id=ev_id, request=req, db=db)
                assert resp.status_code == 200
                assert "Evidence Vault Acquisition" in resp.body.decode("utf-8")
            finally:
                evidence_vault.delete_evidence(ev_id)
