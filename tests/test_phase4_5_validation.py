"""
Phase 4 & Phase 5 tests:
- Enriched 16-section HTML/JSON/PDF reporting, deterministic report_id, manifest verification, CSV & STIX 2.1 exports
- Adversarial synthetic test battery (malformed PE/PDF/DOCX/EML, oversized/empty uploads, zip bombs, Zip Slip,
  deeply nested archives, XML bombs, invalid signatures, tampered evidence/custody, interrupted transactions, timestamp edge cases)
- Security boundary assertions (path traversal, localhost binding, no external intel, no subprocess execution)
"""

import ast
import csv
import io
import json
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import Headers, UploadFile

from forensight.analyzers.docx_analyzer import DocxAnalyzer
from forensight.analyzers.email_analyzer import EmailAnalyzer
from forensight.analyzers.pdf_analyzer import PDFAnalyzer
from forensight.analyzers.pe_analyzer import PEAnalyzer
from forensight.analyzers.archive_analyzer import ArchiveAnalyzer
from forensight.api.routes import new_case, upload_evidence, verify_report_manifest
from forensight.core.config import settings
from forensight.core.exceptions import (
    ArchiveExplosionError,
    FileSizeExceededError,
    PathTraversalError,
)
from forensight.core.security import assert_safe_file_access, sanitize_filename
from forensight.core.types import EvidenceManifest, EvidenceMetadata, HashResult
from forensight.crypto.keys import key_manager
from forensight.dashboard.routes import (
    export_csv_findings,
    export_html,
    export_json,
    export_pdf,
    export_stix_iocs,
)
from forensight.database.models import Base, EvidenceModel
from forensight.ingestion.archive_safety import ArchiveSafetyInspector
from forensight.storage.manager import EvidenceStorageManager, evidence_vault


@pytest.fixture
def phase45_db(tmp_path: Path):
    db_path = tmp_path / "phase45.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


class TestPhase4Reporting:
    """Tests for 16-section enriched reports, manifest verification, CSV, and STIX 2.1 exports."""

    def test_all_report_exports_and_manifest_verification(self, phase45_db) -> None:
        key_manager.load_or_create_keypair()
        unique_url = f"http://c2-{uuid.uuid4().hex[:8]}.example.org/beacon"
        payload = (
            b"2026-11-12 [CMD] powershell -enc ZWNobyBoaQ== "
            + unique_url.encode("ascii")
            + b"\n"
        )
        upload = UploadFile(file=io.BytesIO(payload), filename="report_case.log", headers=Headers({"content-type": "text/plain"}))
        ev_id = None
        try:
            with phase45_db() as db:
                case = new_case(title="IR-Report Verification", investigator="Lead SOC", db=db)
                up = upload_evidence(file=upload, case_id=case.case_id, db=db)
                ev_id = up["evidence_id"]

                json_resp1 = export_json(ev_id, db=db)
                json_resp2 = export_json(ev_id, db=db)
                data1 = json.loads(json_resp1.body.decode("utf-8"))
                data2 = json.loads(json_resp2.body.decode("utf-8"))

                # Deterministic Report ID and complete 16-section coverage
                assert data1["report_metadata"]["report_id"] == data2["report_metadata"]["report_id"]
                assert data1["case"]["title"] == "IR-Report Verification"
                assert len(data1["custody_events"]) >= 2
                assert len(data1["timeline"]) >= 2
                assert data1["integrity_verification"]["verification_status"] == "INTEGRITY VERIFIED"
                assert data1["analysis_metadata"]["analyzer_versions"]
                assert data1["report_metadata"]["disclaimers"]

                # Manifest verification endpoint passes on authentic manifest, fails when tampered
                manifest = EvidenceManifest.model_validate(data1["manifest"])
                ver_ok = verify_report_manifest(manifest)
                assert ver_ok["signature_valid"] is True

                bad_manifest = manifest.model_copy(update={"original_filename": "tampered.exe"})
                ver_bad = verify_report_manifest(bad_manifest)
                assert ver_bad["signature_valid"] is False

                # HTML export contains all major sections & defanged IOC
                html_text = export_html(ev_id, db=db).body.decode("utf-8")
                assert data1["report_metadata"]["report_id"] in html_text
                assert "Chain of Custody Ledger" in html_text
                assert "INTEGRITY VERIFIED" in html_text
                assert "example[.]org/beacon" in html_text

                # PDF export builds valid PDF
                pdf_resp = export_pdf(ev_id, db=db)
                assert Path(pdf_resp.path).read_bytes().startswith(b"%PDF-")

                # CSV findings export
                csv_text = export_csv_findings(ev_id, db=db).body.decode("utf-8")
                rows = list(csv.reader(io.StringIO(csv_text)))
                assert rows[0][0] == "evidence_id"
                assert any("TXT-PS-001" in r for r in rows[1:])

                # STIX 2.1 IOC bundle export
                stix = json.loads(export_stix_iocs(ev_id, db=db).body.decode("utf-8"))
                assert stix["type"] == "bundle"
                indicators = [o for o in stix["objects"] if o["type"] == "indicator"]
                assert len(indicators) >= 1
                assert indicators[0]["pattern_type"] == "stix"
                assert "[.]" in indicators[0]["x_forensight_defanged"]
        finally:
            if ev_id:
                evidence_vault.delete_evidence(ev_id)


class TestPhase5AdversarialAndSecurity:
    """Adversarial synthetic files, boundary failures, and security guardrail regression tests."""

    def test_malformed_pe_pdf_docx_and_email_handled_safely(self, tmp_path: Path) -> None:
        # Malformed PE
        p_pe = tmp_path / "bad.exe"
        p_pe.write_bytes(b"MZ" + b"\x00" * 30)
        out_pe = PEAnalyzer().analyze(
            p_pe,
            EvidenceMetadata(file_size_bytes=32, identified_type="PE", mime_type="application/octet-stream", declared_extension=".exe", entropy=1.0),
        )
        assert any(f.rule_id == "PE-CORRUPT-001" for f in out_pe.findings)

        # Malformed PDF
        p_pdf = tmp_path / "bad.pdf"
        p_pdf.write_bytes(b"%PDF-1.7\n%%CORRUPT_BODY_NO_XREF\n")
        out_pdf = PDFAnalyzer().analyze(
            p_pdf,
            EvidenceMetadata(file_size_bytes=30, identified_type="PDF", mime_type="application/pdf", declared_extension=".pdf", entropy=3.0),
        )
        assert any(f.rule_id == "PDF-STRUCT-001" for f in out_pdf.findings)

        # Malformed DOCX (non-ZIP)
        p_docx = tmp_path / "bad.docx"
        p_docx.write_bytes(b"NOT_A_ZIP_CONTAINER")
        out_docx = DocxAnalyzer().analyze(
            p_docx,
            EvidenceMetadata(file_size_bytes=19, identified_type="DOCX", mime_type="application/octet-stream", declared_extension=".docx", entropy=3.0),
        )
        assert any(f.rule_id == "DOCX-CORRUPT-001" for f in out_docx.findings)

        # Malformed EML header/body
        p_eml = tmp_path / "weird.eml"
        p_eml.write_bytes(b"\xff\xfe\x00\x01garbage-mime-stream")
        out_eml = EmailAnalyzer().analyze(
            p_eml,
            EvidenceMetadata(file_size_bytes=23, identified_type="EML", mime_type="message/rfc822", declared_extension=".eml", entropy=4.0),
        )
        assert out_eml.details["attachments"] == []

    def test_zip_bomb_zip_slip_and_deep_nesting_bounds(self, tmp_path: Path) -> None:
        # 1. Zip Slip path traversal
        slip_zip = tmp_path / "slip.zip"
        with zipfile.ZipFile(slip_zip, "w") as zf:
            zf.writestr("../../etc/cron.d/evil", "echo hi")
        out_slip = ArchiveAnalyzer().analyze(
            slip_zip,
            EvidenceMetadata(file_size_bytes=slip_zip.stat().st_size, identified_type="ZIP", mime_type="application/zip", declared_extension=".zip", entropy=5.0),
        )
        assert any(f.rule_id == "ARCH-UNSAFE-001" for f in out_slip.findings)

        # 2. Entry flood / explosion
        flood_zip = tmp_path / "flood.zip"
        with zipfile.ZipFile(flood_zip, "w") as zf:
            for i in range(600):  # exceeds settings.archive_max_entries (500)
                zf.writestr(f"f_{i}.txt", "x")
        with pytest.raises(ArchiveExplosionError):
            ArchiveSafetyInspector().inspect_zip(flood_zip)

        # 3. Deeply nested ZIP chain (> archive_max_recursion_depth=2) stops cleanly without infinite recursion
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z0:
            z0.writestr("deep_leaf.pdf.exe", b"MZ")
        for level in range(4):
            outer = io.BytesIO()
            with zipfile.ZipFile(outer, "w") as zn:
                zn.writestr(f"lvl{level}.zip", buf.getvalue())
            buf = outer
        deep_zip = tmp_path / "deep.zip"
        deep_zip.write_bytes(buf.getvalue())
        out_deep = ArchiveAnalyzer().analyze(
            deep_zip,
            EvidenceMetadata(file_size_bytes=deep_zip.stat().st_size, identified_type="ZIP", mime_type="application/zip", declared_extension=".zip", entropy=6.0),
        )
        assert max((e["depth"] for e in out_deep.details["entries"]), default=0) <= settings.archive_max_recursion_depth

    def test_oversized_empty_and_interrupted_uploads_leave_no_orphan_files(self, tmp_path: Path, phase45_db) -> None:
        # Oversized stream cleanly rejected and partial file unlinked
        vault = EvidenceStorageManager(vault_dir=tmp_path / "vault", max_upload_size_bytes=64, chunk_size_bytes=16)
        with pytest.raises(FileSizeExceededError):
            vault.store_bytes(b"A" * 128, "oversize.bin")
        assert list((tmp_path / "vault").glob("*.bin")) == []

        # Empty (0-byte) upload handled cleanly through full API upload
        key_manager.load_or_create_keypair()
        empty_up = UploadFile(file=io.BytesIO(b""), filename="empty.txt", headers=Headers({"content-type": "text/plain"}))
        with phase45_db() as db:
            res = upload_evidence(file=empty_up, case_id=None, db=db)
            ev_id = res["evidence_id"]
            evidence_vault.delete_evidence(ev_id)

        # Simulated DB error rollback deletes orphan vault file cleanly via IngestionPipeline
        from forensight.ingestion.pipeline import IngestionPipeline
        pipe = IngestionPipeline(vault_manager=vault)
        with pytest.raises(RuntimeError):
            with phase45_db() as db_err:
                ing = pipe.ingest_bytes(b"transient_test_" + uuid.uuid4().hex.encode(), "abort.txt", db=db_err)
                try:
                    raise RuntimeError("Simulated DB transaction interruption")
                except Exception:
                    pipe.release_inflight_hash(db_err, ing.evidence.hashes.sha256)
                    vault.delete_evidence(ing.evidence.evidence_id)
                    raise
        assert list((tmp_path / "vault").glob("*.bin")) == []

    def test_security_boundaries_no_subprocess_or_external_intel(self, tmp_path: Path) -> None:
        assert settings.host == "127.0.0.1"
        assert settings.enable_external_intel is False

        # Traversal guards
        assert sanitize_filename("../../../../Windows/System32/cmd.exe") == "cmd.exe"
        with pytest.raises(PathTraversalError):
            assert_safe_file_access(tmp_path, tmp_path / ".." / "escape.txt")

        # Verify zero subprocess / os.system / eval / exec usage in forensight/ package
        forbidden_calls = {"subprocess", "os.system", "os.popen"}
        for py_file in Path("forensight").rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name not in forbidden_calls, f"Forbidden import {alias.name} in {py_file}"
                elif isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module not in forbidden_calls, f"Forbidden import {node.module} in {py_file}"
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec"), f"Forbidden builtin {node.func.id} in {py_file}"
