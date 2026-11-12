"""
RESTful API endpoints for ForenSight programmatic triage and automation.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy.orm import Session

from forensight.analyzers import get_analyzer_for_type
from forensight.core.config import settings
from forensight.core.exceptions import (
    DuplicateEvidenceError,
    EvidenceNotFoundError,
    FileSizeExceededError,
    IntegrityCompromisedError,
)
from forensight.core.types import (
    AnalysisResult,
    ConfidenceLevel,
    EvidenceManifest,
    EvidenceMetadata,
    EvidenceRecord,
    Finding,
    FindingSeverity,
    HashResult,
    IOCRecord,
    IOCType,
    RiskScore,
    TimelineEvent,
    TimelineEventType,
)
from forensight.crypto.keys import key_manager
from forensight.crypto.signing import sign_manifest
from forensight.database import (
    create_case,
    create_evidence,
    get_case,
    get_dashboard_summary,
    get_db,
    get_evidence,
    get_latest_analysis_run,
    list_cases,
    list_custody_events,
    list_evidence,
    record_analysis_run,
    save_custody_event,
)
from forensight.evidence.custody import custody_ledger
from forensight.ingestion.pipeline import ingestion_pipeline
from forensight.intelligence.scoring import risk_engine
from forensight.reports.generator import report_generator
from forensight.storage.manager import evidence_vault

api_router = APIRouter(prefix="/api/v1", tags=["API v1"])


@api_router.get("/health")
def health_check() -> Dict[str, str]:
    """Service health and version probe."""
    return {"status": "HEALTHY", "app": settings.app_name, "version": settings.version}


@api_router.get("/dashboard/summary")
def dashboard_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Retrieve high-level triage statistics."""
    return get_dashboard_summary(db)


def _sanitize_form_str(val: Any, default: Optional[str] = None) -> Optional[str]:
    """Sanitize FastAPI Form() defaults when endpoint callables are invoked directly."""
    if val is None or hasattr(val, "default"):
        return default
    cleaned = str(val).strip()
    return cleaned if cleaned else default


# --- Case Endpoints ---

@api_router.get("/cases")
def get_cases(db: Session = Depends(get_db)):
    """List all investigation cases."""
    return list_cases(db)


@api_router.post("/cases")
def new_case(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    investigator: str = Form("Lead Investigator"),
    db: Session = Depends(get_db),
):
    """Create a new investigation case."""
    clean_title = _sanitize_form_str(title, "Untitled Case") or "Untitled Case"
    clean_desc = _sanitize_form_str(description, None)
    clean_inv = _sanitize_form_str(investigator, "Lead Investigator") or "Lead Investigator"
    case = create_case(db, title=clean_title, description=clean_desc, investigator=clean_inv)
    return case


@api_router.get("/cases/{case_id}")
def case_details(case_id: str, db: Session = Depends(get_db)):
    """Get investigation case details and associated evidence items."""
    case = get_case(db, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    evidence_list = list_evidence(db, case_id=case_id)
    return {"case": case, "evidence": evidence_list}


# --- Evidence Ingestion & Analysis Endpoints ---

@api_router.post("/evidence/upload")
def upload_evidence(
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """
    Secure evidence upload, streaming ingestion, duplicate detection, and static analysis.
    """
    clean_case_id = _sanitize_form_str(case_id, None)
    filename = file.filename or "uploaded_artifact.bin"

    try:
        # Ingest stream into vault with authoritative SQLite duplicate detection
        ingest_result = ingestion_pipeline.ingest_stream(
            stream=file.file,
            original_filename=filename,
            case_id=clean_case_id,
            allow_duplicates=False,
            db=db,
        )
    except DuplicateEvidenceError as dup:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(dup),
        )
    except FileSizeExceededError as size_err:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(size_err),
        )
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"Ingestion failed: {err}")

    sha256 = ingest_result.evidence.hashes.sha256
    try:
        # Digitally sign the evidence manifest using Ed25519
        priv_key, pub_key = key_manager.load_or_create_keypair()
        signed_manifest = sign_manifest(ingest_result.manifest, priv_key)

        # Persist evidence record
        evidence_model = create_evidence(
            db,
            evidence=ingest_result.evidence,
            metadata=ingest_result.metadata,
            manifest=signed_manifest,
        )
    finally:
        ingestion_pipeline.release_inflight_hash(db, sha256)

    # Record persistent hash-chained custody acquisition event
    try:
        custody_ledger.record_event(
            evidence_id=ingest_result.evidence.evidence_id,
            case_id=clean_case_id,
            event_type="ACQUISITION",
            details=f"Acquired untrusted artifact '{filename}' (SHA-256: {sha256})",
            db=db,
        )
    except IntegrityCompromisedError as integrity_err:
        raise HTTPException(status_code=500, detail=str(integrity_err))

    # Execute designated static analyzer
    stored_path = Path(ingest_result.evidence.storage_path)
    analyzer = get_analyzer_for_type(ingest_result.metadata.identified_type)

    if analyzer:
        analysis_output = analyzer.analyze(stored_path, ingest_result.metadata)
    else:
        from forensight.analyzers.base import AnalyzerOutput
        analysis_output = AnalyzerOutput()

    # Calculate explainable risk score
    risk = risk_engine.calculate_risk(analysis_output.findings)

    # Assemble complete UTC timeline events for persistence
    ev_id = ingest_result.evidence.evidence_id
    persisted_timeline: List[TimelineEvent] = []
    for tev in analysis_output.timeline_events:
        persisted_timeline.append(
            tev.model_copy(
                update={
                    "evidence_id": ev_id,
                    "original_timestamp": tev.original_timestamp or tev.timestamp.isoformat(),
                }
            )
        )
    persisted_timeline.append(
        TimelineEvent(
            event_id=str(uuid.uuid4()),
            evidence_id=ev_id,
            timestamp=ingest_result.evidence.stored_at,
            original_timestamp=ingest_result.evidence.stored_at.isoformat(),
            timestamp_type=TimelineEventType.INGESTION,
            source="Evidence Vault Acquisition",
            description=f"Artifact '{filename}' ingested and hashed (SHA-256: {sha256[:16]}...)",
            confidence=ConfidenceLevel.CONFIRMED,
        )
    )
    analysis_ts = datetime.now(timezone.utc)
    persisted_timeline.append(
        TimelineEvent(
            event_id=str(uuid.uuid4()),
            evidence_id=ev_id,
            timestamp=analysis_ts,
            original_timestamp=analysis_ts.isoformat(),
            timestamp_type=TimelineEventType.ANALYSIS,
            source=analyzer.name if analyzer else "Static Triage Pipeline",
            description=f"Static analysis completed: Verdict={risk.verdict} ({risk.score}/100)",
            confidence=ConfidenceLevel.CONFIRMED,
        )
    )

    # Persist analysis run and timeline events
    record_analysis_run(
        db,
        evidence_id=ev_id,
        risk=risk,
        findings=analysis_output.findings,
        iocs=analysis_output.iocs,
        details=analysis_output.details,
        timeline_events=persisted_timeline,
    )

    # Record analysis event in persistent custody ledger
    try:
        custody_ledger.record_event(
            evidence_id=ev_id,
            case_id=clean_case_id,
            event_type="ANALYSIS_RUN",
            details=f"Static analysis executed by '{analyzer.name if analyzer else 'None'}': Verdict={risk.verdict} ({risk.score}/100)",
            db=db,
        )
    except IntegrityCompromisedError as integrity_err:
        raise HTTPException(status_code=500, detail=str(integrity_err))

    return {
        "evidence_id": ingest_result.evidence.evidence_id,
        "filename": filename,
        "sha256": ingest_result.evidence.hashes.sha256,
        "identified_type": ingest_result.metadata.identified_type,
        "risk_score": risk.score,
        "verdict": risk.verdict,
        "findings_count": len(analysis_output.findings),
        "iocs_count": len(analysis_output.iocs),
    }


@api_router.post("/evidence/{evidence_id}/verify")
def verify_integrity(evidence_id: str, db: Session = Depends(get_db)):
    """
    Perform live multi-factor cryptographic audit comparing recorded hashes against stored file.
    """
    ev = get_evidence(db, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    expected_hashes = HashResult(
        sha256=ev.sha256,
        sha1=ev.sha1,
        md5=ev.md5,
        size_bytes=ev.file_size_bytes,
    )

    audit = evidence_vault.verify_evidence_integrity(evidence_id, expected_hashes)

    # Record audit event in persistent custody ledger
    try:
        custody_ledger.record_event(
            evidence_id=evidence_id,
            case_id=ev.case_id,
            event_type="INTEGRITY_AUDIT",
            details=f"Live cryptographic audit: {'PASSED' if audit.is_valid else 'FAILED'} ({audit.details})",
            db=db,
        )
    except IntegrityCompromisedError as integrity_err:
        raise HTTPException(status_code=500, detail=str(integrity_err))

    return audit.model_dump()
