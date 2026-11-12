"""
RESTful API endpoints for ForenSight programmatic triage and automation.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
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
    list_case_activities,
    list_cases,
    list_custody_events,
    list_evidence,
    list_findings,
    list_timeline_events,
    record_analysis_run,
    save_custody_event,
    update_case_workflow,
    update_evidence_tags,
    update_finding_review,
)
from forensight.evidence.custody import custody_ledger
from forensight.evidence.timeline import timeline_aggregator
from forensight.evidence.verification import verify_evidence_comprehensive
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
        analysis_output.findings = analyzer.finalize_findings(
            analysis_output.findings,
            evidence_reference=ingest_result.evidence.evidence_id,
        )
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
    Perform comprehensive multi-factor cryptographic audit (hashes, size, Ed25519 manifest,
    and persisted Chain of Custody continuity) and store verification telemetry.
    """
    result = verify_evidence_comprehensive(db, evidence_id, record_custody=True)
    if result is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return result


@api_router.post("/verification/verify-all")
def verify_all_evidence(db: Session = Depends(get_db)):
    """Run comprehensive verification across all vaulted evidence artifacts."""
    items = list_evidence(db, limit=200)
    results = []
    for ev in items:
        res = verify_evidence_comprehensive(db, ev.evidence_id, record_custody=False)
        if res is not None:
            results.append(res)
    custody_valid, custody_err, _ = custody_ledger.verify_persisted_chain(db)
    return {
        "total_checked": len(results),
        "custody_chain_valid": custody_valid,
        "custody_chain_error": custody_err,
        "results": results,
    }


# --- Analyst Case Workflow, Evidence Tags & Finding Investigation Endpoints (Phase 3) ---

class CaseWorkflowPatch(BaseModel):
    status: Optional[str] = Field(default=None, description="OPEN, IN_PROGRESS, UNDER_REVIEW, or CLOSED")
    investigator: Optional[str] = None
    investigator_notes: Optional[str] = None
    case_summary: Optional[str] = None
    tags: Optional[List[str]] = None
    closure_notes: Optional[str] = None
    actor: str = "SOC Analyst"


class EvidenceTagsBody(BaseModel):
    tags: List[str] = Field(default_factory=list)


class FindingReviewBody(BaseModel):
    review_status: str = Field(description="OPEN, CONFIRMED, NEEDS_FOLLOWUP, or FALSE_POSITIVE")
    is_false_positive: bool = False
    analyst_notes: Optional[str] = None
    reviewed_by: str = "SOC Analyst"


@api_router.patch("/cases/{case_id}")
def patch_case_workflow(case_id: str, body: CaseWorkflowPatch, db: Session = Depends(get_db)):
    """Update case status, notes, tags, summary, and closure attribution."""
    try:
        updated = update_case_workflow(
            db,
            case_id,
            status=body.status,
            investigator=body.investigator,
            investigator_notes=body.investigator_notes,
            case_summary=body.case_summary,
            tags=body.tags,
            closure_notes=body.closure_notes,
            actor=body.actor,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    if not updated:
        raise HTTPException(status_code=404, detail="Case not found")
    return {
        "case_id": updated.case_id,
        "status": updated.status,
        "investigator": updated.investigator,
        "investigator_notes": updated.investigator_notes,
        "case_summary": updated.case_summary,
        "closed_by": updated.closed_by,
        "closed_at": updated.closed_at.isoformat() if updated.closed_at else None,
    }


@api_router.post("/evidence/{evidence_id}/tags")
def set_evidence_tags(evidence_id: str, body: EvidenceTagsBody, db: Session = Depends(get_db)):
    """Update analyst classification tags on an evidence artifact."""
    ev = update_evidence_tags(db, evidence_id, body.tags)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {"evidence_id": ev.evidence_id, "tags": body.tags}


@api_router.get("/findings")
def query_findings(
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    review_status: Optional[str] = None,
    rule_id: Optional[str] = None,
    analyzer_name: Optional[str] = None,
    evidence_id: Optional[str] = None,
    case_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Query findings with rule provenance, evidence attribution, and analyst disposition."""
    rows = list_findings(
        db,
        severity=severity,
        confidence=confidence,
        review_status=review_status,
        rule_id=rule_id,
        analyzer_name=analyzer_name,
        evidence_id=evidence_id,
        case_id=case_id,
    )
    return [
        {
            "finding_id": r["finding"].finding_id,
            "rule_id": r["finding"].rule_id,
            "rule_version": r["finding"].rule_version,
            "analyzer_name": r["finding"].analyzer_name,
            "analyzer_version": r["finding"].analyzer_version,
            "severity": r["finding"].severity,
            "confidence": r["finding"].confidence,
            "title": r["finding"].title,
            "description": r["finding"].description,
            "explanation": r["finding"].explanation,
            "object_reference": r["finding"].object_reference,
            "offset": r["finding"].offset,
            "review_status": r["finding"].review_status,
            "is_false_positive": r["finding"].is_false_positive,
            "analyst_notes": r["finding"].analyst_notes,
            "reviewed_by": r["finding"].reviewed_by,
            "reviewed_at": r["finding"].reviewed_at.isoformat() if r["finding"].reviewed_at else None,
            "review_history": r["review_history"],
            "evidence_id": r["evidence"].evidence_id,
            "evidence_filename": r["evidence"].original_filename,
            "case_id": r["evidence"].case_id,
        }
        for r in rows
    ]


@api_router.post("/findings/{finding_id}/review")
def review_finding(finding_id: str, body: FindingReviewBody, db: Session = Depends(get_db)):
    """Record analyst disposition, false-positive flag, and notes on a finding."""
    try:
        updated = update_finding_review(
            db,
            finding_id,
            review_status=body.review_status,
            is_false_positive=body.is_false_positive,
            analyst_notes=body.analyst_notes,
            reviewed_by=body.reviewed_by,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "finding_id": updated.finding_id,
        "review_status": updated.review_status,
        "is_false_positive": updated.is_false_positive,
        "analyst_notes": updated.analyst_notes,
        "reviewed_by": updated.reviewed_by,
        "reviewed_at": updated.reviewed_at.isoformat() if updated.reviewed_at else None,
    }


@api_router.get("/timeline")
def get_unified_timeline(
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Retrieve unified multi-source UTC timeline (metadata, ingestion, analysis, custody, case activity)."""
    if evidence_id:
        ev = get_evidence(db, evidence_id)
        if not ev:
            raise HTTPException(status_code=404, detail="Evidence not found")
        t_events = list_timeline_events(db, evidence_id=evidence_id)
        c_events = list_custody_events(db, evidence_id=evidence_id)
        unified = timeline_aggregator.build_unified_investigation_timeline(
            timeline_events=t_events,
            custody_rows=c_events,
            evidence_names={ev.evidence_id: ev.original_filename},
        )
    elif case_id:
        case = get_case(db, case_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        ev_items = list_evidence(db, case_id=case_id)
        ev_map = {e.evidence_id: e.original_filename for e in ev_items}
        t_events = []
        c_events = []
        for e in ev_items:
            t_events.extend(list_timeline_events(db, evidence_id=e.evidence_id))
            c_events.extend(list_custody_events(db, evidence_id=e.evidence_id))
        activities = list_case_activities(db, case_id=case_id)
        unified = timeline_aggregator.build_unified_investigation_timeline(
            timeline_events=t_events,
            custody_rows=c_events,
            case_activities=activities,
            evidence_names=ev_map,
        )
    else:
        ev_items = list_evidence(db, limit=100)
        ev_map = {e.evidence_id: e.original_filename for e in ev_items}
        t_events = list_timeline_events(db)
        c_events = list_custody_events(db)
        unified = timeline_aggregator.build_unified_investigation_timeline(
            timeline_events=t_events,
            custody_rows=c_events,
            evidence_names=ev_map,
        )

    return {
        "disclaimer": timeline_aggregator.METADATA_DISCLAIMER,
        "events": [
            {**item, "timestamp": item["timestamp"].isoformat()}
            for item in unified
        ],
    }
