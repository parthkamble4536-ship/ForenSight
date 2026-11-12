"""
Dashboard web presentation routes for ForenSight (FastAPI + Jinja2).
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from forensight.analyzers import get_analyzer_for_type
from forensight.core.config import settings
from forensight.core.exceptions import (
    DuplicateEvidenceError,
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
from forensight.evidence.correlation import evidence_correlator
from forensight.evidence.custody import custody_ledger
from forensight.evidence.timeline import timeline_aggregator
from forensight.evidence.verification import verify_evidence_comprehensive
from forensight.ingestion.pipeline import ingestion_pipeline
from forensight.intelligence.scoring import risk_engine
from forensight.reports.generator import report_generator

dashboard_router = APIRouter(include_in_schema=False)

templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@dashboard_router.get("/", response_class=HTMLResponse)
def index_page(request: Request, db: Session = Depends(get_db)):
    """Main SOC triage dashboard page."""
    summary = get_dashboard_summary(db)
    evidence_items = list_evidence(db, limit=50)
    cases = list_cases(db, limit=50)
    risk_map = {
        ev.evidence_id: get_latest_analysis_run(db, ev.evidence_id)
        for ev in evidence_items
    }
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_tab": "dashboard",
            "summary": summary,
            "evidence_list": evidence_items,
            "cases": cases,
            "risk_map": risk_map,
        },
    )


@dashboard_router.post("/upload")
def handle_dashboard_upload(
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Handle drag-and-drop file upload from dashboard and redirect to triage view."""
    clean_case_id = case_id.strip() if isinstance(case_id, str) and case_id.strip() else None
    filename = file.filename or "uploaded_artifact.bin"

    # Ingest file into storage vault with SQLite authoritative duplicate detection
    try:
        ingest_result = ingestion_pipeline.ingest_stream(
            stream=file.file,
            original_filename=filename,
            case_id=clean_case_id,
            allow_duplicates=False,
            db=db,
        )
    except DuplicateEvidenceError as dup:
        existing_id = getattr(dup, "existing_evidence_id", None)
        if existing_id and get_evidence(db, existing_id):
            return RedirectResponse(url=f"/evidence/{existing_id}", status_code=303)
        raise HTTPException(status_code=409, detail=str(dup))
    except FileSizeExceededError as size_err:
        raise HTTPException(status_code=413, detail=str(size_err))

    sha256 = ingest_result.evidence.hashes.sha256
    try:
        # Sign manifest
        priv_key, pub_key = key_manager.load_or_create_keypair()
        signed_manifest = sign_manifest(ingest_result.manifest, priv_key)

        # Persist evidence
        create_evidence(
            db,
            evidence=ingest_result.evidence,
            metadata=ingest_result.metadata,
            manifest=signed_manifest,
        )
    finally:
        ingestion_pipeline.release_inflight_hash(db, sha256)

    # Persistent custody log
    try:
        custody_ledger.record_event(
            evidence_id=ingest_result.evidence.evidence_id,
            case_id=clean_case_id,
            event_type="ACQUISITION",
            details=f"Acquired artifact '{filename}' (SHA-256: {sha256})",
            db=db,
        )
    except IntegrityCompromisedError as integrity_err:
        raise HTTPException(status_code=500, detail=str(integrity_err))

    # Execute analyzer
    stored_path = Path(ingest_result.evidence.storage_path)
    analyzer = get_analyzer_for_type(ingest_result.metadata.identified_type)

    if analyzer:
        output = analyzer.analyze(stored_path, ingest_result.metadata)
        output.findings = analyzer.finalize_findings(
            output.findings,
            evidence_reference=ingest_result.evidence.evidence_id,
        )
    else:
        from forensight.analyzers.base import AnalyzerOutput
        output = AnalyzerOutput()

    risk = risk_engine.calculate_risk(output.findings)

    # Assemble normalized UTC timeline events for SQLite persistence
    ev_id = ingest_result.evidence.evidence_id
    persisted_timeline: List[TimelineEvent] = []
    for tev in output.timeline_events:
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
        findings=output.findings,
        iocs=output.iocs,
        details=output.details,
        timeline_events=persisted_timeline,
    )

    try:
        custody_ledger.record_event(
            evidence_id=ev_id,
            case_id=clean_case_id,
            event_type="ANALYSIS_RUN",
            details=f"Analysis completed: Verdict={risk.verdict} ({risk.score}/100)",
            db=db,
        )
    except IntegrityCompromisedError as integrity_err:
        raise HTTPException(status_code=500, detail=str(integrity_err))

    return RedirectResponse(
        url=f"/evidence/{ingest_result.evidence.evidence_id}",
        status_code=303,
    )


@dashboard_router.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request, db: Session = Depends(get_db)):
    """Investigation cases index."""
    cases = list_cases(db)
    return templates.TemplateResponse(
        request=request,
        name="cases.html",
        context={
            "active_tab": "cases",
            "cases": cases,
        },
    )


@dashboard_router.post("/cases")
def create_case_form(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    investigator: str = Form("Lead Investigator"),
    db: Session = Depends(get_db),
):
    """Handle case creation form submission."""
    create_case(db, title=title, description=description, investigator=investigator)
    return RedirectResponse(url="/cases", status_code=303)


@dashboard_router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail_page(case_id: str, request: Request, db: Session = Depends(get_db)):
    """Case detail page with associated evidence and correlation edges."""
    case = get_case(db, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence_items = list_evidence(db, case_id=case_id)

    # Reconstruct AnalysisResults for correlation graph
    case_results = []
    risk_map = {}
    for ev in evidence_items:
        run = get_latest_analysis_run(db, ev.evidence_id)
        if run:
            risk_map[ev.evidence_id] = run
            findings = [
                Finding(
                    finding_id=f.finding_id,
                    rule_id=f.rule_id,
                    category=f.category,
                    title=f.title,
                    description=f.description,
                    severity=FindingSeverity(f.severity),
                    score_impact=f.score_impact,
                    object_reference=f.object_reference,
                    explanation=f.explanation,
                    mitre_technique=f.mitre_technique,
                )
                for f in run.findings
            ]
            iocs = [
                IOCRecord(
                    ioc_type=IOCType(i.ioc_type),
                    value=i.value,
                    defanged_value=i.defanged_value,
                    context=i.context,
                )
                for i in run.iocs
            ]
            raw_details = json.loads(run.raw_details_json) if run.raw_details_json else {}

            case_results.append(
                AnalysisResult(
                    evidence=EvidenceRecord(
                        evidence_id=ev.evidence_id,
                        case_id=ev.case_id,
                        original_filename=ev.original_filename,
                        sanitized_filename=ev.sanitized_filename,
                        storage_path=ev.storage_path,
                        hashes=HashResult(
                            sha256=ev.sha256,
                            sha1=ev.sha1,
                            md5=ev.md5,
                            size_bytes=ev.file_size_bytes,
                        ),
                    ),
                    metadata=EvidenceMetadata(
                        file_size_bytes=ev.file_size_bytes,
                        identified_type=ev.identified_type,
                        mime_type=ev.mime_type,
                        declared_extension=ev.declared_extension,
                        is_extension_mismatch=ev.is_extension_mismatch,
                        entropy=ev.entropy,
                    ),
                    risk=RiskScore(score=run.risk_score, verdict=run.verdict, summary=run.summary or ""),
                    findings=findings,
                    iocs=iocs,
                    analyzer_details=raw_details,
                )
            )

    relationships = evidence_correlator.correlate_case_evidence(case_results)
    activities = list_case_activities(db, case_id=case_id)
    case_tags = []
    if getattr(case, "tags_json", None):
        try:
            case_tags = json.loads(case.tags_json)
        except Exception:
            case_tags = []

    case_timeline_events: List[TimelineEvent] = []
    case_custody_events = []
    ev_name_map = {e.evidence_id: e.original_filename for e in evidence_items}
    for e in evidence_items:
        case_timeline_events.extend(list_timeline_events(db, evidence_id=e.evidence_id))
        case_custody_events.extend(list_custody_events(db, evidence_id=e.evidence_id))

    unified_timeline = timeline_aggregator.build_unified_investigation_timeline(
        timeline_events=case_timeline_events,
        custody_rows=case_custody_events,
        case_activities=activities,
        evidence_names=ev_name_map,
    )

    return templates.TemplateResponse(
        request=request,
        name="case_detail.html",
        context={
            "active_tab": "cases",
            "case": case,
            "evidence_items": evidence_items,
            "relationships": relationships,
            "risk_map": risk_map,
            "activities": activities,
            "case_tags": case_tags,
            "unified_timeline": unified_timeline,
            "timeline_disclaimer": timeline_aggregator.METADATA_DISCLAIMER,
        },
    )


@dashboard_router.post("/cases/{case_id}/workflow")
def update_case_workflow_form(
    case_id: str,
    status: str = Form(...),
    investigator: str = Form("Lead Investigator"),
    investigator_notes: Optional[str] = Form(None),
    case_summary: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    closure_notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Handle case workflow update submission (status, notes, tags, closure)."""
    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    try:
        updated = update_case_workflow(
            db,
            case_id,
            status=status,
            investigator=investigator,
            investigator_notes=investigator_notes,
            case_summary=case_summary,
            tags=tag_list,
            closure_notes=closure_notes,
            actor=investigator,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    if not updated:
        raise HTTPException(status_code=404, detail="Case not found")
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@dashboard_router.post("/evidence/{evidence_id}/tags")
def update_evidence_tags_form(
    evidence_id: str,
    tags: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Save analyst classification tags for an evidence artifact."""
    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    ev = update_evidence_tags(db, evidence_id, tag_list)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return RedirectResponse(url=f"/evidence/{evidence_id}", status_code=303)


@dashboard_router.get("/verification", response_class=HTMLResponse)
def verification_center_page(request: Request, db: Session = Depends(get_db)):
    """Dedicated Evidence Verification Center showing hashes, Ed25519 manifest, and custody status."""
    items = list_evidence(db, limit=100)
    _, pub_key = key_manager.load_or_create_keypair()
    active_fp = key_manager.get_public_key_fingerprint(pub_key)
    custody_valid, custody_err, custody_events = custody_ledger.verify_persisted_chain(db)

    verifications = [verify_evidence_comprehensive(db, ev.evidence_id, record_custody=False) for ev in items]
    verifications = [v for v in verifications if v is not None]
    ev_by_id = {ev.evidence_id: ev for ev in items}

    status_counts: dict[str, int] = {}
    for v in verifications:
        st = v["verification_status"]
        status_counts[st] = status_counts.get(st, 0) + 1

    return templates.TemplateResponse(
        request=request,
        name="verification.html",
        context={
            "active_tab": "verification",
            "verifications": verifications,
            "ev_by_id": ev_by_id,
            "status_counts": status_counts,
            "active_fp": active_fp,
            "custody_valid": custody_valid,
            "custody_err": custody_err,
            "custody_count": len(custody_events),
        },
    )


@dashboard_router.post("/verification/run")
def verification_run_all_form(db: Session = Depends(get_db)):
    """Trigger full verification across all vaulted items and record custody audit."""
    for ev in list_evidence(db, limit=200):
        verify_evidence_comprehensive(db, ev.evidence_id, record_custody=False)
    return RedirectResponse(url="/verification", status_code=303)


@dashboard_router.get("/findings", response_class=HTMLResponse)
def findings_center_page(
    request: Request,
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    review_status: Optional[str] = None,
    rule_id: Optional[str] = None,
    analyzer_name: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Findings Investigation Center with analyst review disposition & provenance."""
    records = list_findings(
        db,
        severity=severity or None,
        confidence=confidence or None,
        review_status=review_status or None,
        rule_id=rule_id or None,
        analyzer_name=analyzer_name or None,
    )
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "active_tab": "findings",
            "records": records,
            "filters": {
                "severity": severity or "",
                "confidence": confidence or "",
                "review_status": review_status or "",
                "rule_id": rule_id or "",
                "analyzer_name": analyzer_name or "",
            },
        },
    )


@dashboard_router.post("/findings/{finding_id}/review")
def review_finding_form(
    finding_id: str,
    review_status: str = Form(...),
    is_false_positive: Optional[str] = Form(None),
    analyst_notes: Optional[str] = Form(None),
    reviewed_by: str = Form("SOC Analyst"),
    redirect_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Persist analyst finding disposition and redirect cleanly."""
    fp_flag = str(is_false_positive or "").lower() in ("true", "1", "on", "yes")
    try:
        updated = update_finding_review(
            db,
            finding_id,
            review_status=review_status,
            is_false_positive=fp_flag,
            analyst_notes=analyst_notes,
            reviewed_by=reviewed_by,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    target = redirect_to if (redirect_to and redirect_to.startswith("/")) else "/findings"
    return RedirectResponse(url=target, status_code=303)


@dashboard_router.get("/timeline", response_class=HTMLResponse)
def global_timeline_page(
    request: Request,
    case_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Advanced multi-source UTC chronological timeline explorer."""
    cases = list_cases(db, limit=50)
    ev_items = list_evidence(db, case_id=case_id or None, limit=100)
    ev_map = {e.evidence_id: e.original_filename for e in ev_items}
    t_events: List[TimelineEvent] = []
    c_events = []
    for e in ev_items:
        t_events.extend(list_timeline_events(db, evidence_id=e.evidence_id))
        c_events.extend(list_custody_events(db, evidence_id=e.evidence_id))
    activities = list_case_activities(db, case_id=case_id) if case_id else []

    unified = timeline_aggregator.build_unified_investigation_timeline(
        timeline_events=t_events,
        custody_rows=c_events,
        case_activities=activities,
        evidence_names=ev_map,
    )
    return templates.TemplateResponse(
        request=request,
        name="timeline.html",
        context={
            "active_tab": "timeline",
            "events": unified,
            "cases": cases,
            "selected_case_id": case_id or "",
            "disclaimer": timeline_aggregator.METADATA_DISCLAIMER,
        },
    )


@dashboard_router.get("/evidence/{evidence_id}", response_class=HTMLResponse)
def evidence_detail_page(evidence_id: str, request: Request, db: Session = Depends(get_db)):
    """Deep forensic triage view for an evidence artifact."""
    ev = get_evidence(db, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence artifact not found")

    run = get_latest_analysis_run(db, evidence_id)
    custody_events = list_custody_events(db, evidence_id=evidence_id)
    case_obj = get_case(db, ev.case_id) if ev.case_id else None

    raw_details_str = None
    parsed_details = {}
    if run and run.raw_details_json:
        try:
            parsed = json.loads(run.raw_details_json)
            if isinstance(parsed, dict):
                parsed_details = parsed
            raw_details_str = json.dumps(parsed, indent=2)
        except Exception:
            raw_details_str = run.raw_details_json

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if run and run.findings:
        for finding in run.findings:
            sev = (finding.severity or "INFO").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Load persisted normalized timeline events from SQLite (never re-run analyzer on GET)
    timeline_events = list_timeline_events(db, evidence_id=evidence_id)
    unified_timeline = timeline_aggregator.build_unified_investigation_timeline(
        timeline_events=timeline_events,
        custody_rows=custody_events,
        evidence_names={ev.evidence_id: ev.original_filename},
    )

    evidence_tags = []
    if getattr(ev, "tags_json", None):
        try:
            evidence_tags = json.loads(ev.tags_json)
        except Exception:
            evidence_tags = []

    verification_summary = verify_evidence_comprehensive(db, evidence_id, record_custody=False)

    return templates.TemplateResponse(
        request=request,
        name="evidence_detail.html",
        context={
            "active_tab": "dashboard",
            "evidence": ev,
            "case": case_obj,
            "analysis": run,
            "custody_events": custody_events,
            "raw_details": raw_details_str,
            "parsed_details": parsed_details,
            "severity_counts": severity_counts,
            "timeline_events": timeline_events,
            "unified_timeline": unified_timeline,
            "timeline_disclaimer": timeline_aggregator.METADATA_DISCLAIMER,
            "evidence_tags": evidence_tags,
            "verification_summary": verification_summary,
        },
    )


# --- Report Export Endpoints ---

def _build_analysis_result(
    ev,
    run,
    timeline_events: Optional[List[TimelineEvent]] = None,
) -> AnalysisResult:
    """Helper to reconstruct full AnalysisResult from ORM models."""
    findings = [
        Finding(
            finding_id=f.finding_id,
            rule_id=f.rule_id,
            rule_version=getattr(f, "rule_version", "1.0.0") or "1.0.0",
            category=f.category,
            title=f.title,
            description=f.description,
            severity=FindingSeverity(f.severity),
            confidence=ConfidenceLevel(getattr(f, "confidence", "HIGH") or "HIGH"),
            score_impact=f.score_impact,
            analyzer_name=getattr(f, "analyzer_name", None) or "",
            analyzer_version=getattr(f, "analyzer_version", None) or "2.0.0",
            evidence_source=getattr(f, "analyzer_name", None) or "",
            evidence_reference=getattr(f, "evidence_reference", None) or ev.evidence_id,
            object_reference=f.object_reference,
            offset=getattr(f, "offset", None),
            explanation=f.explanation,
            mitre_technique=f.mitre_technique,
            detected_at=(
                f.detected_at.replace(tzinfo=timezone.utc)
                if getattr(f, "detected_at", None) and f.detected_at.tzinfo is None
                else (f.detected_at if getattr(f, "detected_at", None) else run.analyzed_at.replace(tzinfo=timezone.utc))
            ),
        )
        for f in (run.findings if run else [])
    ]
    iocs = [
        IOCRecord(
            ioc_type=IOCType(i.ioc_type),
            value=i.value,
            defanged_value=i.defanged_value,
            context=i.context,
            offset=getattr(i, "offset", None),
            occurrences=getattr(i, "occurrences", 1) or 1,
            confidence=ConfidenceLevel(getattr(i, "confidence", "HIGH") or "HIGH"),
        )
        for i in (run.iocs if run else [])
    ]
    raw_details = json.loads(run.raw_details_json) if run and run.raw_details_json else {}

    analyzed_ts = run.analyzed_at if (run and run.analyzed_at) else ev.stored_at
    if analyzed_ts.tzinfo is None:
        analyzed_ts = analyzed_ts.replace(tzinfo=timezone.utc)

    return AnalysisResult(
        evidence=EvidenceRecord(
            evidence_id=ev.evidence_id,
            case_id=ev.case_id,
            original_filename=ev.original_filename,
            sanitized_filename=ev.sanitized_filename,
            storage_path=ev.storage_path,
            hashes=HashResult(
                sha256=ev.sha256,
                sha1=ev.sha1,
                md5=ev.md5,
                size_bytes=ev.file_size_bytes,
            ),
        ),
        metadata=EvidenceMetadata(
            file_size_bytes=ev.file_size_bytes,
            identified_type=ev.identified_type,
            mime_type=ev.mime_type,
            declared_extension=ev.declared_extension,
            is_extension_mismatch=ev.is_extension_mismatch,
            entropy=ev.entropy,
        ),
        risk=RiskScore(
            score=run.risk_score if run else 0,
            verdict=run.verdict if run else "UNANALYZED",
            summary=run.summary or "" if run else "No analysis",
        ),
        findings=findings,
        iocs=iocs,
        timeline=timeline_events or [],
        analyzer_details=raw_details,
        analyzed_at=analyzed_ts.astimezone(timezone.utc),
    )


def _build_export_manifest(ev, result: AnalysisResult) -> EvidenceManifest:
    acq = ev.stored_at if ev.stored_at.tzinfo else ev.stored_at.replace(tzinfo=timezone.utc)
    return EvidenceManifest(
        manifest_id=getattr(ev, "manifest_id", None) or str(ev.evidence_id),
        evidence_id=ev.evidence_id,
        case_id=ev.case_id,
        original_filename=ev.original_filename,
        hashes=result.evidence.hashes,
        file_type=ev.identified_type,
        acquired_at=acq.astimezone(timezone.utc),
        signature=ev.manifest_signature,
        public_key_fingerprint=ev.public_key_fingerprint,
    )


def _prepare_export_bundle(db: Session, evidence_id: str) -> dict:
    """Assemble full 16-section context (evidence, case, verification, custody, timeline, correlations) for exports."""
    ev = get_evidence(db, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    run = get_latest_analysis_run(db, evidence_id)
    timeline_events = list_timeline_events(db, evidence_id=evidence_id)
    custody_events = list_custody_events(db, evidence_id=evidence_id)
    result = _build_analysis_result(ev, run, timeline_events=timeline_events)
    manifest = _build_export_manifest(ev, result)
    verification = verify_evidence_comprehensive(db, evidence_id, record_custody=False)

    case_info = None
    relationships = []
    if ev.case_id:
        case_obj = get_case(db, ev.case_id)
        if case_obj:
            case_info = {
                "case_id": case_obj.case_id,
                "title": case_obj.title,
                "investigator": case_obj.investigator,
                "status": case_obj.status,
                "description": case_obj.description,
                "case_summary": getattr(case_obj, "case_summary", None),
            }
        peer_items = list_evidence(db, case_id=ev.case_id, limit=50)
        if len(peer_items) >= 2:
            peer_results = []
            for p_ev in peer_items:
                p_run = get_latest_analysis_run(db, p_ev.evidence_id)
                if p_run:
                    peer_results.append(_build_analysis_result(p_ev, p_run))
            all_rels = evidence_correlator.correlate_case_evidence(peer_results)
            relationships = [
                r for r in all_rels
                if r.source_evidence_id == evidence_id or r.target_evidence_id == evidence_id
            ]

    return {
        "ev": ev,
        "result": result,
        "manifest": manifest,
        "custody_events": custody_events,
        "case_info": case_info,
        "verification": verification,
        "relationships": relationships,
    }


@dashboard_router.get("/evidence/{evidence_id}/export/html")
def export_html(evidence_id: str, db: Session = Depends(get_db)):
    """Export self-contained standalone HTML forensic report."""
    b = _prepare_export_bundle(db, evidence_id)
    html_content = report_generator.generate_html_report(
        b["result"],
        manifest=b["manifest"],
        custody_events=b["custody_events"],
        case_info=b["case_info"],
        verification=b["verification"],
        relationships=b["relationships"],
    )
    return HTMLResponse(content=html_content)


@dashboard_router.get("/evidence/{evidence_id}/export/json")
def export_json(evidence_id: str, db: Session = Depends(get_db)):
    """Export machine-readable JSON forensic report."""
    b = _prepare_export_bundle(db, evidence_id)
    json_content = report_generator.generate_json_report(
        b["result"],
        manifest=b["manifest"],
        custody_events=b["custody_events"],
        case_info=b["case_info"],
        verification=b["verification"],
        relationships=b["relationships"],
    )
    return Response(content=json_content, media_type="application/json")


@dashboard_router.get("/evidence/{evidence_id}/export/pdf")
def export_pdf(evidence_id: str, db: Session = Depends(get_db)):
    """Export publication-quality PDF forensic report."""
    b = _prepare_export_bundle(db, evidence_id)
    ev = b["ev"]
    pdf_path = settings.reports_dir / f"forensight_report_{evidence_id}.pdf"
    report_generator.generate_pdf_report(
        b["result"],
        output_path=pdf_path,
        manifest=b["manifest"],
        custody_events=b["custody_events"],
        case_info=b["case_info"],
        verification=b["verification"],
        relationships=b["relationships"],
    )

    return FileResponse(
        path=str(pdf_path),
        filename=f"ForenSight_Report_{ev.sanitized_filename}.pdf",
        media_type="application/pdf",
    )


@dashboard_router.get("/evidence/{evidence_id}/export/csv")
def export_csv_findings(evidence_id: str, db: Session = Depends(get_db)):
    """Export forensic findings and provenance as CSV."""
    b = _prepare_export_bundle(db, evidence_id)
    csv_text = report_generator.generate_csv_findings_report(b["result"])
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="ForenSight_Findings_{b["ev"].sanitized_filename}.csv"'
        },
    )


@dashboard_router.get("/evidence/{evidence_id}/export/stix")
def export_stix_iocs(evidence_id: str, db: Session = Depends(get_db)):
    """Export extracted IOCs as a STIX 2.1 Threat Intelligence bundle."""
    b = _prepare_export_bundle(db, evidence_id)
    stix_text = report_generator.generate_stix21_bundle(b["result"])
    return Response(
        content=stix_text,
        media_type="application/stix+json",
        headers={
            "Content-Disposition": f'attachment; filename="ForenSight_STIX21_{b["ev"].sanitized_filename}.json"'
        },
    )
