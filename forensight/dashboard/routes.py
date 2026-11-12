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
    list_cases,
    list_custody_events,
    list_evidence,
    list_timeline_events,
    record_analysis_run,
    save_custody_event,
)
from forensight.evidence.correlation import evidence_correlator
from forensight.evidence.custody import custody_ledger
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

    return templates.TemplateResponse(
        request=request,
        name="case_detail.html",
        context={
            "active_tab": "cases",
            "case": case,
            "evidence_items": evidence_items,
            "relationships": relationships,
            "risk_map": risk_map,
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
    )


@dashboard_router.get("/evidence/{evidence_id}/export/html")
def export_html(evidence_id: str, db: Session = Depends(get_db)):
    """Export self-contained standalone HTML forensic report."""
    ev = get_evidence(db, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    run = get_latest_analysis_run(db, evidence_id)
    timeline_events = list_timeline_events(db, evidence_id=evidence_id)
    result = _build_analysis_result(ev, run, timeline_events=timeline_events)

    manifest = EvidenceManifest(
        manifest_id=str(ev.evidence_id),
        evidence_id=ev.evidence_id,
        case_id=ev.case_id,
        original_filename=ev.original_filename,
        hashes=result.evidence.hashes,
        file_type=ev.identified_type,
        acquired_at=ev.stored_at,
        signature=ev.manifest_signature,
        public_key_fingerprint=ev.public_key_fingerprint,
    )

    html_content = report_generator.generate_html_report(result, manifest=manifest)
    return HTMLResponse(content=html_content)


@dashboard_router.get("/evidence/{evidence_id}/export/json")
def export_json(evidence_id: str, db: Session = Depends(get_db)):
    """Export machine-readable JSON forensic report."""
    ev = get_evidence(db, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    run = get_latest_analysis_run(db, evidence_id)
    timeline_events = list_timeline_events(db, evidence_id=evidence_id)
    result = _build_analysis_result(ev, run, timeline_events=timeline_events)

    manifest = EvidenceManifest(
        manifest_id=str(ev.evidence_id),
        evidence_id=ev.evidence_id,
        case_id=ev.case_id,
        original_filename=ev.original_filename,
        hashes=result.evidence.hashes,
        file_type=ev.identified_type,
        acquired_at=ev.stored_at,
        signature=ev.manifest_signature,
        public_key_fingerprint=ev.public_key_fingerprint,
    )

    json_content = report_generator.generate_json_report(result, manifest=manifest)
    return Response(content=json_content, media_type="application/json")


@dashboard_router.get("/evidence/{evidence_id}/export/pdf")
def export_pdf(evidence_id: str, db: Session = Depends(get_db)):
    """Export publication-quality PDF forensic report."""
    ev = get_evidence(db, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    run = get_latest_analysis_run(db, evidence_id)
    timeline_events = list_timeline_events(db, evidence_id=evidence_id)
    result = _build_analysis_result(ev, run, timeline_events=timeline_events)

    manifest = EvidenceManifest(
        manifest_id=str(ev.evidence_id),
        evidence_id=ev.evidence_id,
        case_id=ev.case_id,
        original_filename=ev.original_filename,
        hashes=result.evidence.hashes,
        file_type=ev.identified_type,
        acquired_at=ev.stored_at,
        signature=ev.manifest_signature,
        public_key_fingerprint=ev.public_key_fingerprint,
    )

    pdf_path = settings.reports_dir / f"forensight_report_{evidence_id}.pdf"
    report_generator.generate_pdf_report(result, output_path=pdf_path, manifest=manifest)

    return FileResponse(
        path=str(pdf_path),
        filename=f"ForenSight_Report_{ev.sanitized_filename}.pdf",
        media_type="application/pdf",
    )
