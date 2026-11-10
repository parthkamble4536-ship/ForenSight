"""
Dashboard web presentation routes for ForenSight (FastAPI + Jinja2).
"""

import json
from pathlib import Path
from typing import Any, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from forensight.analyzers import get_analyzer_for_type
from forensight.core.config import settings
from forensight.core.types import (
    AnalysisResult,
    EvidenceManifest,
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
from forensight.evidence.correlation import evidence_correlator
from forensight.evidence.custody import custody_ledger
from forensight.ingestion.pipeline import ingestion_pipeline
from forensight.intelligence.scoring import risk_engine
from forensight.reports.generator import report_generator

dashboard_router = APIRouter(include_in_schema=False)

templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


def _clean_form_str(val: Any, default: Optional[str] = None) -> Optional[str]:
    """Sanitize Form-injected values to primitives if called directly as a Python callable."""
    if val is None or hasattr(val, "default"):
        return default
    return str(val)


@dashboard_router.get("/", response_class=HTMLResponse)
def index_page(request: Request, db: Session = Depends(get_db)):
    """Main dashboard page."""
    summary = get_dashboard_summary(db)
    evidence_items = list_evidence(db, limit=15)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "active_tab": "dashboard",
            "summary": summary,
            "evidence_list": evidence_items,
        },
    )


@dashboard_router.post("/upload")
def handle_dashboard_upload(
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Handle drag-and-drop file upload from dashboard and redirect to triage view."""
    clean_case_id = _clean_form_str(case_id, None)
    filename = file.filename or "uploaded_artifact.bin"

    # Ingest file into storage vault
    ingest_result = ingestion_pipeline.ingest_stream(
        stream=file.file,
        original_filename=filename,
        case_id=clean_case_id,
        allow_duplicates=False,
    )

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

    # Custody log
    custody_ev = custody_ledger.record_event(
        evidence_id=ingest_result.evidence.evidence_id,
        case_id=case_id,
        event_type="ACQUISITION",
        details=f"Acquired artifact '{filename}' (SHA-256: {ingest_result.evidence.hashes.sha256})",
    )
    save_custody_event(db, custody_ev)

    # Execute analyzer
    stored_path = Path(ingest_result.evidence.storage_path)
    analyzer = get_analyzer_for_type(ingest_result.metadata.identified_type)

    if analyzer:
        output = analyzer.analyze(stored_path, ingest_result.metadata)
    else:
        from forensight.analyzers.base import AnalyzerOutput
        output = AnalyzerOutput()

    risk = risk_engine.calculate_risk(output.findings)

    # Persist analysis
    record_analysis_run(
        db,
        evidence_id=ingest_result.evidence.evidence_id,
        risk=risk,
        findings=output.findings,
        iocs=output.iocs,
        details=output.details,
    )

    analysis_custody = custody_ledger.record_event(
        evidence_id=ingest_result.evidence.evidence_id,
        case_id=case_id,
        event_type="ANALYSIS_RUN",
        details=f"Analysis completed: Verdict={risk.verdict} ({risk.score}/100)",
    )
    save_custody_event(db, analysis_custody)

    return RedirectResponse(
        url=f"/evidence/{ingest_result.evidence.evidence_id}",
        status_code=303,
    )


@dashboard_router.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request, db: Session = Depends(get_db)):
    """Investigation cases index."""
    cases = list_cases(db)
    return templates.TemplateResponse(
        "cases.html",
        {
            "request": request,
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
    clean_title = _clean_form_str(title, "Untitled Case") or "Untitled Case"
    clean_desc = _clean_form_str(description, None)
    clean_inv = _clean_form_str(investigator, "Lead Investigator") or "Lead Investigator"
    create_case(db, title=clean_title, description=clean_desc, investigator=clean_inv)
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
    for ev in evidence_items:
        run = get_latest_analysis_run(db, ev.evidence_id)
        if run:
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
        "case_detail.html",
        {
            "request": request,
            "active_tab": "cases",
            "case": case,
            "evidence_items": evidence_items,
            "relationships": relationships,
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

    raw_details_str = None
    if run and run.raw_details_json:
        try:
            parsed = json.loads(run.raw_details_json)
            raw_details_str = json.dumps(parsed, indent=2)
        except Exception:
            raw_details_str = run.raw_details_json

    # Reconstruct timeline events if analyzer run exists
    timeline_events = []
    if ev.identified_type:
        analyzer = get_analyzer_for_type(ev.identified_type)
        if analyzer and Path(ev.storage_path).exists():
            meta = EvidenceMetadata(
                file_size_bytes=ev.file_size_bytes,
                identified_type=ev.identified_type,
                mime_type=ev.mime_type,
                declared_extension=ev.declared_extension,
                is_extension_mismatch=ev.is_extension_mismatch,
                entropy=ev.entropy,
            )
            out = analyzer.analyze(Path(ev.storage_path), meta)
            timeline_events = out.timeline_events

    return templates.TemplateResponse(
        "evidence_detail.html",
        {
            "request": request,
            "active_tab": "dashboard",
            "evidence": ev,
            "analysis": run,
            "custody_events": custody_events,
            "raw_details": raw_details_str,
            "timeline_events": timeline_events,
        },
    )


# --- Report Export Endpoints ---

def _build_analysis_result(ev, run) -> AnalysisResult:
    """Helper to reconstruct full AnalysisResult from ORM models."""
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
        for f in (run.findings if run else [])
    ]
    iocs = [
        IOCRecord(
            ioc_type=IOCType(i.ioc_type),
            value=i.value,
            defanged_value=i.defanged_value,
            context=i.context,
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
        analyzer_details=raw_details,
    )


@dashboard_router.get("/evidence/{evidence_id}/export/html")
def export_html(evidence_id: str, db: Session = Depends(get_db)):
    """Export self-contained standalone HTML forensic report."""
    ev = get_evidence(db, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    run = get_latest_analysis_run(db, evidence_id)
    result = _build_analysis_result(ev, run)

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
    result = _build_analysis_result(ev, run)

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
    result = _build_analysis_result(ev, run)

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
