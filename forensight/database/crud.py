"""
CRUD query operations and forensic persistence layer helpers.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from forensight.core.types import (
    AnalysisResult,
    ChainOfCustodyEvent,
    EvidenceManifest,
    EvidenceMetadata,
    EvidenceRecord,
    Finding,
    IOCRecord,
    RiskScore,
)
from forensight.database.models import (
    AnalysisRunModel,
    CaseModel,
    CustodyEventModel,
    EvidenceModel,
    FindingModel,
    IOCModel,
)


# --- Case Operations ---

def create_case(db: Session, title: str, description: Optional[str] = None, investigator: str = "Lead Investigator") -> CaseModel:
    """Create and persist a new investigation case."""
    case = CaseModel(
        case_id=str(uuid.uuid4()),
        title=title,
        description=description,
        investigator=investigator,
        created_at=datetime.now(timezone.utc),
        status="ACTIVE",
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def get_case(db: Session, case_id: str) -> Optional[CaseModel]:
    """Retrieve case by UUID."""
    return db.query(CaseModel).filter(CaseModel.case_id == case_id).first()


def list_cases(db: Session, limit: int = 50) -> List[CaseModel]:
    """List recent investigation cases."""
    return db.query(CaseModel).order_by(desc(CaseModel.created_at)).limit(limit).all()


# --- Evidence Operations ---

def create_evidence(
    db: Session,
    evidence: EvidenceRecord,
    metadata: EvidenceMetadata,
    manifest: Optional[EvidenceManifest] = None,
) -> EvidenceModel:
    """Persist an ingested evidence item record."""
    item = EvidenceModel(
        evidence_id=evidence.evidence_id,
        case_id=evidence.case_id,
        original_filename=evidence.original_filename,
        sanitized_filename=evidence.sanitized_filename,
        storage_path=evidence.storage_path,
        sha256=evidence.hashes.sha256,
        sha1=evidence.hashes.sha1,
        md5=evidence.hashes.md5,
        file_size_bytes=evidence.hashes.size_bytes,
        identified_type=metadata.identified_type,
        mime_type=metadata.mime_type,
        declared_extension=metadata.declared_extension,
        is_extension_mismatch=metadata.is_extension_mismatch,
        entropy=metadata.entropy,
        stored_at=evidence.stored_at,
        is_read_only=evidence.is_read_only,
        manifest_signature=manifest.signature if manifest else None,
        public_key_fingerprint=manifest.public_key_fingerprint if manifest else None,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def get_evidence(db: Session, evidence_id: str) -> Optional[EvidenceModel]:
    """Retrieve evidence artifact by UUID."""
    return db.query(EvidenceModel).filter(EvidenceModel.evidence_id == evidence_id).first()


def get_evidence_by_hash(db: Session, sha256: str) -> Optional[EvidenceModel]:
    """Find existing evidence by SHA-256 digest."""
    return db.query(EvidenceModel).filter(EvidenceModel.sha256 == sha256.lower()).first()


def list_evidence(db: Session, case_id: Optional[str] = None, limit: int = 100) -> List[EvidenceModel]:
    """List evidence items, optionally filtered by case."""
    q = db.query(EvidenceModel)
    if case_id:
        q = q.filter(EvidenceModel.case_id == case_id)
    return q.order_by(desc(EvidenceModel.stored_at)).limit(limit).all()


# --- Analysis Run Operations ---

def record_analysis_run(
    db: Session,
    evidence_id: str,
    risk: RiskScore,
    findings: List[Finding],
    iocs: List[IOCRecord],
    details: Dict[str, Any],
) -> AnalysisRunModel:
    """Record an immutable static analysis run with findings and IOCs."""
    run_id = str(uuid.uuid4())
    run = AnalysisRunModel(
        run_id=run_id,
        evidence_id=evidence_id,
        analyzed_at=datetime.now(timezone.utc),
        risk_score=risk.score,
        verdict=risk.verdict,
        summary=risk.summary,
        raw_details_json=json.dumps(details, default=str),
    )
    db.add(run)

    for f in findings:
        f_model = FindingModel(
            finding_id=f.finding_id or str(uuid.uuid4()),
            run_id=run_id,
            rule_id=f.rule_id,
            category=f.category,
            title=f.title,
            description=f.description,
            severity=f.severity.value,
            confidence=f.confidence.value,
            score_impact=f.score_impact,
            object_reference=f.object_reference,
            explanation=f.explanation,
            mitre_technique=f.mitre_technique,
        )
        db.add(f_model)

    for ioc in iocs:
        ioc_model = IOCModel(
            ioc_id=str(uuid.uuid4()),
            run_id=run_id,
            ioc_type=ioc.ioc_type.value,
            value=ioc.value,
            defanged_value=ioc.defanged_value,
            context=ioc.context,
            confidence=ioc.confidence.value,
        )
        db.add(ioc_model)

    db.commit()
    db.refresh(run)
    return run


def get_latest_analysis_run(db: Session, evidence_id: str) -> Optional[AnalysisRunModel]:
    """Retrieve the most recent analysis run for an evidence artifact."""
    return (
        db.query(AnalysisRunModel)
        .filter(AnalysisRunModel.evidence_id == evidence_id)
        .order_by(desc(AnalysisRunModel.analyzed_at))
        .first()
    )


# --- Chain of Custody Operations ---

def save_custody_event(db: Session, event: ChainOfCustodyEvent) -> CustodyEventModel:
    """Persist a chain of custody audit event."""
    model = CustodyEventModel(
        event_id=event.event_id,
        evidence_id=event.evidence_id,
        case_id=event.case_id,
        event_type=event.event_type,
        actor=event.actor,
        timestamp=event.timestamp,
        details=event.details,
        previous_event_hash=event.previous_event_hash or "",
        event_hash=event.event_hash,
    )
    db.add(model)
    db.commit()
    db.refresh(model)
    return model


def list_custody_events(db: Session, evidence_id: Optional[str] = None) -> List[CustodyEventModel]:
    """List custody audit events ordered chronologically."""
    q = db.query(CustodyEventModel)
    if evidence_id:
        q = q.filter(CustodyEventModel.evidence_id == evidence_id)
    return q.order_by(CustodyEventModel.timestamp).all()


# --- Dashboard Aggregations ---

def get_dashboard_summary(db: Session) -> Dict[str, Any]:
    """Compute high-level summary metrics for the forensic dashboard."""
    total_cases = db.query(func.count(CaseModel.case_id)).scalar() or 0
    total_evidence = db.query(func.count(EvidenceModel.evidence_id)).scalar() or 0
    suspicious_count = (
        db.query(func.count(AnalysisRunModel.run_id))
        .filter(AnalysisRunModel.risk_score >= 45)
        .scalar()
        or 0
    )
    critical_findings_count = (
        db.query(func.count(FindingModel.finding_id))
        .filter(FindingModel.severity == "CRITICAL")
        .scalar()
        or 0
    )

    return {
        "total_cases": total_cases,
        "total_evidence": total_evidence,
        "suspicious_evidence": suspicious_count,
        "critical_findings": critical_findings_count,
    }
