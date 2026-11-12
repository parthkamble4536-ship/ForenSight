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
    ConfidenceLevel,
    EvidenceManifest,
    EvidenceMetadata,
    EvidenceRecord,
    Finding,
    IOCRecord,
    RiskScore,
    TimelineEvent,
    TimelineEventType,
)
from forensight.database.models import (
    AnalysisRunModel,
    CaseActivityModel,
    CaseModel,
    CustodyEventModel,
    EvidenceModel,
    FindingModel,
    IOCModel,
    TimelineEventModel,
)


ALLOWED_CASE_STATUSES = {"OPEN", "IN_PROGRESS", "UNDER_REVIEW", "CLOSED"}
ALLOWED_FINDING_STATUSES = {"OPEN", "CONFIRMED", "NEEDS_FOLLOWUP", "FALSE_POSITIVE"}


# --- Case Operations ---

def create_case(db: Session, title: str, description: Optional[str] = None, investigator: str = "Lead Investigator") -> CaseModel:
    """Create and persist a new investigation case with initial workflow history."""
    now = datetime.now(timezone.utc)
    case_id = str(uuid.uuid4())
    case = CaseModel(
        case_id=case_id,
        title=title,
        description=description,
        investigator=investigator,
        created_at=now,
        updated_at=now,
        status="OPEN",
    )
    db.add(case)
    db.add(
        CaseActivityModel(
            activity_id=str(uuid.uuid4()),
            case_id=case_id,
            actor=investigator,
            action="CASE_OPENED",
            details=f"Case dossier '{title}' opened by {investigator}.",
            created_at=now,
        )
    )
    db.commit()
    db.refresh(case)
    return case


def record_case_activity(
    db: Session,
    case_id: str,
    actor: str,
    action: str,
    details: str,
) -> CaseActivityModel:
    """Append an audit activity record to a case dossier."""
    act = CaseActivityModel(
        activity_id=str(uuid.uuid4()),
        case_id=case_id,
        actor=actor or "analyst",
        action=action,
        details=details,
        created_at=datetime.now(timezone.utc),
    )
    db.add(act)
    db.commit()
    db.refresh(act)
    return act


def list_case_activities(db: Session, case_id: str, limit: int = 100) -> List[CaseActivityModel]:
    """Retrieve case workflow & activity history chronologically (newest first)."""
    return (
        db.query(CaseActivityModel)
        .filter(CaseActivityModel.case_id == case_id)
        .order_by(desc(CaseActivityModel.created_at))
        .limit(limit)
        .all()
    )


def update_case_workflow(
    db: Session,
    case_id: str,
    *,
    status: Optional[str] = None,
    investigator: Optional[str] = None,
    investigator_notes: Optional[str] = None,
    case_summary: Optional[str] = None,
    tags: Optional[List[str]] = None,
    closure_notes: Optional[str] = None,
    actor: str = "Lead Investigator",
) -> Optional[CaseModel]:
    """Update case status, notes, tags, summary, and closure attribution."""
    case = get_case(db, case_id)
    if not case:
        return None

    now = datetime.now(timezone.utc)
    changes: List[str] = []

    if status is not None:
        norm_status = status.strip().upper()
        if norm_status not in ALLOWED_CASE_STATUSES:
            raise ValueError(f"Unsupported case status: {status}. Allowed: {sorted(ALLOWED_CASE_STATUSES)}")
        if case.status != norm_status:
            changes.append(f"status {case.status} -> {norm_status}")
            case.status = norm_status
            if norm_status == "CLOSED":
                case.closed_by = actor
                case.closed_at = now
            elif case.closed_at is not None:
                case.closed_by = None
                case.closed_at = None

    if investigator is not None and investigator.strip():
        if case.investigator != investigator.strip():
            changes.append(f"investigator -> {investigator.strip()}")
            case.investigator = investigator.strip()

    if investigator_notes is not None:
        case.investigator_notes = investigator_notes.strip() or None
        changes.append("investigator notes updated")

    if case_summary is not None:
        case.case_summary = case_summary.strip() or None
        changes.append("case summary updated")

    if tags is not None:
        cleaned_tags = sorted({t.strip() for t in tags if t and t.strip()})[:30]
        case.tags_json = json.dumps(cleaned_tags)
        changes.append(f"tags updated ({len(cleaned_tags)})")

    if closure_notes is not None:
        case.closure_notes = closure_notes.strip() or None

    case.updated_at = now
    db.add(
        CaseActivityModel(
            activity_id=str(uuid.uuid4()),
            case_id=case_id,
            actor=actor or case.investigator,
            action="CASE_WORKFLOW_UPDATED" if case.status != "CLOSED" else "CASE_CLOSED",
            details="; ".join(changes) if changes else "Case workflow metadata saved.",
            created_at=now,
        )
    )
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
        manifest_id=manifest.manifest_id if manifest else None,
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
    timeline_events: Optional[List[TimelineEvent]] = None,
) -> AnalysisRunModel:
    """Record an immutable static analysis run with findings, IOCs, and timeline events."""
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
        det_ts = f.detected_at if f.detected_at.tzinfo else f.detected_at.replace(tzinfo=timezone.utc)
        f_model = FindingModel(
            finding_id=f.finding_id or str(uuid.uuid4()),
            run_id=run_id,
            rule_id=f.rule_id,
            rule_version=f.rule_version,
            category=f.category,
            title=f.title,
            description=f.description,
            severity=f.severity.value,
            confidence=f.confidence.value,
            score_impact=f.score_impact,
            analyzer_name=f.analyzer_name or f.evidence_source or None,
            analyzer_version=f.analyzer_version,
            evidence_reference=f.evidence_reference or evidence_id,
            object_reference=f.object_reference,
            offset=f.offset,
            explanation=f.explanation,
            mitre_technique=f.mitre_technique,
            detected_at=det_ts.astimezone(timezone.utc),
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
            offset=ioc.offset,
            occurrences=ioc.occurrences,
            confidence=ioc.confidence.value,
        )
        db.add(ioc_model)

    if timeline_events:
        for tev in timeline_events:
            norm_ts = tev.timestamp if tev.timestamp.tzinfo else tev.timestamp.replace(tzinfo=timezone.utc)
            norm_ts = norm_ts.astimezone(timezone.utc)
            orig_ts = tev.original_timestamp if tev.original_timestamp is not None else tev.timestamp.isoformat()
            t_model = TimelineEventModel(
                event_id=str(uuid.uuid4()),
                evidence_id=evidence_id,
                run_id=run_id,
                timestamp=norm_ts,
                original_timestamp=orig_ts[:100],
                timestamp_type=tev.timestamp_type.value,
                source=tev.source[:255],
                description=tev.description,
                confidence=tev.confidence.value,
            )
            db.add(t_model)

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


# --- Timeline Persistence Operations ---

def save_timeline_events(
    db: Session,
    evidence_id: str,
    timeline_events: List[TimelineEvent],
    run_id: Optional[str] = None,
) -> List[TimelineEventModel]:
    """Persist normalized UTC timeline events for an evidence artifact."""
    created: List[TimelineEventModel] = []
    for tev in timeline_events:
        norm_ts = tev.timestamp if tev.timestamp.tzinfo else tev.timestamp.replace(tzinfo=timezone.utc)
        norm_ts = norm_ts.astimezone(timezone.utc)
        orig_ts = tev.original_timestamp if tev.original_timestamp is not None else tev.timestamp.isoformat()
        model = TimelineEventModel(
            event_id=str(uuid.uuid4()),
            evidence_id=evidence_id,
            run_id=run_id,
            timestamp=norm_ts,
            original_timestamp=orig_ts[:100],
            timestamp_type=tev.timestamp_type.value,
            source=tev.source[:255],
            description=tev.description,
            confidence=tev.confidence.value,
        )
        db.add(model)
        created.append(model)
    if created:
        db.commit()
        for m in created:
            db.refresh(m)
    return created


def list_timeline_events(
    db: Session,
    evidence_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[TimelineEvent]:
    """Retrieve persisted timeline events ordered chronologically in UTC."""
    q = db.query(TimelineEventModel)
    if evidence_id:
        q = q.filter(TimelineEventModel.evidence_id == evidence_id)
    if run_id:
        q = q.filter(TimelineEventModel.run_id == run_id)
    rows = q.order_by(TimelineEventModel.timestamp).all()

    events: List[TimelineEvent] = []
    for row in rows:
        ts = row.timestamp if row.timestamp.tzinfo else row.timestamp.replace(tzinfo=timezone.utc)
        ts = ts.astimezone(timezone.utc)
        events.append(
            TimelineEvent(
                event_id=row.event_id,
                evidence_id=row.evidence_id,
                timestamp=ts,
                original_timestamp=row.original_timestamp,
                timestamp_type=TimelineEventType(row.timestamp_type),
                source=row.source,
                description=row.description,
                confidence=ConfidenceLevel(row.confidence),
            )
        )
    return events


# --- Chain of Custody Operations ---

def save_custody_event(
    db: Session,
    event: ChainOfCustodyEvent,
    sequence_index: Optional[int] = None,
) -> CustodyEventModel:
    """Persist a chain of custody audit event."""
    if sequence_index is None:
        max_seq = db.query(func.max(CustodyEventModel.sequence_index)).scalar()
        total = db.query(func.count(CustodyEventModel.event_id)).scalar() or 0
        sequence_index = (max_seq + 1) if (max_seq is not None and total > 0) else 0

    norm_ts = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)
    norm_ts = norm_ts.astimezone(timezone.utc)

    model = CustodyEventModel(
        event_id=event.event_id,
        evidence_id=event.evidence_id,
        case_id=event.case_id,
        event_type=event.event_type,
        actor=event.actor,
        timestamp=norm_ts,
        details=event.details,
        previous_event_hash=event.previous_event_hash or "",
        event_hash=event.event_hash,
        sequence_index=sequence_index,
    )
    db.add(model)
    db.commit()
    db.refresh(model)
    return model


def list_custody_events(db: Session, evidence_id: Optional[str] = None) -> List[CustodyEventModel]:
    """List custody audit events ordered chronologically and deterministically."""
    q = db.query(CustodyEventModel)
    if evidence_id:
        q = q.filter(CustodyEventModel.evidence_id == evidence_id)
    return q.order_by(CustodyEventModel.sequence_index, CustodyEventModel.timestamp).all()


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


# --- Verification, Evidence Tags & Finding Investigation Operations (Phase 3) ---

def update_evidence_tags(db: Session, evidence_id: str, tags: List[str]) -> Optional[EvidenceModel]:
    """Persist normalized analyst tags on an evidence record."""
    ev = get_evidence(db, evidence_id)
    if not ev:
        return None
    cleaned = sorted({t.strip() for t in tags if t and t.strip()})[:30]
    ev.tags_json = json.dumps(cleaned)
    if ev.case_id:
        db.add(
            CaseActivityModel(
                activity_id=str(uuid.uuid4()),
                case_id=ev.case_id,
                actor="analyst",
                action="EVIDENCE_TAGGED",
                details=f"Updated tags on '{ev.original_filename}': {', '.join(cleaned) if cleaned else 'none'}",
                created_at=datetime.now(timezone.utc),
            )
        )
    db.commit()
    db.refresh(ev)
    return ev


def update_evidence_verification(
    db: Session,
    evidence_id: str,
    verification_status: str,
    verification_details: str,
    verified_at: Optional[datetime] = None,
) -> Optional[EvidenceModel]:
    """Persist latest comprehensive integrity & signature verification status."""
    ev = get_evidence(db, evidence_id)
    if not ev:
        return None
    ev.last_verification_status = verification_status
    ev.last_verification_details = verification_details
    ev.last_verified_at = verified_at or datetime.now(timezone.utc)
    db.commit()
    db.refresh(ev)
    return ev


def get_finding(db: Session, finding_id: str) -> Optional[FindingModel]:
    """Retrieve a single FindingModel by UUID."""
    return db.query(FindingModel).filter(FindingModel.finding_id == finding_id).first()


def list_findings(
    db: Session,
    *,
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    review_status: Optional[str] = None,
    rule_id: Optional[str] = None,
    analyzer_name: Optional[str] = None,
    evidence_id: Optional[str] = None,
    case_id: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Query findings enriched with parent evidence & case context for the Findings Investigation Center."""
    q = (
        db.query(FindingModel, AnalysisRunModel, EvidenceModel, CaseModel)
        .join(AnalysisRunModel, FindingModel.run_id == AnalysisRunModel.run_id)
        .join(EvidenceModel, AnalysisRunModel.evidence_id == EvidenceModel.evidence_id)
        .outerjoin(CaseModel, EvidenceModel.case_id == CaseModel.case_id)
    )

    if severity:
        q = q.filter(FindingModel.severity == severity.strip().upper())
    if confidence:
        q = q.filter(FindingModel.confidence == confidence.strip().upper())
    if review_status:
        q = q.filter(FindingModel.review_status == review_status.strip().upper())
    if rule_id:
        q = q.filter(FindingModel.rule_id.ilike(f"%{rule_id.strip()}%"))
    if analyzer_name:
        q = q.filter(FindingModel.analyzer_name.ilike(f"%{analyzer_name.strip()}%"))
    if evidence_id:
        q = q.filter(EvidenceModel.evidence_id == evidence_id)
    if case_id:
        q = q.filter(EvidenceModel.case_id == case_id)

    rows = q.order_by(desc(AnalysisRunModel.analyzed_at)).limit(limit).all()
    results: List[Dict[str, Any]] = []
    for f_row, run_row, ev_row, case_row in rows:
        history = []
        if f_row.review_history_json:
            try:
                history = json.loads(f_row.review_history_json)
            except Exception:
                history = []
        results.append({
            "finding": f_row,
            "run": run_row,
            "evidence": ev_row,
            "case": case_row,
            "review_history": history,
        })
    return results


def update_finding_review(
    db: Session,
    finding_id: str,
    *,
    review_status: str,
    is_false_positive: bool = False,
    analyst_notes: Optional[str] = None,
    reviewed_by: str = "SOC Analyst",
) -> Optional[FindingModel]:
    """Update analyst disposition, review status, false-positive flag, and append audit history."""
    finding = get_finding(db, finding_id)
    if not finding:
        return None

    norm_status = review_status.strip().upper()
    if norm_status not in ALLOWED_FINDING_STATUSES:
        raise ValueError(f"Unsupported review status: {review_status}. Allowed: {sorted(ALLOWED_FINDING_STATUSES)}")

    now = datetime.now(timezone.utc)
    if norm_status == "FALSE_POSITIVE":
        is_false_positive = True

    history: List[Dict[str, Any]] = []
    if finding.review_history_json:
        try:
            history = json.loads(finding.review_history_json)
        except Exception:
            history = []

    history.append({
        "timestamp": now.isoformat(),
        "actor": reviewed_by or "SOC Analyst",
        "previous_status": finding.review_status,
        "new_status": norm_status,
        "is_false_positive": bool(is_false_positive),
        "notes": analyst_notes or "",
    })

    finding.review_status = norm_status
    finding.is_false_positive = bool(is_false_positive)
    finding.analyst_notes = analyst_notes.strip() if isinstance(analyst_notes, str) and analyst_notes.strip() else None
    finding.reviewed_by = reviewed_by or "SOC Analyst"
    finding.reviewed_at = now
    finding.review_history_json = json.dumps(history)

    run_obj = db.query(AnalysisRunModel).filter(AnalysisRunModel.run_id == finding.run_id).first()
    if run_obj:
        ev_obj = get_evidence(db, run_obj.evidence_id)
        if ev_obj and ev_obj.case_id:
            db.add(
                CaseActivityModel(
                    activity_id=str(uuid.uuid4()),
                    case_id=ev_obj.case_id,
                    actor=reviewed_by or "SOC Analyst",
                    action="FINDING_REVIEWED",
                    details=(
                        f"Finding {finding.rule_id} on '{ev_obj.original_filename}' reviewed: "
                        f"{norm_status} (false_positive={bool(is_false_positive)})"
                    ),
                    created_at=now,
                )
            )

    db.commit()
    db.refresh(finding)
    return finding

