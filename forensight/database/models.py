"""
SQLAlchemy 2.0 ORM models for ForenSight case management and forensic persistence.
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


class CaseModel(Base):
    """Investigation case container grouping related digital evidence items."""

    __tablename__ = "cases"

    case_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    investigator: Mapped[str] = mapped_column(String(100), default="Lead Investigator")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")

    # Relationships
    evidence_items: Mapped[List["EvidenceModel"]] = relationship(
        "EvidenceModel",
        back_populates="case",
        cascade="all, delete-orphan",
    )


class EvidenceModel(Base):
    """Ingested evidence artifact cataloged in the secure storage vault."""

    __tablename__ = "evidence_items"

    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("cases.case_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sanitized_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)

    # Hashes
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    # Identification metadata
    identified_type: Mapped[str] = mapped_column(String(50), default="UNKNOWN")
    mime_type: Mapped[str] = mapped_column(String(100), default="application/octet-stream")
    declared_extension: Mapped[str] = mapped_column(String(20), default="")
    is_extension_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    entropy: Mapped[float] = mapped_column(Float, default=0.0)

    stored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    is_read_only: Mapped[bool] = mapped_column(Boolean, default=True)

    # Cryptographic Manifest signature
    manifest_signature: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    public_key_fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Relationships
    case: Mapped[Optional["CaseModel"]] = relationship("CaseModel", back_populates="evidence_items")
    analysis_runs: Mapped[List["AnalysisRunModel"]] = relationship(
        "AnalysisRunModel",
        back_populates="evidence",
        cascade="all, delete-orphan",
    )


class AnalysisRunModel(Base):
    """Historical execution run of static forensic analysis on an evidence item."""

    __tablename__ = "analysis_runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("evidence_items.evidence_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    # Risk summary
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(50), default="BENIGN")
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Serialized analyzer output details (JSON)
    raw_details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    evidence: Mapped["EvidenceModel"] = relationship("EvidenceModel", back_populates="analysis_runs")
    findings: Mapped[List["FindingModel"]] = relationship(
        "FindingModel",
        back_populates="analysis_run",
        cascade="all, delete-orphan",
    )
    iocs: Mapped[List["IOCModel"]] = relationship(
        "IOCModel",
        back_populates="analysis_run",
        cascade="all, delete-orphan",
    )


class FindingModel(Base):
    """Individual explainable triage finding."""

    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_runs.run_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="INFO")
    confidence: Mapped[str] = mapped_column(String(20), default="HIGH")
    score_impact: Mapped[int] = mapped_column(Integer, default=0)
    object_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    analysis_run: Mapped["AnalysisRunModel"] = relationship("AnalysisRunModel", back_populates="findings")


class IOCModel(Base):
    """Extracted Indicator of Compromise."""

    __tablename__ = "iocs"

    ioc_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_runs.run_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    defanged_value: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    confidence: Mapped[str] = mapped_column(String(20), default="HIGH")

    analysis_run: Mapped["AnalysisRunModel"] = relationship("AnalysisRunModel", back_populates="iocs")


class CustodyEventModel(Base):
    """Persistent record of a cryptographically linked Chain of Custody event."""

    __tablename__ = "custody_events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    case_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    actor: Mapped[str] = mapped_column(String(100), default="system")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    previous_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
