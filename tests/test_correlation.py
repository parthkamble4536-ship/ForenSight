"""
Unit tests for multi-evidence correlation and timeline sequencing.
"""

from datetime import datetime, timezone
import pytest

from forensight.core.types import (
    AnalysisResult,
    EvidenceMetadata,
    EvidenceRecord,
    HashResult,
    IOCRecord,
    IOCType,
    RelationshipType,
    RiskScore,
    TimelineEvent,
    TimelineEventType,
)
from forensight.evidence.correlation import EvidenceCorrelator
from forensight.evidence.timeline import TimelineAggregator


def make_dummy_result(
    evidence_id: str,
    filename: str,
    sha256: str,
    iocs=None,
    author=None,
    attachments=None,
) -> AnalysisResult:
    """Construct minimal AnalysisResult for correlation testing."""
    return AnalysisResult(
        evidence=EvidenceRecord(
            evidence_id=evidence_id,
            case_id="case-alpha",
            original_filename=filename,
            sanitized_filename=filename,
            storage_path=f"/vault/{evidence_id}.bin",
            hashes=HashResult(
                sha256=sha256,
                sha1="1" * 40,
                md5="1" * 32,
                size_bytes=1000,
            ),
        ),
        metadata=EvidenceMetadata(
            file_size_bytes=1000,
            identified_type="PE",
            mime_type="application/octet-stream",
            declared_extension=".bin",
            entropy=4.0,
        ),
        risk=RiskScore(score=10, verdict="BENIGN", summary="clean"),
        iocs=iocs or [],
        analyzer_details={
            "author": author,
            "attachments": attachments or [],
        },
    )


class TestEvidenceCorrelation:
    """Tests for discovering relationships between evidence items in a case."""

    def test_shared_ioc_correlation_discovered(self) -> None:
        """Verify two files sharing a C2 URL are correlated."""
        c2_url = "http://bad-actor-infrastructure.net/api"
        ioc = IOCRecord(ioc_type=IOCType.URL, value=c2_url, defanged_value="hxxp://bad-actor-infrastructure[.]net/api")

        item1 = make_dummy_result("ev-1", "script.ps1", "a" * 64, iocs=[ioc])
        item2 = make_dummy_result("ev-2", "dropper.exe", "b" * 64, iocs=[ioc])

        correlator = EvidenceCorrelator()
        relations = correlator.correlate_case_evidence([item1, item2])

        assert len(relations) == 1
        assert relations[0].relationship_type == RelationshipType.SHARED_IOC
        assert relations[0].shared_value == c2_url

    def test_shared_author_correlation_discovered(self) -> None:
        """Verify two documents created by the same author are correlated."""
        item1 = make_dummy_result("ev-1", "contract.pdf", "a" * 64, author="Adversary_Alias_X")
        item2 = make_dummy_result("ev-2", "invoice.docx", "b" * 64, author="Adversary_Alias_X")

        correlator = EvidenceCorrelator()
        relations = correlator.correlate_case_evidence([item1, item2])

        assert len(relations) == 1
        assert relations[0].relationship_type == RelationshipType.SHARED_AUTHOR
        assert relations[0].shared_value == "Adversary_Alias_X"

    def test_timeline_chronological_ordering(self) -> None:
        """Verify timeline aggregator orders discrete events chronologically."""
        t1 = datetime(2026, 11, 10, 8, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)

        e1 = TimelineEvent(event_id="e1", evidence_id="ev-1", timestamp=t3, timestamp_type=TimelineEventType.INGESTION, source="Ingest", description="Analyzed")
        e2 = TimelineEvent(event_id="e2", evidence_id="ev-1", timestamp=t1, timestamp_type=TimelineEventType.COMPILE_TIME, source="PE Header", description="Compiled")
        e3 = TimelineEvent(event_id="e3", evidence_id="ev-1", timestamp=t2, timestamp_type=TimelineEventType.EMAIL_RECEIVED, source="Email", description="Sent")

        aggregator = TimelineAggregator()
        ordered = aggregator.build_case_timeline([e1, e2, e3])

        assert [ev.event_id for ev in ordered] == ["e2", "e3", "e1"]

