"""
Unit tests for forensic report generation (HTML, JSON, and PDF).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

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
from forensight.reports.generator import ReportGenerator


@pytest.fixture
def sample_analysis_result() -> AnalysisResult:
    """Provide a complete AnalysisResult fixture for report generation tests."""
    return AnalysisResult(
        evidence=EvidenceRecord(
            evidence_id="ev-test-1",
            original_filename="sample_payload.docx",
            sanitized_filename="sample_payload.docx",
            storage_path="/vault/ev-test-1.bin",
            hashes=HashResult(
                sha256="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
                sha1="2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
                md5="9e107d9d372bb6826bd81d3542a419d6",
                size_bytes=10240,
            ),
        ),
        metadata=EvidenceMetadata(
            file_size_bytes=10240,
            identified_type="DOCX",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            declared_extension=".docx",
            entropy=4.5,
        ),
        risk=RiskScore(score=85, verdict="HIGH RISK", summary="Remote Template Injection weaponization observed"),
        findings=[
            Finding(
                rule_id="DOCX-TEMPLATE-001",
                category="TEMPLATE_INJECTION",
                title="Remote Template Injection Attack (MITRE T1221)",
                description="Document fetches external macro template from remote staging server.",
                severity=FindingSeverity.CRITICAL,
                score_impact=50,
                mitre_technique="T1221",
            )
        ],
        iocs=[
            IOCRecord(
                ioc_type=IOCType.URL,
                value="http://adversary-c2.net/payload.dotm",
                defanged_value="hxxp://adversary-c2[.]net/payload[.]dotm",
                context="Attached Template Relationship",
            )
        ],
    )


class TestReportGenerator:
    """Tests for HTML, JSON, and PDF report creation."""

    def test_generate_json_report(self, sample_analysis_result: AnalysisResult) -> None:
        """Verify JSON report generates valid parseable JSON."""
        generator = ReportGenerator()
        json_str = generator.generate_json_report(sample_analysis_result)

        parsed = json.loads(json_str)
        assert parsed["evidence"]["original_filename"] == "sample_payload.docx"
        assert parsed["risk_score"]["score"] == 85
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["rule_id"] == "DOCX-TEMPLATE-001"

    def test_generate_html_report(self, sample_analysis_result: AnalysisResult) -> None:
        """Verify HTML report is standalone, valid HTML with embedded CSS and findings."""
        generator = ReportGenerator()
        html_str = generator.generate_html_report(sample_analysis_result)

        assert "<!DOCTYPE html>" in html_str
        assert "sample_payload.docx" in html_str
        assert "DOCX-TEMPLATE-001" in html_str
        assert "hxxp://adversary-c2[.]net/payload[.]dotm" in html_str
        assert "85/100" in html_str

    def test_generate_pdf_report(self, sample_analysis_result: AnalysisResult, tmp_path: Path) -> None:
        """Verify PDF report is generated successfully with valid PDF header."""
        generator = ReportGenerator()
        pdf_out = tmp_path / "test_report.pdf"

        manifest = EvidenceManifest(
            manifest_id="man-test",
            evidence_id=sample_analysis_result.evidence.evidence_id,
            original_filename="sample_payload.docx",
            hashes=sample_analysis_result.evidence.hashes,
            file_type="DOCX",
            acquired_at=datetime.now(timezone.utc),
            signature="a" * 128,
            public_key_fingerprint="b" * 64,
        )

        result_path = generator.generate_pdf_report(sample_analysis_result, pdf_out, manifest=manifest)

        assert result_path.exists()
        pdf_bytes = result_path.read_bytes()
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF-")
