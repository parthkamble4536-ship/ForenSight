"""
Unit tests for the PDF forensic static analyzer.
"""

from pathlib import Path
import pytest

from forensight.analyzers.pdf_analyzer import PDFAnalyzer
from forensight.core.types import EvidenceMetadata, FindingSeverity, IOCType


class TestPDFAnalyzer:
    """Tests for PDF metadata parsing, dangerous action detection, and URL extraction."""

    def test_benign_pdf_analysis(self, tmp_path: Path) -> None:
        """Verify clean PDF without active elements yields zero malicious action findings."""
        pdf_path = tmp_path / "clean.pdf"
        pdf_content = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        pdf_path.write_bytes(pdf_content)

        meta = EvidenceMetadata(
            file_size_bytes=len(pdf_content),
            identified_type="PDF",
            mime_type="application/pdf",
            declared_extension=".pdf",
            entropy=4.5,
        )

        analyzer = PDFAnalyzer()
        output = analyzer.analyze(pdf_path, meta)

        # No /JavaScript or /Launch findings
        js_findings = [f for f in output.findings if "PDF-JS" in f.rule_id]
        launch_findings = [f for f in output.findings if "PDF-LAUNCH" in f.rule_id]
        assert len(js_findings) == 0
        assert len(launch_findings) == 0

    def test_pdf_with_javascript_and_launch_action(self, tmp_path: Path) -> None:
        """Verify PDF containing /JavaScript and /Launch triggers correct findings."""
        pdf_path = tmp_path / "weaponized.pdf"
        pdf_content = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /S /JavaScript /JS (app.alert('PWNED');) >>\nendobj\n"
            b"3 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        pdf_path.write_bytes(pdf_content)

        meta = EvidenceMetadata(
            file_size_bytes=len(pdf_content),
            identified_type="PDF",
            mime_type="application/pdf",
            declared_extension=".pdf",
            entropy=5.0,
        )

        analyzer = PDFAnalyzer()
        output = analyzer.analyze(pdf_path, meta)

        rule_ids = {f.rule_id for f in output.findings}
        assert "PDF-JS-001" in rule_ids or "PDF-JS-002" in rule_ids
        assert "PDF-ACTION-001" in rule_ids
        assert "PDF-LAUNCH-001" in rule_ids

        launch_finding = next(f for f in output.findings if f.rule_id == "PDF-LAUNCH-001")
        assert launch_finding.severity == FindingSeverity.CRITICAL

    def test_pdf_uri_action_extracts_defanged_url_ioc(self, tmp_path: Path) -> None:
        """Verify /URI action targets are extracted as defanged URL IOCs."""
        pdf_path = tmp_path / "phishing.pdf"
        target_url = "http://malicious-c2-staging.org/update.exe"
        pdf_content = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Action /S /URI /URI (" + target_url.encode("ascii") + b") >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        pdf_path.write_bytes(pdf_content)

        meta = EvidenceMetadata(
            file_size_bytes=len(pdf_content),
            identified_type="PDF",
            mime_type="application/pdf",
            declared_extension=".pdf",
            entropy=4.8,
        )

        analyzer = PDFAnalyzer()
        output = analyzer.analyze(pdf_path, meta)

        url_iocs = [ioc for ioc in output.iocs if ioc.ioc_type == IOCType.URL]
        assert len(url_iocs) >= 1
        assert url_iocs[0].value == target_url
        assert "hxxp://malicious-c2-staging[.]org/update[.]exe" in url_iocs[0].defanged_value

