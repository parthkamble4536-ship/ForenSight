"""
Unit tests for the Archive forensic static analyzer (ZIP structural triage).
"""

import zipfile
from pathlib import Path
import pytest

from forensight.analyzers.archive_analyzer import ArchiveAnalyzer
from forensight.core.types import EvidenceMetadata, FindingSeverity


class TestArchiveAnalyzer:
    """Tests for double extension detection, encrypted entries, and archive timelines."""

    def test_double_extension_executable_flagged(self, tmp_path: Path) -> None:
        """Verify archive bundling an executable with double extension triggers Critical finding."""
        zip_path = tmp_path / "payload.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            # Craft double extension
            zf.writestr("monthly_statement.pdf.exe", b"MZ_EXECUTABLE_BYTES")
            zf.writestr("readme.txt", b"Safe instructions")

        meta = EvidenceMetadata(
            file_size_bytes=zip_path.stat().st_size,
            identified_type="ZIP",
            mime_type="application/zip",
            declared_extension=".zip",
            entropy=4.2,
        )

        analyzer = ArchiveAnalyzer()
        output = analyzer.analyze(zip_path, meta)

        rule_ids = {f.rule_id for f in output.findings}
        assert "ARCH-DECEPTION-001" in rule_ids

        finding = next(f for f in output.findings if f.rule_id == "ARCH-DECEPTION-001")
        assert finding.severity == FindingSeverity.CRITICAL
        assert "monthly_statement.pdf.exe" in finding.description
        assert len(output.timeline_events) >= 1

