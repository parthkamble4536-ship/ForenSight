"""
Verification tests for synthetic demonstration samples.

Ensures all synthetic samples in data/samples/ can be ingested and statically
analyzed without errors and trigger their expected triage findings.
"""

from pathlib import Path
import pytest

from forensight.analyzers import get_analyzer_for_type
from forensight.core.config import settings
from forensight.ingestion.identifier import identify_file
from forensight.intelligence.scoring import risk_engine
from forensight.storage.hasher import compute_hashes_from_file


class TestSyntheticSamples:
    """Verifies that all demonstration specimens analyze cleanly and trigger intended indicators."""

    @pytest.fixture(scope="class")
    def samples_dir(self) -> Path:
        p = Path(__file__).resolve().parent.parent / "data" / "samples"
        assert p.exists(), f"Samples directory {p} must exist"
        return p

    def test_sample_clean_pe(self, samples_dir: Path) -> None:
        """Clean PE should parse without critical alerts."""
        f = samples_dir / "sample_clean.exe"
        meta = identify_file(f, f.name)
        assert meta.identified_type == "PE"
        analyzer = get_analyzer_for_type("PE")
        out = analyzer.analyze(f, meta)
        assert out.details.get("machine") in ("IMAGE_FILE_MACHINE_I386", "i386", "0x14c")

    def test_sample_masquerade(self, samples_dir: Path) -> None:
        """Deceptive PE masquerading as PDF must trigger extension mismatch alert."""
        f = samples_dir / "sample_masquerade.pdf"
        meta = identify_file(f, f.name)
        assert meta.identified_type == "PE"
        assert meta.is_extension_mismatch is True

    def test_sample_actions_pdf(self, samples_dir: Path) -> None:
        """Sample PDF should trigger /JavaScript and /Launch action findings."""
        f = samples_dir / "sample_actions.pdf"
        meta = identify_file(f, f.name)
        assert meta.identified_type == "PDF"
        analyzer = get_analyzer_for_type("PDF")
        out = analyzer.analyze(f, meta)
        rules = [find.rule_id for find in out.findings]
        assert "PDF-JS-001" in rules
        assert "PDF-LAUNCH-001" in rules

    def test_sample_template_injection_docx(self, samples_dir: Path) -> None:
        """DOCX should trigger Remote Template Injection finding (MITRE T1221)."""
        f = samples_dir / "sample_template_injection.docx"
        meta = identify_file(f, f.name)
        assert meta.identified_type == "DOCX"
        analyzer = get_analyzer_for_type("DOCX")
        out = analyzer.analyze(f, meta)
        rules = [find.rule_id for find in out.findings]
        assert "DOCX-TEMPLATE-001" in rules

    def test_sample_phishing_eml(self, samples_dir: Path) -> None:
        """Phishing EML should detect From/Reply-To mismatch and dangerous attachment."""
        f = samples_dir / "sample_phishing.eml"
        meta = identify_file(f, f.name)
        assert meta.identified_type == "EML"
        analyzer = get_analyzer_for_type("EML")
        out = analyzer.analyze(f, meta)
        rules = [find.rule_id for find in out.findings]
        assert "EML-SPOOF-001" in rules
        assert "EML-ATT-001" in rules

    def test_sample_double_extension_zip(self, samples_dir: Path) -> None:
        """ZIP archive should flag invoice.pdf.exe double-extension."""
        f = samples_dir / "sample_double_extension.zip"
        meta = identify_file(f, f.name)
        assert meta.identified_type == "ZIP"
        analyzer = get_analyzer_for_type("ZIP")
        out = analyzer.analyze(f, meta)
        rules = [find.rule_id for find in out.findings]
        assert "ARCH-DECEPTION-001" in rules

    def test_sample_ransomware_log(self, samples_dir: Path) -> None:
        """Ransomware log should identify shadow copy deletion and encoded PowerShell."""
        f = samples_dir / "sample_ransomware_log.txt"
        meta = identify_file(f, f.name)
        assert meta.identified_type == "TXT"
        analyzer = get_analyzer_for_type("TXT")
        out = analyzer.analyze(f, meta)
        rules = [find.rule_id for find in out.findings]
        assert "TXT-RANSOM-001" in rules
        assert "TXT-PS-001" in rules
