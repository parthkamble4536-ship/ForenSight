"""
Unit tests for file identification and extension masquerading detection.
"""

import io
import zipfile
from pathlib import Path
import pytest

from forensight.ingestion.identifier import (
    calculate_entropy,
    identify_file,
    inspect_openxml_container,
)


class TestIdentifier:
    """Tests for file identification, magic byte inspection, and masquerading alerts."""

    def test_pe_binary_identification(self, tmp_path: Path) -> None:
        """Verify DOS/PE binary is identified correctly via MZ header."""
        pe_path = tmp_path / "test_app.exe"
        # Synthetic minimal MZ header
        pe_path.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

        metadata = identify_file(pe_path, "test_app.exe")
        assert metadata.identified_type == "PE"
        assert metadata.is_extension_mismatch is False
        assert "portable-executable" in metadata.mime_type

    def test_pdf_identification(self, tmp_path: Path) -> None:
        """Verify PDF document is identified via %PDF- header."""
        pdf_path = tmp_path / "report.pdf"
        pdf_path.write_bytes(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF")

        metadata = identify_file(pdf_path, "report.pdf")
        assert metadata.identified_type == "PDF"
        assert metadata.is_extension_mismatch is False
        assert metadata.mime_type == "application/pdf"

    def test_deceptive_pe_masquerading_as_pdf(self, tmp_path: Path) -> None:
        """Verify executable masquerading as a PDF triggers an extension mismatch alert."""
        fake_pdf = tmp_path / "invoice.pdf"
        # MZ executable header disguised with .pdf extension
        fake_pdf.write_bytes(b"MZ" + b"\x00" * 100)

        metadata = identify_file(fake_pdf, "invoice.pdf")
        assert metadata.identified_type == "PE"
        assert metadata.is_extension_mismatch is True

    def test_docx_vs_docm_differentiation(self, tmp_path: Path) -> None:
        """Verify DOCX (clean) is differentiated from DOCM (macro-enabled) via ZIP structure."""
        # Create synthetic clean DOCX
        docx_path = tmp_path / "sample.docx"
        with zipfile.ZipFile(docx_path, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", "<w:document/>")

        docx_meta = identify_file(docx_path, "sample.docx")
        assert docx_meta.identified_type == "DOCX"
        assert docx_meta.is_extension_mismatch is False

        # Create synthetic DOCM containing vbaProject.bin
        docm_path = tmp_path / "macro_doc.docm"
        with zipfile.ZipFile(docm_path, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0")  # Synthetic VBA binary

        docm_meta = identify_file(docm_path, "macro_doc.docm")
        assert docm_meta.identified_type == "DOCM"
        assert docm_meta.is_extension_mismatch is False

    def test_docm_disguised_as_docx_alert(self, tmp_path: Path) -> None:
        """Verify macro-enabled document disguised with .docx extension triggers mismatch."""
        disguised_path = tmp_path / "innocent.docx"
        with zipfile.ZipFile(disguised_path, "w") as zf:
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("word/vbaProject.bin", b"VBA_PAYLOAD")

        meta = identify_file(disguised_path, "innocent.docx")
        assert meta.identified_type == "DOCM"
        assert meta.is_extension_mismatch is True

    def test_plaintext_identification(self, tmp_path: Path) -> None:
        """Verify plaintext log file is identified correctly."""
        log_path = tmp_path / "system.log"
        log_path.write_text("2026-11-10 12:00:00 INFO Service started successfully.\n")

        meta = identify_file(log_path, "system.log")
        assert meta.identified_type == "TXT"
        assert meta.is_extension_mismatch is False

    def test_shannon_entropy_calculation(self) -> None:
        """Verify entropy calculation: uniform bytes yield 0.0, random bytes yield near 8.0."""
        # Single repeated byte: entropy = 0.0
        assert calculate_entropy(b"A" * 100) == 0.0

        # Uniform distribution of all 256 bytes: entropy = 8.0
        all_bytes = bytes(range(256))
        assert calculate_entropy(all_bytes) == 8.0

