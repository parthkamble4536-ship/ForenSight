"""
Unit tests for the Windows Portable Executable (PE) forensic static analyzer.
"""

import struct
from pathlib import Path
import pytest

from forensight.analyzers.pe_analyzer import PEAnalyzer
from forensight.core.types import EvidenceMetadata, FindingSeverity


def create_minimal_pe() -> bytes:
    """
    Construct a deterministic, synthetic 32-bit PE binary in memory for safe unit testing.
    Contains valid DOS header, NT headers, File header, Optional header, and one section (.text).
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew at offset 0x3C pointing to NT headers at 0x80
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    # Pad up to offset 0x80
    pe_data = bytearray(dos_header)
    pe_data.extend(b"\x00" * (0x80 - len(pe_data)))

    # Signature: PE\0\0
    pe_data.extend(b"PE\x00\x00")

    # IMAGE_FILE_HEADER (20 bytes)
    # Machine = 0x014c (i386), NumberOfSections = 1, TimeDateStamp = 0 (zeroed), SizeOfOptionalHeader = 224, Characteristics = 0x0102
    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
    pe_data.extend(file_header)

    # IMAGE_OPTIONAL_HEADER32 (224 bytes)
    # Magic = 0x10b (PE32), AddressOfEntryPoint = 0x1000, BaseOfCode = 0x1000, ImageBase = 0x400000, SectionAlignment = 0x1000, FileAlignment = 0x200
    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x010B)  # Magic PE32
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt_header, 28, 0x00400000)  # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt_header, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x400)  # SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, 2)  # Subsystem Windows GUI
    struct.pack_into("<I", opt_header, 92, 16)  # NumberOfRvaAndSizes
    pe_data.extend(opt_header)

    # IMAGE_SECTION_HEADER (.text, 40 bytes)
    # Name (.text), Misc_VirtualSize = 0x500, VirtualAddress = 0x1000, SizeOfRawData = 0x200, PointerToRawData = 0x400, Characteristics = 0x60000020 (CODE | EXECUTE | READ)
    sec_name = b".text\x00\x00\x00"
    sec_header = struct.pack(
        "<8sIIIIIIHHI",
        sec_name,
        0x500,
        0x1000,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    pe_data.extend(sec_header)

    # Pad to SizeOfHeaders (0x400)
    pe_data.extend(b"\x00" * (0x400 - len(pe_data)))

    # Section Raw Data (.text) at offset 0x400 (0x200 bytes)
    pe_data.extend(b"\x90" * 0x200)  # NOP instructions

    return bytes(pe_data)


class TestPEAnalyzer:
    """Tests for PE header parsing, section inspection, timestamps, and malformed binary handling."""

    def test_corrupted_pe_header_handled_gracefully(self, tmp_path: Path) -> None:
        """Verify corrupted PE binary generates PE-CORRUPT-001 finding without crashing."""
        corrupt_pe = tmp_path / "corrupt.exe"
        # MZ header with invalid PE pointer
        corrupt_pe.write_bytes(b"MZ\x90\x00" + b"\xff" * 100)

        meta = EvidenceMetadata(
            file_size_bytes=corrupt_pe.stat().st_size,
            identified_type="PE",
            mime_type="application/vnd.microsoft.portable-executable",
            declared_extension=".exe",
            entropy=5.0,
        )

        analyzer = PEAnalyzer()
        output = analyzer.analyze(corrupt_pe, meta)

        assert len(output.findings) >= 1
        assert output.findings[0].rule_id == "PE-CORRUPT-001"
        assert output.findings[0].severity == FindingSeverity.HIGH

    def test_synthetic_pe_structure_and_timestomp_detection(self, tmp_path: Path) -> None:
        """Verify synthetic PE parses machine type, sections, and flags zeroed timestamp."""
        pe_bytes = create_minimal_pe()
        pe_path = tmp_path / "synthetic.exe"
        pe_path.write_bytes(pe_bytes)

        meta = EvidenceMetadata(
            file_size_bytes=len(pe_bytes),
            identified_type="PE",
            mime_type="application/vnd.microsoft.portable-executable",
            declared_extension=".exe",
            entropy=4.0,
        )

        analyzer = PEAnalyzer()
        output = analyzer.analyze(pe_path, meta)

        # Machine and section details parsed
        assert "IMAGE_FILE_MACHINE_I386" in output.details["machine"]
        assert output.details["number_of_sections"] == 1
        assert len(output.details["sections"]) == 1
        assert output.details["sections"][0]["name"] == ".text"

        # Zeroed timestamp rule triggered
        zero_ts_finding = [f for f in output.findings if f.rule_id == "PE-TIMESTAMP-003"]
        assert len(zero_ts_finding) == 1

