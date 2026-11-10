"""
Unit tests for memory-bounded multi-encoding string extraction.
"""

from pathlib import Path
import pytest

from forensight.extraction.strings import StringExtractor


class TestStringExtractor:
    """Tests for ASCII and UTF-16LE string extraction and bounds enforcement."""

    def test_ascii_string_extraction_with_offsets(self) -> None:
        """Verify ASCII strings are extracted with correct byte offsets."""
        data = b"\x00\x00\x00Hello_World\x00\x01\x02Target_Binary\x00"
        extractor = StringExtractor(min_len=4, max_len=50, max_strings=100)
        report = extractor.extract_from_bytes(data)

        values = [s.value for s in report.strings]
        assert "Hello_World" in values
        assert "Target_Binary" in values

        hello_str = next(s for s in report.strings if s.value == "Hello_World")
        assert hello_str.offset == 3
        assert hello_str.encoding == "ascii"

    def test_utf16le_string_extraction(self) -> None:
        """Verify UTF-16LE (wide char) strings are extracted correctly."""
        # "Windows_Registry" encoded in UTF-16LE
        wide_str = "Windows_Registry".encode("utf-16le")
        data = b"\xff\xff" + wide_str + b"\x00\x00"

        extractor = StringExtractor(min_len=4, max_len=50, max_strings=100)
        report = extractor.extract_from_bytes(data)

        values = [s.value for s in report.strings]
        assert "Windows_Registry" in values

        found_str = next(s for s in report.strings if s.value == "Windows_Registry")
        assert found_str.encoding == "utf-16le"

    def test_max_strings_ceiling_enforced(self) -> None:
        """Verify extraction halts and sets is_truncated=True when ceiling is reached."""
        data = b"".join(f"String_{i:04d}\x00".encode("ascii") for i in range(100))
        extractor = StringExtractor(min_len=4, max_len=50, max_strings=10)
        report = extractor.extract_from_bytes(data)

        assert len(report.strings) == 10
        assert report.is_truncated is True
        assert report.limit_applied == 10

