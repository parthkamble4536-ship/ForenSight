"""
Memory-bounded multi-encoding string extractor (ASCII and UTF-16LE).

Extracts readable strings with byte offsets while enforcing strict bounds on
string length and total extracted count to prevent resource exhaustion.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List

from forensight.core.config import settings


@dataclass
class ExtractedString:
    """Individual extracted string token with offset and encoding."""

    value: str
    offset: int
    encoding: str  # 'ascii' or 'utf-16le'


@dataclass
class StringExtractionReport:
    """Results of a bounded string extraction scan."""

    strings: List[ExtractedString]
    total_found: int
    is_truncated: bool
    limit_applied: int


class StringExtractor:
    """
    Extracts ASCII and UTF-16LE strings from binary or text artifacts.
    """

    def __init__(
        self,
        min_len: int = settings.min_string_len,
        max_len: int = settings.max_string_len,
        max_strings: int = settings.max_string_extract,
    ) -> None:
        self.min_len = min_len
        self.max_len = max_len
        self.max_strings = max_strings

    def extract_from_bytes(self, data: bytes) -> StringExtractionReport:
        """
        Extract printable strings from raw bytes.
        """
        results: List[ExtractedString] = []
        data_len = len(data)

        # 1. Extract ASCII strings
        current_ascii: List[int] = []
        ascii_start_offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte <= 126 or byte == 9:  # Printable ASCII or tab
                if not current_ascii:
                    ascii_start_offset = i
                current_ascii.append(byte)
                if len(current_ascii) > self.max_len:
                    # Flush if max_len reached
                    val = bytes(current_ascii).decode("ascii", errors="ignore")
                    results.append(ExtractedString(value=val, offset=ascii_start_offset, encoding="ascii"))
                    current_ascii = []
                    if len(results) >= self.max_strings:
                        return StringExtractionReport(
                            strings=results,
                            total_found=len(results),
                            is_truncated=True,
                            limit_applied=self.max_strings,
                        )
            else:
                if len(current_ascii) >= self.min_len:
                    val = bytes(current_ascii).decode("ascii", errors="ignore")
                    results.append(ExtractedString(value=val, offset=ascii_start_offset, encoding="ascii"))
                    if len(results) >= self.max_strings:
                        return StringExtractionReport(
                            strings=results,
                            total_found=len(results),
                            is_truncated=True,
                            limit_applied=self.max_strings,
                        )
                current_ascii = []

        # Flush trailing ASCII
        if len(current_ascii) >= self.min_len:
            val = bytes(current_ascii).decode("ascii", errors="ignore")
            results.append(ExtractedString(value=val, offset=ascii_start_offset, encoding="ascii"))
            if len(results) >= self.max_strings:
                return StringExtractionReport(
                    strings=results,
                    total_found=len(results),
                    is_truncated=True,
                    limit_applied=self.max_strings,
                )

        # 2. Extract UTF-16LE strings (char, 0x00 pattern)
        i = 0
        current_utf16: List[int] = []
        utf16_start_offset = 0

        while i < data_len - 1:
            char_byte = data[i]
            null_byte = data[i + 1]

            if null_byte == 0 and (32 <= char_byte <= 126 or char_byte == 9):
                if not current_utf16:
                    utf16_start_offset = i
                current_utf16.extend([char_byte, null_byte])
                i += 2
                if len(current_utf16) // 2 > self.max_len:
                    val = bytes(current_utf16).decode("utf-16le", errors="ignore")
                    results.append(ExtractedString(value=val, offset=utf16_start_offset, encoding="utf-16le"))
                    current_utf16 = []
                    if len(results) >= self.max_strings:
                        return StringExtractionReport(
                            strings=results,
                            total_found=len(results),
                            is_truncated=True,
                            limit_applied=self.max_strings,
                        )
            else:
                if len(current_utf16) // 2 >= self.min_len:
                    val = bytes(current_utf16).decode("utf-16le", errors="ignore")
                    results.append(ExtractedString(value=val, offset=utf16_start_offset, encoding="utf-16le"))
                    if len(results) >= self.max_strings:
                        return StringExtractionReport(
                            strings=results,
                            total_found=len(results),
                            is_truncated=True,
                            limit_applied=self.max_strings,
                        )
                current_utf16 = []
                i += 1

        # Flush trailing UTF-16LE
        if len(current_utf16) // 2 >= self.min_len:
            val = bytes(current_utf16).decode("utf-16le", errors="ignore")
            results.append(ExtractedString(value=val, offset=utf16_start_offset, encoding="utf-16le"))

        is_truncated = len(results) >= self.max_strings
        return StringExtractionReport(
            strings=results,
            total_found=len(results),
            is_truncated=is_truncated,
            limit_applied=self.max_strings,
        )

    def extract_from_file(self, file_path: Path, max_bytes: int = 10 * 1024 * 1024) -> StringExtractionReport:
        """
        Extract strings from a file on disk (reads up to max_bytes to bound memory).
        """
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
        return self.extract_from_bytes(data)

