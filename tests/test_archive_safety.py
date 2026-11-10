"""
Unit tests for archive safety inspection and decompression defenses.
"""

import zipfile
from pathlib import Path
import pytest

from forensight.core.exceptions import ArchiveExplosionError, CorruptArchiveError
from forensight.ingestion.archive_safety import ArchiveSafetyInspector


class TestArchiveSafety:
    """Tests for zip-bomb prevention, entry limits, and path traversal detection."""

    def test_benign_zip_inspection(self, tmp_path: Path) -> None:
        """Verify normal benign zip archive passes safety audit."""
        zip_file = tmp_path / "benign.zip"
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("notes.txt", "Forensic analysis report")
            zf.writestr("data/config.json", '{"version": "1.0"}')

        inspector = ArchiveSafetyInspector()
        report = inspector.inspect_zip(zip_file)

        assert report.is_safe is True
        assert report.total_entries == 2
        assert report.traversal_attempts_count == 0
        assert report.rejection_reason is None

    def test_zip_entry_count_limit_enforced(self, tmp_path: Path) -> None:
        """Verify archive exceeding max entries threshold is rejected."""
        zip_file = tmp_path / "many_files.zip"
        with zipfile.ZipFile(zip_file, "w") as zf:
            for i in range(20):
                zf.writestr(f"file_{i}.txt", f"Content {i}")

        inspector = ArchiveSafetyInspector(max_entries=10)
        with pytest.raises(ArchiveExplosionError, match="exceeding limit of 10"):
            inspector.inspect_zip(zip_file)

    def test_zip_path_traversal_detected(self, tmp_path: Path) -> None:
        """Verify archive containing path traversal entry is flagged as unsafe."""
        zip_file = tmp_path / "traversal.zip"
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("normal.txt", "harmless")
            # Craft member with directory traversal
            zf.writestr("../../etc/passwd", "root:x:0:0:root")

        inspector = ArchiveSafetyInspector()
        report = inspector.inspect_zip(zip_file)

        assert report.is_safe is False
        assert report.traversal_attempts_count >= 1
        assert "Path traversal" in (report.rejection_reason or "")

    def test_corrupt_zip_handling(self, tmp_path: Path) -> None:
        """Verify corrupt zip bytes raise CorruptArchiveError safely."""
        corrupt_file = tmp_path / "damaged.zip"
        corrupt_file.write_bytes(b"PK\x03\x04\xff\xff\xffcorrupt_data")

        inspector = ArchiveSafetyInspector()
        with pytest.raises(CorruptArchiveError):
            inspector.inspect_zip(corrupt_file)

