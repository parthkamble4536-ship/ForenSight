"""
Security and boundary tests for the evidence storage vault and integrity subsystem.
"""

from pathlib import Path
import pytest

from forensight.core.exceptions import (
    EvidenceNotFoundError,
    FileSizeExceededError,
    IntegrityCompromisedError,
    PathTraversalError,
)
from forensight.core.security import make_writable, sanitize_filename
from forensight.core.types import HashResult
from forensight.storage.manager import EvidenceStorageManager


class TestStorageSecurity:
    """Security tests verifying isolation, boundary enforcement, and tamper detection."""

    def test_store_evidence_isolates_with_uuid(
        self,
        storage_manager: EvidenceStorageManager,
        benign_sample_bytes: bytes,
    ) -> None:
        """Verify uploaded evidence is renamed to a UUID on disk, preserving original name in record."""
        original_name = "sample_malware.exe"
        record = storage_manager.store_bytes(benign_sample_bytes, original_name)

        # Record integrity
        assert record.evidence_id is not None
        assert record.original_filename == original_name
        assert record.sanitized_filename == original_name

        # On-disk file must be <uuid>.bin, never the untrusted original name
        expected_path = storage_manager.vault_dir / f"{record.evidence_id}.bin"
        assert Path(record.storage_path) == expected_path
        assert expected_path.is_file()
        assert not (storage_manager.vault_dir / original_name).exists()

        # Hashes match stored bytes
        assert record.hashes.size_bytes == len(benign_sample_bytes)

    def test_file_size_exceeded_enforcement_and_cleanup(
        self,
        temp_vault_dir: Path,
    ) -> None:
        """Verify exceeding max upload size aborts immediately and unlinks partial file."""
        tiny_manager = EvidenceStorageManager(
            vault_dir=temp_vault_dir,
            max_upload_size_bytes=100,  # Strict 100-byte limit
            chunk_size_bytes=32,
        )

        oversized_data = b"A" * 250

        with pytest.raises(FileSizeExceededError) as exc_info:
            tiny_manager.store_bytes(oversized_data, "large_file.bin")

        assert exc_info.value.max_allowed_bytes == 100
        assert exc_info.value.size_bytes > 100

        # Verify no orphaned or partial files remain in the vault
        vault_files = list(temp_vault_dir.glob("*.bin"))
        assert len(vault_files) == 0

    @pytest.mark.parametrize(
        "untrusted_input,expected_sanitized",
        [
            ("../../../etc/passwd", "passwd"),
            ("..\\..\\Windows\\System32\\cmd.exe", "cmd.exe"),
            ("harmless.txt\x00.exe", "harmless.txt.exe"),
            ("   ...spaced_name...   ", "spaced_name"),
            ("", "unnamed_evidence.bin"),
            (None, "unnamed_evidence.bin"),
        ],
    )
    def test_sanitize_filename_traversal_stripping(
        self,
        untrusted_input: str | None,
        expected_sanitized: str,
    ) -> None:
        """Verify filename sanitizer strips traversal paths, null bytes, and malicious tokens."""
        assert sanitize_filename(untrusted_input) == expected_sanitized

    def test_retrieve_evidence_path_valid(
        self,
        storage_manager: EvidenceStorageManager,
        benign_sample_bytes: bytes,
    ) -> None:
        """Verify path retrieval succeeds for legitimately ingested evidence."""
        record = storage_manager.store_bytes(benign_sample_bytes, "doc.pdf")
        retrieved_path = storage_manager.retrieve_evidence_path(record.evidence_id)

        assert retrieved_path.is_file()
        assert retrieved_path.name == f"{record.evidence_id}.bin"

    def test_retrieve_evidence_path_traversal_rejected(
        self,
        storage_manager: EvidenceStorageManager,
    ) -> None:
        """Verify identifier path traversal attempts are rejected as invalid UUID format."""
        with pytest.raises(PathTraversalError):
            storage_manager.retrieve_evidence_path("../../etc/shadow")

        with pytest.raises(PathTraversalError):
            storage_manager.retrieve_evidence_path("non-uuid-string")

    def test_retrieve_nonexistent_evidence_raises(
        self,
        storage_manager: EvidenceStorageManager,
    ) -> None:
        """Verify querying a non-existent UUID raises EvidenceNotFoundError."""
        non_existent_uuid = "a0000000-0000-4000-8000-000000000000"
        with pytest.raises(EvidenceNotFoundError):
            storage_manager.retrieve_evidence_path(non_existent_uuid)

    def test_evidence_integrity_audit_passes_for_clean_file(
        self,
        storage_manager: EvidenceStorageManager,
        benign_sample_bytes: bytes,
    ) -> None:
        """Verify integrity audit succeeds when stored evidence remains intact."""
        record = storage_manager.store_bytes(benign_sample_bytes, "clean.bin")
        audit = storage_manager.verify_evidence_integrity(record.evidence_id, record.hashes)

        assert audit.is_valid is True
        assert audit.is_path_safe is True
        assert audit.computed_sha256 == record.hashes.sha256
        assert audit.computed_sha1 == record.hashes.sha1
        assert audit.computed_md5 == record.hashes.md5
        assert audit.computed_size_bytes == record.hashes.size_bytes

    def test_evidence_integrity_audit_detects_byte_tampering(
        self,
        storage_manager: EvidenceStorageManager,
        benign_sample_bytes: bytes,
    ) -> None:
        """Verify altering a single byte in stored evidence is detected as an integrity failure."""
        record = storage_manager.store_bytes(benign_sample_bytes, "evidence.bin")
        target_path = Path(record.storage_path)

        # Simulate tampering by mutating bytes on disk
        make_writable(target_path)
        with open(target_path, "r+b") as f:
            f.seek(0)
            f.write(b"X")  # Overwrite first byte

        audit = storage_manager.verify_evidence_integrity(record.evidence_id, record.hashes)

        assert audit.is_valid is False
        assert audit.is_path_safe is True
        assert audit.computed_sha256 != record.hashes.sha256
        assert "SHA-256 mismatch" in audit.details

        # Ensure strict mode raises IntegrityCompromisedError
        with pytest.raises(IntegrityCompromisedError) as exc_info:
            storage_manager.verify_evidence_integrity(
                record.evidence_id,
                record.hashes,
                raise_on_mismatch=True,
            )
        assert record.evidence_id in str(exc_info.value)

    def test_evidence_integrity_audit_detects_size_tampering(
        self,
        storage_manager: EvidenceStorageManager,
        benign_sample_bytes: bytes,
    ) -> None:
        """Verify appending data to evidence is detected as size mismatch."""
        record = storage_manager.store_bytes(benign_sample_bytes, "audit.bin")
        target_path = Path(record.storage_path)

        # Simulate tampering by appending data
        make_writable(target_path)
        with open(target_path, "ab") as f:
            f.write(b"\x00\x00\x00\x00")

        audit = storage_manager.verify_evidence_integrity(record.evidence_id, record.hashes)
        assert audit.is_valid is False
        assert "Size mismatch" in audit.details

