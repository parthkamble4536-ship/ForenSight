"""
Secure evidence storage vault manager.

Implements write-once isolation, UUID storage mapping, bounded streaming ingestion,
tamper detection, and dual-layer integrity verification.
"""

import io
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional

from forensight.core.config import settings
from forensight.core.exceptions import (
    EvidenceNotFoundError,
    EvidenceStorageError,
    FileSizeExceededError,
    IntegrityCompromisedError,
    PathTraversalError,
    SecurityViolationError,
)
from forensight.core.security import (
    assert_safe_file_access,
    is_safe_path,
    make_read_only,
    make_writable,
    sanitize_filename,
)
from forensight.core.types import EvidenceRecord, HashResult, IntegrityCheckResult
from forensight.storage.hasher import StreamHasher, compute_hashes_from_file


class EvidenceStorageManager:
    """
    Manages untrusted evidence artifacts stored in an isolated filesystem vault.

    Security Guarantees:
    - User filenames are sanitized and never used on disk; files are stored strictly as <uuid>.bin.
    - Streaming writes enforce strict size bounds and delete partial files if limits are exceeded.
    - Files are made read-only on the filesystem upon storage completion.
    - Ingest hashes (SHA-256, SHA-1, MD5) and size are recorded prior to analysis.
    - Re-verification audits validate all three hashes, file size, and path containment.
    """

    UUID_REGEX = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    def __init__(
        self,
        vault_dir: Path | None = None,
        max_upload_size_bytes: int | None = None,
        chunk_size_bytes: int | None = None,
    ) -> None:
        self.vault_dir = (vault_dir or settings.evidence_dir).resolve()
        self.max_upload_size = (
            max_upload_size_bytes
            if max_upload_size_bytes is not None
            else settings.max_upload_size_bytes
        )
        self.chunk_size = (
            chunk_size_bytes
            if chunk_size_bytes is not None
            else settings.chunk_size_bytes
        )
        self.ensure_vault_exists()

    def ensure_vault_exists(self) -> None:
        """Create the evidence storage directory if it does not already exist."""
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def _validate_evidence_id(self, evidence_id: str) -> None:
        """Ensure evidence_id is a valid UUIDv4 string to prevent identifier-based path traversal."""
        if not evidence_id or not self.UUID_REGEX.match(evidence_id):
            raise PathTraversalError(
                message=f"Invalid evidence identifier format: [{evidence_id}]. Must be a valid UUIDv4."
            )

    def _get_target_path(self, evidence_id: str) -> Path:
        """Compute the safe on-disk storage path for a given evidence UUID."""
        self._validate_evidence_id(evidence_id)
        candidate = self.vault_dir / f"{evidence_id}.bin"
        return assert_safe_file_access(self.vault_dir, candidate)

    def store_stream(
        self,
        stream: BinaryIO,
        original_filename: str,
    ) -> EvidenceRecord:
        """
        Stream an incoming untrusted file directly to the evidence vault.

        Computes cryptographic hashes (SHA-256, SHA-1, MD5) on-the-fly and strictly
        enforces max_upload_size bounds. If the limit is exceeded, the partial file
        is unlinked immediately.
        """
        evidence_id = str(uuid.uuid4())
        sanitized = sanitize_filename(original_filename)
        dest_path = self._get_target_path(evidence_id)

        hasher = StreamHasher()
        bytes_written = 0

        try:
            with open(dest_path, "wb") as dest:
                while True:
                    chunk = stream.read(self.chunk_size)
                    if not chunk:
                        break

                    bytes_written += len(chunk)
                    if bytes_written > self.max_upload_size:
                        # Close file handle before deletion
                        dest.close()
                        self._safe_unlink(dest_path)
                        raise FileSizeExceededError(
                            size_bytes=bytes_written,
                            max_allowed_bytes=self.max_upload_size,
                        )

                    dest.write(chunk)
                    hasher.update(chunk)
                dest.flush()

            # Finalize hashes and set filesystem read-only permissions
            hash_result = hasher.finalize()
            make_read_only(dest_path)

            return EvidenceRecord(
                evidence_id=evidence_id,
                original_filename=original_filename,
                sanitized_filename=sanitized,
                storage_path=str(dest_path),
                hashes=hash_result,
                stored_at=datetime.now(timezone.utc),
                is_read_only=True,
            )

        except Exception:
            # Guarantee no partial artifact remains in vault on unexpected failure
            self._safe_unlink(dest_path)
            raise

    def store_bytes(
        self,
        data: bytes,
        original_filename: str,
    ) -> EvidenceRecord:
        """
        Store an in-memory byte buffer as an evidence item in the vault.
        """
        return self.store_stream(
            stream=io.BytesIO(data),
            original_filename=original_filename,
        )

    def retrieve_evidence_path(self, evidence_id: str) -> Path:
        """
        Locate and return the safe Path to an ingested evidence artifact.

        Raises EvidenceNotFoundError if the file does not exist, or PathTraversalError
        if containment validation fails.
        """
        path = self._get_target_path(evidence_id)
        if not path.is_file():
            raise EvidenceNotFoundError(
                message=f"Evidence artifact [{evidence_id}] was not found in storage vault."
            )
        return path

    def verify_evidence_integrity(
        self,
        evidence_id: str,
        expected_hashes: HashResult,
        raise_on_mismatch: bool = False,
    ) -> IntegrityCheckResult:
        """
        Audit evidence integrity by comparing recorded hashes and file size
        against freshly computed values from disk.

        Verifies:
        1. Storage path remains strictly inside the configured vault directory.
        2. Computed SHA-256 matches expected SHA-256.
        3. Computed SHA-1 matches expected SHA-1.
        4. Computed MD5 matches expected MD5.
        5. File size matches expected size in bytes.
        """
        self._validate_evidence_id(evidence_id)
        target_path = self.vault_dir / f"{evidence_id}.bin"

        discrepancies: list[str] = []
        is_path_safe = is_safe_path(self.vault_dir, target_path)

        if not is_path_safe:
            discrepancies.append(f"Storage path [{target_path}] violates vault boundary [{self.vault_dir}]")

        if not target_path.is_file():
            discrepancies.append(f"Evidence file [{target_path}] does not exist on disk")
            result = IntegrityCheckResult(
                evidence_id=evidence_id,
                is_valid=False,
                is_path_safe=is_path_safe,
                expected_sha256=expected_hashes.sha256,
                computed_sha256="",
                expected_sha1=expected_hashes.sha1,
                computed_sha1="",
                expected_md5=expected_hashes.md5,
                computed_md5="",
                expected_size_bytes=expected_hashes.size_bytes,
                computed_size_bytes=0,
                details="; ".join(discrepancies),
            )
            if raise_on_mismatch:
                raise IntegrityCompromisedError(evidence_id, discrepancies)
            return result

        # Compute fresh live hashes directly from stored artifact
        live_hashes = compute_hashes_from_file(target_path, chunk_size=self.chunk_size)

        if live_hashes.sha256 != expected_hashes.sha256.lower():
            discrepancies.append(
                f"SHA-256 mismatch: expected {expected_hashes.sha256}, got {live_hashes.sha256}"
            )
        if live_hashes.sha1 != expected_hashes.sha1.lower():
            discrepancies.append(
                f"SHA-1 mismatch: expected {expected_hashes.sha1}, got {live_hashes.sha1}"
            )
        if live_hashes.md5 != expected_hashes.md5.lower():
            discrepancies.append(
                f"MD5 mismatch: expected {expected_hashes.md5}, got {live_hashes.md5}"
            )
        if live_hashes.size_bytes != expected_hashes.size_bytes:
            discrepancies.append(
                f"Size mismatch: expected {expected_hashes.size_bytes} bytes, got {live_hashes.size_bytes} bytes"
            )

        is_valid = len(discrepancies) == 0 and is_path_safe
        details = "Integrity verified: all cryptographic digests and file size match" if is_valid else "; ".join(discrepancies)

        result = IntegrityCheckResult(
            evidence_id=evidence_id,
            is_valid=is_valid,
            is_path_safe=is_path_safe,
            expected_sha256=expected_hashes.sha256,
            computed_sha256=live_hashes.sha256,
            expected_sha1=expected_hashes.sha1,
            computed_sha1=live_hashes.sha1,
            expected_md5=expected_hashes.md5,
            computed_md5=live_hashes.md5,
            expected_size_bytes=expected_hashes.size_bytes,
            computed_size_bytes=live_hashes.size_bytes,
            details=details,
        )

        if not is_valid and raise_on_mismatch:
            raise IntegrityCompromisedError(evidence_id, discrepancies)

        return result

    def delete_evidence(self, evidence_id: str) -> bool:
        """
        Safely remove an evidence item from the vault (used during test teardown).
        """
        try:
            target_path = self._get_target_path(evidence_id)
            if target_path.is_file():
                make_writable(target_path)
                target_path.unlink()
                return True
        except Exception:
            pass
        return False

    def _safe_unlink(self, path: Path) -> None:
        """Unlink file with write permissions restored, ignoring non-existence."""
        try:
            if path.exists():
                make_writable(path)
                path.unlink()
        except OSError:
            pass


# Singleton vault manager bound to global configuration
evidence_vault = EvidenceStorageManager()

