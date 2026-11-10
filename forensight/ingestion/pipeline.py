"""
Advanced evidence ingestion pipeline.

Coordinates secure streaming ingestion, concurrent multi-hashing, duplicate detection,
magic byte identification, metadata extraction, and cryptographic manifest creation.
"""

import io
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Dict, Optional

from forensight.core.config import settings
from forensight.core.exceptions import (
    DuplicateEvidenceError,
    FileSizeExceededError,
    PathTraversalError,
)
from forensight.core.types import (
    EvidenceManifest,
    EvidenceMetadata,
    EvidenceRecord,
    HashResult,
)
from forensight.ingestion.identifier import identify_file
from forensight.storage.hasher import StreamHasher
from forensight.storage.manager import EvidenceStorageManager, evidence_vault


@dataclass
class IngestionResult:
    """Consolidated result returned by the ingestion pipeline."""

    evidence: EvidenceRecord
    metadata: EvidenceMetadata
    manifest: EvidenceManifest
    is_duplicate: bool = False
    existing_evidence_id: Optional[str] = None


class IngestionPipeline:
    """
    End-to-end evidence ingestion pipeline.

    Guarantees:
    - Zero execution of uploaded binaries or embedded scripts.
    - Write-once storage in isolated UUID vault.
    - Pre-analysis hashing and manifest issuance.
    - Identification of true format and extension masquerading.
    - Duplicate artifact detection by SHA-256.
    """

    def __init__(
        self,
        vault_manager: Optional[EvidenceStorageManager] = None,
    ) -> None:
        self.vault = vault_manager or evidence_vault
        # Local hash index to detect duplicate artifacts
        self._sha256_registry: Dict[str, str] = {}

    def register_known_hash(self, sha256: str, evidence_id: str) -> None:
        """Register a known SHA-256 to enable duplicate tracking across sessions."""
        self._sha256_registry[sha256.lower()] = evidence_id

    def ingest_stream(
        self,
        stream: BinaryIO,
        original_filename: str,
        case_id: Optional[str] = None,
        allow_duplicates: bool = False,
    ) -> IngestionResult:
        """
        Ingest an untrusted binary stream.

        Steps:
        1. Streams to disk vault while computing hashes and checking size bounds.
        2. Detects duplicate evidence by SHA-256.
        3. Identifies true file type using magic bytes.
        4. Detects extension mismatch.
        5. Issues an immutable Evidence Manifest.
        """
        # Store securely in vault
        record = self.vault.store_stream(stream=stream, original_filename=original_filename)
        record.case_id = case_id
        stored_path = Path(record.storage_path)

        sha256 = record.hashes.sha256

        # Duplicate check
        is_duplicate = False
        existing_id = self._sha256_registry.get(sha256)

        if existing_id is not None:
            is_duplicate = True
            if not allow_duplicates:
                # Rollback current stored file and raise
                self.vault.delete_evidence(record.evidence_id)
                raise DuplicateEvidenceError(sha256=sha256, existing_evidence_id=existing_id)
        else:
            self._sha256_registry[sha256] = record.evidence_id

        # File Identification & Masquerade Detection
        metadata = identify_file(stored_path, original_filename)

        # Issue Cryptographic Evidence Manifest
        manifest = EvidenceManifest(
            manifest_id=str(uuid.uuid4()),
            evidence_id=record.evidence_id,
            case_id=case_id,
            original_filename=record.original_filename,
            hashes=record.hashes,
            file_type=metadata.identified_type,
            acquired_at=record.stored_at,
        )

        return IngestionResult(
            evidence=record,
            metadata=metadata,
            manifest=manifest,
            is_duplicate=is_duplicate,
            existing_evidence_id=existing_id,
        )

    def ingest_bytes(
        self,
        data: bytes,
        original_filename: str,
        case_id: Optional[str] = None,
        allow_duplicates: bool = False,
    ) -> IngestionResult:
        """Convenience method for ingesting in-memory byte buffers."""
        return self.ingest_stream(
            stream=io.BytesIO(data),
            original_filename=original_filename,
            case_id=case_id,
            allow_duplicates=allow_duplicates,
        )


# Global ingestion pipeline instance
ingestion_pipeline = IngestionPipeline()

