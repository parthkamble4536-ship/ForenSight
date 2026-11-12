"""
Advanced evidence ingestion pipeline.

Coordinates secure streaming ingestion, concurrent multi-hashing, duplicate detection,
magic byte identification, metadata extraction, and cryptographic manifest creation.
"""

import io
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional, Tuple
from sqlalchemy.orm import Session

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
from forensight.database.crud import get_evidence_by_hash
from forensight.database.models import EvidenceModel
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
        self._lock = threading.RLock()
        # Fallback in-memory hash index when ingesting without a DB session
        self._sha256_registry: Dict[str, str] = {}
        # Tracks uncommitted in-flight hashes per database engine to prevent concurrent duplicates
        self._inflight_hashes: Dict[Tuple[int, str], str] = {}

    @staticmethod
    def _db_scope_key(db: Session, sha256: str) -> Tuple[int, str]:
        bind = getattr(db, "bind", None)
        url_key = hash(str(bind.url)) if getattr(bind, "url", None) is not None else id(db)
        return (url_key, sha256.lower())

    def register_known_hash(self, sha256: str, evidence_id: str) -> None:
        """Register a known SHA-256 to enable duplicate tracking across sessions."""
        with self._lock:
            self._sha256_registry[sha256.lower()] = evidence_id

    def rehydrate_from_db(self, db: Session) -> int:
        """Populate in-memory SHA-256 index from persisted SQLite evidence rows."""
        rows = db.query(EvidenceModel.sha256, EvidenceModel.evidence_id).all()
        with self._lock:
            for sha256, ev_id in rows:
                if sha256:
                    self._sha256_registry[sha256.lower()] = ev_id
        return len(rows)

    def release_inflight_hash(self, db: Optional[Session], sha256: str) -> None:
        """Release an uncommitted in-flight SHA-256 reservation once DB persistence completes or aborts."""
        if db is None:
            return
        key = self._db_scope_key(db, sha256)
        with self._lock:
            self._inflight_hashes.pop(key, None)

    def ingest_stream(
        self,
        stream: BinaryIO,
        original_filename: str,
        case_id: Optional[str] = None,
        allow_duplicates: bool = False,
        db: Optional[Session] = None,
    ) -> IngestionResult:
        """
        Ingest an untrusted binary stream.

        Steps:
        1. Streams to disk vault while computing hashes and checking size bounds.
        2. Detects duplicate evidence by SHA-256 (authoritatively in SQLite when db is provided).
        3. Identifies true file type using magic bytes.
        4. Detects extension mismatch.
        5. Issues an immutable Evidence Manifest.
        """
        # Store securely in vault
        record = self.vault.store_stream(stream=stream, original_filename=original_filename)
        record.case_id = case_id
        stored_path = Path(record.storage_path)

        sha256 = record.hashes.sha256.lower()

        # Thread-safe authoritative duplicate check
        is_duplicate = False
        existing_id: Optional[str] = None

        with self._lock:
            if db is not None:
                existing_model = get_evidence_by_hash(db, sha256)
                scope_key = self._db_scope_key(db, sha256)
                if existing_model is not None:
                    existing_id = existing_model.evidence_id
                elif scope_key in self._inflight_hashes:
                    existing_id = self._inflight_hashes[scope_key]

                if existing_id is not None:
                    is_duplicate = True
                    if not allow_duplicates:
                        self.vault.delete_evidence(record.evidence_id)
                        raise DuplicateEvidenceError(sha256=sha256, existing_evidence_id=existing_id)
                else:
                    self._inflight_hashes[scope_key] = record.evidence_id
                    self._sha256_registry[sha256] = record.evidence_id
            else:
                existing_id = self._sha256_registry.get(sha256)
                if existing_id is not None:
                    is_duplicate = True
                    if not allow_duplicates:
                        self.vault.delete_evidence(record.evidence_id)
                        raise DuplicateEvidenceError(sha256=sha256, existing_evidence_id=existing_id)
                else:
                    self._sha256_registry[sha256] = record.evidence_id

        try:
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
        except Exception:
            if db is not None:
                self.release_inflight_hash(db, sha256)
            self.vault.delete_evidence(record.evidence_id)
            raise

    def ingest_bytes(
        self,
        data: bytes,
        original_filename: str,
        case_id: Optional[str] = None,
        allow_duplicates: bool = False,
        db: Optional[Session] = None,
    ) -> IngestionResult:
        """Convenience method for ingesting in-memory byte buffers."""
        return self.ingest_stream(
            stream=io.BytesIO(data),
            original_filename=original_filename,
            case_id=case_id,
            allow_duplicates=allow_duplicates,
            db=db,
        )


# Global ingestion pipeline instance
ingestion_pipeline = IngestionPipeline()

