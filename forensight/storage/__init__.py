"""
Evidence ingestion, secure storage vault, and cryptographic hashing subsystem.
"""

from forensight.storage.hasher import (
    StreamHasher,
    compute_hashes_from_stream,
    compute_hashes_from_file,
    compute_hashes_from_bytes,
)
from forensight.storage.manager import EvidenceStorageManager, evidence_vault

__all__ = [
    "StreamHasher",
    "compute_hashes_from_stream",
    "compute_hashes_from_file",
    "compute_hashes_from_bytes",
    "EvidenceStorageManager",
    "evidence_vault",
]

