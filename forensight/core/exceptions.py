"""
Comprehensive custom exception hierarchy for the ForenSight digital forensics framework.
"""

from typing import List, Optional


class ForenSightError(Exception):
    """Base exception for all ForenSight application errors."""

    def __init__(self, message: str, details: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class EvidenceStorageError(ForenSightError):
    """Raised when an error occurs during evidence ingestion or storage operations."""
    pass


class PathTraversalError(EvidenceStorageError):
    """Raised when an unsafe path or path traversal attempt is detected."""
    pass


class FileSizeExceededError(EvidenceStorageError):
    """Raised when an uploaded evidence file exceeds the configured maximum size limit."""

    def __init__(self, size_bytes: int, max_allowed_bytes: int) -> None:
        message = (
            f"Evidence file size ({size_bytes:,} bytes) exceeds "
            f"maximum permitted limit ({max_allowed_bytes:,} bytes)."
        )
        super().__init__(message)
        self.size_bytes = size_bytes
        self.max_allowed_bytes = max_allowed_bytes


class DuplicateEvidenceError(EvidenceStorageError):
    """Raised when duplicate evidence is detected within an investigation case."""

    def __init__(self, sha256: str, existing_evidence_id: str) -> None:
        message = (
            f"Duplicate evidence detected. Artifact with SHA-256 [{sha256}] "
            f"is already cataloged under Evidence ID [{existing_evidence_id}]."
        )
        super().__init__(message)
        self.sha256 = sha256
        self.existing_evidence_id = existing_evidence_id


class EvidenceNotFoundError(EvidenceStorageError):
    """Raised when requested evidence cannot be located in the secure storage vault."""
    pass


class IntegrityCompromisedError(EvidenceStorageError):
    """Raised when stored evidence fails cryptographic integrity verification."""

    def __init__(
        self,
        evidence_id: str,
        discrepancies: List[str],
        details: Optional[str] = None,
    ) -> None:
        formatted_disc = "; ".join(discrepancies)
        message = (
            f"Cryptographic integrity check FAILED for evidence [{evidence_id}]. "
            f"Discrepancies: [{formatted_disc}]."
        )
        super().__init__(message, details)
        self.evidence_id = evidence_id
        self.discrepancies = discrepancies


class ArchiveSafetyError(ForenSightError):
    """Base exception for archive inspection safety boundary violations."""
    pass


class ArchiveExplosionError(ArchiveSafetyError):
    """Raised when an archive exceeds decompression limits (zip-bomb or ratio threshold)."""

    def __init__(self, reason: str, details: Optional[str] = None) -> None:
        super().__init__(f"Archive decompression safety limit exceeded: {reason}", details)


class CorruptArchiveError(ArchiveSafetyError):
    """Raised when an archive contains malformed headers or corrupt streams."""
    pass


class IdentificationError(ForenSightError):
    """Raised when file type or signature identification encounters an unrecoverable failure."""
    pass


class AnalysisError(ForenSightError):
    """Raised when a static analysis module encounters an unrecoverable parsing failure."""
    pass


class MalformedFileError(AnalysisError):
    """Raised when a file has severely corrupt or intentionally malformed structures."""
    pass


class CryptographicSignatureError(ForenSightError):
    """Raised when Ed25519 digital signature creation or verification fails."""
    pass


class SecurityViolationError(ForenSightError):
    """Raised when an operation violates digital forensics security boundaries."""
    pass
