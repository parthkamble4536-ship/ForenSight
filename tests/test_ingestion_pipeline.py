"""
Unit tests for the complete evidence ingestion pipeline.
"""

from pathlib import Path
import pytest

from forensight.core.exceptions import DuplicateEvidenceError
from forensight.ingestion.pipeline import IngestionPipeline
from forensight.storage.manager import EvidenceStorageManager


class TestIngestionPipeline:
    """Tests for pipeline ingestion, duplicate detection, and manifest creation."""

    def test_ingestion_pipeline_end_to_end(
        self,
        storage_manager: EvidenceStorageManager,
        benign_sample_bytes: bytes,
    ) -> None:
        """Verify successful ingestion returns valid EvidenceRecord, EvidenceMetadata, and Manifest."""
        pipeline = IngestionPipeline(vault_manager=storage_manager)
        result = pipeline.ingest_bytes(
            data=benign_sample_bytes,
            original_filename="sample_log.txt",
            case_id="case-101",
        )

        # Check evidence record
        assert result.evidence.evidence_id is not None
        assert result.evidence.case_id == "case-101"
        assert result.evidence.original_filename == "sample_log.txt"
        assert result.evidence.is_read_only is True

        # Check metadata
        assert result.metadata.identified_type == "TXT"
        assert result.metadata.is_extension_mismatch is False

        # Check manifest
        assert result.manifest.manifest_id is not None
        assert result.manifest.evidence_id == result.evidence.evidence_id
        assert result.manifest.hashes.sha256 == result.evidence.hashes.sha256
        assert result.manifest.original_filename == "sample_log.txt"

        assert result.is_duplicate is False

    def test_duplicate_evidence_rejection(
        self,
        storage_manager: EvidenceStorageManager,
        benign_sample_bytes: bytes,
    ) -> None:
        """Verify ingesting the exact same artifact twice raises DuplicateEvidenceError."""
        pipeline = IngestionPipeline(vault_manager=storage_manager)

        # First ingestion succeeds
        first_result = pipeline.ingest_bytes(benign_sample_bytes, "first.txt")
        assert first_result.is_duplicate is False

        # Second ingestion with identical bytes raises DuplicateEvidenceError by default
        with pytest.raises(DuplicateEvidenceError) as exc_info:
            pipeline.ingest_bytes(benign_sample_bytes, "second.txt")

        assert exc_info.value.sha256 == first_result.evidence.hashes.sha256
        assert exc_info.value.existing_evidence_id == first_result.evidence.evidence_id

