"""
Pytest configuration, shared fixtures, and synthetic test data generators for ForenSight.
"""

import shutil
import tempfile
from pathlib import Path
from typing import Generator

import pytest

from forensight.core.security import make_writable
from forensight.storage.manager import EvidenceStorageManager


@pytest.fixture
def temp_vault_dir() -> Generator[Path, None, None]:
    """
    Provide an isolated temporary directory for evidence storage during tests.
    Ensures all files are made writable before recursive cleanup.
    """
    temp_dir = Path(tempfile.mkdtemp(prefix="forensight_test_vault_"))
    try:
        yield temp_dir
    finally:
        # Restore write permissions to all files before rmtree to prevent Windows permission errors
        if temp_dir.exists():
            for item in temp_dir.rglob("*"):
                if item.is_file():
                    make_writable(item)
            shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def storage_manager(temp_vault_dir: Path) -> EvidenceStorageManager:
    """
    Provide an EvidenceStorageManager instance bound to the temporary vault directory,
    configured with a 1 MB size limit for fast test execution.
    """
    return EvidenceStorageManager(
        vault_dir=temp_vault_dir,
        max_upload_size_bytes=1024 * 1024,  # 1 MB test limit
        chunk_size_bytes=16 * 1024,  # 16 KB chunk
    )


@pytest.fixture
def benign_sample_bytes() -> bytes:
    """Provide a deterministic synthetic benign byte string."""
    return b"ForenSight Digital Forensics Test Artifact - Synthetic Evidence Sample\n"

