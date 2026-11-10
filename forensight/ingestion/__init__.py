"""
Evidence ingestion, file identification, and archive safety subsystem.
"""

from forensight.ingestion.archive_safety import (
    ArchiveEntryInfo,
    ArchiveSafetyInspector,
    ArchiveSafetyReport,
)
from forensight.ingestion.identifier import (
    calculate_entropy,
    calculate_file_entropy,
    identify_file,
    inspect_openxml_container,
)
from forensight.ingestion.pipeline import IngestionPipeline, IngestionResult, ingestion_pipeline
from forensight.ingestion.signatures import SIGNATURE_CATALOG, MagicSignature

__all__ = [
    "MagicSignature",
    "SIGNATURE_CATALOG",
    "identify_file",
    "calculate_entropy",
    "calculate_file_entropy",
    "inspect_openxml_container",
    "ArchiveEntryInfo",
    "ArchiveSafetyReport",
    "ArchiveSafetyInspector",
    "IngestionResult",
    "IngestionPipeline",
    "ingestion_pipeline",
]

