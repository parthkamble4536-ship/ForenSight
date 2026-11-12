"""
Safe archive inspection and decompression explosion defense engine.

Enforces strict recursion depth, expanded size ceilings, compression ratio limits,
and path traversal checks before any archive content can be inspected.
"""

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, List, Optional, Union

from forensight.core.config import settings
from forensight.core.exceptions import (
    ArchiveExplosionError,
    CorruptArchiveError,
    PathTraversalError,
)
from forensight.core.security import validate_archive_member_path


@dataclass
class ArchiveEntryInfo:
    """Metadata regarding a single entry inside an inspected archive."""

    filename: str
    compressed_size: int
    uncompressed_size: int
    is_directory: bool
    is_encrypted: bool
    is_nested_archive: bool
    is_executable: bool
    is_path_traversal: bool


@dataclass
class ArchiveSafetyReport:
    """Comprehensive safety and structural report for an archive artifact."""

    is_safe: bool
    total_entries: int
    total_compressed_size: int
    total_uncompressed_size: int
    overall_compression_ratio: float
    encrypted_entries_count: int
    executable_entries_count: int
    nested_archives_count: int
    traversal_attempts_count: int
    entries: List[ArchiveEntryInfo] = field(default_factory=list)
    rejection_reason: Optional[str] = None


class ArchiveSafetyInspector:
    """
    Inspects archive structure and validates safety limits without extracting files to disk.

    Guards against:
    - Zip-bombs (excessive uncompressed size or extreme compression ratio)
    - Resource exhaustion (entry count flood)
    - Directory climbing & Zip Slip attacks
    - Hidden nested payloads
    """

    EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh"}
    ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".iso"}

    def __init__(
        self,
        max_entries: int = settings.archive_max_entries,
        max_expanded_size_bytes: int = settings.archive_max_expanded_size_bytes,
        max_compression_ratio: float = settings.archive_max_compression_ratio,
        max_recursion_depth: int = settings.archive_max_recursion_depth,
    ) -> None:
        self.max_entries = max_entries
        self.max_expanded_size_bytes = max_expanded_size_bytes
        self.max_compression_ratio = max_compression_ratio
        self.max_recursion_depth = max_recursion_depth

    def inspect_zip(self, archive_path: Union[Path, BinaryIO]) -> ArchiveSafetyReport:
        """
        Inspect a ZIP archive (Path or in-memory file-like object) safely without extracting files to disk.
        """
        if isinstance(archive_path, Path) and not zipfile.is_zipfile(archive_path):
            raise CorruptArchiveError(f"Target file [{archive_path.name}] is not a valid ZIP archive.")

        total_entries = 0
        total_compressed = 0
        total_uncompressed = 0
        encrypted_count = 0
        executable_count = 0
        nested_count = 0
        traversal_count = 0
        entry_list: List[ArchiveEntryInfo] = []

        dummy_root = Path("/safe_virtual_root")

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                infolist = zf.infolist()
                total_entries = len(infolist)

                if total_entries > self.max_entries:
                    raise ArchiveExplosionError(
                        f"Archive contains {total_entries:,} entries, exceeding limit of {self.max_entries:,}."
                    )

                for info in infolist:
                    filename = info.filename
                    compressed = info.compress_size
                    uncompressed = info.file_size
                    is_dir = info.is_dir()
                    is_enc = (info.flag_bits & 0x1) != 0

                    total_compressed += compressed
                    total_uncompressed += uncompressed

                    if is_enc:
                        encrypted_count += 1

                    # Check for path traversal attempt in member name
                    is_traversal = False
                    try:
                        validate_archive_member_path(filename, dummy_root)
                    except PathTraversalError:
                        is_traversal = True
                        traversal_count += 1

                    # Check for executable or script payloads
                    ext = Path(filename).suffix.lower()
                    is_exec = ext in self.EXECUTABLE_EXTENSIONS
                    if is_exec:
                        executable_count += 1

                    # Check for nested archive
                    is_nested = ext in self.ARCHIVE_EXTENSIONS
                    if is_nested:
                        nested_count += 1

                    entry_list.append(
                        ArchiveEntryInfo(
                            filename=filename,
                            compressed_size=compressed,
                            uncompressed_size=uncompressed,
                            is_directory=is_dir,
                            is_encrypted=is_enc,
                            is_nested_archive=is_nested,
                            is_executable=is_exec,
                            is_path_traversal=is_traversal,
                        )
                    )

            # Check total expanded size
            if total_uncompressed > self.max_expanded_size_bytes:
                raise ArchiveExplosionError(
                    f"Total uncompressed size ({total_uncompressed:,} bytes) exceeds limit ({self.max_expanded_size_bytes:,} bytes)."
                )

            # Check compression ratio
            ratio = (total_uncompressed / max(1, total_compressed)) if total_compressed > 0 else 1.0
            if ratio > self.max_compression_ratio and total_uncompressed > 1024 * 1024:
                raise ArchiveExplosionError(
                    f"Suspicious compression ratio ({ratio:.1f}:1) exceeds limit ({self.max_compression_ratio:.1f}:1) - potential zip-bomb."
                )

            is_safe = (traversal_count == 0)
            rejection = "Path traversal attempts detected in archive members" if not is_safe else None

            return ArchiveSafetyReport(
                is_safe=is_safe,
                total_entries=total_entries,
                total_compressed_size=total_compressed,
                total_uncompressed_size=total_uncompressed,
                overall_compression_ratio=round(ratio, 2),
                encrypted_entries_count=encrypted_count,
                executable_entries_count=executable_count,
                nested_archives_count=nested_count,
                traversal_attempts_count=traversal_count,
                entries=entry_list,
                rejection_reason=rejection,
            )

        except zipfile.BadZipFile as err:
            raise CorruptArchiveError(f"Corrupt or malformed ZIP archive: {err}")

