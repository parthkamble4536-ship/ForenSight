"""
Security utilities and boundary enforcement for digital forensics operations.
"""

import os
import re
import stat
from pathlib import Path
from typing import Optional

from forensight.core.exceptions import PathTraversalError, SecurityViolationError


def sanitize_filename(filename: Optional[str]) -> str:
    """
    Sanitize an untrusted user-supplied or archive-embedded filename.

    Strips directory separators, traversal tokens, null bytes, and non-printable
    characters. Returns a safe basename string. If empty or invalid, returns a
    safe fallback name.
    """
    if not filename:
        return "unnamed_evidence.bin"

    # Remove null bytes and non-printable control characters
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", filename)

    # Extract strictly the basename to prevent directory climbing
    cleaned = Path(cleaned).name

    # Remove any remaining dangerous tokens or path traversal remnants
    cleaned = cleaned.replace("..", "").replace("/", "").replace("\\", "").strip()

    # Strip leading/trailing dots and whitespace
    cleaned = cleaned.strip(". ")

    if not cleaned:
        return "unnamed_evidence.bin"

    # Truncate extremely long filenames to 255 chars
    return cleaned[:255]


def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """
    Verify that target_path resolves strictly within base_dir.

    Prevents directory traversal attacks (e.g., ../../etc/passwd or C:\\Windows).
    """
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_target.is_relative_to(resolved_base)
    except (ValueError, RuntimeError):
        return False


def assert_safe_file_access(base_dir: Path, file_path: Path) -> Path:
    """
    Assert that file_path is strictly contained within base_dir.

    Returns the resolved Path if safe; raises PathTraversalError otherwise.
    """
    resolved_base = base_dir.resolve()
    resolved_target = file_path.resolve()

    if not resolved_target.is_relative_to(resolved_base):
        raise PathTraversalError(
            message=f"Access denied: Path [{file_path}] escapes evidence vault [{base_dir}]."
        )
    return resolved_target


def validate_archive_member_path(member_name: str, extraction_root: Path) -> Path:
    """
    Safely compute and validate the target path for an archive entry.

    Guarantees that an archive member cannot escape the designated extraction_root
    (Zip Slip defense). Raises PathTraversalError if traversal is attempted.
    """
    # Reject explicit absolute paths and drive letters
    if member_name.startswith(("/", "\\")) or (len(member_name) > 1 and member_name[1] == ":"):
        raise PathTraversalError(
            message=f"Archive entry [{member_name}] specifies an absolute path, which is prohibited."
        )

    # Normalize path segments
    resolved_root = extraction_root.resolve()
    target_path = (resolved_root / member_name).resolve()

    if not target_path.is_relative_to(resolved_root):
        raise PathTraversalError(
            message=f"Archive entry [{member_name}] escapes extraction root via path traversal."
        )

    return target_path


def make_read_only(file_path: Path) -> None:
    """
    Set file permissions to read-only on the filesystem.

    Works cross-platform across Windows (S_IREAD) and Kali/Linux (0o444).
    """
    if not file_path.is_file():
        return

    try:
        os.chmod(file_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


def make_writable(file_path: Path) -> None:
    """
    Restore write permissions to a file (useful during test teardown).
    """
    if not file_path.is_file():
        return

    try:
        os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def defang_ioc(value: str) -> str:
    """
    Defang an indicator of compromise (URL, domain, IP) for safe presentation.

    Examples:
        http://evil.com/mal -> hxxp://evil[.]com/mal
        https://bad.org -> hxxps://bad[.]org
        192.168.1.10 -> 192[.]168[.]1[.]10
    """
    if not value:
        return ""

    # Defang scheme
    defanged = re.sub(r"^http://", "hxxp://", value, flags=re.IGNORECASE)
    defanged = re.sub(r"^https://", "hxxps://", defanged, flags=re.IGNORECASE)
    defanged = re.sub(r"^ftp://", "fxp://", defanged, flags=re.IGNORECASE)

    # Defang periods in domain/IP context (avoiding double defanging)
    if "[.]" not in defanged:
        # If it looks like an IP or URL or domain with dots
        defanged = defanged.replace(".", "[.]")

    return defanged
