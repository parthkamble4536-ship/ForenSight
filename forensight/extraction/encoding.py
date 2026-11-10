"""
Character encoding detection and normalization for text and log artifacts.
"""

from pathlib import Path
from typing import Tuple


def detect_encoding(sample_bytes: bytes) -> Tuple[str, float]:
    """
    Detect character encoding with confidence score based on BOM and byte patterns.
    Returns (encoding_name, confidence).
    """
    if not sample_bytes:
        return ("utf-8", 1.0)

    # Check Byte Order Marks (BOM)
    if sample_bytes.startswith(b"\xef\xbb\xbf"):
        return ("utf-8-sig", 1.0)
    if sample_bytes.startswith(b"\xff\xfe"):
        return ("utf-16le", 1.0)
    if sample_bytes.startswith(b"\xfe\xff"):
        return ("utf-16be", 1.0)

    # Try standard UTF-8
    try:
        sample_bytes.decode("utf-8")
        return ("utf-8", 0.95)
    except UnicodeDecodeError:
        pass

    # Try UTF-16LE heuristic (alternating nulls)
    if len(sample_bytes) >= 4 and sample_bytes[1] == 0 and sample_bytes[3] == 0:
        try:
            sample_bytes.decode("utf-16le")
            return ("utf-16le", 0.85)
        except UnicodeDecodeError:
            pass

    # Fallback to Latin-1 (always succeeds for 8-bit bytes)
    return ("latin-1", 0.70)

