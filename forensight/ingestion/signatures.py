"""
Binary magic signatures, byte patterns, and extension mapping database for ForenSight.
"""

from typing import Dict, List, NamedTuple, Optional, Tuple


class MagicSignature(NamedTuple):
    """File format magic byte signature pattern."""

    category: str
    mime_type: str
    magic_bytes: bytes
    offset: int = 0
    description: str = ""
    valid_extensions: Tuple[str, ...] = ()


# Common binary format signatures for static forensic triage
SIGNATURE_CATALOG: List[MagicSignature] = [
    # Windows Executable / Dynamic Link Library
    MagicSignature(
        category="PE",
        mime_type="application/vnd.microsoft.portable-executable",
        magic_bytes=b"MZ",
        offset=0,
        description="DOS/PE Executable or Dynamic Link Library (MZ header)",
        valid_extensions=(".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"),
    ),
    # PDF Documents
    MagicSignature(
        category="PDF",
        mime_type="application/pdf",
        magic_bytes=b"%PDF-",
        offset=0,
        description="Portable Document Format",
        valid_extensions=(".pdf",),
    ),
    # Zip Container (Standard ZIP, DOCX, DOCM, JAR)
    MagicSignature(
        category="ZIP",
        mime_type="application/zip",
        magic_bytes=b"PK\x03\x04",
        offset=0,
        description="ZIP Archive or OpenXML Package",
        valid_extensions=(".zip", ".docx", ".docm", ".xlsx", ".pptx", ".jar"),
    ),
    MagicSignature(
        category="ZIP",
        mime_type="application/zip",
        magic_bytes=b"PK\x05\x06",
        offset=0,
        description="Empty ZIP Archive",
        valid_extensions=(".zip",),
    ),
    # Microsoft Compound File Binary (OLE2) - Legacy Office (.doc, .xls) and Outlook (.msg)
    MagicSignature(
        category="OLE2",
        mime_type="application/x-ole-storage",
        magic_bytes=b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        offset=0,
        description="Microsoft Compound File Binary (OLE2 / MSG / Legacy Office)",
        valid_extensions=(".msg", ".doc", ".xls", ".ppt"),
    ),
    # Common Images
    MagicSignature(
        category="IMAGE_JPEG",
        mime_type="image/jpeg",
        magic_bytes=b"\xff\xd8\xff",
        offset=0,
        description="JPEG Image",
        valid_extensions=(".jpg", ".jpeg"),
    ),
    MagicSignature(
        category="IMAGE_PNG",
        mime_type="image/png",
        magic_bytes=b"\x89PNG\r\n\x1a\n",
        offset=0,
        description="Portable Network Graphics (PNG)",
        valid_extensions=(".png",),
    ),
    MagicSignature(
        category="IMAGE_GIF",
        mime_type="image/gif",
        magic_bytes=b"GIF87a",
        offset=0,
        description="GIF Image (87a)",
        valid_extensions=(".gif",),
    ),
    MagicSignature(
        category="IMAGE_GIF",
        mime_type="image/gif",
        magic_bytes=b"GIF89a",
        offset=0,
        description="GIF Image (89a)",
        valid_extensions=(".gif",),
    ),
    # UTF Byte Order Marks
    MagicSignature(
        category="TEXT",
        mime_type="text/plain; charset=utf-8",
        magic_bytes=b"\xef\xbb\xbf",
        offset=0,
        description="UTF-8 Text with Byte Order Mark",
        valid_extensions=(".txt", ".log", ".csv", ".json", ".xml"),
    ),
    MagicSignature(
        category="TEXT",
        mime_type="text/plain; charset=utf-16le",
        magic_bytes=b"\xff\xfe",
        offset=0,
        description="UTF-16 Little-Endian Text",
        valid_extensions=(".txt", ".log", ".csv"),
    ),
    MagicSignature(
        category="TEXT",
        mime_type="text/plain; charset=utf-16be",
        magic_bytes=b"\xfe\xff",
        offset=0,
        description="UTF-16 Big-Endian Text",
        valid_extensions=(".txt", ".log", ".csv"),
    ),
]

