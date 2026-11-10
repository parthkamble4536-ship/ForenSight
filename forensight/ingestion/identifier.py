"""
File format identification and extension mismatch detection engine.

Uses puremagic and forensic byte signatures to inspect true file types and detect
deceptive extension masquerading without relying on native shared libraries.
"""

import math
import zipfile
from collections import Counter
from pathlib import Path
from typing import Optional, Tuple

import puremagic

from forensight.core.types import EvidenceMetadata
from forensight.ingestion.signatures import SIGNATURE_CATALOG, MagicSignature


def calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte sequence.

    Returns a float between 0.0 (uniform bytes) and 8.0 (completely random or encrypted).
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return round(entropy, 4)


def calculate_file_entropy(file_path: Path, max_sample_bytes: int = 1024 * 1024) -> float:
    """
    Calculate Shannon entropy across a sample of the file (up to 1 MB) to bound memory.
    """
    try:
        with open(file_path, "rb") as f:
            sample = f.read(max_sample_bytes)
            return calculate_entropy(sample)
    except Exception:
        return 0.0


def is_text_content(header_bytes: bytes) -> bool:
    """
    Heuristically determine if bytes represent printable ASCII or UTF-8 text.
    """
    if not header_bytes:
        return True

    # Allow common whitespace characters
    allowed_control = {9, 10, 13}  # \t, \n, \r
    printable_count = 0
    for byte in header_bytes:
        if 32 <= byte <= 126 or byte in allowed_control or byte >= 128:
            printable_count += 1
        elif byte == 0:
            # Null bytes are strong indicators of binary
            return False

    return (printable_count / len(header_bytes)) > 0.85


def inspect_openxml_container(file_path: Path) -> Tuple[str, str]:
    """
    Differentiate DOCX vs DOCM vs generic ZIP by safely inspecting zip member names.
    Does not extract or execute any contents.
    """
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            namelist = set(zf.namelist())

            has_word_doc = "word/document.xml" in namelist
            has_vba_macro = (
                "word/vbaProject.bin" in namelist
                or any(name.startswith("word/vba") for name in namelist)
            )

            if has_word_doc:
                if has_vba_macro:
                    return ("DOCM", "application/vnd.ms-word.document.macroEnabled.12")
                return ("DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")

            # Check Excel OpenXML
            if "xl/workbook.xml" in namelist:
                return ("XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

            return ("ZIP", "application/zip")
    except Exception:
        return ("ZIP", "application/zip")


def inspect_eml_header(header_bytes: bytes) -> bool:
    """
    Check if text header matches standard RFC 822 email headers.
    """
    try:
        text = header_bytes[:2048].decode("utf-8", errors="ignore").lower()
        required_indicators = ["from:", "to:", "subject:", "date:", "message-id:", "received:"]
        matches = sum(1 for ind in required_indicators if ind in text)
        return matches >= 2
    except Exception:
        return False


def identify_file(file_path: Path, original_filename: str) -> EvidenceMetadata:
    """
    Perform deep static file identification.

    Examines magic bytes, resolves true MIME types, calculates entropy,
    and checks for deceptive extension masquerading.
    """
    file_size = file_path.stat().st_size
    declared_ext = Path(original_filename).suffix.lower()

    # Read the first 4096 bytes for header inspection
    with open(file_path, "rb") as f:
        header = f.read(4096)

    entropy = calculate_file_entropy(file_path)

    identified_type = "UNKNOWN"
    mime_type = "application/octet-stream"
    match_details = "Generic binary file"

    # Step 1: Match against built-in forensic signatures
    matched_sig: Optional[MagicSignature] = None
    for sig in SIGNATURE_CATALOG:
        end_offset = sig.offset + len(sig.magic_bytes)
        if len(header) >= end_offset and header[sig.offset : end_offset] == sig.magic_bytes:
            matched_sig = sig
            break

    if matched_sig is not None:
        identified_type = matched_sig.category
        mime_type = matched_sig.mime_type
        match_details = matched_sig.description

        # Deepen ZIP containers to DOCX or DOCM
        if identified_type == "ZIP":
            specific_type, specific_mime = inspect_openxml_container(file_path)
            identified_type = specific_type
            mime_type = specific_mime
            if specific_type == "DOCM":
                match_details = "Microsoft Word Macro-Enabled Document (OpenXML with VBA)"
            elif specific_type == "DOCX":
                match_details = "Microsoft Word Document (OpenXML)"

    else:
        # Step 2: Fall back to puremagic for standard formats
        try:
            magic_matches = puremagic.magic_file(str(file_path))
            if magic_matches:
                primary = magic_matches[0]
                mime_type = primary.mime_type or "application/octet-stream"
                match_details = primary.name

                if "pdf" in mime_type.lower():
                    identified_type = "PDF"
                elif "executable" in mime_type.lower() or "dosexec" in mime_type.lower():
                    identified_type = "PE"
                elif "zip" in mime_type.lower():
                    identified_type = "ZIP"
                elif "image" in mime_type.lower():
                    identified_type = "IMAGE"
                elif "text" in mime_type.lower():
                    identified_type = "TXT"
        except Exception:
            pass

        # Step 3: Check for text or email formats if still unknown
        if identified_type == "UNKNOWN":
            if inspect_eml_header(header):
                identified_type = "EML"
                mime_type = "message/rfc822"
                match_details = "RFC 822 Email Message"
            elif is_text_content(header):
                identified_type = "TXT"
                mime_type = "text/plain"
                match_details = "Plaintext document or log"

    # Normalize TEXT -> TXT
    if identified_type == "TEXT":
        identified_type = "TXT"

    # Step 4: Extension Mismatch & Masquerade Detection
    is_mismatch = False

    # Masquerade check: Executable with deceptive non-executable extension
    if identified_type == "PE" and declared_ext not in (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"):
        is_mismatch = True
    # Masquerade check: PDF with non-pdf extension
    elif identified_type == "PDF" and declared_ext != ".pdf":
        is_mismatch = True
    # Masquerade check: Non-PDF claiming to be a PDF
    elif declared_ext == ".pdf" and identified_type != "PDF":
        is_mismatch = True
    # Masquerade check: DOCM (macros) claiming to be standard DOCX
    elif identified_type == "DOCM" and declared_ext == ".docx":
        is_mismatch = True
    # Masquerade check: Executable disguised as text or image
    elif declared_ext in (".txt", ".log", ".jpg", ".png", ".pdf") and identified_type in ("PE", "ZIP"):
        is_mismatch = True

    return EvidenceMetadata(
        file_size_bytes=file_size,
        identified_type=identified_type,
        mime_type=mime_type,
        declared_extension=declared_ext,
        is_extension_mismatch=is_mismatch,
        magic_match_details=match_details,
        entropy=entropy,
    )
