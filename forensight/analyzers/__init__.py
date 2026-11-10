"""
Static forensic analysis modules for ForenSight.
"""

from typing import Dict, Optional

from forensight.analyzers.archive_analyzer import ArchiveAnalyzer
from forensight.analyzers.base import AnalyzerOutput, BaseAnalyzer
from forensight.analyzers.docx_analyzer import DocxAnalyzer
from forensight.analyzers.email_analyzer import EmailAnalyzer
from forensight.analyzers.image_analyzer import ImageAnalyzer
from forensight.analyzers.pdf_analyzer import PDFAnalyzer
from forensight.analyzers.pe_analyzer import PEAnalyzer
from forensight.analyzers.text_analyzer import TextAnalyzer

# Analyzer registry mapping file category to analyzer instance
_ANALYZERS: Dict[str, BaseAnalyzer] = {
    "PE": PEAnalyzer(),
    "PDF": PDFAnalyzer(),
    "DOCX": DocxAnalyzer(),
    "DOCM": DocxAnalyzer(),
    "EML": EmailAnalyzer(),
    "MSG": EmailAnalyzer(),
    "ZIP": ArchiveAnalyzer(),
    "IMAGE_JPEG": ImageAnalyzer(),
    "IMAGE_PNG": ImageAnalyzer(),
    "IMAGE_GIF": ImageAnalyzer(),
    "IMAGE": ImageAnalyzer(),
    "TXT": TextAnalyzer(),
    "LOG": TextAnalyzer(),
    "TEXT": TextAnalyzer(),
    "UNKNOWN": TextAnalyzer(),
}


def get_analyzer_for_type(file_type: str) -> Optional[BaseAnalyzer]:
    """Retrieve the designated static forensic analyzer for a given file category."""
    return _ANALYZERS.get(file_type.upper(), _ANALYZERS.get("UNKNOWN"))


def register_analyzer(analyzer: BaseAnalyzer) -> None:
    """Register a new analyzer instance."""
    for supported in analyzer.supported_types:
        _ANALYZERS[supported.upper()] = analyzer


__all__ = [
    "BaseAnalyzer",
    "AnalyzerOutput",
    "PEAnalyzer",
    "PDFAnalyzer",
    "DocxAnalyzer",
    "EmailAnalyzer",
    "ArchiveAnalyzer",
    "ImageAnalyzer",
    "TextAnalyzer",
    "get_analyzer_for_type",
    "register_analyzer",
]
