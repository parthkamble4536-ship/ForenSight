"""
Abstract base analyzer interface for all ForenSight static analysis modules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from forensight.core.types import (
    ConfidenceLevel,
    EvidenceMetadata,
    Finding,
    FindingSeverity,
    IOCRecord,
    TimelineEvent,
)


@dataclass
class AnalyzerOutput:
    """Unified container for outputs produced by individual static analyzers."""

    findings: List[Finding] = field(default_factory=list)
    iocs: List[IOCRecord] = field(default_factory=list)
    timeline_events: List[TimelineEvent] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


class BaseAnalyzer(ABC):
    """
    Abstract interface for forensic file analyzers.

    Principles:
    - Never execute uploaded files, macros, scripts, or embedded streams.
    - Produce explainable findings with transparent technical justifications.
    - Extract observable indicators without communicating across the network.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Analyzer module name."""
        pass

    @property
    @abstractmethod
    def supported_types(self) -> List[str]:
        """List of file categories handled by this analyzer."""
        pass

    @abstractmethod
    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        """
        Perform static inspection on the designated file.

        Args:
            file_path: Path to the stored evidence file.
            metadata: Basic identification metadata.

        Returns:
            AnalyzerOutput with findings, IOCs, timeline events, and structural details.
        """
        pass

