"""
Abstract base analyzer interface for all ForenSight static analysis modules.
"""

import uuid
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
    def version(self) -> str:
        """Semantic version of this static analyzer module."""
        return "2.0.0"

    @property
    @abstractmethod
    def supported_types(self) -> List[str]:
        """List of file categories handled by this analyzer."""
        pass

    def finalize_findings(
        self,
        findings: List[Finding],
        evidence_reference: Optional[str] = None,
    ) -> List[Finding]:
        """Ensure every Finding carries full detection provenance metadata."""
        stamped: List[Finding] = []
        for finding in findings:
            updates: Dict[str, Any] = {}
            if not finding.finding_id:
                updates["finding_id"] = str(uuid.uuid4())
            if not finding.analyzer_name:
                updates["analyzer_name"] = self.name
            if not finding.evidence_source:
                updates["evidence_source"] = self.name
            if not finding.analyzer_version:
                updates["analyzer_version"] = self.version
            if evidence_reference and not finding.evidence_reference:
                updates["evidence_reference"] = evidence_reference
            stamped.append(finding.model_copy(update=updates) if updates else finding)
        return stamped

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

