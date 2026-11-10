"""
Archive forensic static analyzer (ZIP container structural triage).

Performs structural inspection, double-extension detection, nested payload hunting,
and timeline reconstruction without extracting untrusted files to the host system.
"""

import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from forensight.analyzers.base import AnalyzerOutput, BaseAnalyzer
from forensight.core.types import (
    ConfidenceLevel,
    EvidenceMetadata,
    Finding,
    FindingSeverity,
    TimelineEvent,
    TimelineEventType,
)
from forensight.ingestion.archive_safety import ArchiveSafetyInspector


class ArchiveAnalyzer(BaseAnalyzer):
    """
    Static forensic analyzer for ZIP archives.
    """

    EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl"}
    NESTED_ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".7z", ".rar", ".iso", ".img", ".vhd"}

    @property
    def name(self) -> str:
        return "Archive Forensic Analyzer"

    @property
    def supported_types(self) -> List[str]:
        return ["ZIP"]

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        timeline: List[TimelineEvent] = []
        details: Dict[str, Any] = {}

        inspector = ArchiveSafetyInspector()
        try:
            report = inspector.inspect_zip(file_path)
            details["safety_report"] = {
                "total_entries": report.total_entries,
                "total_compressed": report.total_compressed_size,
                "total_uncompressed": report.total_uncompressed_size,
                "compression_ratio": report.overall_compression_ratio,
                "encrypted_count": report.encrypted_entries_count,
            }

            if not report.is_safe:
                findings.append(
                    Finding(
                        rule_id="ARCH-UNSAFE-001",
                        category="SECURITY_VIOLATION",
                        title="Archive Contains Path Traversal Attempts",
                        description=report.rejection_reason or "Archive member entries attempt to escape extraction directory.",
                        severity=FindingSeverity.CRITICAL,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=50,
                        evidence_source=self.name,
                        mitre_technique="T1027",
                        explanation="Zip Slip vulnerability exploitation allows an attacker to overwrite arbitrary files on an extracting system.",
                    )
                )

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="ARCH-CORRUPT-001",
                    category="ANOMALY",
                    title="Corrupted or Non-Standard Archive",
                    description=f"Archive structure failed safety audit: {err}",
                    severity=FindingSeverity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=30,
                    evidence_source=self.name,
                )
            )
            output.findings = findings
            return output

        # Deep entry inspection
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                executable_entries: List[str] = []
                double_ext_entries: List[str] = []
                encrypted_entries: List[str] = []
                nested_archives: List[str] = []

                for info in zf.infolist():
                    name = info.filename
                    ext = Path(name).suffix.lower()

                    # Extract entry modification time
                    if info.date_time and info.date_time[0] > 1980:
                        try:
                            entry_dt = datetime(*info.date_time, tzinfo=timezone.utc)
                            timeline.append(
                                TimelineEvent(
                                    event_id=f"zip-entry-{info.CRC}",
                                    evidence_id="",
                                    timestamp=entry_dt,
                                    timestamp_type=TimelineEventType.ARCHIVE_ENTRY,
                                    source=f"ZIP Entry Header ({name})",
                                    description=f"Archive entry '{name}' modified: {entry_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                    confidence=ConfidenceLevel.HIGH,
                                )
                            )
                        except Exception:
                            pass

                    # Check for executables
                    if ext in self.EXECUTABLE_EXTS:
                        executable_entries.append(name)

                    # Check for double extension tricks (e.g. invoice.pdf.exe)
                    stem_ext = Path(Path(name).stem).suffix.lower()
                    if stem_ext in (".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png") and ext in self.EXECUTABLE_EXTS:
                        double_ext_entries.append(name)

                    # Check for encryption
                    if (info.flag_bits & 0x1) != 0:
                        encrypted_entries.append(name)

                    # Check for nested archives
                    if ext in self.NESTED_ARCHIVE_EXTS:
                        nested_archives.append(name)

                # Findings generation
                if double_ext_entries:
                    findings.append(
                        Finding(
                            rule_id="ARCH-DECEPTION-001",
                            category="DECEPTION",
                            title=f"Double Extension Executable Detected ({len(double_ext_entries)} items)",
                            description=f"Archive contains executable disguising itself with a document extension: {', '.join(double_ext_entries)}",
                            severity=FindingSeverity.CRITICAL,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=45,
                            evidence_source=self.name,
                            mitre_technique="T1036.007",
                            explanation="Adversaries employ double extensions to trick users into executing binaries mistaken for benign documents or images.",
                        )
                    )

                if executable_entries and not double_ext_entries:
                    findings.append(
                        Finding(
                            rule_id="ARCH-EXEC-001",
                            category="SUSPICIOUS_PAYLOAD",
                            title=f"Executable Binaries Inside Archive ({len(executable_entries)} items)",
                            description=f"Archive bundles direct executable payloads: {', '.join(executable_entries[:3])}",
                            severity=FindingSeverity.MEDIUM,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=20,
                            evidence_source=self.name,
                            mitre_technique="T1027",
                            explanation="Email gateways frequently inspect archives for embedded binaries used in dropper attacks.",
                        )
                    )

                if encrypted_entries:
                    findings.append(
                        Finding(
                            rule_id="ARCH-ENCRYPT-001",
                            category="EVASION",
                            title=f"Encrypted Archive Entries Detected ({len(encrypted_entries)} items)",
                            description=f"Archive contains password-protected entries preventing inspection: {', '.join(encrypted_entries[:3])}",
                            severity=FindingSeverity.MEDIUM,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=20,
                            evidence_source=self.name,
                            mitre_technique="T1027.013",
                            explanation="Password protection prevents automated scanning by security gateways and static analysis sandboxes.",
                        )
                    )

                if nested_archives:
                    findings.append(
                        Finding(
                            rule_id="ARCH-NESTED-001",
                            category="EVASION",
                            title=f"Nested Archive Structure Detected ({len(nested_archives)} items)",
                            description=f"Archive bundles secondary archives within its structure: {', '.join(nested_archives[:3])}",
                            severity=FindingSeverity.LOW,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=10,
                            evidence_source=self.name,
                            explanation="Nested archives are utilized to exhaust inspection timeouts and bypass recursion limits in gateway scanners.",
                        )
                    )

                details["executable_entries"] = executable_entries
                details["double_extension_entries"] = double_ext_entries
                details["encrypted_entries"] = encrypted_entries
                details["nested_archives"] = nested_archives

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="ARCH-READ-001",
                    category="ANOMALY",
                    title="Error Reading Archive Entries",
                    description=f"Could not iterate archive entries: {err}",
                    severity=FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    score_impact=15,
                    evidence_source=self.name,
                )
            )

        output.findings = findings
        output.timeline_events = timeline
        output.details = details
        return output

