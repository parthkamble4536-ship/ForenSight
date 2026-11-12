"""
Archive forensic static analyzer (ZIP container structural triage).

Performs structural inspection, double-extension detection, nested payload hunting,
and timeline reconstruction without extracting untrusted files to the host system.
"""

import io
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from forensight.analyzers.base import AnalyzerOutput, BaseAnalyzer
from forensight.core.config import settings
from forensight.core.exceptions import ArchiveSafetyError
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
    Static forensic analyzer for ZIP archives with bounded recursive inspection.
    """

    EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl"}
    NESTED_ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".7z", ".rar", ".iso", ".img", ".vhd"}
    MAX_PROCESSING_SECONDS = 5.0
    MAX_NESTED_BYTES = 10 * 1024 * 1024  # 10 MB per nested ZIP buffer

    @property
    def name(self) -> str:
        return "Archive Forensic Analyzer"

    @property
    def version(self) -> str:
        return "2.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["ZIP"]

    def _inspect_zip_entries(
        self,
        zf: zipfile.ZipFile,
        *,
        depth: int,
        prefix: str,
        deadline: float,
        remaining_bytes: List[int],
        findings: List[Finding],
        timeline: List[TimelineEvent],
        executable_entries: List[str],
        double_ext_entries: List[str],
        encrypted_entries: List[str],
        nested_archives: List[str],
        entry_stats: List[Dict[str, Any]],
        dir_set: set[str],
    ) -> None:
        for info in zf.infolist()[: settings.archive_max_entries]:
            if time.monotonic() > deadline:
                findings.append(
                    Finding(
                        rule_id="ARCH-LIMIT-001",
                        rule_version="1.0.0",
                        category="RESOURCE_BOUND",
                        title="Archive Inspection Time Budget Reached",
                        description=f"Stopped archive traversal at depth {depth} after exceeding {self.MAX_PROCESSING_SECONDS:.1f}s safety budget.",
                        severity=FindingSeverity.LOW,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=5,
                        evidence_source=self.name,
                        object_reference=prefix or "root",
                    )
                )
                return

            name = f"{prefix}{info.filename}"
            ext = Path(info.filename).suffix.lower()
            if info.is_dir():
                dir_set.add(name.rstrip("/"))
            elif "/" in info.filename:
                dir_set.add(f"{prefix}{info.filename.rsplit('/', 1)[0]}")

            comp_sz = max(0, info.compress_size)
            uncomp_sz = max(0, info.file_size)
            ratio = round(uncomp_sz / max(1, comp_sz), 2) if uncomp_sz > 0 else 0.0
            is_enc = (info.flag_bits & 0x1) != 0

            if len(entry_stats) < 100:
                entry_stats.append({
                    "name": name,
                    "depth": depth,
                    "compressed_size": comp_sz,
                    "uncompressed_size": uncomp_sz,
                    "compression_ratio": ratio,
                    "is_encrypted": is_enc,
                })

            if info.date_time and info.date_time[0] > 1980:
                try:
                    entry_dt = datetime(*info.date_time, tzinfo=timezone.utc)
                    timeline.append(
                        TimelineEvent(
                            event_id=f"zip-entry-{depth}-{info.CRC}",
                            evidence_id="",
                            timestamp=entry_dt,
                            original_timestamp=f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} {info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}",
                            timestamp_type=TimelineEventType.ARCHIVE_ENTRY,
                            source=f"ZIP Entry Header ({name})",
                            description=f"Archive entry '{name}' header mtime: {entry_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                            confidence=ConfidenceLevel.MEDIUM,
                        )
                    )
                except Exception:
                    pass

            if ext in self.EXECUTABLE_EXTS:
                executable_entries.append(name)

            stem_ext = Path(Path(info.filename).stem).suffix.lower()
            if stem_ext in (".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png") and ext in self.EXECUTABLE_EXTS:
                double_ext_entries.append(name)

            if is_enc:
                encrypted_entries.append(name)

            if ext in self.NESTED_ARCHIVE_EXTS:
                nested_archives.append(name)

                # Bounded in-memory inspection of nested .zip containers (never written to disk)
                if ext == ".zip" and not is_enc and depth < settings.archive_max_recursion_depth:
                    budget = min(self.MAX_NESTED_BYTES, remaining_bytes[0])
                    if budget > 0 and uncomp_sz <= budget:
                        try:
                            with zf.open(info, "r") as nested_stream:
                                nested_bytes = nested_stream.read(budget + 1)
                            if len(nested_bytes) > budget:
                                findings.append(
                                    Finding(
                                        rule_id="ARCH-BOMB-002",
                                        rule_version="1.0.0",
                                        category="SECURITY_VIOLATION",
                                        title=f"Nested Archive Exceeds Declared Size [{name}]",
                                        description=f"Nested ZIP entry '{name}' decompressed past the {budget:,}-byte safety budget (header mismatch / zip-bomb indicator).",
                                        severity=FindingSeverity.CRITICAL,
                                        confidence=ConfidenceLevel.CONFIRMED,
                                        score_impact=45,
                                        evidence_source=self.name,
                                        object_reference=name,
                                    )
                                )
                            else:
                                remaining_bytes[0] -= len(nested_bytes)
                                nested_buf = io.BytesIO(nested_bytes)
                                nested_inspector = ArchiveSafetyInspector()
                                nested_report = nested_inspector.inspect_zip(nested_buf)
                                if not nested_report.is_safe:
                                    findings.append(
                                        Finding(
                                            rule_id="ARCH-UNSAFE-001",
                                            rule_version="1.1.0",
                                            category="SECURITY_VIOLATION",
                                            title=f"Nested Archive Contains Path Traversal [{name}]",
                                            description=nested_report.rejection_reason or "Nested archive attempts path traversal.",
                                            severity=FindingSeverity.CRITICAL,
                                            confidence=ConfidenceLevel.CONFIRMED,
                                            score_impact=50,
                                            evidence_source=self.name,
                                            object_reference=name,
                                            mitre_technique="T1027",
                                        )
                                    )
                                nested_buf.seek(0)
                                with zipfile.ZipFile(nested_buf, "r") as nested_zf:
                                    self._inspect_zip_entries(
                                        nested_zf,
                                        depth=depth + 1,
                                        prefix=f"{name}!/",
                                        deadline=deadline,
                                        remaining_bytes=remaining_bytes,
                                        findings=findings,
                                        timeline=timeline,
                                        executable_entries=executable_entries,
                                        double_ext_entries=double_ext_entries,
                                        encrypted_entries=encrypted_entries,
                                        nested_archives=nested_archives,
                                        entry_stats=entry_stats,
                                        dir_set=dir_set,
                                    )
                        except ArchiveSafetyError as sec_err:
                            findings.append(
                                Finding(
                                    rule_id="ARCH-CORRUPT-001",
                                    rule_version="1.1.0",
                                    category="ANOMALY",
                                    title=f"Nested Archive Safety Failure [{name}]",
                                    description=str(sec_err),
                                    severity=FindingSeverity.HIGH,
                                    confidence=ConfidenceLevel.HIGH,
                                    score_impact=30,
                                    evidence_source=self.name,
                                    object_reference=name,
                                )
                            )
                        except Exception:
                            pass

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
                "max_recursion_depth": settings.archive_max_recursion_depth,
            }

            if not report.is_safe:
                findings.append(
                    Finding(
                        rule_id="ARCH-UNSAFE-001",
                        rule_version="1.1.0",
                        category="SECURITY_VIOLATION",
                        title="Archive Contains Path Traversal Attempts",
                        description=report.rejection_reason or "Archive member entries attempt to escape extraction directory.",
                        severity=FindingSeverity.CRITICAL,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=50,
                        evidence_source=self.name,
                        mitre_technique="T1027",
                        explanation="Zip Slip vulnerability allows crafted entries to overwrite arbitrary paths during naive extraction.",
                    )
                )

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="ARCH-CORRUPT-001",
                    rule_version="1.1.0",
                    category="ANOMALY",
                    title="Corrupted or Non-Standard Archive",
                    description=f"Archive structure failed safety audit: {err}",
                    severity=FindingSeverity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=30,
                    evidence_source=self.name,
                )
            )
            output.findings = self.finalize_findings(findings)
            return output

        # Deep bounded entry inspection
        try:
            deadline = time.monotonic() + self.MAX_PROCESSING_SECONDS
            remaining_bytes = [settings.archive_max_expanded_size_bytes]
            with zipfile.ZipFile(file_path, "r") as zf:
                executable_entries: List[str] = []
                double_ext_entries: List[str] = []
                encrypted_entries: List[str] = []
                nested_archives: List[str] = []
                entry_stats: List[Dict[str, Any]] = []
                dir_set: set[str] = set()

                if zf.comment:
                    details["archive_comment"] = zf.comment.decode("utf-8", errors="ignore")[:512]

                self._inspect_zip_entries(
                    zf,
                    depth=0,
                    prefix="",
                    deadline=deadline,
                    remaining_bytes=remaining_bytes,
                    findings=findings,
                    timeline=timeline,
                    executable_entries=executable_entries,
                    double_ext_entries=double_ext_entries,
                    encrypted_entries=encrypted_entries,
                    nested_archives=nested_archives,
                    entry_stats=entry_stats,
                    dir_set=dir_set,
                )

                if double_ext_entries:
                    findings.append(
                        Finding(
                            rule_id="ARCH-DECEPTION-001",
                            rule_version="1.1.0",
                            category="DECEPTION",
                            title=f"Double Extension Executable Detected ({len(double_ext_entries)} items)",
                            description=f"Archive contains executable disguising itself with a document extension: {', '.join(double_ext_entries)}",
                            severity=FindingSeverity.CRITICAL,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=45,
                            evidence_source=self.name,
                            object_reference=double_ext_entries[0],
                            mitre_technique="T1036.007",
                            explanation="Adversaries employ double extensions to trick users into launching executables mistaken for documents or images.",
                        )
                    )

                if executable_entries and not double_ext_entries:
                    findings.append(
                        Finding(
                            rule_id="ARCH-EXEC-001",
                            rule_version="1.1.0",
                            category="SUSPICIOUS_PAYLOAD",
                            title=f"Executable Binaries Inside Archive ({len(executable_entries)} items)",
                            description=f"Archive bundles direct executable payloads: {', '.join(executable_entries[:3])}",
                            severity=FindingSeverity.MEDIUM,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=20,
                            evidence_source=self.name,
                            object_reference=executable_entries[0],
                            mitre_technique="T1027",
                            explanation="Bundled scripts or binaries may represent software installers or dropped payloads.",
                        )
                    )

                if encrypted_entries:
                    findings.append(
                        Finding(
                            rule_id="ARCH-ENCRYPT-001",
                            rule_version="1.1.0",
                            category="EVASION",
                            title=f"Encrypted Archive Entries Detected ({len(encrypted_entries)} items)",
                            description=f"Archive contains password-protected entries preventing inspection: {', '.join(encrypted_entries[:3])}",
                            severity=FindingSeverity.MEDIUM,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=20,
                            evidence_source=self.name,
                            object_reference=encrypted_entries[0],
                            mitre_technique="T1027.013",
                            explanation="Password protection blocks automated inspection by security scanners.",
                        )
                    )

                if nested_archives:
                    findings.append(
                        Finding(
                            rule_id="ARCH-NESTED-001",
                            rule_version="1.1.0",
                            category="EVASION",
                            title=f"Nested Archive Structure Detected ({len(nested_archives)} items)",
                            description=f"Archive bundles secondary archives within its structure: {', '.join(nested_archives[:3])}",
                            severity=FindingSeverity.LOW,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=10,
                            evidence_source=self.name,
                            object_reference=nested_archives[0],
                            explanation="Nested archives are sometimes used to complicate inspection pipelines.",
                        )
                    )

                details["executable_entries"] = executable_entries
                details["double_extension_entries"] = double_ext_entries
                details["encrypted_entries"] = encrypted_entries
                details["nested_archives"] = nested_archives
                details["directory_summary"] = sorted(dir_set)[:50]
                details["entries"] = entry_stats

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="ARCH-READ-001",
                    rule_version="1.1.0",
                    category="ANOMALY",
                    title="Error Reading Archive Entries",
                    description=f"Could not iterate archive entries: {err}",
                    severity=FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    score_impact=15,
                    evidence_source=self.name,
                )
            )

        output.findings = self.finalize_findings(findings)
        output.timeline_events = timeline
        output.details = details
        return output

