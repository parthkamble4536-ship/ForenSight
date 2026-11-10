"""
Office document forensic analyzer (DOCX and DOCM OpenXML inspection).

Inspects OpenXML container relationships, embedded VBA macros (vbaProject.bin),
remote template injection attacks, OLE packages, and document authorship metadata
without executing macros or embedded objects.
"""

import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from forensight.analyzers.base import AnalyzerOutput, BaseAnalyzer
from forensight.core.security import defang_ioc
from forensight.core.types import (
    ConfidenceLevel,
    EvidenceMetadata,
    Finding,
    FindingSeverity,
    IOCRecord,
    IOCType,
    TimelineEvent,
    TimelineEventType,
)


class DocxAnalyzer(BaseAnalyzer):
    """
    Static forensic analyzer for Microsoft Office OpenXML documents (DOCX and DOCM).
    """

    @property
    def name(self) -> str:
        return "Office Document Forensic Analyzer"

    @property
    def supported_types(self) -> List[str]:
        return ["DOCX", "DOCM"]

    def _parse_xml_timestamp(self, text: Optional[str]) -> Optional[datetime]:
        """Parse ISO 8601 XML timestamp strings (e.g. 2026-11-10T12:00:00Z)."""
        if not text:
            return None
        try:
            cleaned = text.strip().replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except Exception:
            return None

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        iocs: List[IOCRecord] = []
        timeline: List[TimelineEvent] = []
        details: Dict[str, Any] = {}

        if not zipfile.is_zipfile(file_path):
            findings.append(
                Finding(
                    rule_id="DOCX-CORRUPT-001",
                    category="ANOMALY",
                    title="Invalid OpenXML Package",
                    description="File claims to be an Office document but is not a valid ZIP container.",
                    severity=FindingSeverity.HIGH,
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=30,
                    evidence_source=self.name,
                    explanation="May indicate an encrypted non-OpenXML format, legacy OLE2 binary, or corrupted file.",
                )
            )
            output.findings = findings
            return output

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = set(zf.namelist())
                details["total_entries"] = len(namelist)

                # 1. VBA Macro Detection
                has_vba_bin = "word/vbaProject.bin" in namelist or any("vba" in name.lower() for name in namelist)
                details["has_vba_macros"] = has_vba_bin

                if has_vba_bin:
                    is_docx_ext = metadata.declared_extension.lower() == ".docx"
                    if is_docx_ext:
                        findings.append(
                            Finding(
                                rule_id="DOCX-MACRO-002",
                                category="DECEPTION",
                                title="VBA Macro Disguised in .docx Extension",
                                description="Document contains embedded VBA macros (vbaProject.bin) despite declaring a .docx extension.",
                                severity=FindingSeverity.HIGH,
                                confidence=ConfidenceLevel.CONFIRMED,
                                score_impact=40,
                                evidence_source=self.name,
                                object_reference="word/vbaProject.bin",
                                mitre_technique="T1204.002",
                                explanation="Standard DOCX files cannot execute macros. Placing macros in .docx or renaming .docm to .docx is a common adversary evasion technique.",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                rule_id="DOCX-MACRO-001",
                                category="MACRO",
                                title="Embedded Visual Basic for Applications (VBA) Macro",
                                description="Document contains a compiled VBA macro storage stream (word/vbaProject.bin).",
                                severity=FindingSeverity.HIGH,
                                confidence=ConfidenceLevel.CONFIRMED,
                                score_impact=35,
                                evidence_source=self.name,
                                object_reference="word/vbaProject.bin",
                                mitre_technique="T1059.005",
                                explanation="VBA macros can execute arbitrary shellcode, invoke PowerShell, or drop malware upon opening.",
                            )
                        )

                # 2. Embedded OLE Objects & Packages
                ole_entries = [name for name in namelist if "embeddings" in name.lower() or name.endswith(".bin")]
                # Filter out standard vbaProject.bin from OLE count
                non_vba_ole = [name for name in ole_entries if "vbaproject" not in name.lower()]
                details["embedded_ole_count"] = len(non_vba_ole)

                if non_vba_ole:
                    findings.append(
                        Finding(
                            rule_id="DOCX-OLE-001",
                            category="EMBEDDED_OBJECT",
                            title=f"Embedded OLE Binary Objects Detected ({len(non_vba_ole)} files)",
                            description=f"Document contains embedded binary OLE objects: {', '.join(non_vba_ole[:3])}{'...' if len(non_vba_ole) > 3 else ''}.",
                            severity=FindingSeverity.HIGH,
                            confidence=ConfidenceLevel.HIGH,
                            score_impact=30,
                            evidence_source=self.name,
                            mitre_technique="T1204.002",
                            explanation="Embedded OLE objects are frequently used to weaponize documents with legacy Equation Editor exploits (CVE-2017-11882) or embedded executables.",
                        )
                    )

                # 3. External Relationships & Remote Template Injection (MITRE T1221)
                external_targets: List[str] = []
                for rels_path in [name for name in namelist if name.endswith(".rels")]:
                    try:
                        content = zf.read(rels_path)
                        root = ET.fromstring(content)
                        for rel in root.iter():
                            if rel.attrib.get("TargetMode") == "External":
                                target = rel.attrib.get("Target", "")
                                rel_type = rel.attrib.get("Type", "")

                                external_targets.append(target)

                                # Check for Remote Template Injection
                                if "attachedtemplate" in rel_type.lower() or target.lower().endswith((".dotm", ".dot")):
                                    findings.append(
                                        Finding(
                                            rule_id="DOCX-TEMPLATE-001",
                                            category="TEMPLATE_INJECTION",
                                            title="Remote Template Injection Attack (MITRE T1221)",
                                            description=f"Document instructs Microsoft Word to download and execute an external remote template from: {target}",
                                            severity=FindingSeverity.CRITICAL,
                                            confidence=ConfidenceLevel.CONFIRMED,
                                            score_impact=50,
                                            evidence_source=self.name,
                                            object_reference=rels_path,
                                            mitre_technique="T1221",
                                            explanation="Remote Template Injection allows an attacker to send a benign-looking document that dynamically retrieves weaponized malicious macros from a remote staging server.",
                                        )
                                    )

                                # Extract target URL as an IOC
                                if target.startswith(("http://", "https://", "ftp://")):
                                    iocs.append(
                                        IOCRecord(
                                            ioc_type=IOCType.URL,
                                            value=target,
                                            defanged_value=defang_ioc(target),
                                            context=f"External OpenXML Relationship ({rels_path})",
                                            confidence=ConfidenceLevel.CONFIRMED,
                                        )
                                    )
                    except Exception:
                        pass

                details["external_relationships"] = external_targets

                # 4. Document Properties & Authorship Metadata (docProps/core.xml)
                if "docProps/core.xml" in namelist:
                    try:
                        core_content = zf.read("docProps/core.xml")
                        core_root = ET.fromstring(core_content)

                        # XML namespaces for Dublin Core and OpenXML properties
                        ns = {
                            "dc": "http://purl.org/dc/elements/1.1/",
                            "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                            "dcterms": "http://purl.org/dc/terms/",
                        }

                        creator = core_root.findtext("dc:creator", namespaces=ns) or ""
                        last_modified_by = core_root.findtext("cp:lastModifiedBy", namespaces=ns) or ""
                        revision = core_root.findtext("cp:revision", namespaces=ns) or ""
                        created_str = core_root.findtext("dcterms:created", namespaces=ns)
                        modified_str = core_root.findtext("dcterms:modified", namespaces=ns)

                        details["creator"] = creator
                        details["last_modified_by"] = last_modified_by
                        details["revision"] = revision

                        # Parse creation timestamp
                        created_dt = self._parse_xml_timestamp(created_str)
                        if created_dt:
                            details["created_iso"] = created_dt.isoformat()
                            timeline.append(
                                TimelineEvent(
                                    event_id="docx-created",
                                    evidence_id="",
                                    timestamp=created_dt,
                                    timestamp_type=TimelineEventType.METADATA,
                                    source="OpenXML docProps/core.xml (created)",
                                    description=f"Document created by '{creator or 'Unknown'}': {created_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                    confidence=ConfidenceLevel.HIGH,
                                )
                            )

                        # Parse modification timestamp
                        modified_dt = self._parse_xml_timestamp(modified_str)
                        if modified_dt:
                            details["modified_iso"] = modified_dt.isoformat()
                            timeline.append(
                                TimelineEvent(
                                    event_id="docx-modified",
                                    evidence_id="",
                                    timestamp=modified_dt,
                                    timestamp_type=TimelineEventType.METADATA,
                                    source="OpenXML docProps/core.xml (modified)",
                                    description=f"Document modified by '{last_modified_by or 'Unknown'}': {modified_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                    confidence=ConfidenceLevel.HIGH,
                                )
                            )
                    except Exception:
                        pass

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="DOCX-PARSE-001",
                    category="ANOMALY",
                    title="Error Parsing OpenXML Document",
                    description=f"Exception encountered while inspecting document components: {err}",
                    severity=FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    score_impact=15,
                    evidence_source=self.name,
                    explanation="Severely corrupt XML or intentional malformations can cause parser failure.",
                )
            )

        output.findings = findings
        output.iocs = iocs
        output.timeline_events = timeline
        output.details = details
        return output

