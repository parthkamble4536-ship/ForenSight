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

    MAX_XML_PART_BYTES = 2 * 1024 * 1024  # 2 MB cap per XML zip member

    @property
    def name(self) -> str:
        return "Office Document Forensic Analyzer"

    @property
    def version(self) -> str:
        return "2.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["DOCX", "DOCM"]

    def _safe_read_xml_member(self, zf: zipfile.ZipFile, member_name: str) -> Optional[bytes]:
        """Read an XML/rels member safely within MAX_XML_PART_BYTES to defend against compressed XML bombs."""
        try:
            info = zf.getinfo(member_name)
            if info.file_size > self.MAX_XML_PART_BYTES:
                return None
            data = zf.read(member_name)
            if len(data) > self.MAX_XML_PART_BYTES:
                return None
            return data
        except Exception:
            return None

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
            output.findings = self.finalize_findings(findings)
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
                                rule_version="1.1.0",
                                category="DECEPTION",
                                title="VBA Macro Disguised in .docx Extension",
                                description="Document contains embedded VBA macro storage (vbaProject.bin) despite declaring a .docx extension.",
                                severity=FindingSeverity.HIGH,
                                confidence=ConfidenceLevel.CONFIRMED,
                                score_impact=40,
                                evidence_source=self.name,
                                object_reference="word/vbaProject.bin",
                                mitre_technique="T1204.002",
                                explanation="Standard .docx packages do not normally carry executable macro projects. Note: presence of VBA storage alone is a capability indicator rather than proof of malicious payload.",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                rule_id="DOCX-MACRO-001",
                                rule_version="1.1.0",
                                category="MACRO",
                                title="Embedded Visual Basic for Applications (VBA) Macro Storage",
                                description="Document contains a VBA macro project stream (word/vbaProject.bin).",
                                severity=FindingSeverity.HIGH,
                                confidence=ConfidenceLevel.CONFIRMED,
                                score_impact=35,
                                evidence_source=self.name,
                                object_reference="word/vbaProject.bin",
                                mitre_technique="T1059.005",
                                explanation="VBA macro streams enable script execution upon user approval, though legitimate enterprise templates also use macros. Static inspection notes capability only.",
                            )
                        )

                # 2. Embedded OLE Objects & Packages
                ole_entries = [name for name in namelist if "embeddings" in name.lower() or name.endswith(".bin")]
                non_vba_ole = [name for name in ole_entries if "vbaproject" not in name.lower()]
                details["embedded_ole_count"] = len(non_vba_ole)
                details["embedded_ole_parts"] = non_vba_ole[:50]

                if non_vba_ole:
                    findings.append(
                        Finding(
                            rule_id="DOCX-OLE-001",
                            rule_version="1.1.0",
                            category="EMBEDDED_OBJECT",
                            title=f"Embedded OLE Binary Objects Detected ({len(non_vba_ole)} files)",
                            description=f"Document contains embedded binary OLE objects: {', '.join(non_vba_ole[:3])}{'...' if len(non_vba_ole) > 3 else ''}.",
                            severity=FindingSeverity.HIGH,
                            confidence=ConfidenceLevel.HIGH,
                            score_impact=30,
                            evidence_source=self.name,
                            object_reference=non_vba_ole[0],
                            mitre_technique="T1204.002",
                            explanation="Embedded OLE packages may contain secondary payloads or legacy Equation Editor objects.",
                        )
                    )

                # 3. Bounded External Relationships & Remote Template Injection (MITRE T1221)
                external_targets: List[str] = []
                external_rel_details: List[Dict[str, str]] = []
                for rels_path in sorted(name for name in namelist if name.endswith(".rels"))[:100]:
                    try:
                        content = self._safe_read_xml_member(zf, rels_path)
                        if not content:
                            continue
                        root = ET.fromstring(content)
                        for rel in root.iter():
                            if rel.attrib.get("TargetMode") == "External":
                                target = rel.attrib.get("Target", "")
                                rel_type = rel.attrib.get("Type", "")

                                external_targets.append(target)
                                external_rel_details.append({
                                    "rels_part": rels_path,
                                    "relationship_type": rel_type,
                                    "target_defanged": defang_ioc(target),
                                })

                                if "attachedtemplate" in rel_type.lower() or target.lower().endswith((".dotm", ".dot")):
                                    findings.append(
                                        Finding(
                                            rule_id="DOCX-TEMPLATE-001",
                                            rule_version="1.1.0",
                                            category="TEMPLATE_INJECTION",
                                            title="Remote Template Injection Attack (MITRE T1221)",
                                            description=f"Document instructs Microsoft Word to retrieve an external template from: {defang_ioc(target)}",
                                            severity=FindingSeverity.CRITICAL,
                                            confidence=ConfidenceLevel.CONFIRMED,
                                            score_impact=50,
                                            evidence_source=self.name,
                                            object_reference=rels_path,
                                            mitre_technique="T1221",
                                            explanation="Remote Template Injection references an external .dot/.dotm template retrieved over HTTP/SMB on document open.",
                                        )
                                    )
                                elif target.startswith(("http://", "https://", "ftp://", "\\\\")):
                                    findings.append(
                                        Finding(
                                            rule_id="DOCX-EXTREL-001",
                                            rule_version="1.0.0",
                                            category="EXTERNAL_REFERENCE",
                                            title="External Relationship Reference in OpenXML Container",
                                            description=f"External TargetMode reference ({rel_type.rsplit('/', 1)[-1]}) points to {defang_ioc(target)}.",
                                            severity=FindingSeverity.LOW,
                                            confidence=ConfidenceLevel.CONFIRMED,
                                            score_impact=10,
                                            evidence_source=self.name,
                                            object_reference=rels_path,
                                            explanation="External relationships can trigger automatic network fetches (e.g. tracking beacons or NTLM UNC leaks) or be benign web hyperlinks.",
                                        )
                                    )

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
                details["external_relationship_details"] = external_rel_details

                # 4. Document Properties & Authorship Metadata (docProps/core.xml)
                if "docProps/core.xml" in namelist:
                    try:
                        core_content = self._safe_read_xml_member(zf, "docProps/core.xml")
                        if core_content:
                            core_root = ET.fromstring(core_content)
                            ns = {
                                "dc": "http://purl.org/dc/elements/1.1/",
                                "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                                "dcterms": "http://purl.org/dc/terms/",
                            }

                            creator = core_root.findtext("dc:creator", namespaces=ns) or ""
                            title_prop = core_root.findtext("dc:title", namespaces=ns) or ""
                            subject_prop = core_root.findtext("dc:subject", namespaces=ns) or ""
                            last_modified_by = core_root.findtext("cp:lastModifiedBy", namespaces=ns) or ""
                            revision = core_root.findtext("cp:revision", namespaces=ns) or ""
                            created_str = core_root.findtext("dcterms:created", namespaces=ns)
                            modified_str = core_root.findtext("dcterms:modified", namespaces=ns)

                            details["creator"] = creator
                            details["title"] = title_prop
                            details["subject"] = subject_prop
                            details["last_modified_by"] = last_modified_by
                            details["revision"] = revision

                            created_dt = self._parse_xml_timestamp(created_str)
                            if created_dt:
                                details["created_iso"] = created_dt.isoformat()
                                timeline.append(
                                    TimelineEvent(
                                        event_id="docx-created",
                                        evidence_id="",
                                        timestamp=created_dt,
                                        original_timestamp=created_str,
                                        timestamp_type=TimelineEventType.METADATA,
                                        source="OpenXML docProps/core.xml (created)",
                                        description=f"OpenXML metadata created claim (author '{creator or 'Unknown'}'): {created_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                        confidence=ConfidenceLevel.MEDIUM,
                                    )
                                )

                            modified_dt = self._parse_xml_timestamp(modified_str)
                            if modified_dt:
                                details["modified_iso"] = modified_dt.isoformat()
                                timeline.append(
                                    TimelineEvent(
                                        event_id="docx-modified",
                                        evidence_id="",
                                        timestamp=modified_dt,
                                        original_timestamp=modified_str,
                                        timestamp_type=TimelineEventType.METADATA,
                                        source="OpenXML docProps/core.xml (modified)",
                                        description=f"OpenXML metadata modified claim (by '{last_modified_by or 'Unknown'}'): {modified_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                        confidence=ConfidenceLevel.MEDIUM,
                                    )
                                )
                    except Exception:
                        pass

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="DOCX-PARSE-001",
                    rule_version="1.1.0",
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

        output.findings = self.finalize_findings(findings)
        output.iocs = iocs
        output.timeline_events = timeline
        output.details = details
        return output

