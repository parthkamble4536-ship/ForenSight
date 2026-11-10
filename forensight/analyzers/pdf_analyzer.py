"""
Deep PDF static forensic analyzer.

Inspects document structure, metadata, encryption, and dangerous action keywords
(/JavaScript, /OpenAction, /Launch, /EmbeddedFiles, /URI) without executing actions.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pypdf import PdfReader

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


class PDFAnalyzer(BaseAnalyzer):
    """
    Static forensic analyzer for Portable Document Format (PDF) files.
    """

    SUSPICIOUS_KEYWORD_PATTERNS = {
        "/JavaScript": {
            "rule_id": "PDF-JS-001",
            "title": "Embedded JavaScript Structure (/JavaScript)",
            "description": "Document contains embedded JavaScript code intended to execute inside the PDF viewer.",
            "severity": FindingSeverity.HIGH,
            "score_impact": 35,
            "mitre": "T1059.007",
            "explanation": "PDF JavaScript is heavily abused to trigger memory corruption flaws, shellcode injection, or deceptive phishing prompts.",
        },
        "/JS": {
            "rule_id": "PDF-JS-002",
            "title": "Embedded JavaScript Action (/JS)",
            "description": "Document contains a /JS action trigger pointing to executable scripts.",
            "severity": FindingSeverity.HIGH,
            "score_impact": 35,
            "mitre": "T1059.007",
            "explanation": "Alternative shorthand keyword for JavaScript execution streams.",
        },
        "/OpenAction": {
            "rule_id": "PDF-ACTION-001",
            "title": "Automatic Execution on Document Open (/OpenAction)",
            "description": "Document specifies an /OpenAction directive that executes automatically upon opening.",
            "severity": FindingSeverity.MEDIUM,
            "score_impact": 25,
            "mitre": "T1204.002",
            "explanation": "Often paired with JavaScript or Launch actions to trigger payload execution without explicit user interaction.",
        },
        "/AA": {
            "rule_id": "PDF-ACTION-002",
            "title": "Additional Action Event Triggers (/AA)",
            "description": "Document defines /AA event triggers that fire when pages or form fields are navigated or closed.",
            "severity": FindingSeverity.LOW,
            "score_impact": 15,
            "mitre": "T1204.002",
            "explanation": "Enables delayed or evasion execution triggered by viewer behavior rather than initial open.",
        },
        "/Launch": {
            "rule_id": "PDF-LAUNCH-001",
            "title": "Arbitrary Application Launch Action (/Launch)",
            "description": "Document contains a /Launch directive requesting the execution of an external system command or binary.",
            "severity": FindingSeverity.CRITICAL,
            "score_impact": 50,
            "mitre": "T1204.002",
            "explanation": "The /Launch action allows documents to invoke cmd.exe, PowerShell, or external binaries directly from the reader.",
        },
        "/EmbeddedFiles": {
            "rule_id": "PDF-EMBED-001",
            "title": "Embedded File Attachment (/EmbeddedFiles)",
            "description": "Document contains one or more embedded files or dropped payloads.",
            "severity": FindingSeverity.MEDIUM,
            "score_impact": 20,
            "mitre": "T1027",
            "explanation": "Malicious PDFs frequently embed secondary executables, scripts, or archives to evade email gateway filtering.",
        },
        "/SubmitForm": {
            "rule_id": "PDF-EXFIL-001",
            "title": "Data Exfiltration Form Action (/SubmitForm)",
            "description": "Document defines a form that transmits data to a remote URL endpoint.",
            "severity": FindingSeverity.MEDIUM,
            "score_impact": 20,
            "mitre": "T1048",
            "explanation": "Used in phishing and credential harvesting attacks to post entered form credentials to adversary C2 servers.",
        },
    }

    @property
    def name(self) -> str:
        return "PDF Forensic Analyzer"

    @property
    def supported_types(self) -> List[str]:
        return ["PDF"]

    def _parse_pdf_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse PDF date format: D:YYYYMMDDHHmmSSOHH'mm' into standard UTC datetime.
        """
        if not date_str or not isinstance(date_str, str):
            return None

        # Clean prefix
        cleaned = date_str.replace("D:", "").replace("'", "")
        # Basic match for at least YYYYMMDD
        match = re.match(r"^(\d{4})(\d{2})(\d{2})?(\d{2})?(\d{2})?(\d{2})?", cleaned)
        if match:
            year, month = int(match.group(1)), int(match.group(2))
            day = int(match.group(3)) if match.group(3) else 1
            hour = int(match.group(4)) if match.group(4) else 0
            minute = int(match.group(5)) if match.group(5) else 0
            second = int(match.group(6)) if match.group(6) else 0
            try:
                return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
            except ValueError:
                return None
        return None

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        iocs: List[IOCRecord] = []
        timeline: List[TimelineEvent] = []
        details: Dict[str, Any] = {}

        # 1. Structural inspection via raw byte scan (catches obfuscated or malformed PDF streams)
        raw_bytes = file_path.read_bytes()

        detected_keywords: Dict[str, int] = {}
        for keyword in self.SUSPICIOUS_KEYWORD_PATTERNS:
            pattern = keyword.encode("ascii")
            count = raw_bytes.count(pattern)
            if count > 0:
                detected_keywords[keyword] = count

        # Extract embedded URLs from /URI actions
        uri_matches = re.findall(rb"/URI\s*\((https?://[^)]+)\)", raw_bytes, re.IGNORECASE)
        for raw_url in uri_matches:
            url_str = raw_url.decode("utf-8", errors="ignore")
            iocs.append(
                IOCRecord(
                    ioc_type=IOCType.URL,
                    value=url_str,
                    defanged_value=defang_ioc(url_str),
                    context="PDF /URI Action Target",
                    confidence=ConfidenceLevel.CONFIRMED,
                )
            )

        # 2. Structural parsing via pypdf
        try:
            reader = PdfReader(str(file_path), strict=False)
            details["is_encrypted"] = reader.is_encrypted
            details["page_count"] = len(reader.pages)

            # Metadata extraction
            doc_info = reader.metadata
            if doc_info:
                author = doc_info.author or ""
                creator = doc_info.creator or ""
                producer = doc_info.producer or ""
                title = doc_info.title or ""

                details["author"] = author
                details["creator"] = creator
                details["producer"] = producer
                details["title"] = title

                # Creation timestamp
                if doc_info.creation_date:
                    dt = doc_info.creation_date
                    if isinstance(dt, datetime):
                        creation_dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                    else:
                        creation_dt = self._parse_pdf_date(str(dt))

                    if creation_dt:
                        details["creation_time_iso"] = creation_dt.isoformat()
                        timeline.append(
                            TimelineEvent(
                                event_id="pdf-creation",
                                evidence_id="",
                                timestamp=creation_dt,
                                timestamp_type=TimelineEventType.METADATA,
                                source="PDF Metadata (CreationDate)",
                                description=f"PDF document created: {creation_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                confidence=ConfidenceLevel.HIGH,
                            )
                        )

                # Modification timestamp
                if doc_info.modification_date:
                    dt = doc_info.modification_date
                    if isinstance(dt, datetime):
                        mod_dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                    else:
                        mod_dt = self._parse_pdf_date(str(dt))

                    if mod_dt:
                        details["modification_time_iso"] = mod_dt.isoformat()
                        timeline.append(
                            TimelineEvent(
                                event_id="pdf-modification",
                                evidence_id="",
                                timestamp=mod_dt,
                                timestamp_type=TimelineEventType.METADATA,
                                source="PDF Metadata (ModDate)",
                                description=f"PDF document modified: {mod_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                confidence=ConfidenceLevel.HIGH,
                            )
                        )

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="PDF-STRUCT-001",
                    category="ANOMALY",
                    title="Malformed PDF Object Tree",
                    description=f"PDF object tree could not be fully parsed by standard reader: {err}",
                    severity=FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=15,
                    evidence_source=self.name,
                    explanation="Crafted malformed structures are frequently utilized in PDF exploits to evade security scanners while still rendering in Acrobat.",
                )
            )

        # 3. Generate Findings from detected keywords
        for keyword, count in detected_keywords.items():
            rule = self.SUSPICIOUS_KEYWORD_PATTERNS[keyword]
            findings.append(
                Finding(
                    rule_id=rule["rule_id"],
                    category="DOCUMENT_ACTION",
                    title=f"{rule['title']} ({count} occurrences)",
                    description=f"{rule['description']} Found {count} instances in object streams.",
                    severity=rule["severity"],
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=rule["score_impact"],
                    evidence_source=self.name,
                    object_reference=keyword,
                    mitre_technique=rule["mitre"],
                    explanation=rule["explanation"],
                )
            )

        details["detected_suspicious_keywords"] = detected_keywords
        output.findings = findings
        output.iocs = iocs
        output.timeline_events = timeline
        output.details = details
        return output

