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
from forensight.core.config import settings
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

    MAX_PDF_PAGES = 200
    MAX_EXTRACTED_URIS = 100

    @property
    def name(self) -> str:
        return "PDF Forensic Analyzer"

    @property
    def version(self) -> str:
        return "2.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["PDF"]

    def _parse_pdf_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse PDF date format: D:YYYYMMDDHHmmSSOHH'mm' into standard UTC datetime.
        """
        if not date_str or not isinstance(date_str, str):
            return None

        cleaned = date_str.replace("D:", "").replace("'", "")
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

        # 1. Bounded raw byte structural inspection (catches obfuscated/malformed PDF streams)
        with open(file_path, "rb") as f:
            raw_bytes = f.read(settings.max_upload_size_bytes)

        detected_keywords: Dict[str, int] = {}
        keyword_offsets: Dict[str, int] = {}
        for keyword in self.SUSPICIOUS_KEYWORD_PATTERNS:
            pattern = keyword.encode("ascii")
            count = raw_bytes.count(pattern)
            if count > 0:
                detected_keywords[keyword] = count
                keyword_offsets[keyword] = raw_bytes.find(pattern)

        # Structural counts (forms, XFA, annotations, RichMedia, object streams)
        acroform_count = raw_bytes.count(b"/AcroForm")
        xfa_count = raw_bytes.count(b"/XFA")
        annot_count = raw_bytes.count(b"/Annot")
        richmedia_count = raw_bytes.count(b"/RichMedia")
        objstm_count = raw_bytes.count(b"/ObjStm")

        details["acroform_count"] = acroform_count
        details["xfa_count"] = xfa_count
        details["annotation_count"] = annot_count
        details["richmedia_count"] = richmedia_count
        details["object_stream_count"] = objstm_count

        if acroform_count > 0 or xfa_count > 0:
            findings.append(
                Finding(
                    rule_id="PDF-FORM-001",
                    rule_version="1.0.0",
                    category="STRUCTURE",
                    title=f"Interactive PDF Forms Detected (AcroForm={acroform_count}, XFA={xfa_count})",
                    description="Document contains /AcroForm or /XFA interactive XML form structures.",
                    severity=FindingSeverity.LOW if xfa_count == 0 else FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=10 if xfa_count == 0 else 20,
                    evidence_source=self.name,
                    object_reference="/XFA" if xfa_count > 0 else "/AcroForm",
                    offset=raw_bytes.find(b"/XFA") if xfa_count > 0 else raw_bytes.find(b"/AcroForm"),
                    explanation="PDF forms are common in legitimate business documents, though XFA XML forms have historically expanded parser attack surfaces.",
                )
            )

        if richmedia_count > 0:
            findings.append(
                Finding(
                    rule_id="PDF-MEDIA-001",
                    rule_version="1.0.0",
                    category="EMBEDDED_OBJECT",
                    title="RichMedia Annotation Stream (/RichMedia)",
                    description=f"Document contains {richmedia_count} /RichMedia embedded stream markers.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=20,
                    evidence_source=self.name,
                    object_reference="/RichMedia",
                    offset=raw_bytes.find(b"/RichMedia"),
                    explanation="Embedded RichMedia/Flash streams were historically abused to deliver memory-corruption payloads inside PDFs.",
                )
            )

        # Extract embedded URLs from /URI actions (bounded & deduplicated)
        seen_urls: Set[str] = set()
        for match in re.finditer(rb"/URI\s*\((https?://[^)]+)\)", raw_bytes, re.IGNORECASE):
            if len(seen_urls) >= self.MAX_EXTRACTED_URIS:
                break
            url_str = match.group(1).decode("utf-8", errors="ignore")
            if url_str not in seen_urls:
                seen_urls.add(url_str)
                iocs.append(
                    IOCRecord(
                        ioc_type=IOCType.URL,
                        value=url_str,
                        defanged_value=defang_ioc(url_str),
                        context="PDF /URI Action Target",
                        offset=match.start(),
                        confidence=ConfidenceLevel.CONFIRMED,
                    )
                )

        # 2. Bounded structural parsing via pypdf (strictly static, never executes JS)
        embedded_files: List[str] = []
        try:
            reader = PdfReader(str(file_path), strict=False)
            details["is_encrypted"] = reader.is_encrypted
            details["page_count"] = len(reader.pages)
            details["pages_inspected"] = min(len(reader.pages), self.MAX_PDF_PAGES)

            if reader.is_encrypted:
                findings.append(
                    Finding(
                        rule_id="PDF-ENC-001",
                        rule_version="1.0.0",
                        category="EVASION",
                        title="Encrypted PDF Document",
                        description="PDF stream is encrypted, which can obscure object contents from static scanners.",
                        severity=FindingSeverity.LOW,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=10,
                        evidence_source=self.name,
                        object_reference="PDF Trailer /Encrypt",
                        explanation="Encryption is used legitimately for confidential documents and maliciously to evade content inspection.",
                    )
                )

            # Inspect page annotations bounded by MAX_PDF_PAGES
            if not reader.is_encrypted:
                for page_idx, page in enumerate(reader.pages[: self.MAX_PDF_PAGES]):
                    annots = page.get("/Annots")
                    if not annots:
                        continue
                    try:
                        annot_list = annots.get_object() if hasattr(annots, "get_object") else annots
                        for annot_ref in list(annot_list)[:100]:
                            annot_obj = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                            if not isinstance(annot_obj, dict):
                                continue
                            action = annot_obj.get("/A")
                            action_obj = action.get_object() if hasattr(action, "get_object") else action
                            if isinstance(action_obj, dict) and "/URI" in action_obj:
                                uri_val = str(action_obj["/URI"])
                                if uri_val.startswith(("http://", "https://")) and uri_val not in seen_urls and len(seen_urls) < self.MAX_EXTRACTED_URIS:
                                    seen_urls.add(uri_val)
                                    iocs.append(
                                        IOCRecord(
                                            ioc_type=IOCType.URL,
                                            value=uri_val,
                                            defanged_value=defang_ioc(uri_val),
                                            context=f"PDF Page {page_idx + 1} Annotation /URI",
                                            confidence=ConfidenceLevel.CONFIRMED,
                                        )
                                    )
                    except Exception:
                        continue

                # Inspect Catalog /Names /EmbeddedFiles filenames safely without extracting payloads
                try:
                    root = reader.trailer.get("/Root", {})
                    root_obj = root.get_object() if hasattr(root, "get_object") else root
                    if isinstance(root_obj, dict) and "/Names" in root_obj:
                        names = root_obj["/Names"]
                        names_obj = names.get_object() if hasattr(names, "get_object") else names
                        if isinstance(names_obj, dict) and "/EmbeddedFiles" in names_obj:
                            ef_tree = names_obj["/EmbeddedFiles"]
                            ef_obj = ef_tree.get_object() if hasattr(ef_tree, "get_object") else ef_tree
                            if isinstance(ef_obj, dict) and "/Names" in ef_obj:
                                raw_ef_names = ef_obj["/Names"]
                                for item in list(raw_ef_names)[0:50:2]:
                                    embedded_files.append(str(item))
                except Exception:
                    pass

            details["embedded_files"] = embedded_files

            # Metadata extraction
            doc_info = reader.metadata
            if doc_info:
                author = doc_info.author or ""
                creator = doc_info.creator or ""
                producer = doc_info.producer or ""
                title = doc_info.title or ""
                subject = getattr(doc_info, "subject", None) or ""

                details["author"] = author
                details["creator"] = creator
                details["producer"] = producer
                details["title"] = title
                details["subject"] = subject

                if doc_info.creation_date:
                    raw_dt = str(doc_info.creation_date)
                    dt = doc_info.creation_date
                    creation_dt = (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)) if isinstance(dt, datetime) else self._parse_pdf_date(raw_dt)
                    if creation_dt:
                        creation_dt = creation_dt.astimezone(timezone.utc)
                        details["creation_time_iso"] = creation_dt.isoformat()
                        timeline.append(
                            TimelineEvent(
                                event_id="pdf-creation",
                                evidence_id="",
                                timestamp=creation_dt,
                                original_timestamp=raw_dt,
                                timestamp_type=TimelineEventType.METADATA,
                                source="PDF Metadata (CreationDate)",
                                description=f"PDF metadata CreationDate claim: {creation_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                confidence=ConfidenceLevel.MEDIUM,
                            )
                        )

                if doc_info.modification_date:
                    raw_mdt = str(doc_info.modification_date)
                    dt = doc_info.modification_date
                    mod_dt = (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)) if isinstance(dt, datetime) else self._parse_pdf_date(raw_mdt)
                    if mod_dt:
                        mod_dt = mod_dt.astimezone(timezone.utc)
                        details["modification_time_iso"] = mod_dt.isoformat()
                        timeline.append(
                            TimelineEvent(
                                event_id="pdf-modification",
                                evidence_id="",
                                timestamp=mod_dt,
                                original_timestamp=raw_mdt,
                                timestamp_type=TimelineEventType.METADATA,
                                source="PDF Metadata (ModDate)",
                                description=f"PDF metadata ModDate claim: {mod_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                confidence=ConfidenceLevel.MEDIUM,
                            )
                        )

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="PDF-STRUCT-001",
                    rule_version="1.1.0",
                    category="ANOMALY",
                    title="Malformed PDF Object Tree",
                    description=f"PDF object tree could not be fully parsed by standard reader: {err}",
                    severity=FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=15,
                    evidence_source=self.name,
                    explanation="Crafted malformed structures are frequently utilized in PDF exploits or corrupted captures.",
                )
            )

        # 3. Generate Findings from detected active/script keywords
        for keyword, count in detected_keywords.items():
            rule = self.SUSPICIOUS_KEYWORD_PATTERNS[keyword]
            findings.append(
                Finding(
                    rule_id=rule["rule_id"],
                    rule_version="1.1.0",
                    category="DOCUMENT_ACTION",
                    title=f"{rule['title']} ({count} occurrences)",
                    description=f"{rule['description']} Observed {count} instances in bounded byte scan.",
                    severity=rule["severity"],
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=rule["score_impact"],
                    evidence_source=self.name,
                    object_reference=keyword,
                    offset=keyword_offsets.get(keyword),
                    mitre_technique=rule["mitre"],
                    explanation=rule["explanation"],
                )
            )

        details["detected_suspicious_keywords"] = detected_keywords
        output.findings = self.finalize_findings(findings)
        output.iocs = iocs
        output.timeline_events = timeline
        output.details = details
        return output

