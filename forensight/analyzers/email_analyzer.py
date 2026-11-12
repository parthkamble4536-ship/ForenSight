"""
Email forensic static analyzer (EML and MSG message inspection).

Parses RFC 822 header chains, Received hops, SPF/DKIM/DMARC authentication flags,
attachment hashes, and body links without communicating over the network.
"""

import email
import email.policy
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

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
from forensight.intelligence.ioc_extractor import ioc_extractor
from forensight.storage.hasher import compute_hashes_from_bytes


class EmailAnalyzer(BaseAnalyzer):
    """
    Static forensic analyzer for EML email messages.
    """

    DANGEROUS_ATTACHMENT_EXTENSIONS = {
        ".exe", ".scr", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".wsf", ".hta", ".iso", ".img", ".vhd", ".docm", ".xlsm"
    }

    URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

    @property
    def name(self) -> str:
        return "Email Forensic Analyzer"

    @property
    def version(self) -> str:
        return "2.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["EML"]

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        iocs: List[IOCRecord] = []
        timeline: List[TimelineEvent] = []
        details: Dict[str, Any] = {
            "authentication_disclaimer": (
                "SPF, DKIM, DMARC, and Authentication-Results entries represent header claims "
                "contained inside the message file; ForenSight performs zero network DNS/DKIM key verification."
            )
        }

        try:
            with open(file_path, "rb") as f:
                raw_email = f.read(settings.max_upload_size_bytes)
            msg = email.message_from_bytes(raw_email, policy=email.policy.default)
        except Exception as err:
            findings.append(
                Finding(
                    rule_id="EML-PARSE-001",
                    rule_version="1.1.0",
                    category="ANOMALY",
                    title="Malformed Email Message Structure",
                    description=f"Email message headers could not be parsed: {err}",
                    severity=FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=15,
                    evidence_source=self.name,
                )
            )
            output.findings = self.finalize_findings(findings)
            return output

        # 1. Header Extraction
        subject = msg.get("Subject", "")
        sender = msg.get("From", "")
        recipient = msg.get("To", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        date_str = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")

        details["subject"] = subject
        details["from"] = sender
        details["to"] = recipient
        details["reply_to"] = reply_to
        details["return_path"] = return_path
        details["message_id"] = message_id

        # Extract email address IOCs across sender/routing headers
        seen_emails: set[str] = set()
        for addr_field, addr_val in [
            ("From", sender),
            ("To", recipient),
            ("Reply-To", reply_to),
            ("Return-Path", return_path),
        ]:
            if addr_val:
                found_emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", str(addr_val))
                for em in found_emails:
                    em_low = em.lower()
                    if em_low not in seen_emails:
                        seen_emails.add(em_low)
                        iocs.append(
                            IOCRecord(
                                ioc_type=IOCType.EMAIL,
                                value=em,
                                defanged_value=em.replace("@", "[at]").replace(".", "[.]"),
                                context=f"Email Header ({addr_field})",
                                confidence=ConfidenceLevel.CONFIRMED,
                            )
                        )

        # 2. Date and Received Header Chain
        if date_str:
            try:
                date_dt = parsedate_to_datetime(date_str)
                if not date_dt.tzinfo:
                    date_dt = date_dt.replace(tzinfo=timezone.utc)
                date_dt = date_dt.astimezone(timezone.utc)
                details["date_iso"] = date_dt.isoformat()

                timeline.append(
                    TimelineEvent(
                        event_id="eml-date",
                        evidence_id="",
                        timestamp=date_dt,
                        original_timestamp=str(date_str),
                        timestamp_type=TimelineEventType.EMAIL_RECEIVED,
                        source="Email Header (Date)",
                        description=f"Email header Date claim (Subject '{subject or 'No Subject'}'): {date_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                        confidence=ConfidenceLevel.MEDIUM,
                    )
                )
            except Exception:
                pass

        received_headers = msg.get_all("Received", [])
        details["received_hops_count"] = len(received_headers)
        details["received_hops"] = [str(h).strip()[:200] for h in received_headers[:15]]

        # 3. Sender Inconsistencies (From vs Reply-To / Return-Path)
        sender_emails = re.findall(r"[\w\.-]+@[\w\.-]+", str(sender).lower()) if sender else []
        reply_emails = re.findall(r"[\w\.-]+@[\w\.-]+", str(reply_to).lower()) if reply_to else []
        return_emails = re.findall(r"[\w\.-]+@[\w\.-]+", str(return_path).lower()) if return_path else []

        if sender_emails and reply_emails and sender_emails[0] != reply_emails[0]:
            findings.append(
                Finding(
                    rule_id="EML-SPOOF-001",
                    rule_version="1.1.0",
                    category="PHISHING",
                    title="Sender / Reply-To Address Mismatch",
                    description=f"From address ({sender_emails[0]}) differs from Reply-To address ({reply_emails[0]}).",
                    severity=FindingSeverity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=25,
                    evidence_source=self.name,
                    object_reference="From / Reply-To Headers",
                    mitre_technique="T1566.002",
                    explanation="Phishing messages frequently present a trusted From header while routing replies via Reply-To to an external mailbox.",
                )
            )

        if sender_emails and return_emails:
            sender_dom = sender_emails[0].split("@")[-1]
            ret_dom = return_emails[0].split("@")[-1]
            if sender_dom != ret_dom and not ret_dom.endswith(f".{sender_dom}"):
                findings.append(
                    Finding(
                        rule_id="EML-SPOOF-002",
                        rule_version="1.0.0",
                        category="PHISHING",
                        title="From / Return-Path Domain Alignment Mismatch",
                        description=f"Visible From domain ({sender_dom}) differs from envelope Return-Path domain ({ret_dom}).",
                        severity=FindingSeverity.LOW,
                        confidence=ConfidenceLevel.MEDIUM,
                        score_impact=10,
                        evidence_source=self.name,
                        object_reference="From / Return-Path Headers",
                        mitre_technique="T1566",
                        explanation="Domain alignment mismatch can indicate envelope spoofing or third-party bulk-mail relay infrastructure.",
                    )
                )

        # 4. Authentication Header Claims (SPF / DKIM / DMARC)
        auth_results = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")
        dkim_sig = msg.get("DKIM-Signature", "")
        details["authentication_results"] = str(auth_results)
        details["received_spf"] = str(received_spf)
        details["has_dkim_signature_header"] = bool(dkim_sig)

        if auth_results or received_spf:
            auth_text = f"{auth_results} {received_spf}".lower()
            if "spf=fail" in auth_text or "spf=softfail" in auth_text or auth_text.strip().startswith("fail"):
                findings.append(
                    Finding(
                        rule_id="EML-AUTH-001",
                        rule_version="1.1.0",
                        category="AUTHENTICATION",
                        title="SPF Authentication Failure Claim in Header",
                        description="Message header Authentication-Results/Received-SPF reports SPF failure or softfail.",
                        severity=FindingSeverity.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        score_impact=20,
                        evidence_source=self.name,
                        object_reference="Authentication-Results / Received-SPF",
                        explanation="Header claims sending IP failed SPF check. Remember that email header strings are self-reported artifacts, not independently verified cryptographic proof.",
                    )
                )
            if "dkim=fail" in auth_text:
                findings.append(
                    Finding(
                        rule_id="EML-AUTH-002",
                        rule_version="1.1.0",
                        category="AUTHENTICATION",
                        title="DKIM Failure Claim in Header",
                        description="Message header Authentication-Results reports DKIM signature check failure.",
                        severity=FindingSeverity.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        score_impact=20,
                        evidence_source=self.name,
                        object_reference="Authentication-Results",
                        explanation="Header claims DKIM verification failed. Header fields represent upstream server claims captured in the EML artifact.",
                    )
                )
            if "dmarc=fail" in auth_text:
                findings.append(
                    Finding(
                        rule_id="EML-AUTH-003",
                        rule_version="1.0.0",
                        category="AUTHENTICATION",
                        title="DMARC Failure Claim in Header",
                        description="Message header Authentication-Results reports DMARC policy failure.",
                        severity=FindingSeverity.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        score_impact=20,
                        evidence_source=self.name,
                        object_reference="Authentication-Results",
                        explanation="Header claims message failed DMARC domain alignment or policy validation.",
                    )
                )

        # 5. MIME Structure, Attachment Hashing & Bounded Body Extraction
        attachments_info: List[Dict[str, Any]] = []
        body_text_parts: List[str] = []
        mime_parts: List[Dict[str, Any]] = []

        for idx, part in enumerate(msg.walk()):
            if idx >= 100:
                break
            content_disposition = part.get_content_disposition()
            content_type = part.get_content_type()
            mime_parts.append({
                "index": idx,
                "content_type": content_type,
                "disposition": content_disposition or "inline",
                "filename": part.get_filename(),
            })

            if content_disposition in ("attachment", "inline") and part.get_filename():
                att_name = part.get_filename() or "unnamed_attachment"
                payload_bytes = part.get_payload(decode=True) or b""
                att_hashes = compute_hashes_from_bytes(payload_bytes)
                att_ext = Path(att_name).suffix.lower()

                attachments_info.append({
                    "filename": att_name,
                    "content_type": content_type,
                    "size_bytes": len(payload_bytes),
                    "sha256": att_hashes.sha256,
                    "md5": att_hashes.md5,
                })

                if att_ext in self.DANGEROUS_ATTACHMENT_EXTENSIONS:
                    findings.append(
                        Finding(
                            rule_id="EML-ATT-001",
                            rule_version="1.1.0",
                            category="ATTACHMENT",
                            title=f"High-Risk Attachment Detected [{att_name}]",
                            description=f"Email carries a high-risk executable/script attachment ({att_name}) with SHA-256: {att_hashes.sha256}",
                            severity=FindingSeverity.HIGH,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=35,
                            evidence_source=self.name,
                            object_reference=att_name,
                            mitre_technique="T1566.001",
                            explanation="Executable, script, macro-enabled, or disk-image attachments are a primary phishing delivery vector.",
                        )
                    )

            elif content_type in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text_parts.append(payload[: 2 * 1024 * 1024].decode("utf-8", errors="ignore"))
                except Exception:
                    pass

        details["mime_structure"] = mime_parts
        details["attachments"] = attachments_info

        # 6. Extract Defanged URLs & Domain/IP IOCs from Body (Bounded, No Network Calls)
        combined_body = "\n".join(body_text_parts)
        extracted_urls = sorted(set(self.URL_REGEX.findall(combined_body)))[:50]
        seen_url_set: set[str] = set()
        for url in extracted_urls:
            clean_url = url.rstrip(".,;)>'\"")
            if clean_url not in seen_url_set:
                seen_url_set.add(clean_url)
                iocs.append(
                    IOCRecord(
                        ioc_type=IOCType.URL,
                        value=clean_url,
                        defanged_value=defang_ioc(clean_url),
                        context="Email Body Hyperlink",
                        confidence=ConfidenceLevel.CONFIRMED,
                    )
                )

        # Also extract non-duplicate domain/IP/hash IOCs from body
        extra_iocs = ioc_extractor.extract_iocs(combined_body[:512 * 1024], context_label="Email Body Text")
        existing_ioc_keys = {(i.ioc_type, i.value) for i in iocs}
        for rec in extra_iocs:
            if (rec.ioc_type, rec.value) not in existing_ioc_keys and rec.ioc_type != IOCType.URL:
                existing_ioc_keys.add((rec.ioc_type, rec.value))
                iocs.append(rec)

        details["body_url_count"] = len(seen_url_set)

        output.findings = self.finalize_findings(findings)
        output.iocs = iocs
        output.timeline_events = timeline
        output.details = details
        return output

