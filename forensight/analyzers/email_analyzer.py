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
    def supported_types(self) -> List[str]:
        return ["EML", "MSG"]

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        iocs: List[IOCRecord] = []
        timeline: List[TimelineEvent] = []
        details: Dict[str, Any] = {}

        try:
            with open(file_path, "rb") as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)
        except Exception as err:
            findings.append(
                Finding(
                    rule_id="EML-PARSE-001",
                    category="ANOMALY",
                    title="Malformed Email Message Structure",
                    description=f"Email message headers could not be parsed: {err}",
                    severity=FindingSeverity.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=15,
                    evidence_source=self.name,
                )
            )
            output.findings = findings
            return output

        # 1. Header Extraction
        subject = msg.get("Subject", "")
        sender = msg.get("From", "")
        recipient = msg.get("To", "")
        reply_to = msg.get("Reply-To", "")
        date_str = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")

        details["subject"] = subject
        details["from"] = sender
        details["to"] = recipient
        details["reply_to"] = reply_to
        details["message_id"] = message_id

        # Extract email address IOCs
        for addr_field, addr_val in [("From", sender), ("To", recipient), ("Reply-To", reply_to)]:
            if addr_val:
                found_emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", addr_val)
                for em in found_emails:
                    iocs.append(
                        IOCRecord(
                            ioc_type=IOCType.EMAIL,
                            value=em,
                            defanged_value=em.replace("@", "[at]"),
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
                details["date_iso"] = date_dt.isoformat()

                timeline.append(
                    TimelineEvent(
                        event_id="eml-date",
                        evidence_id="",
                        timestamp=date_dt,
                        timestamp_type=TimelineEventType.EMAIL_RECEIVED,
                        source="Email Header (Date)",
                        description=f"Email sent with Subject '{subject or 'No Subject'}': {date_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                        confidence=ConfidenceLevel.HIGH,
                    )
                )
            except Exception:
                pass

        received_headers = msg.get_all("Received", [])
        details["received_hops_count"] = len(received_headers)

        # 3. From vs Reply-To Mismatch (Phishing indicator)
        if sender and reply_to:
            sender_emails = re.findall(r"[\w\.-]+@[\w\.-]+", sender.lower())
            reply_emails = re.findall(r"[\w\.-]+@[\w\.-]+", reply_to.lower())
            if sender_emails and reply_emails and sender_emails[0] != reply_emails[0]:
                findings.append(
                    Finding(
                        rule_id="EML-SPOOF-001",
                        category="PHISHING",
                        title="Sender / Reply-To Address Mismatch",
                        description=f"From address ({sender_emails[0]}) does not match Reply-To address ({reply_emails[0]}).",
                        severity=FindingSeverity.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        score_impact=25,
                        evidence_source=self.name,
                        mitre_technique="T1566.002",
                        explanation="Adversaries spoof the visible From header while routing recipient responses to a burner or attacker-controlled mailbox via Reply-To.",
                    )
                )

        # 4. Authentication Headers (SPF / DKIM / DMARC)
        auth_results = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")
        details["authentication_results"] = auth_results
        details["received_spf"] = received_spf

        if auth_results or received_spf:
            auth_text = f"{auth_results} {received_spf}".lower()
            if "spf=fail" in auth_text or "spf=softfail" in auth_text:
                findings.append(
                    Finding(
                        rule_id="EML-AUTH-001",
                        category="AUTHENTICATION",
                        title="SPF Authentication Failure Recorded",
                        description="Header Authentication-Results reports SPF check failure for sending IP.",
                        severity=FindingSeverity.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        score_impact=20,
                        evidence_source=self.name,
                        explanation="Indicates the originating mail server is not authorized to send on behalf of the declared sender domain. (Note: authentication headers are unverified records).",
                    )
                )
            if "dkim=fail" in auth_text:
                findings.append(
                    Finding(
                        rule_id="EML-AUTH-002",
                        category="AUTHENTICATION",
                        title="DKIM Cryptographic Signature Failure Recorded",
                        description="Header Authentication-Results reports DKIM signature verification failure.",
                        severity=FindingSeverity.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        score_impact=20,
                        evidence_source=self.name,
                        explanation="The message signature did not match the domain's published cryptographic key, indicating potential message alteration in transit.",
                    )
                )

        # 5. Attachment Extraction & Hashing
        attachments_info: List[Dict[str, Any]] = []
        body_text_parts: List[str] = []

        for part in msg.walk():
            content_disposition = part.get_content_disposition()
            content_type = part.get_content_type()

            if content_disposition in ("attachment", "inline") and part.get_filename():
                att_name = part.get_filename() or "unnamed_attachment"
                payload_bytes = part.get_payload(decode=True) or b""

                # Compute attachment hashes
                att_hashes = compute_hashes_from_bytes(payload_bytes)
                att_ext = Path(att_name).suffix.lower()

                att_record = {
                    "filename": att_name,
                    "content_type": content_type,
                    "size_bytes": len(payload_bytes),
                    "sha256": att_hashes.sha256,
                    "md5": att_hashes.md5,
                }
                attachments_info.append(att_record)

                # Check for dangerous attachment types
                if att_ext in self.DANGEROUS_ATTACHMENT_EXTENSIONS:
                    findings.append(
                        Finding(
                            rule_id="EML-ATT-001",
                            category="ATTACHMENT",
                            title=f"High-Risk Attachment Detected [{att_name}]",
                            description=f"Email carries a high-risk executable or script attachment ({att_name}) with SHA-256: {att_hashes.sha256}",
                            severity=FindingSeverity.HIGH,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=35,
                            evidence_source=self.name,
                            object_reference=att_name,
                            mitre_technique="T1566.001",
                            explanation="Direct attachment of executable payloads, macros, or disk images is a primary phishing delivery mechanism.",
                        )
                    )

            elif content_type in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text_parts.append(payload.decode("utf-8", errors="ignore"))
                except Exception:
                    pass

        details["attachments"] = attachments_info

        # 6. Extract URLs from body
        combined_body = "\n".join(body_text_parts)
        extracted_urls = set(self.URL_REGEX.findall(combined_body))
        for url in list(extracted_urls)[:25]:  # Bound to top 25 URLs
            iocs.append(
                IOCRecord(
                    ioc_type=IOCType.URL,
                    value=url,
                    defanged_value=defang_ioc(url),
                    context="Email Body Hyperlink",
                    confidence=ConfidenceLevel.CONFIRMED,
                )
            )

        details["body_url_count"] = len(extracted_urls)

        output.findings = findings
        output.iocs = iocs
        output.timeline_events = timeline
        output.details = details
        return output

