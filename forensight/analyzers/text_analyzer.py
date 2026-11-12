"""
Text and log forensic static analyzer (safe bounded triage and IOC extraction).

Performs bounded line reading, encoding detection, suspicious command line hunting,
and Indicator of Compromise extraction from plaintext, scripts, and logs.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from forensight.analyzers.base import AnalyzerOutput, BaseAnalyzer
from forensight.core.config import settings
from forensight.core.types import (
    ConfidenceLevel,
    EvidenceMetadata,
    Finding,
    FindingSeverity,
    IOCRecord,
)
from forensight.extraction.encoding import detect_encoding
from forensight.extraction.strings import StringExtractor
from forensight.intelligence.ioc_extractor import ioc_extractor


class TextAnalyzer(BaseAnalyzer):
    """
    Static forensic analyzer for plaintext files, logs, scripts, and configuration artifacts.
    """

    SUSPICIOUS_KEYWORD_PATTERNS = {
        "powershell -enc": {
            "rule_id": "TXT-PS-001",
            "category": "COMMAND_LINE",
            "title": "Encoded PowerShell Command Execution",
            "description": "Log/script contains base64-encoded PowerShell execution command ('powershell -enc').",
            "severity": FindingSeverity.HIGH,
            "score_impact": 35,
            "mitre": "T1059.001",
            "explanation": "Encoded PowerShell commands obscure malicious script execution from casual log inspection and endpoint defenses.",
        },
        "iex": {
            "rule_id": "TXT-PS-002",
            "category": "COMMAND_LINE",
            "title": "PowerShell Dynamic Code Execution Invoke-Expression (IEX)",
            "description": "Text references 'IEX' (Invoke-Expression), commonly used in fileless memory execution.",
            "severity": FindingSeverity.MEDIUM,
            "score_impact": 20,
            "mitre": "T1059.001",
            "explanation": "Adversaries chain IEX with DownloadString to download and run payloads in memory without writing to disk.",
        },
        "vssadmin delete shadows": {
            "rule_id": "TXT-RANSOM-001",
            "category": "INHIBIT_RECOVERY",
            "title": "Volume Shadow Copy Deletion Command",
            "description": "Command line contains 'vssadmin delete shadows', characteristic of ransomware impact operations.",
            "severity": FindingSeverity.CRITICAL,
            "score_impact": 50,
            "mitre": "T1490",
            "explanation": "Ransomware operators purge volume shadow copies to prevent victims from restoring encrypted files locally.",
        },
        "certutil -urlcache": {
            "rule_id": "TXT-LOLBIN-001",
            "category": "INGRESS_TOOL_TRANSFER",
            "title": "Living-off-the-Land Binary Ingress Download (Certutil)",
            "description": "Command invokes certutil with -urlcache to download remote files.",
            "severity": FindingSeverity.HIGH,
            "score_impact": 30,
            "mitre": "T1105",
            "explanation": "Certutil is a legitimate Windows utility abused as a LOLBin to fetch remote binaries past firewall policies.",
        },
        "mimikatz": {
            "rule_id": "TXT-CRED-001",
            "category": "CREDENTIAL_DUMPING",
            "title": "Credential Theft Tool Reference (Mimikatz)",
            "description": "Text artifact contains explicit reference to credential dumping utility Mimikatz.",
            "severity": FindingSeverity.HIGH,
            "score_impact": 40,
            "mitre": "T1003",
            "explanation": "Widely utilized post-exploitation tool for dumping LSASS plaintext passwords, hashes, and Kerberos tickets.",
        },
        "bitsadmin /transfer": {
            "rule_id": "TXT-LOLBIN-002",
            "category": "INGRESS_TOOL_TRANSFER",
            "title": "Living-off-the-Land Binary Ingress Download (Bitsadmin)",
            "description": "Command invokes bitsadmin /transfer to fetch or move remote payloads.",
            "severity": FindingSeverity.HIGH,
            "score_impact": 30,
            "mitre": "T1197",
            "explanation": "BITS jobs are frequently abused to download payloads asynchronously.",
        },
        "mshta ": {
            "rule_id": "TXT-LOLBIN-003",
            "category": "SIGNED_BINARY_PROXY_EXECUTION",
            "title": "MSHTA Proxy Script Execution Reference",
            "description": "Text references mshta proxy execution of HTML Applications or inline VBScript/JScript.",
            "severity": FindingSeverity.HIGH,
            "score_impact": 30,
            "mitre": "T1218.005",
            "explanation": "Mshta.exe is used as a living-off-the-land proxy to execute remote HTA/script payloads.",
        },
    }

    @property
    def name(self) -> str:
        return "Text & Log Forensic Analyzer"

    @property
    def version(self) -> str:
        return "2.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["TXT", "LOG", "TEXT", "UNKNOWN"]

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        details: Dict[str, Any] = {}

        # 1. Bounded string extraction (ASCII & UTF-16LE)
        extractor = StringExtractor()
        report = extractor.extract_from_file(file_path)

        # Bound lines analyzed when text/log corpus is large
        bounded_strings = report.strings[: settings.max_text_lines]
        details["total_strings_extracted"] = report.total_found
        details["is_truncated"] = report.is_truncated
        details["string_limit_applied"] = report.limit_applied
        details["max_text_lines_cap"] = settings.max_text_lines
        details["encoding_breakdown"] = {
            "ascii": sum(1 for s in bounded_strings if s.encoding == "ascii"),
            "utf16le": sum(1 for s in bounded_strings if s.encoding == "utf-16le"),
        }

        combined_text = "\n".join(s.value for s in bounded_strings)

        # 2. Encoding detection (bounded 4 KB header sample)
        with open(file_path, "rb") as f:
            sample_bytes = f.read(4096)
        enc_name, enc_conf = detect_encoding(sample_bytes)
        details["detected_encoding"] = enc_name
        details["encoding_confidence"] = enc_conf

        # 3. IOC Extraction with exact string byte-offset & source attribution
        raw_iocs = ioc_extractor.extract_iocs(
            combined_text,
            context_label=f"{self.name} ({file_path.name})",
        )
        iocs: List[IOCRecord] = []
        for ioc in raw_iocs:
            matched_offset: Optional[int] = None
            for ext_str in bounded_strings:
                idx = ext_str.value.find(ioc.value)
                if idx != -1:
                    step = 2 if ext_str.encoding == "utf-16le" else 1
                    matched_offset = ext_str.offset + idx * step
                    break
            iocs.append(
                ioc.model_copy(
                    update={"offset": matched_offset if matched_offset is not None else ioc.offset}
                )
            )

        # 4. Suspicious Command & Indicator Hunting with exact byte offsets
        for pattern_kw, rule in self.SUSPICIOUS_KEYWORD_PATTERNS.items():
            first_offset: Optional[int] = None
            match_count = 0
            for ext_str in bounded_strings:
                idx = ext_str.value.lower().find(pattern_kw)
                if idx != -1:
                    match_count += 1
                    if first_offset is None:
                        step = 2 if ext_str.encoding == "utf-16le" else 1
                        first_offset = ext_str.offset + idx * step
            if match_count > 0:
                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        rule_version="1.1.0",
                        category=rule["category"],
                        title=rule["title"],
                        description=f"{rule['description']} (Observed in {match_count} extracted string(s)).",
                        severity=rule["severity"],
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=rule["score_impact"],
                        evidence_source=self.name,
                        object_reference=pattern_kw,
                        offset=first_offset,
                        mitre_technique=rule["mitre"],
                        explanation=rule["explanation"],
                    )
                )

        output.findings = self.finalize_findings(findings)
        output.iocs = iocs
        output.details = details
        return output

