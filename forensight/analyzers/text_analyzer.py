"""
Text and log forensic static analyzer (safe bounded triage and IOC extraction).

Performs bounded line reading, encoding detection, suspicious command line hunting,
and Indicator of Compromise extraction from plaintext, scripts, and logs.
"""

from pathlib import Path
from typing import Any, Dict, List

from forensight.analyzers.base import AnalyzerOutput, BaseAnalyzer
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
    }

    @property
    def name(self) -> str:
        return "Text & Log Forensic Analyzer"

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

        details["total_strings_extracted"] = report.total_found
        details["is_truncated"] = report.is_truncated
        details["string_limit_applied"] = report.limit_applied

        # Combine extracted strings into coherent corpus for analysis
        combined_text = "\n".join(s.value for s in report.strings)

        # 2. Encoding detection
        sample_bytes = file_path.read_bytes()[:4096]
        enc_name, enc_conf = detect_encoding(sample_bytes)
        details["detected_encoding"] = enc_name
        details["encoding_confidence"] = enc_conf

        # 3. IOC Extraction
        iocs = ioc_extractor.extract_iocs(combined_text, context_label=f"Text/Log ({file_path.name})")

        # 4. Suspicious Command & Indicator Hunting
        text_lower = combined_text.lower()
        for pattern_kw, rule in self.SUSPICIOUS_KEYWORD_PATTERNS.items():
            if pattern_kw in text_lower:
                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=rule["score_impact"],
                        evidence_source=self.name,
                        object_reference=pattern_kw,
                        mitre_technique=rule["mitre"],
                        explanation=rule["explanation"],
                    )
                )

        output.findings = findings
        output.iocs = iocs
        output.details = details
        return output

