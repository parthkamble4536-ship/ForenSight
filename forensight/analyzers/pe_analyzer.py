"""
Windows Portable Executable (PE) forensic static analyzer.

Performs deep structural triage on EXE, DLL, and SYS binaries without execution.
Inspects headers, section anomalies, entropy, packing, suspicious imports,
overlay data, and digital signature metadata.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pefile

from forensight.analyzers.base import AnalyzerOutput, BaseAnalyzer
from forensight.core.types import (
    ConfidenceLevel,
    EvidenceMetadata,
    Finding,
    FindingSeverity,
    TimelineEvent,
    TimelineEventType,
)


class PEAnalyzer(BaseAnalyzer):
    """
    Static forensic analyzer for Windows Portable Executable (PE) files.
    """

    SUSPICIOUS_IMPORT_CATALOG: Dict[str, Dict[str, Any]] = {
        # Process Injection & Memory Manipulation
        "VirtualAlloc": {"category": "PROCESS_INJECTION", "mitre": "T1055", "severity": FindingSeverity.HIGH},
        "VirtualAllocEx": {"category": "PROCESS_INJECTION", "mitre": "T1055", "severity": FindingSeverity.HIGH},
        "WriteProcessMemory": {"category": "PROCESS_INJECTION", "mitre": "T1055", "severity": FindingSeverity.HIGH},
        "CreateRemoteThread": {"category": "PROCESS_INJECTION", "mitre": "T1055.002", "severity": FindingSeverity.CRITICAL},
        "QueueUserAPC": {"category": "PROCESS_INJECTION", "mitre": "T1055.004", "severity": FindingSeverity.HIGH},
        "SetThreadContext": {"category": "PROCESS_INJECTION", "mitre": "T1055.003", "severity": FindingSeverity.HIGH},
        "NtMapViewOfSection": {"category": "PROCESS_INJECTION", "mitre": "T1055", "severity": FindingSeverity.HIGH},

        # Keylogging & Input Capture
        "SetWindowsHookExA": {"category": "KEYLOGGING", "mitre": "T1056.001", "severity": FindingSeverity.HIGH},
        "SetWindowsHookExW": {"category": "KEYLOGGING", "mitre": "T1056.001", "severity": FindingSeverity.HIGH},
        "GetAsyncKeyState": {"category": "KEYLOGGING", "mitre": "T1056.001", "severity": FindingSeverity.MEDIUM},
        "GetKeyState": {"category": "KEYLOGGING", "mitre": "T1056.001", "severity": FindingSeverity.LOW},
        "GetClipboardData": {"category": "CREDENTIAL_ACCESS", "mitre": "T1115", "severity": FindingSeverity.MEDIUM},

        # Anti-Debugging & Evasion
        "IsDebuggerPresent": {"category": "ANTI_DEBUG", "mitre": "T1497", "severity": FindingSeverity.LOW},
        "CheckRemoteDebuggerPresent": {"category": "ANTI_DEBUG", "mitre": "T1497", "severity": FindingSeverity.MEDIUM},
        "OutputDebugStringA": {"category": "ANTI_DEBUG", "mitre": "T1497", "severity": FindingSeverity.INFO},
        "NtQueryInformationProcess": {"category": "ANTI_DEBUG", "mitre": "T1497", "severity": FindingSeverity.HIGH},

        # Persistence & Service Installation
        "RegSetValueExA": {"category": "PERSISTENCE", "mitre": "T1547.001", "severity": FindingSeverity.LOW},
        "RegSetValueExW": {"category": "PERSISTENCE", "mitre": "T1547.001", "severity": FindingSeverity.LOW},
        "CreateServiceA": {"category": "PERSISTENCE", "mitre": "T1543.003", "severity": FindingSeverity.HIGH},
        "CreateServiceW": {"category": "PERSISTENCE", "mitre": "T1543.003", "severity": FindingSeverity.HIGH},

        # Network / C2
        "InternetOpenA": {"category": "NETWORK", "mitre": "T1071.001", "severity": FindingSeverity.LOW},
        "InternetConnectA": {"category": "NETWORK", "mitre": "T1071.001", "severity": FindingSeverity.LOW},
        "HttpSendRequestA": {"category": "NETWORK", "mitre": "T1071.001", "severity": FindingSeverity.MEDIUM},
        "WSAStartup": {"category": "NETWORK", "mitre": "T1071", "severity": FindingSeverity.INFO},
    }

    PACKER_SECTION_NAMES: Set[str] = {
        "upx0", "upx1", "upx2", "aspack", "adata", "nsp0", "nsp1",
        "themida", "vmp0", "vmp1", ".petite", ".fsg", "pebundle"
    }

    @property
    def name(self) -> str:
        return "PE Forensic Analyzer"

    @property
    def supported_types(self) -> List[str]:
        return ["PE"]

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        timeline: List[TimelineEvent] = []
        details: Dict[str, Any] = {}

        try:
            pe = pefile.PE(str(file_path), fast_load=False)
        except pefile.PEFormatError as err:
            findings.append(
                Finding(
                    rule_id="PE-CORRUPT-001",
                    category="ANOMALY",
                    title="Malformed PE Header",
                    description=f"File possesses an MZ magic header but contains corrupted PE structures: {err}",
                    severity=FindingSeverity.HIGH,
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=30,
                    evidence_source=self.name,
                    explanation="Crafted or corrupted headers can be used to disrupt static analysis tools or exploit parser flaws.",
                )
            )
            output.findings = findings
            return output

        # 1. Architecture & Machine Details
        machine_code = pe.FILE_HEADER.Machine
        machine_name = pefile.MACHINE_TYPE.get(machine_code, f"Unknown ({hex(machine_code)})")
        subsystem_code = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
        subsystem_name = pefile.SUBSYSTEM_TYPE.get(subsystem_code, f"Unknown ({subsystem_code})")

        details["machine"] = machine_name
        details["subsystem"] = subsystem_name
        details["number_of_sections"] = pe.FILE_HEADER.NumberOfSections

        # 2. Compile Timestamp Analysis
        compile_timestamp = pe.FILE_HEADER.TimeDateStamp
        details["compile_timestamp_raw"] = compile_timestamp

        if compile_timestamp > 0:
            try:
                compile_dt = datetime.fromtimestamp(compile_timestamp, tz=timezone.utc)
                details["compile_timestamp_iso"] = compile_dt.isoformat()
                now_dt = datetime.now(timezone.utc)

                timeline.append(
                    TimelineEvent(
                        event_id=f"compile-{compile_timestamp}",
                        evidence_id="",
                        timestamp=compile_dt,
                        timestamp_type=TimelineEventType.COMPILE_TIME,
                        source="PE File Header (TimeDateStamp)",
                        description=f"PE binary compilation timestamp: {compile_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                        confidence=ConfidenceLevel.HIGH,
                    )
                )

                # Flag future or unrealistic timestamps (timestomping indicator)
                if (compile_dt - now_dt).total_seconds() > 86400:  # > 1 day in future
                    findings.append(
                        Finding(
                            rule_id="PE-TIMESTAMP-001",
                            category="ANOMALY",
                            title="Future Compilation Timestamp (Timestomping)",
                            description=f"Binary header contains a future compilation timestamp: {compile_dt.isoformat()}",
                            severity=FindingSeverity.MEDIUM,
                            confidence=ConfidenceLevel.HIGH,
                            score_impact=20,
                            evidence_source=self.name,
                            explanation="Adversaries frequently alter PE compilation timestamps to deceive investigators and confuse chronological triage.",
                        )
                    )
                elif compile_dt.year < 1995:
                    findings.append(
                        Finding(
                            rule_id="PE-TIMESTAMP-002",
                            category="ANOMALY",
                            title="Anomalously Historic Compilation Timestamp",
                            description=f"Binary claims compilation date in {compile_dt.year}, predating modern PE toolchains.",
                            severity=FindingSeverity.LOW,
                            confidence=ConfidenceLevel.MEDIUM,
                            score_impact=10,
                            evidence_source=self.name,
                            explanation="Artificially set historic timestamps often indicate timestamp wiping or stomping.",
                        )
                    )
            except (ValueError, OSError):
                pass
        else:
            findings.append(
                Finding(
                    rule_id="PE-TIMESTAMP-003",
                    category="ANOMALY",
                    title="Zeroed Compilation Timestamp",
                    description="PE compilation timestamp is set to zero (1970-01-01), indicating stripped or stomped metadata.",
                    severity=FindingSeverity.LOW,
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=10,
                    evidence_source=self.name,
                    explanation="Build tools such as Go or intentional timestomping utilities commonly zero this field.",
                )
            )

        # 3. Section Table Analysis & Entropy
        sections_data: List[Dict[str, Any]] = []
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_section_found = False

        for sec in pe.sections:
            sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00").lower()
            entropy = sec.get_entropy()
            raw_size = sec.SizeOfRawData
            virt_size = sec.Misc_VirtualSize
            characteristics = sec.Characteristics

            is_writable = (characteristics & 0x80000000) != 0
            is_executable = (characteristics & 0x20000000) != 0

            # Check if entry point is in this section
            if sec.VirtualAddress <= entry_point < (sec.VirtualAddress + max(raw_size, virt_size)):
                entry_point_section_found = True

            sec_info = {
                "name": sec_name,
                "virtual_address": hex(sec.VirtualAddress),
                "virtual_size": virt_size,
                "raw_size": raw_size,
                "entropy": round(entropy, 4),
                "is_writable": is_writable,
                "is_executable": is_executable,
            }
            sections_data.append(sec_info)

            # High Section Entropy (Packer/Crypter indicator)
            if entropy > 7.2 and raw_size > 4096:
                findings.append(
                    Finding(
                        rule_id="PE-PACKING-001",
                        category="PACKING",
                        title=f"High Entropy Section [{sec_name}]",
                        description=f"Section [{sec_name}] has an elevated Shannon entropy of {entropy:.2f}/8.0, indicating encryption or compression.",
                        severity=FindingSeverity.MEDIUM,
                        confidence=ConfidenceLevel.HIGH,
                        score_impact=20,
                        evidence_source=self.name,
                        object_reference=sec_name,
                        explanation="Legitimate software rarely exceeds 7.2 entropy in code sections unless packed (e.g. UPX) or containing encrypted payloads.",
                    )
                )

            # Known Packer Section Name
            if sec_name in self.PACKER_SECTION_NAMES:
                findings.append(
                    Finding(
                        rule_id="PE-PACKING-002",
                        category="PACKING",
                        title=f"Recognized Packer Section Name [{sec_name}]",
                        description=f"Section name [{sec_name}] is associated with executable runtime packers (e.g., UPX, Themida, ASPack).",
                        severity=FindingSeverity.MEDIUM,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=25,
                        evidence_source=self.name,
                        object_reference=sec_name,
                        explanation="Packers obfuscate binary code to hinder reverse engineering. While used in some commercial apps, they are heavily prevalent in malware.",
                    )
                )

            # Writable and Executable Section (W^X violation)
            if is_writable and is_executable:
                findings.append(
                    Finding(
                        rule_id="PE-SEC-001",
                        category="SECURITY_VIOLATION",
                        title=f"Writable and Executable Section [{sec_name}]",
                        description=f"Section [{sec_name}] possesses both WRITE and EXECUTE permissions simultaneously.",
                        severity=FindingSeverity.HIGH,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=25,
                        evidence_source=self.name,
                        object_reference=sec_name,
                        explanation="Self-modifying code or unpacked shellcode execution stages require RWX memory, which violates standard secure compilation practices.",
                    )
                )

        details["sections"] = sections_data

        # 4. Entry Point Anomaly
        if not entry_point_section_found and pe.FILE_HEADER.NumberOfSections > 0:
            findings.append(
                Finding(
                    rule_id="PE-ANOMALY-002",
                    category="ANOMALY",
                    title="Entry Point Outside Known Sections",
                    description=f"Entry point address ({hex(entry_point)}) falls outside all defined sections.",
                    severity=FindingSeverity.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=30,
                    evidence_source=self.name,
                    explanation="Entry points outside mapped sections often indicate manual PE header manipulation or file infection techniques.",
                )
            )

        # 5. Suspicious Imported Functions
        detected_suspicious_imports: List[Dict[str, Any]] = []
        total_imports = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
                for imp in entry.imports:
                    total_imports += 1
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                        if func_name in self.SUSPICIOUS_IMPORT_CATALOG:
                            cat_info = self.SUSPICIOUS_IMPORT_CATALOG[func_name]
                            detected_suspicious_imports.append({
                                "dll": dll_name,
                                "function": func_name,
                                "category": cat_info["category"],
                                "mitre": cat_info["mitre"],
                            })

        details["total_imports"] = total_imports
        details["suspicious_imports_count"] = len(detected_suspicious_imports)

        if detected_suspicious_imports:
            # Group by category for clear explainable reporting
            categories_seen = {item["category"] for item in detected_suspicious_imports}
            top_funcs = [item["function"] for item in detected_suspicious_imports[:5]]
            findings.append(
                Finding(
                    rule_id="PE-IMPORT-001",
                    category="CAPABILITY",
                    title=f"Suspicious API Imports Detected ({', '.join(categories_seen)})",
                    description=(
                        f"Binary imports {len(detected_suspicious_imports)} high-risk Windows APIs: "
                        f"{', '.join(top_funcs)}{'...' if len(detected_suspicious_imports) > 5 else ''}."
                    ),
                    severity=FindingSeverity.MEDIUM if len(detected_suspicious_imports) < 4 else FindingSeverity.HIGH,
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=15 + min(25, len(detected_suspicious_imports) * 5),
                    evidence_source=self.name,
                    explanation="These APIs enable process injection, keylogging, or evasion. Note: legitimate utilities (e.g. debuggers, installers) also use some of these APIs.",
                )
            )

        # 6. Digital Signature Presence
        has_signature = False
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if security_dir.VirtualAddress > 0 and security_dir.Size > 0:
            has_signature = True

        details["is_digitally_signed"] = has_signature
        if not has_signature:
            findings.append(
                Finding(
                    rule_id="PE-SIGN-001",
                    category="SIGNATURE",
                    title="Unsigned Binary",
                    description="The executable does not contain an embedded Authenticode digital signature.",
                    severity=FindingSeverity.INFO,
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=5,
                    evidence_source=self.name,
                    explanation="Most enterprise and system software is digitally signed. Unsigned binaries require additional scrutiny.",
                )
            )

        # 7. Overlay Data Check
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None and overlay_offset < file_path.stat().st_size:
            overlay_size = file_path.stat().st_size - overlay_offset
            if overlay_size > 512:
                details["overlay_size_bytes"] = overlay_size
                findings.append(
                    Finding(
                        rule_id="PE-OVERLAY-001",
                        category="ANOMALY",
                        title=f"Binary Overlay Data Appended ({overlay_size:,} bytes)",
                        description=f"File contains {overlay_size:,} bytes of data appended past the last mapped PE section.",
                        severity=FindingSeverity.LOW,
                        confidence=ConfidenceLevel.HIGH,
                        score_impact=10,
                        evidence_source=self.name,
                        explanation="Overlays are used by installers, self-extractors, and digital signatures, but also by droppers storing appended encrypted payloads.",
                    )
                )

        output.findings = findings
        output.timeline_events = timeline
        output.details = details
        return output
