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
    def version(self) -> str:
        return "2.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["PE"]

    @staticmethod
    def _section_perm_str(characteristics: int) -> str:
        perms = []
        if characteristics & 0x40000000:
            perms.append("R")
        if characteristics & 0x80000000:
            perms.append("W")
        if characteristics & 0x20000000:
            perms.append("X")
        return "/".join(perms) if perms else "NONE"

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        timeline: List[TimelineEvent] = []
        details: Dict[str, Any] = {}

        pe = None
        try:
            pe = pefile.PE(str(file_path), fast_load=False)
        except pefile.PEFormatError as err:
            findings.append(
                Finding(
                    rule_id="PE-CORRUPT-001",
                    rule_version="1.1.0",
                    category="ANOMALY",
                    title="Malformed PE Header",
                    description=f"File possesses an MZ magic header but contains corrupted PE structures: {err}",
                    severity=FindingSeverity.HIGH,
                    confidence=ConfidenceLevel.CONFIRMED,
                    score_impact=30,
                    evidence_source=self.name,
                    offset=0,
                    explanation="Crafted or corrupted headers can disrupt static analysis tools or exploit parser flaws.",
                )
            )
            output.findings = self.finalize_findings(findings)
            return output

        try:
            # 1. DOS, NT & Optional Header Metadata (PE32 vs PE32+)
            magic = getattr(pe.OPTIONAL_HEADER, "Magic", 0)
            pe_format = "PE32" if magic == 0x10B else ("PE32+" if magic == 0x20B else f"Unknown ({hex(magic)})")
            machine_code = pe.FILE_HEADER.Machine
            machine_name = pefile.MACHINE_TYPE.get(machine_code, f"Unknown ({hex(machine_code)})")
            subsystem_code = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
            subsystem_name = pefile.SUBSYSTEM_TYPE.get(subsystem_code, f"Unknown ({subsystem_code})")
            file_chars = pe.FILE_HEADER.Characteristics
            is_dll = bool(file_chars & 0x2000)

            details["pe_format"] = pe_format
            details["is_dll"] = is_dll
            details["dos_e_lfanew"] = hex(pe.DOS_HEADER.e_lfanew)
            details["machine"] = machine_name
            details["subsystem"] = subsystem_name
            details["image_base"] = hex(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0))
            details["entry_point_rva"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            details["file_characteristics"] = hex(file_chars)
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
                            original_timestamp=f"{compile_timestamp} ({hex(compile_timestamp)})",
                            timestamp_type=TimelineEventType.COMPILE_TIME,
                            source="PE File Header (TimeDateStamp)",
                            description=f"PE header TimeDateStamp claim (unverified metadata): {compile_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                            confidence=ConfidenceLevel.MEDIUM,
                        )
                    )

                    if (compile_dt - now_dt).total_seconds() > 86400:
                        findings.append(
                            Finding(
                                rule_id="PE-TIMESTAMP-001",
                                rule_version="1.1.0",
                                category="ANOMALY",
                                title="Future Compilation Timestamp (Timestomping)",
                                description=f"Binary header claims a future compilation timestamp: {compile_dt.isoformat()}",
                                severity=FindingSeverity.MEDIUM,
                                confidence=ConfidenceLevel.HIGH,
                                score_impact=20,
                                evidence_source=self.name,
                                object_reference="FILE_HEADER.TimeDateStamp",
                                offset=pe.DOS_HEADER.e_lfanew + 8,
                                explanation="Adversaries frequently alter PE compilation timestamps to confuse chronological triage. Reproducible builds may also set non-standard timestamps.",
                            )
                        )
                    elif compile_dt.year < 1995:
                        findings.append(
                            Finding(
                                rule_id="PE-TIMESTAMP-002",
                                rule_version="1.1.0",
                                category="ANOMALY",
                                title="Anomalously Historic Compilation Timestamp",
                                description=f"Binary claims compilation date in {compile_dt.year}, predating modern PE toolchains.",
                                severity=FindingSeverity.LOW,
                                confidence=ConfidenceLevel.MEDIUM,
                                score_impact=10,
                                evidence_source=self.name,
                                object_reference="FILE_HEADER.TimeDateStamp",
                                offset=pe.DOS_HEADER.e_lfanew + 8,
                                explanation="Artificially historic timestamps often indicate timestamp wiping or deliberate stomping.",
                            )
                        )
                except (ValueError, OSError):
                    pass
            else:
                findings.append(
                    Finding(
                        rule_id="PE-TIMESTAMP-003",
                        rule_version="1.1.0",
                        category="ANOMALY",
                        title="Zeroed Compilation Timestamp",
                        description="PE compilation timestamp is set to zero (1970-01-01), indicating stripped or stomped metadata.",
                        severity=FindingSeverity.LOW,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=10,
                        evidence_source=self.name,
                        object_reference="FILE_HEADER.TimeDateStamp",
                        offset=pe.DOS_HEADER.e_lfanew + 8,
                        explanation="Build toolchains (such as Go or deterministic linkers) or timestomping utilities commonly zero this field.",
                    )
                )

            # 3. Section Table Analysis, Permissions & Entropy
            sections_data: List[Dict[str, Any]] = []
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_point_section_found = False

            for sec in pe.sections[:64]:  # Bound pathological section headers
                sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00").lower()
                entropy = sec.get_entropy()
                raw_size = sec.SizeOfRawData
                virt_size = sec.Misc_VirtualSize
                characteristics = sec.Characteristics

                is_writable = (characteristics & 0x80000000) != 0
                is_executable = (characteristics & 0x20000000) != 0
                perms_str = self._section_perm_str(characteristics)

                if sec.VirtualAddress <= entry_point < (sec.VirtualAddress + max(raw_size, virt_size)):
                    entry_point_section_found = True

                sections_data.append({
                    "name": sec_name,
                    "virtual_address": hex(sec.VirtualAddress),
                    "virtual_size": virt_size,
                    "raw_size": raw_size,
                    "pointer_to_raw_data": sec.PointerToRawData,
                    "entropy": round(entropy, 4),
                    "permissions": perms_str,
                    "characteristics": hex(characteristics),
                    "is_writable": is_writable,
                    "is_executable": is_executable,
                })

                if entropy > 7.2 and raw_size > 4096:
                    findings.append(
                        Finding(
                            rule_id="PE-PACKING-001",
                            rule_version="1.1.0",
                            category="PACKING",
                            title=f"High Entropy Section [{sec_name}]",
                            description=f"Section [{sec_name}] exhibits Shannon entropy {entropy:.2f}/8.0, consistent with packing or encrypted payloads.",
                            severity=FindingSeverity.MEDIUM,
                            confidence=ConfidenceLevel.HIGH,
                            score_impact=20,
                            evidence_source=self.name,
                            object_reference=sec_name,
                            offset=sec.PointerToRawData or None,
                            explanation="High entropy indicates compressed, packed, or encrypted data; legitimate installers and DRM-protected apps can also trigger this observation.",
                        )
                    )

                if sec_name in self.PACKER_SECTION_NAMES:
                    findings.append(
                        Finding(
                            rule_id="PE-PACKING-002",
                            rule_version="1.1.0",
                            category="PACKING",
                            title=f"Recognized Packer Section Name [{sec_name}]",
                            description=f"Section name [{sec_name}] matches known executable runtime packers (e.g., UPX, Themida, ASPack).",
                            severity=FindingSeverity.MEDIUM,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=25,
                            evidence_source=self.name,
                            object_reference=sec_name,
                            offset=sec.PointerToRawData or None,
                            explanation="Packers compress or obfuscate code sections. Legitimate compressed utilities also use UPX.",
                        )
                    )

                if is_writable and is_executable:
                    findings.append(
                        Finding(
                            rule_id="PE-SEC-001",
                            rule_version="1.1.0",
                            category="SECURITY_VIOLATION",
                            title=f"Writable and Executable Section [{sec_name}]",
                            description=f"Section [{sec_name}] declares both WRITE and EXECUTE ({perms_str}) flags simultaneously.",
                            severity=FindingSeverity.HIGH,
                            confidence=ConfidenceLevel.CONFIRMED,
                            score_impact=25,
                            evidence_source=self.name,
                            object_reference=sec_name,
                            offset=sec.PointerToRawData or None,
                            explanation="RWX memory violates W^X hardening and is frequently required by self-modifying packers or shellcode stubs.",
                        )
                    )

                if raw_size == 0 and virt_size > 0 and is_executable:
                    findings.append(
                        Finding(
                            rule_id="PE-SEC-002",
                            rule_version="1.0.0",
                            category="ANOMALY",
                            title=f"Zero Raw-Size Executable Section [{sec_name}]",
                            description=f"Executable section [{sec_name}] allocates {virt_size:,} virtual bytes with 0 raw bytes on disk.",
                            severity=FindingSeverity.MEDIUM,
                            confidence=ConfidenceLevel.HIGH,
                            score_impact=15,
                            evidence_source=self.name,
                            object_reference=sec_name,
                            explanation="Zero raw-size executable sections often serve as runtime unpacking targets (such as UPX0).",
                        )
                    )

            details["sections"] = sections_data

            # 4. Entry Point Anomaly
            if not entry_point_section_found and pe.FILE_HEADER.NumberOfSections > 0:
                findings.append(
                    Finding(
                        rule_id="PE-ANOMALY-002",
                        rule_version="1.1.0",
                        category="ANOMALY",
                        title="Entry Point Outside Known Sections",
                        description=f"Entry point RVA ({hex(entry_point)}) falls outside all mapped sections.",
                        severity=FindingSeverity.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        score_impact=30,
                        evidence_source=self.name,
                        object_reference="OPTIONAL_HEADER.AddressOfEntryPoint",
                        offset=pe.DOS_HEADER.e_lfanew + 40,
                        explanation="Entry points outside defined sections can indicate header manipulation or manual payload injection.",
                    )
                )

            # 5. Imports & Exports (Bounded)
            detected_suspicious_imports: List[Dict[str, Any]] = []
            imported_dlls: List[str] = []
            total_imports = 0

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT[:100]:
                    dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
                    if len(imported_dlls) < 30:
                        imported_dlls.append(dll_name)
                    for imp in entry.imports[:500]:
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

            details["imported_dlls"] = imported_dlls
            details["total_imports"] = total_imports
            details["suspicious_imports_count"] = len(detected_suspicious_imports)
            details["suspicious_imports"] = detected_suspicious_imports[:50]

            if detected_suspicious_imports:
                categories_seen = sorted({item["category"] for item in detected_suspicious_imports})
                top_funcs = [item["function"] for item in detected_suspicious_imports[:5]]
                findings.append(
                    Finding(
                        rule_id="PE-IMPORT-001",
                        rule_version="1.1.0",
                        category="CAPABILITY",
                        title=f"Sensitive Windows API Imports ({', '.join(categories_seen)})",
                        description=(
                            f"Binary imports {len(detected_suspicious_imports)} sensitive APIs across {categories_seen}: "
                            f"{', '.join(top_funcs)}{'...' if len(detected_suspicious_imports) > 5 else ''}."
                        ),
                        severity=FindingSeverity.MEDIUM if len(detected_suspicious_imports) < 4 else FindingSeverity.HIGH,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=15 + min(25, len(detected_suspicious_imports) * 5),
                        evidence_source=self.name,
                        object_reference="DIRECTORY_ENTRY_IMPORT",
                        explanation="These imports indicate capabilities (injection, hooking, evasion, network) observed statically; legitimate installers, debuggers, and admin tools also use them.",
                    )
                )

            exports_list: List[str] = []
            total_exports = 0
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:200]:
                    total_exports += 1
                    if exp.name and len(exports_list) < 50:
                        exports_list.append(exp.name.decode("utf-8", errors="ignore"))
            details["exports"] = {"total_exports": total_exports, "symbols": exports_list}

            # 6. Resource Directory Summary (Bounded)
            resource_types: List[str] = []
            resource_count = 0
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries[:30]:
                    type_label = (
                        res_type.name.decode("utf-8", errors="ignore")
                        if getattr(res_type, "name", None)
                        else pefile.RESOURCE_TYPE.get(res_type.struct.Id, str(res_type.struct.Id))
                    )
                    resource_types.append(type_label)
                    if hasattr(res_type, "directory") and res_type.directory:
                        resource_count += len(res_type.directory.entries)
            details["resources"] = {"total_entries": resource_count, "types": resource_types}

            # 7. Debug Directory (CodeView PDB Path)
            debug_entries: List[Dict[str, Any]] = []
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                for dbg in pe.DIRECTORY_ENTRY_DEBUG[:10]:
                    dbg_entry: Dict[str, Any] = {
                        "type": pefile.DEBUG_TYPE.get(dbg.struct.Type, str(dbg.struct.Type)),
                        "timestamp": dbg.struct.TimeDateStamp,
                    }
                    entry_obj = getattr(dbg, "entry", None)
                    if entry_obj is not None and hasattr(entry_obj, "PdbFileName"):
                        raw_pdb = entry_obj.PdbFileName
                        if isinstance(raw_pdb, bytes):
                            dbg_entry["pdb_path"] = raw_pdb.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
                    debug_entries.append(dbg_entry)
            details["debug_info"] = debug_entries

            # 8. Authenticode Security Directory Metadata
            has_signature = False
            sec_offset = 0
            sec_size = 0
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]:
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
                sec_offset = security_dir.VirtualAddress
                sec_size = security_dir.Size
                if sec_offset > 0 and sec_size > 0:
                    has_signature = True

            details["is_digitally_signed"] = has_signature
            details["authenticode_metadata"] = {
                "table_present": has_signature,
                "file_offset": sec_offset,
                "size_bytes": sec_size,
                "caveat": "Presence of WIN_CERTIFICATE directory only indicates embedded signature structure, not cryptographic trust validation.",
            }
            if not has_signature:
                findings.append(
                    Finding(
                        rule_id="PE-SIGN-001",
                        rule_version="1.1.0",
                        category="SIGNATURE",
                        title="No Embedded Authenticode Certificate Table",
                        description="The executable does not contain an IMAGE_DIRECTORY_ENTRY_SECURITY certificate table.",
                        severity=FindingSeverity.INFO,
                        confidence=ConfidenceLevel.CONFIRMED,
                        score_impact=5,
                        evidence_source=self.name,
                        object_reference="IMAGE_DIRECTORY_ENTRY_SECURITY",
                        explanation="Absence of an embedded Authenticode table means no publisher signature is attached; many benign internal or open-source builds are also unsigned.",
                    )
                )

            # 9. Overlay Data Check
            overlay_offset = pe.get_overlay_data_start_offset()
            file_size = file_path.stat().st_size
            if overlay_offset is not None and overlay_offset < file_size:
                overlay_size = file_size - overlay_offset
                details["overlay_offset"] = overlay_offset
                details["overlay_size_bytes"] = overlay_size
                if overlay_size > 512:
                    findings.append(
                        Finding(
                            rule_id="PE-OVERLAY-001",
                            rule_version="1.1.0",
                            category="ANOMALY",
                            title=f"Binary Overlay Data Appended ({overlay_size:,} bytes)",
                            description=f"File contains {overlay_size:,} bytes appended past the final PE section at offset {overlay_offset}.",
                            severity=FindingSeverity.LOW,
                            confidence=ConfidenceLevel.HIGH,
                            score_impact=10,
                            evidence_source=self.name,
                            object_reference="PE Overlay",
                            offset=overlay_offset,
                            explanation="Overlays appear in installers, self-extractors, and Authenticode blocks, as well as droppers carrying appended payloads.",
                        )
                    )
        finally:
            if pe is not None:
                pe.close()

        output.findings = self.finalize_findings(findings)
        output.timeline_events = timeline
        output.details = details
        return output
