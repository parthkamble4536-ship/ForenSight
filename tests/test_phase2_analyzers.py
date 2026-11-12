"""
Phase 2 P1 tests:
- Enhanced PE, PDF, DOCX, EML, ZIP, Text/IOC analyzers
- Detection provenance (finding_id, rule_version, analyzer_name, analyzer_version, offset, detected_at)
- Bounded nested archive inspection & XML bomb / resource guards
- Persistence of provenance & IOC offsets in SQLite
"""

import io
import struct
import uuid
import zipfile
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from forensight.analyzers import get_analyzer_for_type
from forensight.analyzers.archive_analyzer import ArchiveAnalyzer
from forensight.analyzers.docx_analyzer import DocxAnalyzer
from forensight.analyzers.email_analyzer import EmailAnalyzer
from forensight.analyzers.pdf_analyzer import PDFAnalyzer
from forensight.analyzers.pe_analyzer import PEAnalyzer
from forensight.analyzers.text_analyzer import TextAnalyzer
from forensight.core.types import EvidenceMetadata
from forensight.database.models import Base, FindingModel, IOCModel
from forensight.api.routes import upload_evidence
from forensight.crypto.keys import key_manager
from forensight.storage.manager import evidence_vault
from starlette.datastructures import Headers, UploadFile


def _build_pe_with_rwx_and_zero_raw() -> bytes:
    """Build deterministic PE32 synthetic test binary with RWX + zero-raw executable section."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)
    pe_data = bytearray(dos_header)
    pe_data.extend(b"\x00" * (0x80 - len(pe_data)))
    pe_data.extend(b"PE\x00\x00")
    # 2 sections
    pe_data.extend(struct.pack("<HHIIIHH", 0x014C, 2, 0x65000000, 0, 0, 224, 0x0102))

    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x010B)
    struct.pack_into("<I", opt_header, 16, 0x1000)
    struct.pack_into("<I", opt_header, 28, 0x00400000)
    struct.pack_into("<I", opt_header, 32, 0x1000)
    struct.pack_into("<I", opt_header, 36, 0x200)
    struct.pack_into("<I", opt_header, 56, 0x3000)
    struct.pack_into("<I", opt_header, 60, 0x400)
    struct.pack_into("<H", opt_header, 68, 2)
    struct.pack_into("<I", opt_header, 92, 16)
    pe_data.extend(opt_header)

    # Section 1: .text RWX (0xE0000020)
    pe_data.extend(struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x500, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0xE0000020))
    # Section 2: upx0 zero raw size executable (0x60000020)
    pe_data.extend(struct.pack("<8sIIIIIIHHI", b"upx0\x00\x00\x00\x00", 0x1000, 0x2000, 0, 0, 0, 0, 0, 0, 0x60000020))

    pe_data.extend(b"\x00" * (0x400 - len(pe_data)))
    pe_data.extend(b"\x90" * 0x200)
    return bytes(pe_data)


class TestPhase2Analyzers:
    """Comprehensive Phase 2 analyzer enhancement & provenance tests."""

    def test_pe_analyzer_enhanced_fields_and_provenance(self, tmp_path: Path) -> None:
        pe_bytes = _build_pe_with_rwx_and_zero_raw()
        pe_path = tmp_path / "rwx_stub.exe"
        pe_path.write_bytes(pe_bytes)

        meta = EvidenceMetadata(
            file_size_bytes=len(pe_bytes),
            identified_type="PE",
            mime_type="application/vnd.microsoft.portable-executable",
            declared_extension=".exe",
            entropy=4.0,
        )
        out = PEAnalyzer().analyze(pe_path, meta)

        assert out.details["pe_format"] == "PE32"
        assert out.details["is_dll"] is False
        assert "authenticode_metadata" in out.details
        assert "exports" in out.details
        assert "resources" in out.details
        assert "debug_info" in out.details
        assert out.details["sections"][0]["permissions"] == "R/W/X"

        rule_ids = {f.rule_id for f in out.findings}
        assert "PE-SEC-001" in rule_ids
        assert "PE-SEC-002" in rule_ids
        assert "PE-PACKING-002" in rule_ids

        # Every finding must include complete provenance
        for f in out.findings:
            assert f.finding_id
            assert f.rule_version
            assert f.analyzer_name == "PE Forensic Analyzer"
            assert f.analyzer_version == "2.1.0"
            assert f.detected_at is not None

        assert out.timeline_events[0].original_timestamp is not None

    def test_pdf_analyzer_forms_richmedia_and_uri_dedup(self, tmp_path: Path) -> None:
        pdf_bytes = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Catalog /AcroForm 2 0 R /RichMedia 3 0 R >>\nendobj\n"
            b"2 0 obj\n<< /XFA true >>\nendobj\n"
            b"3 0 obj\n<< /S /URI /URI (http://c2.example.org/payload) >>\nendobj\n"
            b"4 0 obj\n<< /S /URI /URI (http://c2.example.org/payload) >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        pdf_path = tmp_path / "forms.pdf"
        pdf_path.write_bytes(pdf_bytes)

        meta = EvidenceMetadata(
            file_size_bytes=len(pdf_bytes),
            identified_type="PDF",
            mime_type="application/pdf",
            declared_extension=".pdf",
            entropy=4.2,
        )
        out = PDFAnalyzer().analyze(pdf_path, meta)

        rule_ids = {f.rule_id for f in out.findings}
        assert "PDF-FORM-001" in rule_ids
        assert "PDF-MEDIA-001" in rule_ids
        assert out.details["acroform_count"] == 1
        assert out.details["xfa_count"] == 1
        assert len([i for i in out.iocs if i.value == "http://c2.example.org/payload"]) == 1
        assert all(f.analyzer_name == "PDF Forensic Analyzer" and f.analyzer_version == "2.1.0" for f in out.findings)
        form_finding = next(f for f in out.findings if f.rule_id == "PDF-FORM-001")
        assert form_finding.offset is not None

    def test_docx_external_relationship_and_provenance(self, tmp_path: Path) -> None:
        doc_path = tmp_path / "ext_link.docx"
        rels = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="http://tracking.example.net/beacon.png" TargetMode="External"/>'
            '</Relationships>'
        )
        with zipfile.ZipFile(doc_path, "w") as zf:
            zf.writestr("word/document.xml", "<w:document/>")
            zf.writestr("word/_rels/document.xml.rels", rels)

        meta = EvidenceMetadata(
            file_size_bytes=doc_path.stat().st_size,
            identified_type="DOCX",
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            declared_extension=".docx",
            entropy=4.5,
        )
        out = DocxAnalyzer().analyze(doc_path, meta)

        assert any(f.rule_id == "DOCX-EXTREL-001" for f in out.findings)
        assert len(out.details["external_relationship_details"]) == 1
        assert all(f.analyzer_version == "2.1.0" and f.finding_id for f in out.findings)

    def test_email_analyzer_does_not_claim_msg_and_checks_dmarc_return_path(self, tmp_path: Path) -> None:
        assert "MSG" not in EmailAnalyzer().supported_types
        assert get_analyzer_for_type("MSG").name != "Email Forensic Analyzer"

        eml_path = tmp_path / "spoof_dmarc.eml"
        eml_path.write_bytes(
            b"From: Finance <billing@trusted.com>\n"
            b"Return-Path: <bounce@evil-sender.xyz>\n"
            b"To: user@trusted.com\n"
            b"Subject: Wire Update\n"
            b"Date: Tue, 10 Nov 2026 12:00:00 +0000\n"
            b"Authentication-Results: mx.trusted.com; spf=pass; dmarc=fail\n"
            b"MIME-Version: 1.0\nContent-Type: text/plain\n\n"
            b"Visit http://evil-c2.org/login\n"
        )
        meta = EvidenceMetadata(
            file_size_bytes=eml_path.stat().st_size,
            identified_type="EML",
            mime_type="message/rfc822",
            declared_extension=".eml",
            entropy=4.1,
        )
        out = EmailAnalyzer().analyze(eml_path, meta)

        rule_ids = {f.rule_id for f in out.findings}
        assert "EML-SPOOF-002" in rule_ids
        assert "EML-AUTH-003" in rule_ids
        assert "self-reported" in out.details["authentication_disclaimer"].lower() or "claims" in out.details["authentication_disclaimer"].lower()
        assert len(out.details["mime_structure"]) >= 1

    def test_archive_analyzer_bounded_nested_zip_inspection(self, tmp_path: Path) -> None:
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as inner_zf:
            inner_zf.writestr("subdir/invoice.pdf.exe", b"MZ\x90\x00dummy")
        outer_path = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer_path, "w") as outer_zf:
            outer_zf.writestr("nested.zip", inner_buf.getvalue())

        meta = EvidenceMetadata(
            file_size_bytes=outer_path.stat().st_size,
            identified_type="ZIP",
            mime_type="application/zip",
            declared_extension=".zip",
            entropy=5.5,
        )
        out = ArchiveAnalyzer().analyze(outer_path, meta)

        rule_ids = {f.rule_id for f in out.findings}
        assert "ARCH-NESTED-001" in rule_ids
        assert "ARCH-DECEPTION-001" in rule_ids
        assert "nested.zip!/subdir/invoice.pdf.exe" in out.details["double_extension_entries"]
        assert "directory_summary" in out.details
        assert any(e["depth"] == 1 for e in out.details["entries"])

    def test_text_analyzer_records_offsets_and_persists_provenance(self, tmp_path: Path) -> None:
        key_manager.load_or_create_keypair()
        payload = (
            b"PREFIX_PADDING_BYTES____"
            b"cmd /c vssadmin delete shadows /all /quiet "
            b"http://staging-" + uuid.uuid4().hex.encode() + b".example.org/bin\n"
        )
        txt_path = tmp_path / "attack.log"
        txt_path.write_bytes(payload)

        meta = EvidenceMetadata(
            file_size_bytes=len(payload),
            identified_type="TXT",
            mime_type="text/plain",
            declared_extension=".log",
            entropy=4.3,
        )
        out = TextAnalyzer().analyze(txt_path, meta)

        ransom_f = next(f for f in out.findings if f.rule_id == "TXT-RANSOM-001")
        assert ransom_f.offset == payload.find(b"vssadmin delete shadows")
        assert ransom_f.analyzer_version == "2.1.0"
        assert len(out.iocs) >= 1
        assert out.iocs[0].offset is not None

        # Verify persistence into SQLite FindingModel & IOCModel
        db_path = tmp_path / "prov.db"
        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        upload = UploadFile(file=io.BytesIO(payload), filename="attack.log", headers=Headers({"content-type": "text/plain"}))
        with SessionLocal() as db:
            up_res = upload_evidence(file=upload, case_id=None, db=db)
            ev_id = up_res["evidence_id"]
            try:
                f_row = db.query(FindingModel).filter(FindingModel.rule_id == "TXT-RANSOM-001").first()
                assert f_row is not None
                assert f_row.analyzer_name == "Text & Log Forensic Analyzer"
                assert f_row.analyzer_version == "2.1.0"
                assert f_row.rule_version == "1.1.0"
                assert f_row.evidence_reference == ev_id
                assert f_row.offset == ransom_f.offset

                ioc_row = db.query(IOCModel).first()
                assert ioc_row is not None
                assert ioc_row.offset is not None
                assert ioc_row.occurrences >= 1
            finally:
                evidence_vault.delete_evidence(ev_id)
