"""
Forensic report generation engine for ForenSight.

Exports comprehensive investigation reports in Standalone HTML, structured JSON,
and digitally signed PDF formats.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from forensight.core.types import (
    AnalysisResult,
    ChainOfCustodyEvent,
    EvidenceManifest,
)


class ReportGenerator:
    """
    Constructs reproducible, cryptographically verifiable forensic triage reports.
    """

    def generate_json_report(
        self,
        result: AnalysisResult,
        manifest: Optional[EvidenceManifest] = None,
        custody_events: Optional[List[ChainOfCustodyEvent]] = None,
    ) -> str:
        """Export comprehensive analysis results in machine-readable JSON."""
        data = {
            "evidence": result.evidence.model_dump(mode="json"),
            "metadata": result.metadata.model_dump(mode="json"),
            "risk_score": result.risk.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "iocs": [i.model_dump(mode="json") for i in result.iocs],
            "timeline": [t.model_dump(mode="json") for t in result.timeline],
            "manifest": manifest.model_dump(mode="json") if manifest else None,
            "custody_events": [c.model_dump(mode="json") for c in (custody_events or [])],
            "analyzer_details": result.analyzer_details,
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(data, indent=2, default=str)

    def generate_html_report(
        self,
        result: AnalysisResult,
        manifest: Optional[EvidenceManifest] = None,
        custody_events: Optional[List[ChainOfCustodyEvent]] = None,
    ) -> str:
        """
        Produce a self-contained, air-gapped standalone HTML forensic report
        with embedded dark-theme CSS and zero external network calls.
        """
        ev = result.evidence
        meta = result.metadata
        risk = result.risk

        verdict_color = "#10b981" if risk.score < 20 else ("#f59e0b" if risk.score < 70 else "#ef4444")

        findings_rows = ""
        for f in result.findings:
            badge_color = (
                "#ef4444" if f.severity.value in ("CRITICAL", "HIGH")
                else ("#f59e0b" if f.severity.value == "MEDIUM" else "#3b82f6")
            )
            findings_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 10px; font-weight: 600; color: #f8fafc;">{f.rule_id}</td>
                <td style="padding: 10px;"><span style="background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}55; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">{f.severity.value}</span></td>
                <td style="padding: 10px; font-weight: 600; color: #f8fafc;">{f.title}<div style="font-size: 12px; color: #94a3b8; font-weight: normal; margin-top: 4px;">{f.description}</div></td>
                <td style="padding: 10px; font-size: 12px; color: #cbd5e1;">{f.explanation or 'N/A'}</td>
            </tr>
            """

        ioc_rows = ""
        for ioc in result.iocs[:50]:
            ioc_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 8px; font-size: 11px; font-weight: 700; color: #38bdf8;">{ioc.ioc_type.value}</td>
                <td style="padding: 8px; font-family: monospace; font-size: 12px; color: #f8fafc;">{ioc.defanged_value}</td>
                <td style="padding: 8px; font-size: 11px; color: #94a3b8;">{ioc.context or 'Artifact String'}</td>
            </tr>
            """

        manifest_block = ""
        if manifest:
            manifest_block = f"""
            <div style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-top: 24px;">
                <h3 style="margin-top: 0; color: #38bdf8; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;">Cryptographic Manifest & Digital Signature</h3>
                <div style="display: grid; grid-template-columns: 140px 1fr; gap: 8px; font-size: 12px; font-family: monospace;">
                    <div style="color: #94a3b8;">Manifest UUID:</div><div style="color: #f8fafc;">{manifest.manifest_id}</div>
                    <div style="color: #94a3b8;">Key Fingerprint:</div><div style="color: #f8fafc;">{manifest.public_key_fingerprint or 'Unsigned (Local Demo Mode)'}</div>
                    <div style="color: #94a3b8;">Ed25519 Signature:</div><div style="color: #34d399; word-break: break-all;">{manifest.signature or 'None'}</div>
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ForenSight Forensic Report — {ev.sanitized_filename}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #020617; color: #f8fafc; margin: 0; padding: 32px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }}
        h1, h2, h3 {{ color: #f8fafc; margin-top: 0; }}
        .header-bar {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #1e293b; padding-bottom: 20px; margin-bottom: 24px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; font-size: 13px; }}
        .meta-card {{ background: #1e293b55; border: 1px solid #334155; padding: 12px; border-radius: 6px; }}
        .label {{ color: #94a3b8; font-size: 11px; text-transform: uppercase; font-weight: 700; margin-bottom: 4px; }}
        .val {{ font-family: monospace; font-size: 13px; color: #f8fafc; word-break: break-all; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th {{ background: #1e293b; color: #94a3b8; text-align: left; padding: 8px 10px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }}
        .disclaimer {{ margin-top: 32px; font-size: 11px; color: #64748b; border-top: 1px solid #1e293b; padding-top: 16px; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-bar">
            <div>
                <div style="font-size: 12px; font-weight: 800; color: #38bdf8; letter-spacing: 0.1em; text-transform: uppercase;">ForenSight Digital Forensics Platform</div>
                <h1 style="font-size: 24px; margin-top: 4px; margin-bottom: 4px;">Forensic Triage Report</h1>
                <div style="color: #94a3b8; font-size: 13px;">Evidence: <strong>{ev.original_filename}</strong></div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 32px; font-weight: 800; color: {verdict_color};">{risk.score}/100</div>
                <div style="font-size: 12px; font-weight: 700; color: {verdict_color}; letter-spacing: 0.05em;">{risk.verdict}</div>
            </div>
        </div>

        <div class="meta-grid">
            <div class="meta-card">
                <div class="label">SHA-256 Digest</div>
                <div class="val">{ev.hashes.sha256}</div>
            </div>
            <div class="meta-card">
                <div class="label">SHA-1 / MD5</div>
                <div class="val">{ev.hashes.sha1}<br>{ev.hashes.md5}</div>
            </div>
            <div class="meta-card">
                <div class="label">Identification & MIME</div>
                <div class="val">{meta.identified_type} ({meta.mime_type}) {'<span style="color:#ef4444; font-weight:bold;">[EXTENSION MASQUERADE]</span>' if meta.is_extension_mismatch else ''}</div>
            </div>
            <div class="meta-card">
                <div class="label">Size & Shannon Entropy</div>
                <div class="val">{ev.hashes.size_bytes:,} bytes | Entropy: {meta.entropy:.2f}/8.0</div>
            </div>
        </div>

        <h2 style="font-size: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-top: 32px;">Forensic Findings & Anomaly Indicators ({len(result.findings)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 130px;">Rule ID</th>
                    <th style="width: 90px;">Severity</th>
                    <th>Indicator & Description</th>
                    <th>Forensic Context</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows if findings_rows else '<tr><td colspan="4" style="padding: 16px; text-align: center; color: #64748b;">No suspicious findings detected.</td></tr>'}
            </tbody>
        </table>

        {f'''
        <h2 style="font-size: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-top: 32px;">Extracted Defanged IOCs ({len(result.iocs)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 120px;">Type</th>
                    <th>Defanged Value</th>
                    <th>Context</th>
                </tr>
            </thead>
            <tbody>
                {ioc_rows}
            </tbody>
        </table>
        ''' if result.iocs else ''}

        {manifest_block}

        <div class="disclaimer">
            Forensic Notice: This triage report was generated using static heuristic and structural inspection techniques without executing binary code or macros. Static triage findings identify risk indicators and do not constitute legal proof or guaranteed behavioral confirmation without complementary dynamic analysis.
        </div>
    </div>
</body>
</html>"""

    def generate_pdf_report(
        self,
        result: AnalysisResult,
        output_path: Path,
        manifest: Optional[EvidenceManifest] = None,
    ) -> Path:
        """
        Generate a professional, publication-quality forensic PDF report using reportlab.
        """
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        normal_style = styles["Normal"]

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )

        section_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=14,
            spaceAfter=6,
        )

        elements = []

        # Title Block
        elements.append(Paragraph("<b>ForenSight — Digital Forensics Triage Report</b>", title_style))
        elements.append(Paragraph(f"Evidence Artifact: <b>{result.evidence.original_filename}</b>", normal_style))
        elements.append(Paragraph(f"Triage Timestamp: {result.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", normal_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#334155")))
        elements.append(Spacer(1, 10))

        # Risk Score Block
        verdict_color = colors.HexColor("#10b981") if result.risk.score < 20 else (
            colors.HexColor("#f59e0b") if result.risk.score < 70 else colors.HexColor("#ef4444")
        )
        risk_text = f"<b>Risk Assessment:</b> <font color='{verdict_color.hexval()}'><b>{result.risk.score}/100 — {result.risk.verdict}</b></font>"
        elements.append(Paragraph(risk_text, styles["Heading3"]))
        elements.append(Paragraph(result.risk.summary, normal_style))
        elements.append(Spacer(1, 12))

        # Metadata Table
        meta_data = [
            ["Attribute", "Value"],
            ["SHA-256", result.evidence.hashes.sha256],
            ["SHA-1", result.evidence.hashes.sha1],
            ["MD5", result.evidence.hashes.md5],
            ["File Size", f"{result.evidence.hashes.size_bytes:,} bytes"],
            ["Identified Format", f"{result.metadata.identified_type} ({result.metadata.mime_type})"],
            ["Shannon Entropy", f"{result.metadata.entropy:.2f} / 8.0"],
            ["Extension Masquerade", "ALERT: True" if result.metadata.is_extension_mismatch else "False"],
        ]
        meta_table = Table(meta_data, colWidths=[130, 410])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        elements.append(Paragraph("<b>Cryptographic Identification & Metadata</b>", section_style))
        elements.append(meta_table)
        elements.append(Spacer(1, 14))

        # Findings Table
        if result.findings:
            elements.append(Paragraph(f"<b>Forensic Findings ({len(result.findings)})</b>", section_style))
            findings_data = [["Rule ID", "Sev", "Title", "Mitre"]]
            for f in result.findings[:15]:
                findings_data.append([
                    f.rule_id,
                    f.severity.value,
                    Paragraph(f"<b>{f.title}</b><br/>{f.description[:120]}...", normal_style),
                    f.mitre_technique or "—",
                ])
            findings_table = Table(findings_data, colWidths=[80, 50, 340, 70])
            findings_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(findings_table)
            elements.append(Spacer(1, 14))

        # Cryptographic Signature Block
        if manifest and manifest.signature:
            elements.append(Paragraph("<b>Ed25519 Digital Manifest Verification</b>", section_style))
            sig_data = [
                ["Signing Key Fingerprint", manifest.public_key_fingerprint or "None"],
                ["Digital Signature", manifest.signature[:64] + "\n" + manifest.signature[64:]],
            ]
            sig_table = Table(sig_data, colWidths=[140, 400])
            sig_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]))
            elements.append(sig_table)
            elements.append(Spacer(1, 14))

        # Disclaimer
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8")))
        elements.append(Spacer(1, 6))
        disclaimer = (
            "Forensic Disclaimer: This report was produced by ForenSight via static triage and structural parsing. "
            "No active payload execution occurred. Findings indicate heuristic indicators and require confirmation."
        )
        elements.append(Paragraph(disclaimer, ParagraphStyle("Disc", parent=normal_style, fontSize=7, textColor=colors.HexColor("#64748b"))))

        doc.build(elements)
        return output_path


# Global report generator instance
report_generator = ReportGenerator()

