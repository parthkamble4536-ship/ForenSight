"""
Forensic report generation engine for ForenSight.

Exports comprehensive, deterministic investigation reports in:
- Standalone air-gapped HTML (strictly escaped)
- Structured JSON
- Publication-ready ReportLab PDF (XML-escaped)
- CSV Findings ledger
- STIX 2.1 Threat Intelligence IOC Bundle
"""

import csv
import hashlib
import html
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from forensight.core.config import settings
from forensight.core.types import (
    AnalysisResult,
    ChainOfCustodyEvent,
    EvidenceManifest,
    EvidenceRelationship,
    IOCType,
)


class ReportGenerator:
    """
    Constructs reproducible, cryptographically verifiable forensic triage reports.
    """

    STANDARD_DISCLAIMERS = [
        "Static triage only: no untrusted binaries, scripts, macros, or URLs were executed or fetched.",
        "Heuristic risk scores and indicators highlight structural anomalies and do not constitute proof of malicious runtime behavior alone.",
        "Embedded metadata timestamps (PE compile, EXIF, PDF/OpenXML dates, email headers) reflect unverified file claims unless corroborated by vault/custody timestamps.",
        "Cryptographic manifest signatures prove integrity inside ForenSight since acquisition, not external acquisition-host trustworthiness.",
    ]

    @staticmethod
    def compute_report_id(result: AnalysisResult) -> str:
        """Compute deterministic, traceable report ID from evidence & analysis run attributes."""
        seed = f"{result.evidence.evidence_id}|{result.evidence.hashes.sha256}|{result.analyzed_at.isoformat()}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
        return f"FS-RPT-{digest}"

    @staticmethod
    def _collect_analyzer_versions(result: AnalysisResult) -> List[Dict[str, str]]:
        seen = set()
        versions: List[Dict[str, str]] = []
        for f in result.findings:
            name = f.analyzer_name or f.evidence_source or "Static Triage Analyzer"
            ver = f.analyzer_version or "2.0.0"
            key = (name, ver)
            if key not in seen:
                seen.add(key)
                versions.append({"analyzer": name, "version": ver})
        return versions

    @staticmethod
    def _normalize_custody_dicts(custody_events: Optional[List[Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for c in custody_events or []:
            if isinstance(c, ChainOfCustodyEvent):
                out.append(c.model_dump(mode="json"))
            else:
                ts = getattr(c, "timestamp", None)
                ts_iso = ts.isoformat() if isinstance(ts, datetime) else str(ts or "")
                out.append({
                    "event_id": getattr(c, "event_id", ""),
                    "evidence_id": getattr(c, "evidence_id", ""),
                    "case_id": getattr(c, "case_id", None),
                    "event_type": getattr(c, "event_type", ""),
                    "actor": getattr(c, "actor", ""),
                    "timestamp": ts_iso,
                    "details": getattr(c, "details", ""),
                    "previous_event_hash": getattr(c, "previous_event_hash", ""),
                    "event_hash": getattr(c, "event_hash", ""),
                })
        return out

    def generate_json_report(
        self,
        result: AnalysisResult,
        manifest: Optional[EvidenceManifest] = None,
        custody_events: Optional[List[Any]] = None,
        *,
        case_info: Optional[Dict[str, Any]] = None,
        verification: Optional[Dict[str, Any]] = None,
        relationships: Optional[List[EvidenceRelationship]] = None,
    ) -> str:
        """Export complete 16-section forensic investigation telemetry in JSON."""
        report_id = self.compute_report_id(result)
        generated_at = datetime.now(timezone.utc).isoformat()
        custody_list = self._normalize_custody_dicts(custody_events)
        analyzer_versions = self._collect_analyzer_versions(result)

        data = {
            "report_metadata": {
                "report_id": report_id,
                "platform": settings.app_name,
                "platform_version": settings.version,
                "report_generated_at": generated_at,
                "disclaimers": self.STANDARD_DISCLAIMERS,
            },
            "case": case_info or {
                "case_id": result.evidence.case_id,
                "status": "UNASSIGNED" if not result.evidence.case_id else "LINKED",
                "note": "Standalone triage artifact (no case dossier metadata attached).",
            },
            "evidence": result.evidence.model_dump(mode="json"),
            "metadata": result.metadata.model_dump(mode="json"),
            "analysis_metadata": {
                "analyzed_at": result.analyzed_at.isoformat(),
                "analyzer_versions": analyzer_versions,
            },
            "risk_score": result.risk.model_dump(mode="json"),
            "integrity_verification": verification or {
                "verification_status": "NOT_RUN_IN_EXPORT",
                "note": "No live verification result supplied during report export.",
            },
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "iocs": [i.model_dump(mode="json") for i in result.iocs],
            "timeline": [t.model_dump(mode="json") for t in result.timeline],
            "correlations": [r.model_dump(mode="json") for r in (relationships or [])],
            "manifest": manifest.model_dump(mode="json") if manifest else None,
            "custody_events": custody_list,
            "analyzer_details": result.analyzer_details,
            "report_generated_at": generated_at,
        }
        return json.dumps(data, indent=2, default=str)

    def generate_html_report(
        self,
        result: AnalysisResult,
        manifest: Optional[EvidenceManifest] = None,
        custody_events: Optional[List[Any]] = None,
        *,
        case_info: Optional[Dict[str, Any]] = None,
        verification: Optional[Dict[str, Any]] = None,
        relationships: Optional[List[EvidenceRelationship]] = None,
    ) -> str:
        """
        Produce a self-contained, air-gapped standalone HTML forensic report
        with embedded dark-theme CSS, strict HTML escaping, and zero external network calls.
        """
        def esc(val: Any) -> str:
            return html.escape("" if val is None else str(val), quote=True)

        ev = result.evidence
        meta = result.metadata
        risk = result.risk
        report_id = self.compute_report_id(result)
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        custody_list = self._normalize_custody_dicts(custody_events)
        analyzer_versions = self._collect_analyzer_versions(result)

        verdict_color = "#10b981" if risk.score < 20 else ("#f59e0b" if risk.score < 70 else "#ef4444")

        findings_rows = ""
        for f in result.findings:
            badge_color = (
                "#ef4444" if f.severity.value in ("CRITICAL", "HIGH")
                else ("#f59e0b" if f.severity.value == "MEDIUM" else "#3b82f6")
            )
            prov_parts = [
                f"v{esc(f.rule_version)}",
                esc(f.analyzer_name or f.evidence_source or "Static Analyzer"),
                f"v{esc(f.analyzer_version)}" if f.analyzer_version else "",
                f"Offset {f.offset}" if f.offset is not None else "",
                f"ATT&CK {esc(f.mitre_technique)}" if f.mitre_technique else "",
            ]
            prov_str = " &bull; ".join(p for p in prov_parts if p)
            findings_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 10px; font-weight: 600; color: #f8fafc;">
                    {esc(f.rule_id)}
                    <div style="font-size: 10px; color: #64748b; font-weight: normal; margin-top: 3px;">{prov_str}</div>
                </td>
                <td style="padding: 10px;">
                    <span style="background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}55; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">{esc(f.severity.value)}</span>
                    <div style="font-size: 10px; color: #94a3b8; margin-top: 4px;">{esc(f.confidence.value)}</div>
                </td>
                <td style="padding: 10px; font-weight: 600; color: #f8fafc;">
                    {esc(f.title)}
                    <div style="font-size: 12px; color: #94a3b8; font-weight: normal; margin-top: 4px;">{esc(f.description)}</div>
                    {f'<div style="font-size: 11px; color: #38bdf8; margin-top: 3px;">Object: {esc(f.object_reference)}</div>' if f.object_reference else ''}
                </td>
                <td style="padding: 10px; font-size: 12px; color: #cbd5e1;">{esc(f.explanation or 'No supplemental explanation recorded.')}</td>
            </tr>
            """

        ioc_rows = ""
        for ioc in result.iocs[:100]:
            ioc_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 8px; font-size: 11px; font-weight: 700; color: #38bdf8;">{esc(ioc.ioc_type.value)}</td>
                <td style="padding: 8px; font-family: monospace; font-size: 12px; color: #f8fafc;">{esc(ioc.defanged_value)}</td>
                <td style="padding: 8px; font-size: 11px; color: #94a3b8;">{esc(ioc.context or 'Artifact String')}{f' (offset {ioc.offset})' if ioc.offset is not None else ''}</td>
                <td style="padding: 8px; font-size: 11px; color: #94a3b8;">{ioc.occurrences}x ({esc(ioc.confidence.value)})</td>
            </tr>
            """

        timeline_rows = ""
        for t in result.timeline[:100]:
            ts_str = t.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(t.timestamp, datetime) else str(t.timestamp)
            timeline_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 8px; font-family: monospace; font-size: 11px; color: #38bdf8;">{esc(ts_str)}</td>
                <td style="padding: 8px; font-size: 11px; color: #f59e0b;">{esc(t.timestamp_type.value)}</td>
                <td style="padding: 8px; font-size: 11px; color: #cbd5e1;">{esc(t.description)}<div style="font-size: 10px; color: #64748b;">Source: {esc(t.source)} | Raw: {esc(t.original_timestamp or ts_str)}</div></td>
            </tr>
            """

        custody_rows = ""
        for c in custody_list[:100]:
            custody_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 8px; font-family: monospace; font-size: 11px; color: #94a3b8;">{esc(str(c.get('timestamp', ''))[:19])} UTC</td>
                <td style="padding: 8px; font-size: 11px; color: #38bdf8;">{esc(c.get('event_type'))}</td>
                <td style="padding: 8px; font-size: 12px; color: #cbd5e1;">{esc(c.get('details'))}</td>
                <td style="padding: 8px; font-family: monospace; font-size: 10px; color: #64748b;">{esc(str(c.get('event_hash', ''))[:16])}&hellip;</td>
            </tr>
            """

        corr_rows = ""
        for r in (relationships or [])[:50]:
            corr_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 8px; font-size: 11px; color: #f59e0b;">{esc(r.relationship_type.value)}</td>
                <td style="padding: 8px; font-family: monospace; font-size: 11px; color: #cbd5e1;">{esc(r.source_evidence_id[:8])} &harr; {esc(r.target_evidence_id[:8])}</td>
                <td style="padding: 8px; font-size: 12px; color: #cbd5e1;">{esc(r.reason)}</td>
            </tr>
            """

        case_html = ""
        if case_info:
            case_html = f"""
            <div class="meta-card">
                <div class="label">Investigation Case Dossier</div>
                <div class="val">{esc(case_info.get('title'))} [{esc(case_info.get('status'))}]<br>Lead: {esc(case_info.get('investigator'))} | ID: {esc(case_info.get('case_id'))}</div>
            </div>
            """
        else:
            case_html = """
            <div class="meta-card">
                <div class="label">Investigation Case Dossier</div>
                <div class="val">Standalone Artifact Triage (No case assigned)</div>
            </div>
            """

        verif_status = (verification or {}).get("verification_status", "NOT_RUN")
        verif_details = (verification or {}).get("combined_details", "Live verification not executed during export.")
        verif_html = f"""
        <div class="meta-card">
            <div class="label">Evidence Verification &amp; Custody Status</div>
            <div class="val">{esc(verif_status)}<br><span style="font-size: 11px; color: #94a3b8;">{esc(verif_details[:160])}</span></div>
        </div>
        """

        manifest_block = ""
        if manifest:
            manifest_block = f"""
            <div style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-top: 24px;">
                <h3 style="margin-top: 0; color: #38bdf8; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;">Cryptographic Manifest &amp; Digital Signature</h3>
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 8px; font-size: 12px; font-family: monospace;">
                    <div style="color: #94a3b8;">Manifest UUID:</div><div style="color: #f8fafc;">{esc(manifest.manifest_id)}</div>
                    <div style="color: #94a3b8;">Key Fingerprint:</div><div style="color: #f8fafc;">{esc(manifest.public_key_fingerprint or 'Unsigned (Local Mode)')}</div>
                    <div style="color: #94a3b8;">Ed25519 Signature:</div><div style="color: #34d399; word-break: break-all;">{esc(manifest.signature or 'None')}</div>
                </div>
            </div>
            """

        analyzer_summary = ", ".join(f"{a['analyzer']} v{a['version']}" for a in analyzer_versions) or "Static Triage Pipeline"
        disclaimer_items = "".join(f"<li>{esc(d)}</li>" for d in self.STANDARD_DISCLAIMERS)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ForenSight Forensic Report — {esc(ev.sanitized_filename)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #020617; color: #f8fafc; margin: 0; padding: 32px; }}
        .container {{ max-width: 1050px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }}
        h1, h2, h3 {{ color: #f8fafc; margin-top: 0; }}
        .header-bar {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #1e293b; padding-bottom: 20px; margin-bottom: 24px; gap: 16px; flex-wrap: wrap; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; margin-bottom: 24px; font-size: 13px; }}
        .meta-card {{ background: #1e293b55; border: 1px solid #334155; padding: 12px; border-radius: 6px; }}
        .label {{ color: #94a3b8; font-size: 11px; text-transform: uppercase; font-weight: 700; margin-bottom: 4px; }}
        .val {{ font-family: monospace; font-size: 12.5px; color: #f8fafc; word-break: break-all; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th {{ background: #1e293b; color: #94a3b8; text-align: left; padding: 8px 10px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }}
        .disclaimer {{ margin-top: 32px; font-size: 11.5px; color: #94a3b8; border-top: 1px solid #1e293b; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-bar">
            <div>
                <div style="font-size: 12px; font-weight: 800; color: #38bdf8; letter-spacing: 0.1em; text-transform: uppercase;">{esc(settings.app_name)} v{esc(settings.version)} &bull; Digital Forensics Report</div>
                <h1 style="font-size: 24px; margin-top: 4px; margin-bottom: 4px;">Forensic Triage &amp; Investigation Report</h1>
                <div style="color: #94a3b8; font-size: 13px;">Report ID: <strong style="color: #f8fafc;">{esc(report_id)}</strong> &bull; Generated: {esc(generated_at)}</div>
                <div style="color: #94a3b8; font-size: 13px; margin-top: 2px;">Evidence: <strong>{esc(ev.original_filename)}</strong> (UUID: {esc(ev.evidence_id)})</div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 32px; font-weight: 800; color: {verdict_color};">{risk.score}/100</div>
                <div style="font-size: 12px; font-weight: 700; color: {verdict_color}; letter-spacing: 0.05em;">{esc(risk.verdict)}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px; max-width: 280px;">{esc(risk.summary)}</div>
            </div>
        </div>

        <div class="meta-grid">
            <div class="meta-card">
                <div class="label">SHA-256 Digest</div>
                <div class="val">{esc(ev.hashes.sha256)}</div>
            </div>
            <div class="meta-card">
                <div class="label">SHA-1 / MD5</div>
                <div class="val">{esc(ev.hashes.sha1)}<br>{esc(ev.hashes.md5)}</div>
            </div>
            <div class="meta-card">
                <div class="label">Identification &amp; MIME</div>
                <div class="val">{esc(meta.identified_type)} ({esc(meta.mime_type)}) {'<span style="color:#ef4444; font-weight:bold;">[EXTENSION MASQUERADE]</span>' if meta.is_extension_mismatch else ''}</div>
            </div>
            <div class="meta-card">
                <div class="label">Size, Entropy &amp; Analyzers</div>
                <div class="val">{ev.hashes.size_bytes:,} bytes | Entropy: {meta.entropy:.2f}/8.0<br>Engines: {esc(analyzer_summary)}</div>
            </div>
            {case_html}
            {verif_html}
        </div>

        <h2 style="font-size: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-top: 28px;">Forensic Findings &amp; Rule Provenance ({len(result.findings)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 170px;">Rule &amp; Provenance</th>
                    <th style="width: 100px;">Severity</th>
                    <th>Indicator &amp; Description</th>
                    <th>Forensic Context &amp; Limitations</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows if findings_rows else '<tr><td colspan="4" style="padding: 16px; text-align: center; color: #64748b;">No static anomaly indicators triggered by executed rule set.</td></tr>'}
            </tbody>
        </table>

        <h2 style="font-size: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-top: 28px;">Extracted Defanged IOCs ({len(result.iocs)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 110px;">Type</th>
                    <th>Defanged Value</th>
                    <th>Source Context</th>
                    <th style="width: 120px;">Count / Conf</th>
                </tr>
            </thead>
            <tbody>
                {ioc_rows if ioc_rows else '<tr><td colspan="4" style="padding: 14px; text-align: center; color: #64748b;">No network or host indicators extracted.</td></tr>'}
            </tbody>
        </table>

        <h2 style="font-size: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-top: 28px;">Chronological Timeline ({len(result.timeline)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 170px;">Normalized UTC</th>
                    <th style="width: 130px;">Category</th>
                    <th>Event Description &amp; Raw Source</th>
                </tr>
            </thead>
            <tbody>
                {timeline_rows if timeline_rows else '<tr><td colspan="3" style="padding: 14px; text-align: center; color: #64748b;">No timeline records supplied for this export.</td></tr>'}
            </tbody>
        </table>

        <h2 style="font-size: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-top: 28px;">Chain of Custody Ledger ({len(custody_list)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 160px;">UTC Timestamp</th>
                    <th style="width: 140px;">Custody Event</th>
                    <th>Audit Narrative</th>
                    <th style="width: 120px;">Event Hash</th>
                </tr>
            </thead>
            <tbody>
                {custody_rows if custody_rows else '<tr><td colspan="4" style="padding: 14px; text-align: center; color: #64748b;">No custody audit events linked in this export payload.</td></tr>'}
            </tbody>
        </table>

        <h2 style="font-size: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-top: 28px;">Case Evidence Correlations ({len(relationships or [])})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 150px;">Pivot Type</th>
                    <th style="width: 160px;">Linked Artifacts</th>
                    <th>Rationale</th>
                </tr>
            </thead>
            <tbody>
                {corr_rows if corr_rows else '<tr><td colspan="3" style="padding: 14px; text-align: center; color: #64748b;">No shared-hash, shared-IOC, author, or attachment correlations recorded.</td></tr>'}
            </tbody>
        </table>

        {manifest_block}

        <div class="disclaimer">
            <strong>Forensic Limitations &amp; Disclaimers:</strong>
            <ul style="margin: 6px 0 0 18px; padding: 0;">{disclaimer_items}</ul>
        </div>
    </div>
</body>
</html>"""

    def generate_pdf_report(
        self,
        result: AnalysisResult,
        output_path: Path,
        manifest: Optional[EvidenceManifest] = None,
        custody_events: Optional[List[Any]] = None,
        *,
        case_info: Optional[Dict[str, Any]] = None,
        verification: Optional[Dict[str, Any]] = None,
        relationships: Optional[List[EvidenceRelationship]] = None,
    ) -> Path:
        """
        Generate a publication-quality, XML-escaped PDF forensic report using ReportLab.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
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
        report_id = self.compute_report_id(result)
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        custody_list = self._normalize_custody_dicts(custody_events)

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=17,
            leading=21,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )

        section_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=5,
        )

        elements = []

        # 1. Title & Report Identification
        elements.append(Paragraph(f"<b>{xml_escape(settings.app_name)} v{xml_escape(settings.version)} — Digital Forensics Triage Report</b>", title_style))
        elements.append(Paragraph(f"Report ID: <b>{xml_escape(report_id)}</b> &nbsp;|&nbsp; Generated: {xml_escape(generated_at)}", normal_style))
        elements.append(Paragraph(f"Evidence Artifact: <b>{xml_escape(result.evidence.original_filename)}</b> (UUID: {xml_escape(result.evidence.evidence_id)})", normal_style))
        if case_info:
            elements.append(Paragraph(
                f"Case Dossier: <b>{xml_escape(str(case_info.get('title', '')))}</b> [{xml_escape(str(case_info.get('status', '')))}] — Lead: {xml_escape(str(case_info.get('investigator', '')))}",
                normal_style,
            ))
        else:
            elements.append(Paragraph("Case Dossier: Standalone Artifact Triage (Unassigned)", normal_style))
        elements.append(Paragraph(f"Analysis Timestamp: {result.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", normal_style))
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#334155")))
        elements.append(Spacer(1, 8))

        # 2. Risk Score & Verdict
        verdict_color = colors.HexColor("#10b981") if result.risk.score < 20 else (
            colors.HexColor("#f59e0b") if result.risk.score < 70 else colors.HexColor("#ef4444")
        )
        risk_text = f"<b>Risk Assessment:</b> <font color='{verdict_color.hexval()}'><b>{result.risk.score}/100 — {xml_escape(result.risk.verdict)}</b></font>"
        elements.append(Paragraph(risk_text, styles["Heading3"]))
        elements.append(Paragraph(xml_escape(result.risk.summary), normal_style))
        elements.append(Spacer(1, 10))

        # 3. Hashes, File Identification & Verification Summary
        verif_status = (verification or {}).get("verification_status", "NOT_RUN")
        meta_data = [
            ["Attribute", "Value"],
            ["SHA-256", result.evidence.hashes.sha256],
            ["SHA-1", result.evidence.hashes.sha1],
            ["MD5", result.evidence.hashes.md5],
            ["File Size", f"{result.evidence.hashes.size_bytes:,} bytes"],
            ["Identified Format", f"{result.metadata.identified_type} ({result.metadata.mime_type})"],
            ["Shannon Entropy", f"{result.metadata.entropy:.2f} / 8.0"],
            ["Extension Masquerade", "ALERT: True" if result.metadata.is_extension_mismatch else "False"],
            ["Integrity Verification", verif_status],
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
        elements.append(Paragraph("<b>Cryptographic Identification &amp; Verification Status</b>", section_style))
        elements.append(meta_table)
        elements.append(Spacer(1, 12))

        # 4. Findings Table with Rule/Analyzer Provenance
        elements.append(Paragraph(f"<b>Forensic Findings ({len(result.findings)})</b>", section_style))
        if result.findings:
            findings_data = [["Rule & Version", "Sev / Conf", "Title & Description", "MITRE"]]
            for f in result.findings[:25]:
                findings_data.append([
                    Paragraph(f"<b>{xml_escape(f.rule_id)}</b><br/>v{xml_escape(f.rule_version)}<br/>{xml_escape(f.analyzer_version or '')}", normal_style),
                    Paragraph(f"{xml_escape(f.severity.value)}<br/>{xml_escape(f.confidence.value)}", normal_style),
                    Paragraph(f"<b>{xml_escape(f.title)}</b><br/>{xml_escape(f.description[:140])}", normal_style),
                    f.mitre_technique or "—",
                ])
            findings_table = Table(findings_data, colWidths=[95, 70, 315, 60])
            findings_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(findings_table)
        else:
            elements.append(Paragraph("No static anomaly indicators detected.", normal_style))
        elements.append(Spacer(1, 10))

        # 5. Defanged IOCs
        if result.iocs:
            elements.append(Paragraph(f"<b>Extracted Defanged IOCs ({len(result.iocs)})</b>", section_style))
            ioc_data = [["Type", "Defanged Value", "Context"]]
            for ioc in result.iocs[:25]:
                ioc_data.append([
                    ioc.ioc_type.value,
                    Paragraph(xml_escape(ioc.defanged_value[:100]), normal_style),
                    Paragraph(xml_escape((ioc.context or "Artifact")[:60]), normal_style),
                ])
            ioc_table = Table(ioc_data, colWidths=[75, 295, 170])
            ioc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            elements.append(ioc_table)
            elements.append(Spacer(1, 10))

        # 6. Timeline & Chain of Custody Summary
        if result.timeline:
            elements.append(Paragraph(f"<b>Timeline Summary ({len(result.timeline)} events)</b>", section_style))
            tl_data = [["UTC Timestamp", "Type", "Description"]]
            for t in result.timeline[:15]:
                ts_str = t.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(t.timestamp, datetime) else str(t.timestamp)
                tl_data.append([ts_str, t.timestamp_type.value, Paragraph(xml_escape(t.description[:120]), normal_style)])
            tl_table = Table(tl_data, colWidths=[115, 85, 340])
            tl_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            elements.append(tl_table)
            elements.append(Spacer(1, 10))

        if custody_list:
            elements.append(Paragraph(f"<b>Chain of Custody Ledger ({len(custody_list)} events)</b>", section_style))
            cust_data = [["UTC Timestamp", "Event", "Details"]]
            for c in custody_list[:15]:
                cust_data.append([
                    str(c.get("timestamp", ""))[:19],
                    str(c.get("event_type", "")),
                    Paragraph(xml_escape(str(c.get("details", ""))[:120]), normal_style),
                ])
            cust_table = Table(cust_data, colWidths=[110, 95, 335])
            cust_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            elements.append(cust_table)
            elements.append(Spacer(1, 10))

        if relationships:
            elements.append(Paragraph(f"<b>Case Evidence Correlations ({len(relationships)})</b>", section_style))
            for rel in relationships[:10]:
                elements.append(Paragraph(f"&bull; <b>{xml_escape(rel.relationship_type.value)}:</b> {xml_escape(rel.reason)}", normal_style))
            elements.append(Spacer(1, 10))

        # 7. Ed25519 Manifest Signature Block
        if manifest and manifest.signature:
            elements.append(Paragraph("<b>Ed25519 Digital Manifest Verification</b>", section_style))
            sig_data = [
                ["Manifest UUID", manifest.manifest_id],
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
            elements.append(Spacer(1, 10))

        # 8. Forensic Disclaimers
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8")))
        elements.append(Spacer(1, 6))
        disc_style = ParagraphStyle("Disc", parent=normal_style, fontSize=7, textColor=colors.HexColor("#64748b"))
        for d in self.STANDARD_DISCLAIMERS:
            elements.append(Paragraph(f"&bull; {xml_escape(d)}", disc_style))

        doc.build(elements)
        return output_path

    def generate_csv_findings_report(self, result: AnalysisResult) -> str:
        """Export forensic findings and provenance metadata as RFC 4180 CSV."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "evidence_id",
            "finding_id",
            "rule_id",
            "rule_version",
            "analyzer_name",
            "analyzer_version",
            "severity",
            "confidence",
            "score_impact",
            "title",
            "object_reference",
            "offset",
            "mitre_technique",
            "description",
            "explanation",
        ])
        for f in result.findings:
            writer.writerow([
                result.evidence.evidence_id,
                f.finding_id or "",
                f.rule_id,
                f.rule_version,
                f.analyzer_name or f.evidence_source,
                f.analyzer_version,
                f.severity.value,
                f.confidence.value,
                f.score_impact,
                f.title,
                f.object_reference or "",
                "" if f.offset is None else f.offset,
                f.mitre_technique or "",
                f.description,
                f.explanation or "",
            ])
        return buf.getvalue()

    def generate_stix21_bundle(self, result: AnalysisResult) -> str:
        """Export extracted IOCs as a deterministic STIX 2.1 Threat Intelligence JSON bundle."""
        identity_id = "identity--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "forensight.local"))
        created_iso = result.analyzed_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        objects: List[Dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": created_iso,
                "modified": created_iso,
                "name": f"{settings.app_name} Static Triage Platform",
                "identity_class": "system",
            }
        ]

        pattern_map = {
            IOCType.IPV4: lambda v: f"[ipv4-addr:value = '{v}']",
            IOCType.IPV6: lambda v: f"[ipv6-addr:value = '{v}']",
            IOCType.URL: lambda v: f"[url:value = '{v}']",
            IOCType.DOMAIN: lambda v: f"[domain-name:value = '{v}']",
            IOCType.EMAIL: lambda v: f"[email-addr:value = '{v}']",
            IOCType.HASH_MD5: lambda v: f"[file:hashes.'MD5' = '{v}']",
            IOCType.HASH_SHA1: lambda v: f"[file:hashes.'SHA-1' = '{v}']",
            IOCType.HASH_SHA256: lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        }

        for ioc in result.iocs:
            builder = pattern_map.get(ioc.ioc_type)
            if not builder:
                continue
            safe_val = ioc.value.replace("\\", "\\\\").replace("'", "\\'")
            pattern = builder(safe_val)
            ind_id = "indicator--" + str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"{result.evidence.evidence_id}|{ioc.ioc_type.value}|{ioc.value}")
            )
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": created_iso,
                "modified": created_iso,
                "created_by_ref": identity_id,
                "name": f"{ioc.ioc_type.value}: {ioc.defanged_value}",
                "description": ioc.context or f"Extracted from {result.evidence.sanitized_filename}",
                "indicator_types": ["anomalous-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": created_iso,
                "x_forensight_defanged": ioc.defanged_value,
                "x_forensight_evidence_id": result.evidence.evidence_id,
            })

        bundle_id = "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"bundle|{result.evidence.evidence_id}"))
        return json.dumps({"type": "bundle", "id": bundle_id, "objects": objects}, indent=2)


# Global report generator instance
report_generator = ReportGenerator()
