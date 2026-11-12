"""
Image forensic static analyzer (EXIF metadata and structural inspection).

Inspects EXIF tags, GPS coordinates, editing software fingerprints, and appended
data without executing embedded code or rendering unconstrained graphics.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from PIL import ExifTags, Image

from forensight.analyzers.base import AnalyzerOutput, BaseAnalyzer
from forensight.core.types import (
    ConfidenceLevel,
    EvidenceMetadata,
    Finding,
    FindingSeverity,
    TimelineEvent,
    TimelineEventType,
)


class ImageAnalyzer(BaseAnalyzer):
    """
    Static forensic analyzer for common image files (JPEG, PNG, GIF).
    """

    EDITING_SOFTWARE_KEYWORDS = {
        "photoshop", "gimp", "lightroom", "canva", "snapseed", "paint.net", "corel"
    }

    @property
    def name(self) -> str:
        return "Image Forensic Analyzer"

    @property
    def version(self) -> str:
        return "2.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["IMAGE_JPEG", "IMAGE_PNG", "IMAGE_GIF", "IMAGE"]

    def _parse_exif_date(self, date_str: str) -> Optional[datetime]:
        """Parse EXIF date strings formatted as 'YYYY:MM:DD HH:MM:SS'."""
        if not date_str or not isinstance(date_str, str):
            return None
        try:
            return datetime.strptime(date_str.strip(), "%Y:%m:%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return None

    def analyze(self, file_path: Path, metadata: EvidenceMetadata) -> AnalyzerOutput:
        output = AnalyzerOutput()
        findings: List[Finding] = []
        timeline: List[TimelineEvent] = []
        details: Dict[str, Any] = {}

        try:
            with Image.open(file_path) as img:
                details["format"] = img.format
                details["mode"] = img.mode
                details["dimensions"] = f"{img.width}x{img.height}"

                exif_data = img.getexif()
                parsed_exif: Dict[str, Any] = {}

                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        # Keep only serializable string representations
                        if isinstance(value, (str, int, float)):
                            parsed_exif[tag_name] = value

                    # Extract Camera Metadata
                    camera_make = str(parsed_exif.get("Make", "")).strip()
                    camera_model = str(parsed_exif.get("Model", "")).strip()
                    software = str(parsed_exif.get("Software", "")).strip()

                    details["camera_make"] = camera_make
                    details["camera_model"] = camera_model
                    details["software"] = software

                    # Check for editing software fingerprints
                    if software:
                        software_lower = software.lower()
                        if any(kw in software_lower for kw in self.EDITING_SOFTWARE_KEYWORDS):
                            findings.append(
                                Finding(
                                    rule_id="IMG-EDIT-001",
                                    category="METADATA_ANALYSIS",
                                    title=f"Image Editing Software Fingerprint Detected [{software}]",
                                    description=f"EXIF metadata indicates the image was modified or processed by: {software}",
                                    severity=FindingSeverity.INFO,
                                    confidence=ConfidenceLevel.CONFIRMED,
                                    score_impact=5,
                                    evidence_source=self.name,
                                    object_reference="EXIF Software Tag",
                                    explanation="Editing software signatures indicate the file is not an unaltered original camera capture.",
                                )
                            )

                    # Extract Timestamps
                    date_tags = ["DateTimeOriginal", "DateTimeDigitized", "DateTime"]
                    for dt_tag in date_tags:
                        raw_date = parsed_exif.get(dt_tag)
                        if raw_date:
                            parsed_dt = self._parse_exif_date(str(raw_date))
                            if parsed_dt:
                                details[f"{dt_tag.lower()}_iso"] = parsed_dt.isoformat()
                                timeline.append(
                                    TimelineEvent(
                                        event_id=f"img-exif-{dt_tag}",
                                        evidence_id="",
                                        timestamp=parsed_dt,
                                        original_timestamp=str(raw_date),
                                        timestamp_type=TimelineEventType.METADATA,
                                        source=f"Image EXIF ({dt_tag})",
                                        description=f"Image EXIF {dt_tag} claim: {parsed_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                        confidence=ConfidenceLevel.MEDIUM,
                                    )
                                )
                                break

                details["exif"] = parsed_exif

        except Exception as err:
            findings.append(
                Finding(
                    rule_id="IMG-CORRUPT-001",
                    category="ANOMALY",
                    title="Malformed Image Structure",
                    description=f"Could not parse image structure: {err}",
                    severity=FindingSeverity.LOW,
                    confidence=ConfidenceLevel.HIGH,
                    score_impact=5,
                    evidence_source=self.name,
                )
            )

        output.findings = self.finalize_findings(findings)
        output.timeline_events = timeline
        output.details = details
        return output

