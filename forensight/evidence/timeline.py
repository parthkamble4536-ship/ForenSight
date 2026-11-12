"""
Investigation timeline aggregation and chronologic sequencing engine.

Preserves timezone fidelity, distinguishes metadata vs compile vs archive timestamps,
and prevents fabrication of missing chronological events.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

from forensight.core.types import ConfidenceLevel, TimelineEvent


class TimelineAggregator:
    """
    Aggregates and sorts forensic timeline events chronologically across multiple sources.
    """

    METADATA_DISCLAIMER = (
        "Artifact metadata timestamps (PE compile, EXIF, PDF/OpenXML dates, email headers) "
        "may be altered, timezone-skewed, or zeroed and require corroboration with vault/custody timestamps."
    )

    @staticmethod
    def _norm_ts(ts: datetime) -> datetime:
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)

    def build_case_timeline(self, events: List[TimelineEvent]) -> List[TimelineEvent]:
        """
        Sequence discrete timeline events chronologically while preserving source context.
        """
        seen_keys = set()
        deduped: List[TimelineEvent] = []

        for ev in events:
            norm_ts = self._norm_ts(ev.timestamp)
            key = (ev.evidence_id, norm_ts.isoformat(), ev.source)
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(ev.model_copy(update={"timestamp": norm_ts}))

        deduped.sort(key=lambda x: x.timestamp)
        return deduped

    def build_unified_investigation_timeline(
        self,
        *,
        timeline_events: List[TimelineEvent],
        custody_rows: List[Any] | None = None,
        case_activities: List[Any] | None = None,
        evidence_names: Dict[str, str] | None = None,
    ) -> List[Dict[str, Any]]:
        """
        Merge artifact metadata timelines, ingestion/analysis timestamps, custody events,
        and case workflow activity into one chronologically sorted multi-source ledger.
        """
        ev_map = evidence_names or {}
        unified: List[Dict[str, Any]] = []

        for tev in self.build_case_timeline(timeline_events):
            is_system_verified = tev.timestamp_type.value in ("INGESTION", "ANALYSIS")
            unified.append({
                "timestamp": self._norm_ts(tev.timestamp),
                "original_timestamp": tev.original_timestamp or tev.timestamp.isoformat(),
                "category": tev.timestamp_type.value,
                "source": tev.source,
                "evidence_id": tev.evidence_id,
                "evidence_name": ev_map.get(tev.evidence_id, tev.evidence_id[:8]),
                "description": tev.description,
                "confidence": tev.confidence.value,
                "trust_note": "System vault UTC" if is_system_verified else "Artifact claim (unverified)",
            })

        for c_ev in custody_rows or []:
            ts = self._norm_ts(c_ev.timestamp)
            unified.append({
                "timestamp": ts,
                "original_timestamp": ts.isoformat(),
                "category": f"CUSTODY:{c_ev.event_type}",
                "source": f"Custody Ledger ({c_ev.actor})",
                "evidence_id": c_ev.evidence_id,
                "evidence_name": ev_map.get(c_ev.evidence_id, c_ev.evidence_id[:8]),
                "description": c_ev.details,
                "confidence": ConfidenceLevel.CONFIRMED.value,
                "trust_note": "Hash-chained audit ledger",
            })

        for act in case_activities or []:
            ts = self._norm_ts(act.created_at)
            unified.append({
                "timestamp": ts,
                "original_timestamp": ts.isoformat(),
                "category": f"CASE:{act.action}",
                "source": f"Case Workflow ({act.actor})",
                "evidence_id": "",
                "evidence_name": "Case Dossier",
                "description": act.details,
                "confidence": ConfidenceLevel.CONFIRMED.value,
                "trust_note": "Analyst workflow log",
            })

        unified.sort(key=lambda item: item["timestamp"])
        return unified


# Global timeline aggregator
timeline_aggregator = TimelineAggregator()

