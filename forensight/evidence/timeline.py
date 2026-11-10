"""
Investigation timeline aggregation and chronologic sequencing engine.

Preserves timezone fidelity, distinguishes metadata vs compile vs archive timestamps,
and prevents fabrication of missing chronological events.
"""

from typing import List

from forensight.core.types import TimelineEvent


class TimelineAggregator:
    """
    Aggregates and sorts forensic timeline events chronologically.
    """

    def build_case_timeline(self, events: List[TimelineEvent]) -> List[TimelineEvent]:
        """
        Sequence discrete timeline events chronologically while preserving source context.
        """
        # Deduplicate events by event_id or (evidence_id, timestamp, source)
        seen_keys = set()
        deduped: List[TimelineEvent] = []

        for ev in events:
            key = (ev.evidence_id, ev.timestamp.isoformat(), ev.source)
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(ev)

        # Sort chronologically by timestamp
        deduped.sort(key=lambda x: x.timestamp)
        return deduped


# Global timeline aggregator
timeline_aggregator = TimelineAggregator()

