"""
Cryptographically linked Chain of Custody audit ledger.

Maintains an immutable, tamper-evident hash-chained sequence of forensic actions
(acquisition, analysis, integrity audits, report generation).
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from forensight.core.types import ChainOfCustodyEvent


class CustodyLedger:
    """
    Append-only chain of custody audit ledger with SHA-256 block-linking.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self._events: List[ChainOfCustodyEvent] = []

    def _compute_event_hash(
        self,
        event_id: str,
        evidence_id: str,
        case_id: Optional[str],
        event_type: str,
        actor: str,
        timestamp_iso: str,
        details: str,
        previous_hash: str,
    ) -> str:
        """Compute SHA-256 hash chaining previous event hash with current record."""
        payload = f"{previous_hash}|{event_id}|{evidence_id}|{case_id or ''}|{event_type}|{actor}|{timestamp_iso}|{details}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def record_event(
        self,
        evidence_id: str,
        event_type: str,
        details: str,
        case_id: Optional[str] = None,
        actor: str = "forensight_system",
    ) -> ChainOfCustodyEvent:
        """
        Append a new audit event linked to the previous event hash.
        """
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        previous_hash = self._events[-1].event_hash if self._events else self.GENESIS_HASH

        event_hash = self._compute_event_hash(
            event_id=event_id,
            evidence_id=evidence_id,
            case_id=case_id,
            event_type=event_type,
            actor=actor,
            timestamp_iso=now_iso,
            details=details,
            previous_hash=previous_hash,
        )

        event = ChainOfCustodyEvent(
            event_id=event_id,
            evidence_id=evidence_id,
            case_id=case_id,
            event_type=event_type,
            actor=actor,
            timestamp=now,
            details=details,
            previous_event_hash=previous_hash,
            event_hash=event_hash,
        )
        self._events.append(event)
        return event

    def get_events_for_evidence(self, evidence_id: str) -> List[ChainOfCustodyEvent]:
        """Return all custody events concerning a specific evidence artifact."""
        return [e for e in self._events if e.evidence_id == evidence_id]

    def get_all_events(self) -> List[ChainOfCustodyEvent]:
        """Return the complete audit ledger."""
        return list(self._events)

    def verify_ledger_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Verify the cryptographic continuity of the entire audit chain.
        Returns (is_valid, error_description).
        """
        if not self._events:
            return (True, None)

        expected_prev = self.GENESIS_HASH

        for idx, event in enumerate(self._events):
            # Check link to predecessor
            if event.previous_event_hash != expected_prev:
                return (
                    False,
                    f"Chain break at index {idx} (Event ID [{event.event_id}]): previous hash mismatch.",
                )

            # Recompute event hash
            recomputed = self._compute_event_hash(
                event_id=event.event_id,
                evidence_id=event.evidence_id,
                case_id=event.case_id,
                event_type=event.event_type,
                actor=event.actor,
                timestamp_iso=event.timestamp.isoformat(),
                details=event.details,
                previous_hash=expected_prev,
            )

            if event.event_hash != recomputed:
                return (
                    False,
                    f"Integrity failure at index {idx} (Event ID [{event.event_id}]): record content has been altered.",
                )

            expected_prev = event.event_hash

        return (True, None)


# Global custody ledger singleton
custody_ledger = CustodyLedger()
