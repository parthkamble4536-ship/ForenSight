"""
Cryptographically linked Chain of Custody audit ledger.

Maintains an immutable, tamper-evident hash-chained sequence of forensic actions
(acquisition, analysis, integrity audits, report generation).
"""

import hashlib
import threading
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from forensight.core.exceptions import IntegrityCompromisedError
from forensight.core.types import ChainOfCustodyEvent
from forensight.database.crud import list_custody_events, save_custody_event


class CustodyLedger:
    """
    Append-only chain of custody audit ledger with SHA-256 block-linking.

    Supports both isolated in-memory operation and persistent SQLite-backed
    chain restoration, validation, and thread-safe atomic appends.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: List[ChainOfCustodyEvent] = []

    @staticmethod
    def _normalize_timestamp(ts: datetime) -> datetime:
        """Ensure timestamps are always timezone-aware UTC for deterministic hashing."""
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)

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

    @classmethod
    def _row_to_event(cls, row) -> ChainOfCustodyEvent:
        """Convert a SQLAlchemy CustodyEventModel row into a ChainOfCustodyEvent."""
        return ChainOfCustodyEvent(
            event_id=row.event_id,
            evidence_id=row.evidence_id,
            case_id=row.case_id,
            event_type=row.event_type,
            actor=row.actor,
            timestamp=cls._normalize_timestamp(row.timestamp),
            details=row.details,
            previous_event_hash=row.previous_event_hash,
            event_hash=row.event_hash,
        )

    def _verify_sequence(self, events: List[ChainOfCustodyEvent]) -> Tuple[bool, Optional[str]]:
        """Validate cryptographic chain continuity across an ordered list of events."""
        if not events:
            return (True, None)

        expected_prev = self.GENESIS_HASH

        for idx, event in enumerate(events):
            if event.previous_event_hash != expected_prev:
                return (
                    False,
                    f"Chain break at index {idx} (Event ID [{event.event_id}]): previous hash mismatch.",
                )

            norm_ts = self._normalize_timestamp(event.timestamp)
            recomputed = self._compute_event_hash(
                event_id=event.event_id,
                evidence_id=event.evidence_id,
                case_id=event.case_id,
                event_type=event.event_type,
                actor=event.actor,
                timestamp_iso=norm_ts.isoformat(),
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

    def verify_persisted_chain(self, db: Session) -> Tuple[bool, Optional[str], List[ChainOfCustodyEvent]]:
        """Load and validate the complete persisted Chain of Custody from SQLite."""
        rows = list_custody_events(db)
        events = [self._row_to_event(row) for row in rows]
        is_valid, err = self._verify_sequence(events)
        return (is_valid, err, events)

    def load_from_db(self, db: Session) -> List[ChainOfCustodyEvent]:
        """
        Restore custody history from SQLite and fail loudly if tampering or breaks exist.
        Never silently starts a new chain over corrupted history.
        """
        with self._lock:
            is_valid, err, events = self.verify_persisted_chain(db)
            if not is_valid:
                raise IntegrityCompromisedError(
                    evidence_id="custody_ledger",
                    discrepancies=[err or "Persisted chain of custody validation failed."],
                )
            self._events = events
            return list(self._events)

    def record_event(
        self,
        evidence_id: str,
        event_type: str,
        details: str,
        case_id: Optional[str] = None,
        actor: str = "forensight_system",
        db: Optional[Session] = None,
        auto_persist: bool = True,
    ) -> ChainOfCustodyEvent:
        """
        Append a new audit event linked to the previous event hash.

        When db is supplied, verifies the persisted custody chain first under lock,
        refuses to append if history is corrupted, and chains off the DB tail hash.
        """
        with self._lock:
            event_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()

            if db is not None:
                is_valid, err, persisted_events = self.verify_persisted_chain(db)
                if not is_valid:
                    raise IntegrityCompromisedError(
                        evidence_id="custody_ledger",
                        discrepancies=[err or "Persisted chain of custody validation failed."],
                    )
                previous_hash = (
                    persisted_events[-1].event_hash if persisted_events else self.GENESIS_HASH
                )
                seq_idx = len(persisted_events)
            else:
                previous_hash = self._events[-1].event_hash if self._events else self.GENESIS_HASH
                seq_idx = len(self._events)

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

            if db is not None and auto_persist:
                save_custody_event(db, event, sequence_index=seq_idx)
                self._events = persisted_events + [event]
            else:
                self._events.append(event)

            return event

    def get_events_for_evidence(self, evidence_id: str) -> List[ChainOfCustodyEvent]:
        """Return all custody events concerning a specific evidence artifact."""
        with self._lock:
            return [e for e in self._events if e.evidence_id == evidence_id]

    def get_all_events(self) -> List[ChainOfCustodyEvent]:
        """Return the complete audit ledger."""
        with self._lock:
            return list(self._events)

    def verify_ledger_integrity(self, db: Optional[Session] = None) -> Tuple[bool, Optional[str]]:
        """
        Verify the cryptographic continuity of the entire audit chain.
        When db is passed, verifies the persisted SQLite chain; otherwise checks memory.
        """
        with self._lock:
            if db is not None:
                is_valid, err, _ = self.verify_persisted_chain(db)
                return (is_valid, err)
            return self._verify_sequence(self._events)


# Global custody ledger singleton
custody_ledger = CustodyLedger()

