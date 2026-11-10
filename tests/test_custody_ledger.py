"""
Unit tests for the cryptographically linked Chain of Custody audit ledger.
"""

from pathlib import Path
import pytest

from forensight.evidence.custody import CustodyLedger


class TestCustodyLedger:
    """Tests for audit event hashing, chronological chaining, and tamper detection."""

    def test_ledger_continuity_passes_for_valid_chain(self) -> None:
        """Verify sequential audit events form a valid unbroken cryptographic chain."""
        ledger = CustodyLedger()

        ev1 = ledger.record_event(
            evidence_id="ev-100",
            event_type="INGESTION",
            details="Artifact uploaded and stored as UUID",
        )
        assert ev1.previous_event_hash == CustodyLedger.GENESIS_HASH

        ev2 = ledger.record_event(
            evidence_id="ev-100",
            event_type="INTEGRITY_AUDIT",
            details="Integrity audit passed: SHA-256 confirmed",
        )
        assert ev2.previous_event_hash == ev1.event_hash

        ev3 = ledger.record_event(
            evidence_id="ev-100",
            event_type="ANALYSIS_RUN",
            details="PE Static Analysis completed: 3 findings",
        )
        assert ev3.previous_event_hash == ev2.event_hash

        is_valid, error = ledger.verify_ledger_integrity()
        assert is_valid is True
        assert error is None

    def test_ledger_detects_record_tampering(self) -> None:
        """Verify modifying an event in the historical chain is immediately flagged."""
        ledger = CustodyLedger()

        ledger.record_event("ev-100", "INGESTION", "Initial ingestion")
        ledger.record_event("ev-100", "INTEGRITY_AUDIT", "Audit clean")
        ledger.record_event("ev-100", "REPORT_EXPORT", "Report generated")

        # Simulate tampering by mutating the details of the second event directly in memory
        ledger._events[1].details = "Audit FAILED - Tampered narrative inserted"

        is_valid, error = ledger.verify_ledger_integrity()
        assert is_valid is False
        assert "record content has been altered" in (error or "")
