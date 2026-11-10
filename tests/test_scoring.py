"""
Unit tests for the explainable forensic risk assessment engine.
"""

from typing import List
import pytest

from forensight.core.types import ConfidenceLevel, Finding, FindingSeverity
from forensight.intelligence.scoring import RiskEngine


class TestRiskEngine:
    """Tests for risk score calculation, verdict bands, and category capping."""

    def test_empty_findings_produce_benign_score(self) -> None:
        """Verify no findings yields score of 0 and Benign verdict."""
        engine = RiskEngine()
        risk = engine.calculate_risk([])

        assert risk.score == 0
        assert risk.verdict == "BENIGN / INFORMATIONAL"

    def test_confirmed_critical_finding_floors_at_70(self) -> None:
        """Verify any confirmed Critical finding forces score >= 70 (High Risk)."""
        critical_finding = Finding(
            rule_id="PDF-LAUNCH-001",
            category="DOCUMENT_ACTION",
            title="Launch Action",
            description="Arbitrary command execution",
            severity=FindingSeverity.CRITICAL,
            confidence=ConfidenceLevel.CONFIRMED,
            score_impact=50,
        )

        engine = RiskEngine()
        risk = engine.calculate_risk([critical_finding])

        assert risk.score >= 70
        assert "HIGH RISK" in risk.verdict

    def test_category_cap_prevents_inflation(self) -> None:
        """Verify 10 findings in the exact same category cannot exceed CATEGORY_CAP."""
        findings: List[Finding] = [
            Finding(
                rule_id=f"PE-IMPORT-{i:03d}",
                category="SUSPICIOUS_IMPORT",
                title=f"Import {i}",
                description="Suspicious import",
                severity=FindingSeverity.MEDIUM,
                confidence=ConfidenceLevel.CONFIRMED,
                score_impact=20,
            )
            for i in range(10)
        ]

        engine = RiskEngine()
        risk = engine.calculate_risk(findings)

        # 10 * 20 = 200 raw points, but capped at CATEGORY_CAP (55)
        assert risk.score <= 55
        assert risk.verdict == "SUSPICIOUS"

