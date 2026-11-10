"""
Explainable, deterministic risk scoring and forensic verdict engine.

Evaluates findings with severity weighting, confidence discounting, and category-level
capping to prevent double-counting of correlated heuristics.
"""

from typing import Dict, List

from forensight.core.types import (
    ConfidenceLevel,
    Finding,
    FindingSeverity,
    RiskScore,
)


class RiskEngine:
    """
    Explainable, transparent risk assessment engine for digital forensics triage.

    Guarantees:
    - Deterministic, reproducible scoring (0 to 100).
    - Category-based scoring caps to prevent artificial score inflation from correlated indicators.
    - Confidence-weighted contributions.
    - Explicit forensic disclaimers (heuristic triage; not dynamic execution proof).
    """

    SEVERITY_BASE_WEIGHTS: Dict[FindingSeverity, int] = {
        FindingSeverity.INFO: 2,
        FindingSeverity.LOW: 8,
        FindingSeverity.MEDIUM: 20,
        FindingSeverity.HIGH: 35,
        FindingSeverity.CRITICAL: 50,
    }

    CONFIDENCE_MULTIPLIERS: Dict[ConfidenceLevel, float] = {
        ConfidenceLevel.CONFIRMED: 1.0,
        ConfidenceLevel.HIGH: 0.9,
        ConfidenceLevel.MEDIUM: 0.7,
        ConfidenceLevel.LOW: 0.4,
        ConfidenceLevel.INCONCLUSIVE: 0.2,
    }

    # Maximum score that can be contributed by a single category (anti-inflation guard)
    CATEGORY_CAP: int = 55

    def calculate_risk(self, findings: List[Finding]) -> RiskScore:
        """
        Compute an explainable, bounded risk assessment from a set of forensic findings.
        """
        if not findings:
            return RiskScore(
                score=0,
                verdict="BENIGN / INFORMATIONAL",
                confidence=ConfidenceLevel.HIGH,
                severity_counts={},
                summary="No overt anomalous or suspicious static triage indicators were observed.",
                rule_contributions=[],
            )

        severity_counts: Dict[str, int] = {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        category_points: Dict[str, float] = {}
        contributions: List[Dict[str, Any]] = []

        for finding in findings:
            sev_str = finding.severity.value
            severity_counts[sev_str] = severity_counts.get(sev_str, 0) + 1

            # Base weight: use finding's score_impact if set, otherwise standard severity weight
            base = finding.score_impact if finding.score_impact > 0 else self.SEVERITY_BASE_WEIGHTS.get(finding.severity, 5)
            multiplier = self.CONFIDENCE_MULTIPLIERS.get(finding.confidence, 0.8)
            effective_points = round(base * multiplier, 1)

            cat = finding.category.upper()
            current_cat_total = category_points.get(cat, 0.0)

            # Apply category-level saturation cap
            allowed_points = max(0.0, min(effective_points, self.CATEGORY_CAP - current_cat_total))
            category_points[cat] = current_cat_total + allowed_points

            contributions.append({
                "rule_id": finding.rule_id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity.value,
                "raw_impact": finding.score_impact,
                "effective_contribution": allowed_points,
            })

        # Calculate raw aggregate
        raw_total = sum(category_points.values())

        # If any CRITICAL finding is confirmed (e.g. Remote Template Injection, /Launch action, Zip Slip), floor score at 70
        has_confirmed_critical = any(
            f.severity == FindingSeverity.CRITICAL and f.confidence == ConfidenceLevel.CONFIRMED
            for f in findings
        )

        final_score = int(min(100.0, max(0.0, raw_total)))
        if has_confirmed_critical and final_score < 70:
            final_score = 70

        # Map to forensic verdict bands
        if final_score < 20:
            verdict = "BENIGN / INFORMATIONAL"
            summary = "File exhibits standard structural attributes with negligible or purely informational indicators."
        elif final_score < 45:
            verdict = "LOW RISK"
            summary = "Minor structural anomalies or low-risk characteristics observed. Routine triage recommended."
        elif final_score < 70:
            verdict = "SUSPICIOUS"
            summary = "Multiple notable heuristic indicators or suspicious capabilities identified. Escalated examination recommended."
        else:
            verdict = "HIGH RISK / HIGHLY SUSPICIOUS"
            summary = "High-severity adversarial capabilities, deceptive masquerading, or weaponization indicators detected."

        return RiskScore(
            score=final_score,
            verdict=verdict,
            confidence=ConfidenceLevel.HIGH,
            severity_counts=severity_counts,
            summary=summary,
            rule_contributions=contributions,
        )


# Global risk engine instance
risk_engine = RiskEngine()

