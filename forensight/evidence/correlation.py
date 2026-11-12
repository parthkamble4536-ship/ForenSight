"""
Multi-evidence correlation engine for investigation cases.

Discovers pivot relationships, shared IOCs, common infrastructure, and metadata
links between disparate evidence items within an investigation.
"""

import uuid
from typing import Dict, List, Set, Tuple

from forensight.core.types import (
    AnalysisResult,
    EvidenceRelationship,
    RelationshipType,
)


class EvidenceCorrelator:
    """
    Correlates evidence artifacts to discover threat actor infrastructure clusters,
    common tooling, and multi-stage infection chains without external network queries.
    """

    def correlate_case_evidence(self, results: List[AnalysisResult]) -> List[EvidenceRelationship]:
        """
        Analyze a collection of analysis results belonging to an investigation case
        and produce bidirectional correlation edges.
        """
        if len(results) < 2:
            return []

        relationships: List[EvidenceRelationship] = []
        n = len(results)

        for i in range(n):
            for j in range(i + 1, n):
                res_a = results[i]
                res_b = results[j]

                case_id = res_a.evidence.case_id or res_b.evidence.case_id or "case-default"
                id_a = res_a.evidence.evidence_id
                id_b = res_b.evidence.evidence_id

                # 1. Check for Shared Cryptographic Hashes
                if res_a.evidence.hashes.sha256 == res_b.evidence.hashes.sha256:
                    relationships.append(
                        EvidenceRelationship(
                            relationship_id=str(uuid.uuid4()),
                            case_id=case_id,
                            source_evidence_id=id_a,
                            target_evidence_id=id_b,
                            relationship_type=RelationshipType.SHARED_HASH,
                            reason=f"Identical SHA-256 cryptographic digest ({res_a.evidence.hashes.sha256})",
                            shared_value=res_a.evidence.hashes.sha256,
                            weight=1.0,
                        )
                    )

                # 2. Check for Shared IOCs (Network & Host Indicators)
                iocs_a = {(ioc.ioc_type, ioc.value) for ioc in res_a.iocs}
                iocs_b = {(ioc.ioc_type, ioc.value) for ioc in res_b.iocs}

                common_iocs = iocs_a.intersection(iocs_b)
                for ioc_type, val in common_iocs:
                    relationships.append(
                        EvidenceRelationship(
                            relationship_id=str(uuid.uuid4()),
                            case_id=case_id,
                            source_evidence_id=id_a,
                            target_evidence_id=id_b,
                            relationship_type=RelationshipType.SHARED_IOC,
                            reason=f"Shared {ioc_type.value} indicator of compromise: {val}",
                            shared_value=val,
                            weight=0.9,
                        )
                    )

                # 3. Check for Shared Authorship / Creator Metadata
                author_a = res_a.analyzer_details.get("author") or res_a.analyzer_details.get("creator")
                author_b = res_b.analyzer_details.get("author") or res_b.analyzer_details.get("creator")

                if author_a and author_b and isinstance(author_a, str) and isinstance(author_b, str):
                    clean_a, clean_b = author_a.strip().lower(), author_b.strip().lower()
                    if clean_a and clean_b and clean_a == clean_b and clean_a not in ("unknown", "user", "admin"):
                        relationships.append(
                            EvidenceRelationship(
                                relationship_id=str(uuid.uuid4()),
                                case_id=case_id,
                                source_evidence_id=id_a,
                                target_evidence_id=id_b,
                                relationship_type=RelationshipType.SHARED_AUTHOR,
                                reason=(
                                    f"Identical document creator metadata: '{author_a.strip()}' "
                                    "(heuristic correlation only; metadata is unverified and does not prove common ownership)"
                                ),
                                shared_value=author_a.strip(),
                                weight=0.75,
                            )
                        )

                # 4. Check for Email Attachment Relationships (both directions)
                email_attachments_a = res_a.analyzer_details.get("attachments", [])
                for att in email_attachments_a or []:
                    if att.get("sha256") == res_b.evidence.hashes.sha256:
                        relationships.append(
                            EvidenceRelationship(
                                relationship_id=str(uuid.uuid4()),
                                case_id=case_id,
                                source_evidence_id=id_a,
                                target_evidence_id=id_b,
                                relationship_type=RelationshipType.EMAIL_ATTACHMENT,
                                reason=f"Evidence [{res_b.evidence.original_filename}] matches attachment digest in email [{res_a.evidence.original_filename}]",
                                shared_value=att.get("sha256"),
                                weight=1.0,
                            )
                        )

                email_attachments_b = res_b.analyzer_details.get("attachments", [])
                for att in email_attachments_b or []:
                    if att.get("sha256") == res_a.evidence.hashes.sha256:
                        relationships.append(
                            EvidenceRelationship(
                                relationship_id=str(uuid.uuid4()),
                                case_id=case_id,
                                source_evidence_id=id_b,
                                target_evidence_id=id_a,
                                relationship_type=RelationshipType.EMAIL_ATTACHMENT,
                                reason=f"Evidence [{res_a.evidence.original_filename}] matches attachment digest in email [{res_b.evidence.original_filename}]",
                                shared_value=att.get("sha256"),
                                weight=1.0,
                            )
                        )

        return relationships


# Global correlator instance
evidence_correlator = EvidenceCorrelator()

