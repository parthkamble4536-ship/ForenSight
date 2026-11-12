"""
Comprehensive Evidence Verification Center service.

Audits filesystem digests (SHA-256, SHA-1, MD5), file size, vault containment,
Ed25519 manifest signature integrity, and persistent Chain-of-Custody continuity.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from forensight.core.types import EvidenceManifest, HashResult
from forensight.crypto.keys import key_manager
from forensight.crypto.signing import verify_manifest
from forensight.database.crud import get_evidence, update_evidence_verification
from forensight.evidence.custody import custody_ledger
from forensight.storage.manager import evidence_vault


VERIFICATION_STATUSES = (
    "INTEGRITY VERIFIED",
    "SIGNATURE INVALID",
    "EVIDENCE MODIFIED",
    "EVIDENCE MISSING",
    "VERIFICATION INCONCLUSIVE",
)


def verify_evidence_comprehensive(
    db: Session,
    evidence_id: str,
    *,
    record_custody: bool = True,
) -> Optional[Dict[str, Any]]:
    """
    Execute full multi-layer integrity, signature, and custody verification for an evidence item.

    Guarantees:
    - Does not fabricate positive status when signature, file, or custody checks fail.
    - Distinguishes between manifest integrity inside ForenSight and external acquisition provenance.
    - Persists verification telemetry across application restarts.
    """
    ev = get_evidence(db, evidence_id)
    if not ev:
        return None

    checked_at = datetime.now(timezone.utc)
    expected_hashes = HashResult(
        sha256=ev.sha256,
        sha1=ev.sha1,
        md5=ev.md5,
        size_bytes=ev.file_size_bytes,
    )

    storage_audit = evidence_vault.verify_evidence_integrity(evidence_id, expected_hashes)
    file_exists = Path(storage_audit.expected_size_bytes >= 0 and evidence_vault.vault_dir / f"{evidence_id}.bin").is_file()

    # Check Ed25519 manifest signature
    _, pub_key = key_manager.load_or_create_keypair()
    local_fp = key_manager.get_public_key_fingerprint(pub_key)

    manifest_status = "UNSIGNED"
    signature_valid = False
    manifest_error: Optional[str] = None

    if not ev.manifest_signature or not ev.manifest_id:
        manifest_status = "UNSIGNED"
        manifest_error = "Manifest signature or manifest_id missing."
    else:
        acq_dt = ev.stored_at if ev.stored_at.tzinfo else ev.stored_at.replace(tzinfo=timezone.utc)
        manifest = EvidenceManifest(
            manifest_id=ev.manifest_id,
            evidence_id=ev.evidence_id,
            case_id=ev.case_id,
            original_filename=ev.original_filename,
            hashes=expected_hashes,
            file_type=ev.identified_type,
            acquired_at=acq_dt.astimezone(timezone.utc),
            signature=ev.manifest_signature,
            public_key_fingerprint=ev.public_key_fingerprint,
        )
        if ev.public_key_fingerprint and ev.public_key_fingerprint != local_fp:
            manifest_status = "KEY_MISMATCH"
            manifest_error = (
                f"Manifest key fingerprint ({ev.public_key_fingerprint[:16]}...) does not match active "
                f"vault public key ({local_fp[:16]}...)."
            )
        elif verify_manifest(manifest, pub_key):
            manifest_status = "VALID"
            signature_valid = True
        else:
            manifest_status = "INVALID"
            manifest_error = "Ed25519 signature verification failed over canonical manifest payload."

    # Check persistent Chain-of-Custody ledger integrity
    custody_valid, custody_err, custody_events = custody_ledger.verify_persisted_chain(db)

    # Determine explicit Phase 3 verification status
    if not file_exists:
        verification_status = "EVIDENCE MISSING"
    elif not storage_audit.is_valid:
        verification_status = "EVIDENCE MODIFIED"
    elif manifest_status in ("INVALID", "KEY_MISMATCH"):
        verification_status = "SIGNATURE INVALID"
    elif not custody_valid:
        verification_status = "EVIDENCE MODIFIED"
    elif signature_valid and storage_audit.is_valid and custody_valid:
        verification_status = "INTEGRITY VERIFIED"
    else:
        verification_status = "VERIFICATION INCONCLUSIVE"

    summary_parts = [storage_audit.details]
    if manifest_error:
        summary_parts.append(manifest_error)
    else:
        summary_parts.append("Ed25519 manifest signature verified.")
    if not custody_valid and custody_err:
        summary_parts.append(f"Custody ledger error: {custody_err}")
    else:
        summary_parts.append(f"Custody chain verified ({len(custody_events)} events).")

    combined_details = " | ".join(summary_parts)
    update_evidence_verification(
        db,
        evidence_id=evidence_id,
        verification_status=verification_status,
        verification_details=combined_details,
        verified_at=checked_at,
    )

    if record_custody and custody_valid:
        custody_ledger.record_event(
            evidence_id=evidence_id,
            case_id=ev.case_id,
            event_type="INTEGRITY_AUDIT",
            details=f"Verification Center status={verification_status} ({combined_details})",
            db=db,
        )

    payload = storage_audit.model_dump()
    payload.update({
        "verification_status": verification_status,
        "file_exists": file_exists,
        "manifest_id": ev.manifest_id,
        "manifest_status": manifest_status,
        "manifest_signature_valid": signature_valid,
        "public_key_fingerprint": ev.public_key_fingerprint,
        "active_public_key_fingerprint": local_fp,
        "custody_chain_valid": custody_valid,
        "custody_chain_error": custody_err,
        "last_verified_at": checked_at.isoformat(),
        "combined_details": combined_details,
        "verification_caveat": (
            "A valid Ed25519 signature proves manifest integrity since ingestion inside ForenSight; "
            "it does not independently prove trustworthiness of the original acquisition host."
        ),
    })
    return payload
