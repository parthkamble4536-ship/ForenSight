"""
Digital signature creation and verification engine using Ed25519.

Guarantees tamper-evidence and cryptographic non-repudiation for evidence manifests
and forensic analysis reports.
"""

import json
from datetime import timezone
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from forensight.core.exceptions import CryptographicSignatureError
from forensight.core.types import EvidenceManifest
from forensight.crypto.keys import key_manager


def _canonicalize_dict(payload: Dict[str, Any]) -> bytes:
    """Produce deterministic UTF-8 JSON bytes with sorted keys."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> str:
    """
    Sign raw bytes using Ed25519 and return signature in lowercase hexadecimal.
    """
    try:
        raw_sig = private_key.sign(data)
        return raw_sig.hex()
    except Exception as err:
        raise CryptographicSignatureError(f"Failed to generate Ed25519 digital signature: {err}")


def verify_payload_signature(
    data: bytes,
    signature_hex: str,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """
    Verify Ed25519 digital signature against data bytes. Returns True if valid, False otherwise.
    """
    if not signature_hex:
        return False
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        public_key.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_manifest(
    manifest: EvidenceManifest,
    private_key: ed25519.Ed25519PrivateKey,
) -> EvidenceManifest:
    """
    Sign an EvidenceManifest by computing the signature over its canonical fields.
    Attaches the signature and signing key fingerprint to the manifest.
    """
    acq = manifest.acquired_at if manifest.acquired_at.tzinfo else manifest.acquired_at.replace(tzinfo=timezone.utc)
    acq_utc = acq.astimezone(timezone.utc)
    canonical_payload = {
        "manifest_id": manifest.manifest_id,
        "evidence_id": manifest.evidence_id,
        "original_filename": manifest.original_filename,
        "sha256": manifest.hashes.sha256,
        "sha1": manifest.hashes.sha1,
        "md5": manifest.hashes.md5,
        "size_bytes": manifest.hashes.size_bytes,
        "file_type": manifest.file_type,
        "acquired_at": acq_utc.isoformat(),
    }
    canonical_bytes = _canonicalize_dict(canonical_payload)
    sig_hex = sign_payload(canonical_bytes, private_key)
    fp = key_manager.get_public_key_fingerprint(private_key.public_key())

    manifest.signature = sig_hex
    manifest.public_key_fingerprint = fp
    return manifest


def verify_manifest(
    manifest: EvidenceManifest,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """
    Verify the digital signature of an EvidenceManifest.
    """
    if not manifest.signature:
        return False

    acq = manifest.acquired_at if manifest.acquired_at.tzinfo else manifest.acquired_at.replace(tzinfo=timezone.utc)
    acq_utc = acq.astimezone(timezone.utc)
    canonical_payload = {
        "manifest_id": manifest.manifest_id,
        "evidence_id": manifest.evidence_id,
        "original_filename": manifest.original_filename,
        "sha256": manifest.hashes.sha256,
        "sha1": manifest.hashes.sha1,
        "md5": manifest.hashes.md5,
        "size_bytes": manifest.hashes.size_bytes,
        "file_type": manifest.file_type,
        "acquired_at": acq_utc.isoformat(),
    }
    canonical_bytes = _canonicalize_dict(canonical_payload)
    return verify_payload_signature(canonical_bytes, manifest.signature, public_key)

