"""
Unit tests for Ed25519 digital key management, signing, and signature verification.
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from forensight.core.types import EvidenceManifest, HashResult
from forensight.crypto.keys import KeyManager
from forensight.crypto.signing import (
    sign_manifest,
    sign_payload,
    verify_manifest,
    verify_payload_signature,
)


class TestCryptoSigning:
    """Tests for Ed25519 signature generation, verification, and tamper detection."""

    def test_keypair_generation_and_payload_signing(self, tmp_path: Path) -> None:
        """Verify Ed25519 keypair can sign and verify an arbitrary byte payload."""
        km = KeyManager(keys_dir=tmp_path)
        priv_key, pub_key = km.generate_keypair()

        test_data = b"Forensic Investigation Report - Case 2026-ALPHA"
        sig_hex = sign_payload(test_data, priv_key)

        assert len(sig_hex) == 128  # Ed25519 64-byte signature in hex = 128 chars
        assert verify_payload_signature(test_data, sig_hex, pub_key) is True

        # Altering data must fail verification
        tampered_data = b"Forensic Investigation Report - Case 2026-BETA"
        assert verify_payload_signature(tampered_data, sig_hex, pub_key) is False

    def test_manifest_signing_and_tamper_detection(self, tmp_path: Path) -> None:
        """Verify signing EvidenceManifest and detecting tampering of metadata fields."""
        km = KeyManager(keys_dir=tmp_path)
        priv_key, pub_key = km.generate_keypair()

        manifest = EvidenceManifest(
            manifest_id="man-001",
            evidence_id="ev-001",
            original_filename="malware.exe",
            hashes=HashResult(
                sha256="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
                sha1="2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
                md5="9e107d9d372bb6826bd81d3542a419d6",
                size_bytes=43,
            ),
            file_type="PE",
            acquired_at=datetime.now(timezone.utc),
        )

        signed_manifest = sign_manifest(manifest, priv_key)
        assert signed_manifest.signature is not None
        assert signed_manifest.public_key_fingerprint is not None

        # Verify signature is valid
        assert verify_manifest(signed_manifest, pub_key) is True

        # Tampering with filename invalidates signature
        signed_manifest.original_filename = "innocent_document.pdf"
        assert verify_manifest(signed_manifest, pub_key) is False
