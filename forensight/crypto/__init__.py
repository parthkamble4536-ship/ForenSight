"""
Cryptographic key management and digital signing subsystem for ForenSight.
"""

from forensight.crypto.keys import KeyManager, key_manager
from forensight.crypto.signing import (
    sign_manifest,
    sign_payload,
    verify_manifest,
    verify_payload_signature,
)

__all__ = [
    "KeyManager",
    "key_manager",
    "sign_payload",
    "verify_payload_signature",
    "sign_manifest",
    "verify_manifest",
]

