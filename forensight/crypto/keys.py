"""
Cryptographic key management for ForenSight using Ed25519.

Handles generation, persistence, and loading of Ed25519 signing keys.
Keys are stored in data/keys/ with permissions secured and excluded from Git.
"""

import hashlib
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from forensight.core.config import settings
from forensight.core.exceptions import CryptographicSignatureError
from forensight.core.security import make_read_only, make_writable


class KeyManager:
    """
    Manages asymmetric Ed25519 digital signing keys for evidence manifests and reports.
    """

    def __init__(self, keys_dir: Optional[Path] = None) -> None:
        self.keys_dir = (keys_dir or settings.keys_dir).resolve()
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.default_private_path = self.keys_dir / "forensight_ed25519.key"
        self.default_public_path = self.keys_dir / "forensight_ed25519_pub.pem"

    def generate_keypair(
        self,
        private_path: Optional[Path] = None,
        public_path: Optional[Path] = None,
    ) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """
        Generate a new Ed25519 keypair and persist to disk with restricted permissions.
        """
        priv_target = private_path or self.default_private_path
        pub_target = public_path or self.default_public_path

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize private key to PKCS8 PEM without password (local first)
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Serialize public key to SubjectPublicKeyInfo PEM
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        make_writable(priv_target)
        priv_target.write_bytes(priv_bytes)
        make_read_only(priv_target)

        make_writable(pub_target)
        pub_target.write_bytes(pub_bytes)

        return private_key, public_key

    def load_or_create_keypair(
        self,
    ) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """
        Load active Ed25519 keypair from storage vault, or generate if absent.
        """
        if self.default_private_path.exists() and self.default_public_path.exists():
            try:
                priv_bytes = self.default_private_path.read_bytes()
                private_key = serialization.load_pem_private_key(priv_bytes, password=None)
                if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                    raise CryptographicSignatureError("Loaded key is not an Ed25519 private key.")

                pub_bytes = self.default_public_path.read_bytes()
                public_key = serialization.load_pem_public_key(pub_bytes)
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise CryptographicSignatureError("Loaded key is not an Ed25519 public key.")

                return private_key, public_key
            except Exception:
                # Fall back to regenerating keypair on corrupt file
                return self.generate_keypair()

        return self.generate_keypair()

    def get_public_key_fingerprint(self, public_key: ed25519.Ed25519PublicKey) -> str:
        """Compute SHA-256 fingerprint of the public key in lowercase hex."""
        raw_pub = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(raw_pub).hexdigest()


# Global key manager singleton
key_manager = KeyManager()
