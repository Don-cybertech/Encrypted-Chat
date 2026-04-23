"""
crypto/fernet_crypto.py - AES-128-CBC + HMAC via cryptography.fernet

Demo mode: both parties derive the same key from a shared passphrase.
No key exchange needed — ideal for showing encryption basics simply.
"""

import base64
import hashlib
from cryptography.fernet import Fernet


class FernetCrypto:
    """Symmetric encryption using Fernet (AES-128-CBC + HMAC-SHA256)."""

    def __init__(self, key: bytes = None, passphrase: str = None):
        if passphrase:
            self._key = self._derive_key(passphrase)
        elif key:
            self._key = key
        else:
            self._key = Fernet.generate_key()
        self._fernet = Fernet(self._key)

    @staticmethod
    def _derive_key(passphrase: str) -> bytes:
        """PBKDF-lite: SHA-256 of passphrase → base64url (Fernet-compatible)."""
        digest = hashlib.sha256(passphrase.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    @staticmethod
    def generate_key() -> bytes:
        return Fernet.generate_key()

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode()).decode()

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt_bytes(self, data: bytes) -> bytes:
        return self._fernet.decrypt(data)

    @property
    def key(self) -> bytes:
        return self._key

    @property
    def fingerprint(self) -> str:
        """SSH-style fingerprint so both sides can verify key match."""
        h = hashlib.sha256(self._key).hexdigest()
        return ":".join(h[i:i+4] for i in range(0, 24, 4))
