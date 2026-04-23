"""
crypto/rsa_aes_crypto.py - RSA-2048 key exchange + AES-256-GCM message encryption

Full production-grade hybrid encryption:
  1. Each party generates an RSA-2048 keypair on startup
  2. Public keys are exchanged over the socket
  3. Server generates a random AES-256 session key
  4. Session key is RSA-encrypted and sent to the client
  5. All messages encrypted with AES-256-GCM (authenticated encryption)

Why hybrid?
  RSA alone is slow and size-limited.
  AES alone requires a secure way to share the key.
  RSA + AES gives you the best of both: secure key exchange + fast symmetric encryption.
"""

import os
import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── RSA Key Management ─────────────────────────────────────────────────────────

def generate_rsa_keypair():
    """Generate RSA-2048 private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> str:
    """Export public key as PEM string (safe to send over the wire)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def deserialize_public_key(pem_str: str):
    """Load a PEM public key string back to a key object."""
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Encrypt bytes with RSA public key (OAEP padding with SHA-256)."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Decrypt bytes with RSA private key."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )


# ── AES-256-GCM Message Encryption ────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Generate a random 256-bit (32-byte) AES session key."""
    return os.urandom(32)


class AESCipher:
    """
    AES-256-GCM authenticated encryption.

    GCM provides both confidentiality AND integrity — any tampering
    with the ciphertext causes decryption to fail with an error.
    Each message gets a unique 12-byte random nonce.
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes (256 bits)")
        self._key   = key
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt string → base64 JSON blob: {"nonce": "...", "ct": "..."}
        The nonce is sent alongside ciphertext (it's not secret, just unique).
        """
        nonce = os.urandom(12)
        ct    = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        payload = {
            "nonce": base64.b64encode(nonce).decode(),
            "ct":    base64.b64encode(ct).decode(),
        }
        return base64.b64encode(json.dumps(payload).encode()).decode()

    def decrypt(self, token: str) -> str:
        """Decrypt a token produced by encrypt()."""
        payload = json.loads(base64.b64decode(token).decode())
        nonce   = base64.b64decode(payload["nonce"])
        ct      = base64.b64decode(payload["ct"])
        pt      = self._aesgcm.decrypt(nonce, ct, None)
        return pt.decode("utf-8")

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt raw bytes → nonce (12) + ciphertext."""
        nonce = os.urandom(12)
        ct    = self._aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def decrypt_bytes(self, data: bytes) -> bytes:
        """Decrypt raw bytes (nonce + ciphertext)."""
        nonce, ct = data[:12], data[12:]
        return self._aesgcm.decrypt(nonce, ct, None)

    @property
    def key(self) -> bytes:
        return self._key

    @property
    def fingerprint(self) -> str:
        """Hex fingerprint of the AES session key for E2E verification."""
        h = hashlib.sha256(self._key).hexdigest()
        return ":".join(h[i:i+4] for i in range(0, 24, 4))
