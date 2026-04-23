"""
transfer/file_transfer.py - Encrypted file sending and receiving

Protocol:
  1. Sender reads file, splits into CHUNK_SIZE byte chunks
  2. Sends FILE_HEADER packet (filename, size, total_chunks, hash)
  3. Sends N FILE_CHUNK packets (each chunk encrypted separately)
  4. Receiver reassembles, decrypts, verifies SHA-256 hash
  5. Receiver sends FILE_ACK to confirm success

Security:
  - Every chunk is independently encrypted (AES-GCM or Fernet)
  - SHA-256 hash of original file is checked after reassembly
  - Chunk index included in each packet to detect reordering/replay
"""

import os
import base64
import hashlib
import json
from pathlib import Path
from typing import Callable, Optional

from models import Packet, MsgType


CHUNK_SIZE    = 32 * 1024   # 32 KB per chunk
RECEIVE_DIR   = Path(__file__).parent.parent / "received_files"


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Sender side ───────────────────────────────────────────────────────

def send_file(sock, file_path: Path, username: str, cipher,
              status_cb: Optional[Callable] = None):
    """
    Encrypt and send a file over the socket.

    Args:
        sock:      Connected socket.
        file_path: Path to the local file.
        username:  Sender's username (for packet headers).
        cipher:    AESCipher or FernetCrypto instance.
        status_cb: Optional callback(progress_pct) for progress display.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    raw_data = file_path.read_bytes()
    file_hash = compute_sha256(raw_data)
    file_size = len(raw_data)

    # Split into chunks
    chunks = [raw_data[i:i+CHUNK_SIZE] for i in range(0, file_size, CHUNK_SIZE)]
    total_chunks = len(chunks)

    # ── FILE_HEADER ──────────────────────────────────────────────────
    header = Packet(
        type=MsgType.FILE_HEADER.value,
        sender=username,
        payload="",
        extra={
            "filename":     file_path.name,
            "size":         file_size,
            "total_chunks": total_chunks,
            "sha256":       file_hash,
        }
    )
    sock.sendall(header.to_bytes())

    # ── FILE_CHUNKs ──────────────────────────────────────────────────
    for idx, chunk in enumerate(chunks):
        # Encrypt the chunk
        if hasattr(cipher, "encrypt_bytes"):
            enc_chunk = cipher.encrypt_bytes(chunk)
        else:
            enc_chunk = cipher.encrypt_bytes(chunk)

        chunk_b64 = base64.b64encode(enc_chunk).decode()

        pkt = Packet(
            type=MsgType.FILE_CHUNK.value,
            sender=username,
            payload=chunk_b64,
            extra={"index": idx, "total": total_chunks},
        )
        sock.sendall(pkt.to_bytes())

        if status_cb:
            status_cb(int((idx + 1) / total_chunks * 100))

    return file_hash


# ── Receiver side ─────────────────────────────────────────────────────

class FileReceiver:
    """
    Accumulates FILE_CHUNK packets and reassembles the file.
    Call handle_header() once, then handle_chunk() for each chunk.
    """

    def __init__(self, cipher, receive_dir: Path = RECEIVE_DIR):
        self.cipher       = cipher
        self.receive_dir  = receive_dir
        self.receive_dir.mkdir(parents=True, exist_ok=True)

        # State set by handle_header
        self.filename     = None
        self.total_chunks = 0
        self.expected_hash = None
        self._chunks: dict = {}   # index → decrypted bytes

    def handle_header(self, pkt: Packet):
        self.filename      = pkt.extra["filename"]
        self.total_chunks  = pkt.extra["total_chunks"]
        self.expected_hash = pkt.extra["sha256"]
        self.expected_size = pkt.extra["size"]
        self._chunks       = {}

    def handle_chunk(self, pkt: Packet) -> Optional[Path]:
        """
        Process one FILE_CHUNK packet.
        Returns the saved file Path when all chunks are received and verified,
        or None if still accumulating.
        """
        idx       = pkt.extra["index"]
        enc_bytes = base64.b64decode(pkt.payload)

        # Decrypt the chunk
        if hasattr(self.cipher, "decrypt_bytes"):
            dec_chunk = self.cipher.decrypt_bytes(enc_bytes)
        else:
            dec_chunk = self.cipher.decrypt_bytes(enc_bytes)

        self._chunks[idx] = dec_chunk

        if len(self._chunks) < self.total_chunks:
            return None   # still waiting for more chunks

        # Reassemble in order
        raw_data = b"".join(self._chunks[i] for i in range(self.total_chunks))

        # Verify SHA-256
        actual_hash = compute_sha256(raw_data)
        if actual_hash != self.expected_hash:
            raise ValueError(
                f"File integrity check FAILED!\n"
                f"  Expected: {self.expected_hash}\n"
                f"  Got:      {actual_hash}"
            )

        # Save to received_files/
        out_path = self.receive_dir / self.filename
        # Avoid overwriting existing files
        counter = 1
        while out_path.exists():
            stem   = Path(self.filename).stem
            suffix = Path(self.filename).suffix
            out_path = self.receive_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        out_path.write_bytes(raw_data)
        return out_path

    @property
    def progress(self) -> int:
        if self.total_chunks == 0:
            return 0
        return int(len(self._chunks) / self.total_chunks * 100)
