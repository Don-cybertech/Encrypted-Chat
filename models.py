"""
models.py - Shared protocol definitions for Encrypted Chat
"""

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


class MsgType(Enum):
    AUTH_REQUEST  = "auth_request"
    AUTH_RESPONSE = "auth_response"
    KEY_EXCHANGE  = "key_exchange"
    SESSION_KEY   = "session_key"
    MESSAGE       = "message"
    FILE_HEADER   = "file_header"
    FILE_CHUNK    = "file_chunk"
    FILE_ACK      = "file_ack"
    SYSTEM        = "system"
    PING          = "ping"
    PONG          = "pong"
    DISCONNECT    = "disconnect"


class CryptoMode(Enum):
    FERNET  = "fernet"
    RSA_AES = "rsa_aes"


@dataclass
class Packet:
    """Every socket message is a length-prefixed JSON Packet."""
    type:      str
    sender:    str
    payload:   str   = ""
    timestamp: float = field(default_factory=time.time)
    extra:     dict  = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(data: str) -> "Packet":
        d = json.loads(data)
        return Packet(**d)

    def to_bytes(self) -> bytes:
        body = self.to_json().encode("utf-8")
        return len(body).to_bytes(4, "big") + body


def read_packet(sock) -> Optional[Packet]:
    try:
        raw_len = _recv_exact(sock, 4)
        if not raw_len:
            return None
        body = _recv_exact(sock, int.from_bytes(raw_len, "big"))
        if not body:
            return None
        return Packet.from_json(body.decode("utf-8"))
    except Exception:
        return None


def _recv_exact(sock, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
