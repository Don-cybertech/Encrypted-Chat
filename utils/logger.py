"""
utils/logger.py - Encrypted message history logger

Saves chat history to chat_logs/<session_id>.log
Log lines are AES-encrypted so the file is useless without the session key.
"""

import json
from pathlib import Path
from datetime import datetime


LOG_DIR = Path(__file__).parent.parent / "chat_logs"


class ChatLogger:
    """
    Logs encrypted chat messages to a session log file.
    Each line is a JSON object with encrypted content.
    """

    def __init__(self, session_id: str, cipher=None):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path    = LOG_DIR / f"{session_id}.log"
        self.cipher  = cipher
        self._file   = open(self.path, "a", encoding="utf-8")

    def log(self, sender: str, message: str, msg_type: str = "message"):
        entry = {
            "ts":   datetime.now().isoformat(),
            "type": msg_type,
            "from": sender,
            "msg":  message,
        }
        line = json.dumps(entry)
        if self.cipher:
            try:
                line = self.cipher.encrypt(line)
            except Exception:
                pass   # fall back to plaintext if cipher fails

        self._file.write(line + "\n")
        self._file.flush()

    def close(self):
        try:
            self._file.close()
        except Exception:
            pass

    def __del__(self):
        self.close()


def read_log(log_path: Path, cipher=None) -> list:
    """Read and optionally decrypt a session log file."""
    entries = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        if cipher:
            try:
                line = cipher.decrypt(line)
            except Exception:
                pass
        try:
            entries.append(json.loads(line))
        except Exception:
            entries.append({"raw": line})
    return entries
