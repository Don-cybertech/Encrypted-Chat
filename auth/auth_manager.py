"""
auth/auth_manager.py - Username + bcrypt password authentication

Users are stored in a JSON file: users.db
Passwords are NEVER stored in plain text — only bcrypt hashes.

bcrypt automatically:
  - Salts each password (prevents rainbow table attacks)
  - Is computationally expensive (slows brute force attacks)
  - Is designed specifically for password storage
"""

import json
import bcrypt
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime


USERS_DB_PATH = Path(__file__).parent.parent / "keys" / "users.db"


class AuthManager:
    """Handles user registration, login, and session tokens."""

    def __init__(self, db_path: Path = USERS_DB_PATH):
        self.db_path = db_path
        self._users: dict = {}
        self._load()

        # Seed default users if the DB is empty
        if not self._users:
            self._seed_defaults()

    # ── Persistence ────────────────────────────────────────────────────

    def _load(self):
        if self.db_path.exists():
            try:
                self._users = json.loads(self.db_path.read_text())
            except Exception:
                self._users = {}

    def _save(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path.write_text(json.dumps(self._users, indent=2))

    def _seed_defaults(self):
        """Create demo accounts so the project works out of the box."""
        for username, password in [("alice", "alice123"), ("bob", "bob123"),
                                    ("admin", "admin123")]:
            self.register(username, password)

    # ── Public API ─────────────────────────────────────────────────────

    def register(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user.
        Returns (success, message).
        Password is hashed with bcrypt before storage.
        """
        username = username.strip().lower()

        if not username or len(username) < 2:
            return False, "Username must be at least 2 characters."
        if not password or len(password) < 6:
            return False, "Password must be at least 6 characters."
        if username in self._users:
            return False, f"Username '{username}' is already taken."

        # Hash password with bcrypt (cost factor 12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

        self._users[username] = {
            "password_hash": hashed.decode("utf-8"),
            "created_at":    datetime.now().isoformat(),
            "last_login":    None,
        }
        self._save()
        return True, f"User '{username}' registered successfully."

    def authenticate(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Verify username + password.
        Returns (success, message).
        Uses bcrypt.checkpw — constant-time comparison (prevents timing attacks).
        """
        username = username.strip().lower()

        if username not in self._users:
            # Use same error message to prevent username enumeration
            return False, "Invalid username or password."

        record = self._users[username]
        stored_hash = record["password_hash"].encode("utf-8")

        try:
            match = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
        except Exception:
            return False, "Authentication error."

        if not match:
            return False, "Invalid username or password."

        # Update last login
        self._users[username]["last_login"] = datetime.now().isoformat()
        self._save()
        return True, f"Welcome back, {username}!"

    def user_exists(self, username: str) -> bool:
        return username.strip().lower() in self._users

    def list_users(self) -> list:
        return list(self._users.keys())

    def get_last_login(self, username: str) -> Optional[str]:
        u = self._users.get(username.lower())
        return u["last_login"] if u else None
