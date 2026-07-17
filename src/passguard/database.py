"""Persist salted password hashes to prevent reuse of old passwords.

Passwords are **never** stored in plaintext. Each entry stores a random salt
and the PBKDF2-HMAC-SHA256 derivation of the password. Reuse detection works by
re-deriving a candidate password with every stored salt and comparing digests
in constant time.

This mirrors how real systems enforce password-history policies and is a good
vehicle for learning about salting and key-derivation functions.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import time
from pathlib import Path

_PBKDF2_ROUNDS = 200_000
_SALT_BYTES = 16


def _derive(password: str, salt: bytes, rounds: int = _PBKDF2_ROUNDS) -> bytes:
    """Derive a key from a password and salt using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)


class PasswordHistory:
    """A small SQLite-backed store of password hashes for a set of users."""

    def __init__(self, db_path: str | Path = "password_history.db") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_history (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                salt     BLOB NOT NULL,
                hash     BLOB NOT NULL,
                rounds   INTEGER NOT NULL,
                created  REAL NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_history_user "
            "ON password_history(username)"
        )
        self._conn.commit()

    def is_reused(self, username: str, password: str) -> bool:
        """Return True if the password matches any stored hash for the user."""
        rows = self._conn.execute(
            "SELECT salt, hash, rounds FROM password_history WHERE username = ?",
            (username,),
        ).fetchall()
        for row in rows:
            candidate = _derive(password, row["salt"], row["rounds"])
            if hmac.compare_digest(candidate, row["hash"]):
                return True
        return False

    def add_password(self, username: str, password: str) -> None:
        """Store the salted hash of a new password for the user."""
        salt = os.urandom(_SALT_BYTES)
        digest = _derive(password, salt)
        self._conn.execute(
            "INSERT INTO password_history "
            "(username, salt, hash, rounds, created) VALUES (?, ?, ?, ?, ?)",
            (username, salt, digest, _PBKDF2_ROUNDS, time.time()),
        )
        self._conn.commit()

    def register_if_new(self, username: str, password: str) -> bool:
        """Store the password only if it has not been used before.

        Returns True if the password was newly stored, False if it was a reuse.
        """
        if self.is_reused(username, password):
            return False
        self.add_password(username, password)
        return True

    def history_count(self, username: str) -> int:
        """Return how many passwords are stored for the user."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM password_history WHERE username = ?",
            (username,),
        ).fetchone()
        return int(row["n"]) if row else 0

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "PasswordHistory":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
