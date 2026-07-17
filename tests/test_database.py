"""Tests for the password-history database."""

from passguard.database import PasswordHistory


def test_new_password_is_accepted(tmp_path):
    db = tmp_path / "history.db"
    with PasswordHistory(db) as history:
        assert history.register_if_new("alice", "FirstP@ss1") is True
        assert history.history_count("alice") == 1


def test_reused_password_is_rejected(tmp_path):
    db = tmp_path / "history.db"
    with PasswordHistory(db) as history:
        history.register_if_new("bob", "Sup3r$ecret!")
        assert history.is_reused("bob", "Sup3r$ecret!") is True
        assert history.register_if_new("bob", "Sup3r$ecret!") is False
        assert history.history_count("bob") == 1


def test_history_is_per_user(tmp_path):
    db = tmp_path / "history.db"
    with PasswordHistory(db) as history:
        history.register_if_new("alice", "SharedP@ss9")
        # Same password, different user is allowed.
        assert history.register_if_new("bob", "SharedP@ss9") is True
        assert history.is_reused("alice", "SharedP@ss9") is True
        assert history.is_reused("bob", "SharedP@ss9") is True


def test_passwords_are_not_stored_in_plaintext(tmp_path):
    db = tmp_path / "history.db"
    secret = "PlaintextLeak123!"
    with PasswordHistory(db) as history:
        history.register_if_new("carol", secret)
    # Read the raw database bytes and ensure the secret is absent.
    raw = db.read_bytes()
    assert secret.encode() not in raw
