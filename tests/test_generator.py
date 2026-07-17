"""Tests for the password generator."""

import string

import pytest

from passguard.analyzer import PasswordAnalyzer, Strength
from passguard.generator import (
    generate_passphrase,
    generate_password,
    suggest_alternatives,
)


def test_generated_length():
    assert len(generate_password(20)) == 20


def test_generated_password_has_all_classes():
    pw = generate_password(16)
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)


def test_generated_password_is_strong():
    result = PasswordAnalyzer().analyze(generate_password(20))
    assert result.strength >= Strength.STRONG


def test_generate_rejects_tiny_length():
    with pytest.raises(ValueError):
        generate_password(2)


def test_passphrase_structure():
    phrase = generate_passphrase(4, separator="-")
    assert phrase.count("-") == 3


def test_no_symbols_option():
    pw = generate_password(30, use_symbols=False)
    symbols = set("!@#$%^&*()-_=+[]{};:,.?")
    assert not (set(pw) & symbols)


def test_suggestions_are_unique_and_nonempty():
    suggestions = suggest_alternatives("password", count=3)
    assert len(suggestions) == 3
    assert all(suggestions)
