"""Tests for entropy calculations."""

import math

from passguard import entropy


def test_pool_size_lowercase_only():
    assert entropy.character_pool_size("abcdef") == 26


def test_pool_size_mixed():
    # lowercase (26) + uppercase (26) + digits (10) = 62
    assert entropy.character_pool_size("Abc123") == 62


def test_pool_size_with_symbol():
    assert entropy.character_pool_size("Abc123!") == 62 + 32


def test_search_space_entropy_matches_formula():
    pw = "Abc123"
    expected = len(pw) * math.log2(62)
    assert math.isclose(entropy.search_space_entropy(pw), expected)


def test_empty_entropy_is_zero():
    assert entropy.search_space_entropy("") == 0.0
    assert entropy.shannon_entropy("") == 0.0


def test_repeated_chars_low_shannon_entropy():
    assert entropy.shannon_entropy("aaaa") == 0.0
    assert entropy.shannon_entropy("abcd") == 2.0


def test_humanize_seconds():
    assert entropy.humanize_seconds(0.5) == "less than a second"
    assert "second" in entropy.humanize_seconds(1)
    assert "year" in entropy.humanize_seconds(60 * 60 * 24 * 400)


def test_very_long_password_does_not_overflow():
    # Regression: 2 ** entropy_bits used to overflow float for long passwords.
    result = entropy.estimate_crack_time(entropy.search_space_entropy("e" * 300))
    assert result == float("inf")
    assert entropy.humanize_seconds(result) == "longer than the age of the universe"


def test_longer_password_has_more_entropy():
    short = entropy.search_space_entropy("Ab1!")
    long = entropy.search_space_entropy("Ab1!Ab1!Ab1!")
    assert long > short
