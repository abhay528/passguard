"""Tests for the core analyzer."""

from passguard.analyzer import PasswordAnalyzer, Strength


def test_common_password_is_very_weak():
    result = PasswordAnalyzer().analyze("password")
    assert result.is_common is True
    assert result.strength == Strength.VERY_WEAK
    assert result.score == 0


def test_empty_password():
    result = PasswordAnalyzer().analyze("")
    assert result.length == 0
    assert result.score == 0
    assert result.strength == Strength.VERY_WEAK


def test_strong_random_password_scores_high():
    result = PasswordAnalyzer().analyze("gT7$wQ2!pL9#zR4vB")
    assert result.strength >= Strength.STRONG
    assert result.score >= 65
    assert result.checks["has_upper"]
    assert result.checks["has_symbol"]


def test_short_password_flagged():
    result = PasswordAnalyzer(min_length=12).analyze("Ab1!")
    assert result.checks["length_ok"] is False
    assert any("short" in w.lower() for w in result.warnings)


def test_sequence_penalized():
    strong = PasswordAnalyzer().analyze("Xk9!mQ7&vP2#")
    seq = PasswordAnalyzer().analyze("abcdefg123456")
    assert seq.checks["has_sequence"]
    assert seq.score < strong.score


def test_repeat_detected():
    result = PasswordAnalyzer().analyze("aaaaaaaaaaaa")
    assert result.checks["has_repeat"]
    assert result.strength <= Strength.WEAK


def test_keyboard_pattern_detected():
    result = PasswordAnalyzer().analyze("qwertyuiop")
    assert result.checks["has_keyboard_pattern"]


def test_suggestions_for_weak_passwords():
    result = PasswordAnalyzer().analyze("abc")
    assert result.suggestions, "weak passwords should get suggestions"


def test_to_dict_is_serializable():
    import json

    result = PasswordAnalyzer().analyze("Tr0ub4dour&3")
    json.dumps(result.to_dict())  # should not raise
