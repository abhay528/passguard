"""Core password strength analysis.

The :class:`PasswordAnalyzer` combines several signals into a single 0-100
score and a human-readable :class:`Strength` rating:

* **Length & complexity** - character classes and search-space entropy.
* **Uniqueness** - whether the password is a well-known common password, and
  optionally whether it has appeared in a public breach corpus (HIBP).
* **Predictability** - penalties for sequences, repeats, keyboard walks and
  embedded years.

It also produces actionable warnings and concrete stronger alternatives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from . import common, entropy
from .breach import check_pwned
from .generator import suggest_alternatives


class Strength(IntEnum):
    """Ordinal strength buckets derived from the final score."""

    VERY_WEAK = 0
    WEAK = 1
    FAIR = 2
    STRONG = 3
    VERY_STRONG = 4

    @property
    def label(self) -> str:
        return {
            Strength.VERY_WEAK: "Very Weak",
            Strength.WEAK: "Weak",
            Strength.FAIR: "Fair",
            Strength.STRONG: "Strong",
            Strength.VERY_STRONG: "Very Strong",
        }[self]


@dataclass
class AnalysisResult:
    """Structured result of analysing a single password."""

    length: int
    entropy_bits: float
    pool_size: int
    score: int
    strength: Strength
    crack_time: str
    checks: dict[str, bool]
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    is_common: bool = False
    breach_count: Optional[int] = None

    @property
    def is_breached(self) -> Optional[bool]:
        if self.breach_count is None:
            return None
        return self.breach_count > 0

    def to_dict(self) -> dict:
        return {
            "length": self.length,
            "entropy_bits": round(self.entropy_bits, 2),
            "pool_size": self.pool_size,
            "score": self.score,
            "strength": self.strength.label,
            "crack_time": self.crack_time,
            "checks": self.checks,
            "warnings": self.warnings,
            "suggestions": self.suggestions,
            "is_common": self.is_common,
            "breach_count": self.breach_count,
        }


class PasswordAnalyzer:
    """Evaluate password strength.

    Parameters
    ----------
    min_length:
        The minimum acceptable length (default 12, per modern NIST guidance).
    check_breaches:
        When True, query the Have I Been Pwned range API (needs network).
    """

    def __init__(self, *, min_length: int = 12, check_breaches: bool = False) -> None:
        self.min_length = min_length
        self.check_breaches = check_breaches

    def analyze(self, password: str) -> AnalysisResult:
        length = len(password)
        pool_size = entropy.character_pool_size(password)
        entropy_bits = entropy.search_space_entropy(password)
        crack_time = entropy.humanize_seconds(entropy.estimate_crack_time(entropy_bits))

        checks = self._run_checks(password)
        warnings: list[str] = []

        is_common = common.is_common_password(password)
        if is_common:
            warnings.append("This is one of the most common passwords in use.")

        breach_count: Optional[int] = None
        if self.check_breaches:
            breach_count = check_pwned(password)
            if breach_count:
                warnings.append(
                    f"Found in known data breaches {breach_count:,} times."
                )

        # Pattern penalties.
        if not checks["length_ok"]:
            warnings.append(
                f"Too short - use at least {self.min_length} characters."
            )
        if not checks["has_upper"]:
            warnings.append("Add uppercase letters.")
        if not checks["has_lower"]:
            warnings.append("Add lowercase letters.")
        if not checks["has_digit"]:
            warnings.append("Add digits.")
        if not checks["has_symbol"]:
            warnings.append("Add symbols (e.g. !@#$%).")
        if checks["has_sequence"]:
            warnings.append("Avoid sequences like 'abc' or '123'.")
        if checks["has_repeat"]:
            warnings.append("Avoid repeated characters like 'aaa'.")
        if checks["has_keyboard_pattern"]:
            warnings.append("Avoid keyboard patterns like 'qwerty'.")
        if checks["has_year"]:
            warnings.append("Avoid embedding years or dates.")

        score = self._score(entropy_bits, checks, is_common, breach_count)
        strength = self._bucket(score)

        suggestions: list[str] = []
        if strength < Strength.STRONG:
            suggestions = suggest_alternatives(password)

        return AnalysisResult(
            length=length,
            entropy_bits=entropy_bits,
            pool_size=pool_size,
            score=score,
            strength=strength,
            crack_time=crack_time,
            checks=checks,
            warnings=warnings,
            suggestions=suggestions,
            is_common=is_common,
            breach_count=breach_count,
        )

    def _run_checks(self, password: str) -> dict[str, bool]:
        chars = set(password)
        return {
            "length_ok": len(password) >= self.min_length,
            "has_lower": bool(chars & entropy.LOWERCASE),
            "has_upper": bool(chars & entropy.UPPERCASE),
            "has_digit": bool(chars & entropy.DIGITS),
            "has_symbol": bool(chars & entropy.SYMBOLS),
            "has_sequence": common.has_sequential_run(password),
            "has_repeat": common.has_repeated_run(password),
            "has_keyboard_pattern": common.has_keyboard_pattern(password),
            "has_year": common.looks_like_year(password),
        }

    def _score(
        self,
        entropy_bits: float,
        checks: dict[str, bool],
        is_common: bool,
        breach_count: Optional[int],
    ) -> int:
        # A password that is common or breached is unsafe regardless of shape.
        if is_common or (breach_count is not None and breach_count > 0):
            return 0

        # Base score maps entropy onto 0-100 (100 bits ~= excellent).
        score = min(entropy_bits / 100.0, 1.0) * 80.0

        # Reward class diversity (up to 20 points).
        classes = sum(
            1
            for key in ("has_lower", "has_upper", "has_digit", "has_symbol")
            if checks[key]
        )
        score += classes * 5.0

        # Penalise predictable patterns.
        for key, penalty in (
            ("has_sequence", 15),
            ("has_repeat", 15),
            ("has_keyboard_pattern", 20),
            ("has_year", 10),
        ):
            if checks[key]:
                score -= penalty
        if not checks["length_ok"]:
            score -= 20

        return int(max(0, min(100, round(score))))

    @staticmethod
    def _bucket(score: int) -> Strength:
        if score >= 85:
            return Strength.VERY_STRONG
        if score >= 65:
            return Strength.STRONG
        if score >= 45:
            return Strength.FAIR
        if score >= 25:
            return Strength.WEAK
        return Strength.VERY_WEAK
