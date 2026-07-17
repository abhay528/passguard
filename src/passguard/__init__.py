"""PassGuard - a password strength analyzer.

PassGuard evaluates the strength of passwords using entropy-based scoring,
detects weak patterns, checks passwords against a list of common passwords and
(optionally) the Have I Been Pwned breach database, suggests stronger
alternatives, and can persist salted password hashes to prevent reuse.
"""

from .analyzer import PasswordAnalyzer, AnalysisResult, Strength
from .generator import generate_password, suggest_alternatives
from .breach import check_pwned
from .database import PasswordHistory

__all__ = [
    "PasswordAnalyzer",
    "AnalysisResult",
    "Strength",
    "generate_password",
    "suggest_alternatives",
    "check_pwned",
    "PasswordHistory",
]

__version__ = "1.0.0"
