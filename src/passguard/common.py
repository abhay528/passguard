"""Detection of common passwords and predictable patterns."""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

# Rows of a typical QWERTY keyboard, used to detect keyboard-walk patterns.
_KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]


@lru_cache(maxsize=1)
def load_common_passwords() -> frozenset[str]:
    """Load the bundled list of common passwords (lower-cased)."""
    try:
        text = (
            resources.files("passguard.data")
            .joinpath("common_passwords.txt")
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError):
        return frozenset()
    words = {
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }
    return frozenset(words)


def is_common_password(password: str) -> bool:
    """Return True if the password (case-insensitive) is a known common one."""
    return password.lower() in load_common_passwords()


def has_sequential_run(password: str, min_run: int = 3) -> bool:
    """Detect ascending/descending runs like ``abc``, ``321`` or ``cba``."""
    if len(password) < min_run:
        return False
    lowered = password.lower()
    run_up = run_down = 1
    for prev, curr in zip(lowered, lowered[1:]):
        diff = ord(curr) - ord(prev)
        run_up = run_up + 1 if diff == 1 else 1
        run_down = run_down + 1 if diff == -1 else 1
        if run_up >= min_run or run_down >= min_run:
            return True
    return False


def has_repeated_run(password: str, min_run: int = 3) -> bool:
    """Detect a single character repeated ``min_run`` or more times (``aaa``)."""
    return re.search(r"(.)\1{" + str(min_run - 1) + r",}", password) is not None


def has_keyboard_pattern(password: str, min_run: int = 4) -> bool:
    """Detect keyboard walks such as ``qwerty`` or ``asdf``."""
    lowered = password.lower()
    for row in _KEYBOARD_ROWS:
        for start in range(len(row) - min_run + 1):
            chunk = row[start : start + min_run]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def looks_like_year(password: str) -> bool:
    """Detect a 4-digit year (1900-2099) embedded in the password."""
    return re.search(r"(19|20)\d{2}", password) is not None
