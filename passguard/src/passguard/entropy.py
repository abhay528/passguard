"""Entropy calculations for passwords.

The Shannon-style "search space" entropy of a password is estimated as::

    entropy_bits = length * log2(pool_size)

where ``pool_size`` is the size of the character set the password draws from.
This is the standard model used to reason about how many guesses a brute-force
attacker would need. It is an *upper bound*: real passwords built from words or
patterns have far less effective entropy, which is why :mod:`passguard.analyzer`
also applies pattern-based penalties.
"""

from __future__ import annotations

import math
import string

# Size of each character class an attacker would have to search.
LOWERCASE = set(string.ascii_lowercase)
UPPERCASE = set(string.ascii_uppercase)
DIGITS = set(string.digits)
# Common ASCII symbols found on a US keyboard.
SYMBOLS = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
SPACE = {" "}


def character_pool_size(password: str) -> int:
    """Return the size of the character pool the password draws from.

    Every character class that appears at least once contributes its full size
    to the pool, because an attacker who knows the password uses (say) digits
    must search all ten of them.
    """
    chars = set(password)
    pool = 0
    if chars & LOWERCASE:
        pool += len(LOWERCASE)
    if chars & UPPERCASE:
        pool += len(UPPERCASE)
    if chars & DIGITS:
        pool += len(DIGITS)
    if chars & SYMBOLS:
        pool += len(SYMBOLS)
    if chars & SPACE:
        pool += len(SPACE)
    # Anything outside the known classes (e.g. accented / unicode chars).
    other = chars - LOWERCASE - UPPERCASE - DIGITS - SYMBOLS - SPACE
    pool += len(other)
    return pool


def shannon_entropy(password: str) -> float:
    """Return the per-character Shannon entropy (bits/char) of the password.

    This measures the actual character distribution of the string, which is
    useful for spotting highly repetitive passwords such as ``aaaaaaaa``.
    """
    if not password:
        return 0.0
    counts: dict[str, int] = {}
    for ch in password:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(password)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def search_space_entropy(password: str) -> float:
    """Return the brute-force search-space entropy in bits.

    ``entropy = length * log2(pool_size)``
    """
    if not password:
        return 0.0
    pool = character_pool_size(password)
    if pool <= 1:
        return 0.0
    return len(password) * math.log2(pool)


def guesses_from_entropy(entropy_bits: float) -> float:
    """Convert entropy in bits to the number of guesses to exhaust the space.

    For very long/complex passwords ``2 ** entropy_bits`` exceeds the largest
    representable float, so we return ``inf`` instead of raising OverflowError.
    """
    try:
        return 2.0 ** entropy_bits
    except OverflowError:
        return math.inf


def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e10) -> float:
    """Estimate the average time to crack, in seconds.

    An offline attacker with a modern GPU rig can try on the order of 10^10
    (10 billion) hashes per second against a fast hash. On average an attacker
    finds the password after searching half of the space.
    """
    guesses = guesses_from_entropy(entropy_bits)
    if math.isinf(guesses):
        return math.inf
    return (guesses / 2.0) / guesses_per_second


def humanize_seconds(seconds: float) -> str:
    """Turn a number of seconds into a human-friendly duration string."""
    if math.isinf(seconds):
        return "longer than the age of the universe"
    if seconds < 1:
        return "less than a second"
    units = [
        ("century", "centuries", 60 * 60 * 24 * 365 * 100),
        ("year", "years", 60 * 60 * 24 * 365),
        ("month", "months", 60 * 60 * 24 * 30),
        ("day", "days", 60 * 60 * 24),
        ("hour", "hours", 60 * 60),
        ("minute", "minutes", 60),
        ("second", "seconds", 1),
    ]
    for singular, plural, size in units:
        if seconds >= size:
            value = seconds / size
            if value >= 1e6:
                return f"{value:.2e} {plural}"
            rounded = round(value)
            unit = singular if rounded == 1 else plural
            return f"{rounded} {unit}"
    return "less than a second"
