"""Generate strong passwords and suggest improvements to weak ones."""

from __future__ import annotations

import secrets
import string

_AMBIGUOUS = set("Il1O0|`")

_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})

# A small word list for building memorable passphrases.
_WORDS = [
    "anchor", "breeze", "cactus", "dolphin", "ember", "falcon", "glacier",
    "harbor", "island", "jungle", "kernel", "lantern", "meadow", "nebula",
    "orchid", "pixel", "quartz", "ripple", "summit", "timber", "umbra",
    "velvet", "willow", "xenon", "yonder", "zephyr",
]


def generate_password(
    length: int = 16,
    *,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    """Generate a cryptographically secure random password.

    Uses :mod:`secrets` (a CSPRNG) rather than :mod:`random`, and guarantees at
    least one character from each selected class.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4.")

    pools: list[str] = [string.ascii_lowercase]
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")

    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in _AMBIGUOUS) for pool in pools]

    # Guarantee one character from each pool, then fill the rest at random.
    all_chars = "".join(pools)
    password_chars = [secrets.choice(pool) for pool in pools]
    password_chars += [
        secrets.choice(all_chars) for _ in range(length - len(password_chars))
    ]
    # Shuffle so the guaranteed characters are not always at the front.
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def generate_passphrase(words: int = 4, separator: str = "-") -> str:
    """Generate a memorable passphrase (e.g. ``anchor-pixel-quartz-willow42``)."""
    chosen = [secrets.choice(_WORDS) for _ in range(words)]
    # Capitalise one word and append digits for extra entropy.
    idx = secrets.randbelow(words)
    chosen[idx] = chosen[idx].capitalize()
    number = secrets.randbelow(100)
    return separator.join(chosen) + str(number)


def suggest_alternatives(password: str, count: int = 3) -> list[str]:
    """Suggest stronger alternatives derived from and independent of the input.

    The suggestions include:

    * a "leet-speak" and padded variant of the original (easier to remember),
    * a fresh random password, and
    * a memorable passphrase.
    """
    suggestions: list[str] = []

    if password:
        base = password.translate(_LEET)
        if not base[:1].isupper():
            base = base.capitalize()
        padded = f"{base}!{secrets.randbelow(100):02d}"
        suggestions.append(padded)

    suggestions.append(generate_password(16))
    suggestions.append(generate_passphrase(4))

    # Top up with random passwords if we still need more.
    while len(suggestions) < count:
        suggestions.append(generate_password(16))

    return suggestions[:count]
