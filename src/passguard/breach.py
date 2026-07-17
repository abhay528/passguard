"""Check passwords against the Have I Been Pwned (HIBP) breach corpus.

This uses the k-anonymity model of the HIBP "Pwned Passwords" range API so the
full password (or even its full hash) is *never* sent over the network:

1. Compute the SHA-1 hash of the password.
2. Send only the first 5 hex characters of the hash (the "prefix") to the API.
3. The API returns every hash suffix that shares that prefix, plus how many
   times each has appeared in breaches.
4. We compare locally to see whether our suffix is in the list.

Network access is optional: if the request fails, ``check_pwned`` returns
``None`` so callers can degrade gracefully.
"""

from __future__ import annotations

import hashlib
from typing import Optional
from urllib import error, request

_API_ROOT = "https://api.pwnedpasswords.com/range/"
_USER_AGENT = "PassGuard-Password-Analyzer"


def check_pwned(password: str, *, timeout: float = 5.0) -> Optional[int]:
    """Return how many times the password appears in known breaches.

    Returns
    -------
    int
        The breach count (``0`` means the password was not found).
    None
        The check could not be completed (e.g. no network connectivity).
    """
    if not password:
        return None

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    req = request.Request(
        f"{_API_ROOT}{prefix}",
        headers={"User-Agent": _USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (error.URLError, TimeoutError, OSError):
        return None

    for line in body.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        candidate, count = parts
        if candidate.strip().upper() == suffix:
            try:
                return int(count)
            except ValueError:
                return None
    return 0
