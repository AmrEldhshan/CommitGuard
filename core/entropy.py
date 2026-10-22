"""
core/entropy.py
----------------
Shannon entropy helpers used to cut down false positives from generic
secret regexes (for example, a gitleaks rule that matches any 32-char
alphanumeric string).  A real API key usually has high character
diversity; `passwordpasswordpasswordpassword` does not.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """
    Returns the Shannon entropy of `value` in bits per character.

    Examples (approximately):
        "aaaa"            -> 0.0
        "abcd"            -> 2.0
        "aB3xQ9zL0mN2pR7" -> ~3.8
    """
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )
