"""
Password Strength Analyzer — CipherGuard

Analyzes a password across multiple dimensions and assigns:
  - Per-dimension boolean flags
  - A numeric strength score (0–100)
  - An estimated Shannon entropy (bits)
  - A categorical strength label: trivial / common / moderate / strong

Used by the dataset generator to classify passwords before hashing.
"""

import math
import re
import string
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class StrengthResult:
    """
    Full analysis result for a single password.

    Attributes:
        length           : Number of characters
        has_uppercase    : Contains A-Z
        has_lowercase    : Contains a-z
        has_digits       : Contains 0-9
        has_symbols      : Contains special characters
        entropy_bits     : Shannon entropy estimate (bits)
        strength_score   : Composite score 0–100
        strength_category: 'trivial' | 'common' | 'moderate' | 'strong'
    """
    length:            int
    has_uppercase:     bool
    has_lowercase:     bool
    has_digits:        bool
    has_symbols:       bool
    entropy_bits:      float
    strength_score:    int
    strength_category: str


# ---------------------------------------------------------------------------
# Common weak password patterns
# ---------------------------------------------------------------------------

_TRIVIAL_PATTERNS = [
    re.compile(r"^(.)\1+$"),            # All same char: "aaaa", "1111"
    re.compile(r"^(012|123|234|345|456|567|678|789|890|abc|qwe|asd|zxc)", re.I),
    re.compile(r"^(password|pass|letmein|welcome|admin|login|root|qwerty|abc123|iloveyou)", re.I),
]

_COMMON_WORDLIST = frozenset([
    "password", "password1", "123456", "12345678", "1234567890",
    "qwerty", "abc123", "monkey", "1234567", "letmein",
    "dragon", "111111", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "michael", "football",
    "princess", "charlie", "donald", "access", "batman",
])


# ---------------------------------------------------------------------------
# Charset pool size estimator (used for entropy)
# ---------------------------------------------------------------------------

def _charset_pool(password: str) -> int:
    """Return the estimated character pool size for the password."""
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"[0-9]", password): pool += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool += 32  # printable specials
    return max(pool, 1)


# ---------------------------------------------------------------------------
# Entropy estimator
# ---------------------------------------------------------------------------

def estimate_entropy(password: str) -> float:
    """
    Estimate Shannon entropy in bits.

    Formula: H = L × log2(N)
    where L = password length, N = character pool size.

    This is a conservative estimate — it does not account for dictionary
    words or keyboard walks, which would lower effective entropy further.
    """
    if not password:
        return 0.0
    pool = _charset_pool(password)
    return round(len(password) * math.log2(pool), 2)


# ---------------------------------------------------------------------------
# Strength score calculator
# ---------------------------------------------------------------------------

def compute_strength_score(password: str) -> int:
    """
    Compute a 0–100 strength score based on multiple criteria.

    Scoring breakdown:
        Length            : up to 40 pts
        Uppercase letters : 10 pts
        Lowercase letters : 10 pts
        Digits            : 10 pts
        Symbols           : 15 pts
        Entropy bonus     : up to 15 pts

    Penalties:
        -20 if matches a trivial pattern
        -10 if found in common wordlist
    """
    score = 0
    length = len(password)

    # --- Length scoring ---
    if length >= 20:
        score += 40
    elif length >= 16:
        score += 35
    elif length >= 12:
        score += 28
    elif length >= 10:
        score += 22
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 8
    else:
        score += 2

    # --- Character class scoring ---
    if re.search(r"[A-Z]", password): score += 10
    if re.search(r"[a-z]", password): score += 10
    if re.search(r"[0-9]", password): score += 10
    if re.search(r"[^a-zA-Z0-9]", password): score += 15

    # --- Entropy bonus (0-15 pts) ---
    entropy = estimate_entropy(password)
    if entropy >= 60:
        score += 15
    elif entropy >= 45:
        score += 10
    elif entropy >= 30:
        score += 6
    elif entropy >= 20:
        score += 3

    # --- Penalties ---
    if password.lower() in _COMMON_WORDLIST:
        score -= 10

    for pattern in _TRIVIAL_PATTERNS:
        if pattern.search(password):
            score -= 20
            break

    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Category classifier
# ---------------------------------------------------------------------------

def classify_strength(score: int, password: str) -> str:
    """
    Map a numeric score to a named strength category.

    Categories:
        trivial  : Score < 20 or password in common wordlist
        common   : Score 20–39
        moderate : Score 40–64
        strong   : Score >= 65
    """
    if password.lower() in _COMMON_WORDLIST or score < 20:
        return "trivial"
    elif score < 40:
        return "common"
    elif score < 65:
        return "moderate"
    else:
        return "strong"


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> StrengthResult:
    """
    Run a complete strength analysis on a password string.

    Args:
        password: The plaintext password to analyze.

    Returns:
        StrengthResult with all fields populated.
    """
    score    = compute_strength_score(password)
    entropy  = estimate_entropy(password)
    category = classify_strength(score, password)

    return StrengthResult(
        length           = len(password),
        has_uppercase    = bool(re.search(r"[A-Z]", password)),
        has_lowercase    = bool(re.search(r"[a-z]", password)),
        has_digits       = bool(re.search(r"[0-9]", password)),
        has_symbols      = bool(re.search(r"[^a-zA-Z0-9]", password)),
        entropy_bits     = entropy,
        strength_score   = score,
        strength_category= category,
    )
