"""
CipherGuard — Hashers Package

Provides a clean public API for the hashing engine.

Usage:
    from backend.hashers import get_hasher, HASHER_REGISTRY, ALL_ALGORITHMS
    from backend.hashers import HashResult

    result = get_hasher("argon2id").hash_password("my_secret")
"""

from backend.hashers.base_hasher import BaseHasher, HashResult

from backend.hashers.weak_hashers import (
    PlaintextHasher,
    MD5Hasher,
    SHA1Hasher,
    SHA256Hasher,
)
from backend.hashers.strong_hashers import (
    SaltedSHA256Hasher,
    BcryptHasher,
    Argon2idHasher,
)
from backend.hashers.hasher_registry import (
    HASHER_REGISTRY,
    WEAK_ALGORITHMS,
    STRONG_ALGORITHMS,
    ALL_ALGORITHMS,
    get_hasher,
)

__all__ = [
    # Base
    "BaseHasher", "HashResult",
    # Weak
    "PlaintextHasher", "MD5Hasher", "SHA1Hasher", "SHA256Hasher",
    # Strong
    "SaltedSHA256Hasher", "BcryptHasher", "Argon2idHasher",
    # Registry
    "HASHER_REGISTRY", "WEAK_ALGORITHMS", "STRONG_ALGORITHMS",
    "ALL_ALGORITHMS", "get_hasher",
]
