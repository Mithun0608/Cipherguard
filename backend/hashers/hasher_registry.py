"""
Hasher Registry — CipherGuard

Central factory/registry that maps algorithm name strings to their
corresponding hasher instances.

Usage:
    from backend.hashers.hasher_registry import get_hasher, HASHER_REGISTRY

    hasher = get_hasher("bcrypt")
    result = hasher.hash_password("my_secret")

All seven algorithms are registered here.  New algorithms can be added by:
  1. Creating a class that inherits BaseHasher
  2. Adding it to HASHER_REGISTRY below
"""

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

# ---------------------------------------------------------------------------
# Registry: algorithm-name -> hasher instance
# ---------------------------------------------------------------------------
# Instances are singletons here (stateless — safe to reuse).
HASHER_REGISTRY: dict = {
    "plaintext"    : PlaintextHasher(),
    "md5"          : MD5Hasher(),
    "sha1"         : SHA1Hasher(),
    "sha256"       : SHA256Hasher(),
    "salted_sha256": SaltedSHA256Hasher(),
    "bcrypt"       : BcryptHasher(),
    "argon2id"     : Argon2idHasher(),
}

# Convenience lists for categorizing algorithms
WEAK_ALGORITHMS   = ["plaintext", "md5", "sha1", "sha256"]
STRONG_ALGORITHMS = ["salted_sha256", "bcrypt", "argon2id"]
ALL_ALGORITHMS    = list(HASHER_REGISTRY.keys())


def get_hasher(algorithm: str):
    """
    Retrieve a hasher instance by algorithm name.

    Args:
        algorithm: One of the keys in HASHER_REGISTRY.

    Returns:
        A BaseHasher subclass instance.

    Raises:
        ValueError: If the algorithm name is not registered.
    """
    algo = algorithm.lower().strip()
    if algo not in HASHER_REGISTRY:
        supported = ", ".join(HASHER_REGISTRY.keys())
        raise ValueError(
            f"Unknown algorithm '{algorithm}'. "
            f"Supported: {supported}"
        )
    return HASHER_REGISTRY[algo]
