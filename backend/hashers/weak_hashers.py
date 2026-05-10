"""
Weak hashing implementations for CipherGuard.

These algorithms are deliberately insecure and included
ONLY to demonstrate cybersecurity risks in comparison
with modern strong hashing algorithms.

Algorithms:
  - PlaintextHasher  : No hashing — stores password directly
  - MD5Hasher        : MD5, unsalted (broken, collision-prone)
  - SHA1Hasher       : SHA-1, unsalted (deprecated, preimage-vulnerable)
  - SHA256Hasher     : SHA-256, unsalted (fast, rainbow-table-vulnerable)

WARNING: Never use these in a real production application.
"""

import hashlib
import hmac
from typing import Optional

from backend.hashers.base_hasher import BaseHasher, HashResult


# ---------------------------------------------------------------------------
# 1. Plaintext "Hasher"
# ---------------------------------------------------------------------------

class PlaintextHasher(BaseHasher):
    """
    Stores the password completely unmodified.

    This is the most insecure possible approach — included purely for
    educational comparison. A single database breach exposes every user.
    """

    ALGORITHM_NAME = "plaintext"
    HASH_VERSION   = "1.0"

    def hash_password(
        self,
        password: str,
        pepper: Optional[str] = None
    ) -> HashResult:
        seasoned = self._apply_pepper(password, pepper)

        def _hash():
            return seasoned  # "hash" is just the password itself

        result, elapsed_ms = self._timed_hash(_hash)

        return HashResult(
            hash_value     = result,
            salt           = None,
            algorithm      = self.ALGORITHM_NAME,
            hash_version   = self.HASH_VERSION,
            time_to_hash_ms= elapsed_ms,
        )

    def verify_password(
        self,
        password: str,
        stored_hash: str,
        salt: Optional[str] = None,
        pepper: Optional[str] = None
    ) -> bool:
        seasoned = self._apply_pepper(password, pepper)
        # Use hmac.compare_digest to prevent timing attacks even here
        return hmac.compare_digest(seasoned, stored_hash)


# ---------------------------------------------------------------------------
# 2. MD5 Hasher (Weak)
# ---------------------------------------------------------------------------

class MD5Hasher(BaseHasher):
    """
    MD5 hashing without salt.

    MD5 was deprecated for security use in 2004. Collisions are trivially
    computable and enormous precomputed rainbow tables exist for common
    passwords. An attacker who obtains the hash database can crack most
    passwords within seconds using GPU-accelerated lookup tables.
    """

    ALGORITHM_NAME = "md5"
    HASH_VERSION   = "1.0"

    def hash_password(
        self,
        password: str,
        pepper: Optional[str] = None
    ) -> HashResult:
        seasoned = self._apply_pepper(password, pepper)

        def _hash():
            return hashlib.md5(seasoned.encode("utf-8")).hexdigest()

        result, elapsed_ms = self._timed_hash(_hash)

        return HashResult(
            hash_value     = result,
            salt           = None,
            algorithm      = self.ALGORITHM_NAME,
            hash_version   = self.HASH_VERSION,
            time_to_hash_ms= elapsed_ms,
        )

    def verify_password(
        self,
        password: str,
        stored_hash: str,
        salt: Optional[str] = None,
        pepper: Optional[str] = None
    ) -> bool:
        result = self.hash_password(password, pepper)
        return hmac.compare_digest(result.hash_value, stored_hash)


# ---------------------------------------------------------------------------
# 3. SHA-1 Hasher (Weak)
# ---------------------------------------------------------------------------

class SHA1Hasher(BaseHasher):
    """
    SHA-1 hashing without salt.

    SHA-1 was retired by NIST in 2011. Practical collision attacks exist
    (SHAttered, 2017). Without salting, identical passwords produce identical
    hashes, making batch cracking trivial. GPU clusters can compute billions
    of SHA-1 hashes per second.
    """

    ALGORITHM_NAME = "sha1"
    HASH_VERSION   = "1.0"

    def hash_password(
        self,
        password: str,
        pepper: Optional[str] = None
    ) -> HashResult:
        seasoned = self._apply_pepper(password, pepper)

        def _hash():
            return hashlib.sha1(seasoned.encode("utf-8")).hexdigest()

        result, elapsed_ms = self._timed_hash(_hash)

        return HashResult(
            hash_value     = result,
            salt           = None,
            algorithm      = self.ALGORITHM_NAME,
            hash_version   = self.HASH_VERSION,
            time_to_hash_ms= elapsed_ms,
        )

    def verify_password(
        self,
        password: str,
        stored_hash: str,
        salt: Optional[str] = None,
        pepper: Optional[str] = None
    ) -> bool:
        result = self.hash_password(password, pepper)
        return hmac.compare_digest(result.hash_value, stored_hash)


# ---------------------------------------------------------------------------
# 4. SHA-256 Hasher — Unsalted (Weak for passwords, despite strong algorithm)
# ---------------------------------------------------------------------------

class SHA256Hasher(BaseHasher):
    """
    SHA-256 hashing without salt.

    SHA-256 is cryptographically strong as a general-purpose hash, but its
    speed makes it a poor password hasher. Without a unique salt per password,
    two users with the same password have identical hashes, and precomputed
    rainbow tables are effective. GPU hardware can compute ~10 billion SHA-256
    hashes per second.

    NOTE: The SaltedSHA256Hasher below is the correct way to use SHA-256
    for passwords.
    """

    ALGORITHM_NAME = "sha256"
    HASH_VERSION   = "1.0"

    def hash_password(
        self,
        password: str,
        pepper: Optional[str] = None
    ) -> HashResult:
        seasoned = self._apply_pepper(password, pepper)

        def _hash():
            return hashlib.sha256(seasoned.encode("utf-8")).hexdigest()

        result, elapsed_ms = self._timed_hash(_hash)

        return HashResult(
            hash_value     = result,
            salt           = None,
            algorithm      = self.ALGORITHM_NAME,
            hash_version   = self.HASH_VERSION,
            time_to_hash_ms= elapsed_ms,
        )

    def verify_password(
        self,
        password: str,
        stored_hash: str,
        salt: Optional[str] = None,
        pepper: Optional[str] = None
    ) -> bool:
        result = self.hash_password(password, pepper)
        return hmac.compare_digest(result.hash_value, stored_hash)
