"""
Strong hashing implementations for CipherGuard.

These algorithms represent modern best practices for password storage.

Algorithms:
  - SaltedSHA256Hasher : SHA-256 with a unique cryptographic salt per password
  - BcryptHasher        : bcrypt with automatic salting (cost factor = 12)
  - Argon2idHasher      : Argon2id — winner of the 2015 PHC competition

Each hasher generates a unique salt per password, implements timing-safe
verification, and records hashing duration for performance comparison.
"""

import hashlib
import hmac
import secrets
from typing import Optional

import bcrypt as _bcrypt
from argon2 import PasswordHasher as _Argon2PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from backend.hashers.base_hasher import BaseHasher, HashResult


# ---------------------------------------------------------------------------
# 5. Salted SHA-256 Hasher (Moderate — much better, but still not ideal)
# ---------------------------------------------------------------------------

class SaltedSHA256Hasher(BaseHasher):
    """
    SHA-256 with a unique, cryptographically secure random salt per password.

    The salt is stored alongside the hash and re-combined at verification.
    This defeats rainbow-table attacks, but SHA-256 is still very fast —
    GPU clusters can still brute-force common passwords. For true security,
    use bcrypt or Argon2id.

    Hash format stored: <hex_salt>:<hex_hash>  (or salt stored separately)
    """

    ALGORITHM_NAME = "salted_sha256"
    HASH_VERSION   = "1.0"
    SALT_BYTES     = 32   # 256-bit salt

    def hash_password(
        self,
        password: str,
        pepper: Optional[str] = None
    ) -> HashResult:
        # Generate a fresh 256-bit salt for every password
        salt_bytes  = secrets.token_bytes(self.SALT_BYTES)
        salt_hex    = salt_bytes.hex()
        seasoned    = self._apply_pepper(password, pepper)

        def _hash():
            return hashlib.sha256(
                (salt_hex + seasoned).encode("utf-8")
            ).hexdigest()

        result, elapsed_ms = self._timed_hash(_hash)

        return HashResult(
            hash_value     = result,
            salt           = salt_hex,
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
        if salt is None:
            return False
        seasoned   = self._apply_pepper(password, pepper)
        recomputed = hashlib.sha256(
            (salt + seasoned).encode("utf-8")
        ).hexdigest()
        return hmac.compare_digest(recomputed, stored_hash)


# ---------------------------------------------------------------------------
# 6. bcrypt Hasher (Strong)
# ---------------------------------------------------------------------------

class BcryptHasher(BaseHasher):
    """
    bcrypt password hashing.

    bcrypt was designed in 1999 specifically for passwords. It incorporates:
      - Automatic unique salt generation per hash
      - An adjustable work/cost factor (rounds) — default 12 here
      - Intentional computational slowness (~100ms on modern hardware)

    The encoded hash string includes the salt, cost factor, and hash,
    making it fully self-contained for verification.

    Increasing the cost factor by 1 doubles the computation time,
    allowing the work factor to grow with hardware improvements.
    """

    ALGORITHM_NAME = "bcrypt"
    HASH_VERSION   = "1.0"
    ROUNDS         = 12   # Work factor: 2^12 = 4096 iterations

    def hash_password(
        self,
        password: str,
        pepper: Optional[str] = None
    ) -> HashResult:
        seasoned = self._apply_pepper(password, pepper)
        pwd_bytes = seasoned.encode("utf-8")

        def _hash():
            salt       = _bcrypt.gensalt(rounds=self.ROUNDS)
            hash_bytes = _bcrypt.hashpw(pwd_bytes, salt)
            return hash_bytes.decode("utf-8")

        result, elapsed_ms = self._timed_hash(_hash)

        # bcrypt embeds the salt in the hash string; we store it
        # separately as None since it's recoverable from the hash.
        return HashResult(
            hash_value     = result,
            salt           = None,    # embedded inside bcrypt hash string
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
        try:
            seasoned = self._apply_pepper(password, pepper)
            return _bcrypt.checkpw(
                seasoned.encode("utf-8"),
                stored_hash.encode("utf-8")
            )
        except Exception:
            return False


# ---------------------------------------------------------------------------
# 7. Argon2id Hasher (Strongest — recommended by OWASP 2024)
# ---------------------------------------------------------------------------

class Argon2idHasher(BaseHasher):
    """
    Argon2id password hashing — winner of the 2015 Password Hashing Competition.

    Argon2id is memory-hard, meaning attacks require large amounts of RAM in
    addition to computation, making GPU/ASIC-based attacks extremely expensive.

    Parameters used (OWASP recommended minimums):
      - time_cost   : 3 iterations
      - memory_cost : 65536 KB  (64 MB)
      - parallelism : 4 threads
      - hash_len    : 32 bytes

    The argon2-cffi library stores a self-contained encoded string including
    the algorithm version, parameters, salt, and hash.
    """

    ALGORITHM_NAME = "argon2id"
    HASH_VERSION   = "1.0"

    # OWASP minimum recommended parameters for Argon2id
    _ph = _Argon2PasswordHasher(
        time_cost   = 3,       # iterations
        memory_cost = 65536,   # 64 MB
        parallelism = 4,
        hash_len    = 32,
        salt_len    = 16,
    )

    def hash_password(
        self,
        password: str,
        pepper: Optional[str] = None
    ) -> HashResult:
        seasoned = self._apply_pepper(password, pepper)

        def _hash():
            return self._ph.hash(seasoned)

        result, elapsed_ms = self._timed_hash(_hash)

        # Argon2 encodes the salt within the hash string itself
        return HashResult(
            hash_value     = result,
            salt           = None,    # embedded in encoded hash
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
        try:
            seasoned = self._apply_pepper(password, pepper)
            return self._ph.verify(stored_hash, seasoned)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
