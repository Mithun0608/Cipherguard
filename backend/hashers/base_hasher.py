"""
Base hashing interface for CipherGuard.

Implements the Strategy Design Pattern — every hashing algorithm
inherits from this abstract base class and must implement:
  - hash_password()
  - verify_password()

This ensures a consistent, interchangeable interface regardless
of the underlying cryptographic algorithm.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HashResult:
    """
    Returned by every hasher after hashing a password.

    Attributes:
        hash_value     : The resulting hash string
        salt           : Optional salt used (hex string or None)
        algorithm      : Algorithm name (e.g., 'bcrypt', 'md5')
        hash_version   : Version tag for future migration support
        time_to_hash_ms: Time taken in milliseconds
    """
    hash_value: str
    salt: Optional[str]
    algorithm: str
    hash_version: str
    time_to_hash_ms: float


class BaseHasher(ABC):
    """
    Abstract base class for all password hashing strategies.

    Subclasses must implement:
        hash_password(password, pepper) -> HashResult
        verify_password(password, stored_hash, salt, pepper) -> bool
    """

    # Subclasses should override these class-level constants
    ALGORITHM_NAME: str = "base"
    HASH_VERSION: str = "1.0"

    def _timed_hash(self, fn, *args, **kwargs):
        """
        Helper that runs `fn(*args, **kwargs)` and returns
        (result, elapsed_ms) using a high-resolution timer.
        """
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return result, elapsed_ms

    @abstractmethod
    def hash_password(
        self,
        password: str,
        pepper: Optional[str] = None
    ) -> HashResult:
        """
        Hash a plaintext password.

        Args:
            password: The plaintext password string.
            pepper:   Optional server-side secret appended before hashing.

        Returns:
            HashResult containing the hash, salt, timing, and metadata.
        """
        ...

    @abstractmethod
    def verify_password(
        self,
        password: str,
        stored_hash: str,
        salt: Optional[str] = None,
        pepper: Optional[str] = None
    ) -> bool:
        """
        Verify a plaintext password against a stored hash.

        Args:
            password:    The plaintext password to verify.
            stored_hash: The hash stored in the database.
            salt:        Optional salt stored alongside the hash.
            pepper:      Optional server-side secret used during hashing.

        Returns:
            True if the password matches, False otherwise.
        """
        ...

    def _apply_pepper(self, password: str, pepper: Optional[str]) -> str:
        """Append pepper to password if provided."""
        if pepper:
            return password + pepper
        return password
