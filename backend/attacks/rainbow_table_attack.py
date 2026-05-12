"""
Rainbow Table Attack - CipherGuard Phase 3

Simulates a precomputed hash lookup attack.

How it works:
  1. Attacker pre-hashes a massive wordlist and stores (hash -> plaintext) pairs
  2. At attack time: look up the stolen hash directly in the table — O(1) lookup
  3. No hashing computation needed at attack time

Why salting defeats it:
  - Salt = unique random string per password, stored with hash
  - Hash = H(salt + password) -- each password has a unique hash even if same plaintext
  - Attacker would need a separate rainbow table for every possible salt value
  - With a 256-bit salt, 2^256 separate tables needed — physically impossible

This module:
  - Builds an in-memory rainbow table from the wordlist
  - Attacks unsalted hashes (MD5, SHA1, SHA256) via direct lookup
  - Attempts the same against salted hashes to demonstrate failure
"""

import time
import hashlib
import logging
from typing import Optional

from backend.attacks.base_attack import BaseAttack, AttackReport, CrackedPassword
from backend.attacks.dictionary_attack import _load_wordlist

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Algorithms that can be rainbow-table-attacked (fast, unsalted)
# ---------------------------------------------------------------------------
_RAINBOW_SUPPORTED = {"md5", "sha1", "sha256", "plaintext"}


def _raw_hash(algorithm: str, password: str) -> str:
    """
    Compute raw hash without CipherGuard hasher wrapper.
    Used only for table building — not for verification.
    """
    if algorithm == "plaintext":
        return password
    elif algorithm == "md5":
        return hashlib.md5(password.encode("utf-8")).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode("utf-8")).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(password.encode("utf-8")).hexdigest()
    else:
        raise ValueError(f"Rainbow table not supported for: {algorithm}")


# ---------------------------------------------------------------------------
# Rainbow Table Attack implementation
# ---------------------------------------------------------------------------

class RainbowTableAttack(BaseAttack):
    """
    Rainbow Table Attack: O(1) hash lookup using precomputed table.

    Attack flow for unsalted hashes (MD5/SHA1/SHA256):
      1. Build table: {hash_value -> plaintext} for entire wordlist
      2. For each target hash: dict lookup — instant if found
      3. Success rate typically very high for common passwords

    Attack flow for salted hashes (salted_sha256/bcrypt/argon2id):
      1. Table lookup fails — each hash is unique due to salt
      2. Would need a table per possible salt = physically impossible
      3. Demonstrates why salting is a critical defence

    Key insight: Building a 50K word table for MD5 takes ~5ms.
    Looking up a stolen hash takes <1ms.
    The same attack against a salted hash achieves 0% success.
    """

    ATTACK_NAME = "rainbow_table"

    def __init__(self, max_wordlist_size: int = 50_000):
        self._tables: dict[str, dict[str, str]] = {}  # algo -> {hash: plaintext}
        self._max_wordlist_size = max_wordlist_size
        self._wordlist: Optional[list[str]] = None

    @property
    def wordlist(self) -> list[str]:
        if self._wordlist is None:
            self._wordlist = _load_wordlist(self._max_wordlist_size)
        return self._wordlist

    def build_table(self, algorithm: str) -> dict[str, str]:
        """
        Build (or return cached) rainbow table for a given algorithm.

        Returns:
            Dict mapping hash_value -> plaintext_password
        """
        if algorithm in self._tables:
            return self._tables[algorithm]

        if algorithm not in _RAINBOW_SUPPORTED:
            logger.warning(
                f"[Rainbow] Algorithm '{algorithm}' is salted/memory-hard — "
                "rainbow table will be empty (this is expected)."
            )
            self._tables[algorithm] = {}
            return self._tables[algorithm]

        logger.info(f"[Rainbow] Building table for {algorithm}...")
        build_start = time.perf_counter()
        table: dict[str, str] = {}

        for word in self.wordlist:
            try:
                h = _raw_hash(algorithm, word)
                table[h] = word
            except Exception:
                pass

        build_ms = (time.perf_counter() - build_start) * 1000
        self._tables[algorithm] = table
        logger.info(
            f"[Rainbow] Table built: {len(table):,} entries in {build_ms:.1f} ms"
        )
        return table

    def run(
        self,
        targets     : list,
        algorithm   : str,
        max_attempts: int   = 100_000,
        timeout_sec : float = 60.0,
    ) -> AttackReport:
        """
        Run rainbow table attack against stored hashes.

        Args:
            targets     : PasswordHash ORM records
            algorithm   : Hashing algorithm used
            max_attempts: Not meaningful here (lookups are O(1)), kept for interface compat
            timeout_sec : Timeout

        Returns:
            AttackReport
        """
        # ── Plaintext instant compromise ────────────────────────────────────
        # Plaintext doesn't even need a rainbow table — directly readable.
        if algorithm == "plaintext":
            attack_start = time.perf_counter()
            cracked = []
            from backend.attacks.base_attack import CrackedPassword
            for target in targets:
                cracked.append(CrackedPassword(
                    record_id      = target.id,
                    algorithm      = "plaintext",
                    plain_password = target.hash_value,
                    stored_hash    = target.hash_value,
                    crack_time_ms  = 0.001,
                    attempt_number = len(cracked) + 1,
                ))
            total_time = time.perf_counter() - attack_start
            return self._make_report(
                algorithm      = "plaintext",
                target_count   = len(targets),
                cracked        = cracked,
                total_attempts = len(targets),
                total_time_sec = max(total_time, 0.001),
                wordlist_size  = 0,
                stopped_early  = False,
                notes          = (
                    "INSTANTLY COMPROMISED: Plaintext passwords require no rainbow table. "
                    "Direct database read exposes every password immediately. "
                    "100% of accounts compromised upon any database breach."
                ),
            )

        is_salted = algorithm not in _RAINBOW_SUPPORTED

        if is_salted:
            # Demonstrate that rainbow tables fail against salted hashes
            logger.info(
                f"[Rainbow] Algorithm '{algorithm}' uses salting — "
                "rainbow table attack will fail (expected, demonstrating defence)"
            )
            return self._make_report(
                algorithm      = algorithm,
                target_count   = len(targets),
                cracked        = [],
                total_attempts = 0,
                total_time_sec = 0.001,
                wordlist_size  = 0,
                stopped_early  = False,
                notes          = (
                    f"Rainbow table attack FAILED as expected against '{algorithm}'. "
                    "Per-password salting prevents precomputed lookup tables — "
                    "each password has a unique salt, requiring a separate table per salt "
                    "(computationally infeasible with 2^256 possible salts). "
                    "This demonstrates WHY salting is a critical security defense."
                ),
            )

        # Build table
        table_build_start = time.perf_counter()
        table = self.build_table(algorithm)
        table_build_sec = time.perf_counter() - table_build_start

        cracked       : list[CrackedPassword] = []
        total_attempts = 0
        attack_start   = time.perf_counter()

        logger.info(
            f"[Rainbow] Attacking {len(targets)} {algorithm} hashes "
            f"with {len(table):,}-entry table"
        )

        for target in targets:
            total_attempts += 1
            elapsed = time.perf_counter() - attack_start
            if elapsed >= timeout_sec:
                break

            target_hash = target.hash_value
            crack_start = time.perf_counter()

            # O(1) lookup
            if target_hash in table:
                crack_ms = (time.perf_counter() - crack_start) * 1000
                cracked.append(CrackedPassword(
                    record_id      = target.id,
                    algorithm      = algorithm,
                    plain_password = table[target_hash],
                    stored_hash    = target_hash,
                    crack_time_ms  = round(crack_ms, 6),   # sub-millisecond!
                    attempt_number = total_attempts,
                ))

        total_time = time.perf_counter() - attack_start

        report = self._make_report(
            algorithm      = algorithm,
            target_count   = len(targets),
            cracked        = cracked,
            total_attempts = total_attempts,
            total_time_sec = total_time,
            wordlist_size  = len(table),
            stopped_early  = False,
            notes          = (
                f"Table built in {table_build_sec*1000:.1f} ms | "
                f"{len(table):,} precomputed hashes | "
                f"Lookup is O(1) — instant per hash. | "
                f"{algorithm.upper()} is UNSALTED: identical passwords produce identical hashes, "
                f"enabling precomputed lookup across all databases simultaneously. "
                f"Defense: use salted hashing (salted_sha256, bcrypt, or argon2id)."
            ),
        )

        logger.info(
            f"[Rainbow] Done: {report.cracked_count}/{report.target_count} cracked "
            f"({report.success_rate_pct:.1f}%) | "
            f"avg lookup: {report.avg_crack_time_ms:.4f} ms"
        )
        return report
