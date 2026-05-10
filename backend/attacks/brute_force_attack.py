"""
Brute Force Attack - CipherGuard Phase 3

Systematically generates every possible character combination up to a
configurable max length and tests each against stored hashes.

Why it only works against weak algorithms:
  - MD5/SHA1: billions of hashes/sec possible with modern hardware
  - bcrypt (rounds=12): ~5 hashes/sec => 8-char brute force = centuries
  - Argon2id: memory-hard => GPU farms impractical

Demonstrates:
  - Exponential growth of search space with character set and length
  - Why slow key-stretching algorithms defeat brute force
"""

import time
import string
import logging
import itertools
from typing import Optional

from backend.attacks.base_attack import BaseAttack, AttackReport, CrackedPassword
from backend.hashers.hasher_registry import get_hasher

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Character set definitions
# ---------------------------------------------------------------------------

CHARSET_DIGITS     = string.digits                         # 0-9
CHARSET_LOWERCASE  = string.ascii_lowercase                # a-z
CHARSET_UPPERCASE  = string.ascii_uppercase                # A-Z
CHARSET_ALPHA      = string.ascii_letters                  # a-zA-Z
CHARSET_ALPHANUM   = string.ascii_letters + string.digits  # a-zA-Z0-9
CHARSET_SYMBOLS    = string.punctuation                    # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
CHARSET_FULL       = CHARSET_ALPHANUM + CHARSET_SYMBOLS    # all printable

# Pre-baked search space sizes for documentation purposes
SEARCH_SPACE_INFO = {
    "digits_4"   : f"{10**4:,} (10 chars, len 4)",
    "lower_4"    : f"{26**4:,} (26 chars, len 4)",
    "lower_6"    : f"{26**6:,} (26 chars, len 6)",
    "alphanum_6" : f"{62**6:,} (62 chars, len 6)",
    "full_8"     : f"{94**8:,} (94 chars, len 8)",
}


# ---------------------------------------------------------------------------
# Brute Force Attack implementation
# ---------------------------------------------------------------------------

class BruteForceAttack(BaseAttack):
    """
    Brute Force Attack: exhaustive character combination search.

    Attack flow:
      1. Generate all combinations from charset up to max_length
      2. For each candidate, call hasher.verify_password()
      3. Stop on success, timeout, or max_attempts

    Search space examples (why length and charset matter enormously):
      - 4-digit PIN:        10,000 combinations
      - 4 lowercase chars:  456,976 combinations
      - 6 lowercase:        308 million combinations
      - 6 alphanumeric:     56 billion combinations
      - 8 full charset:     6.1 quadrillion combinations

    Key insight: bcrypt at 5 hash/sec makes 6 lowercase chars take
    ~7 years — for a single password. MD5 does all 308M in ~0.3 seconds.
    """

    ATTACK_NAME = "brute_force"

    def run(
        self,
        targets     : list,
        algorithm   : str,
        max_attempts: int   = 100_000,
        timeout_sec : float = 60.0,
        charset     : str   = CHARSET_LOWERCASE + CHARSET_DIGITS,
        min_length  : int   = 1,
        max_length  : int   = 5,
    ) -> AttackReport:
        """
        Run brute force attack.

        Args:
            targets      : PasswordHash ORM records to attack
            algorithm    : Hashing algorithm
            max_attempts : Hard cap on total attempts
            timeout_sec  : Timeout in seconds
            charset      : Characters to combine (default: lower + digits)
            min_length   : Minimum candidate length (default 1)
            max_length   : Maximum candidate length (default 5)

        Returns:
            AttackReport
        """
        hasher         = get_hasher(algorithm)
        cracked        : list[CrackedPassword] = []
        total_attempts = 0
        attack_start   = time.perf_counter()
        stopped_early  = False

        # Calculate theoretical search space
        search_space = sum(len(charset) ** l for l in range(min_length, max_length + 1))

        logger.info(
            f"[BruteForce] Starting: {len(targets)} targets | "
            f"algorithm={algorithm} | charset={len(charset)} chars | "
            f"len {min_length}-{max_length} | "
            f"search space={search_space:,}"
        )

        # Build set of uncracked target IDs for fast lookup
        uncracked = {t.id: t for t in targets}

        outer_done = False
        for length in range(min_length, max_length + 1):
            if outer_done:
                break

            for combo in itertools.product(charset, repeat=length):
                candidate = "".join(combo)
                total_attempts += 1

                elapsed = time.perf_counter() - attack_start
                if elapsed >= timeout_sec or total_attempts >= max_attempts:
                    stopped_early = True
                    outer_done = True
                    break

                # Test this candidate against every remaining target
                for tid in list(uncracked.keys()):
                    target = uncracked[tid]
                    try:
                        crack_start = time.perf_counter()
                        if hasher.verify_password(
                            candidate, target.hash_value, salt=target.salt
                        ):
                            crack_ms = (time.perf_counter() - crack_start) * 1000
                            cracked.append(CrackedPassword(
                                record_id      = target.id,
                                algorithm      = algorithm,
                                plain_password = candidate,
                                stored_hash    = target.hash_value,
                                crack_time_ms  = round(crack_ms, 4),
                                attempt_number = total_attempts,
                            ))
                            del uncracked[tid]
                    except Exception:
                        pass

                if not uncracked:
                    outer_done = True
                    break

        total_time = time.perf_counter() - attack_start

        report = self._make_report(
            algorithm      = algorithm,
            target_count   = len(targets),
            cracked        = cracked,
            total_attempts = total_attempts,
            total_time_sec = total_time,
            wordlist_size  = min(search_space, max_attempts),
            stopped_early  = stopped_early,
            notes          = (
                f"Charset: {len(charset)} chars | "
                f"Length range: {min_length}-{max_length} | "
                f"Theoretical space: {search_space:,} | "
                f"{'Stopped early.' if stopped_early else 'Search space exhausted.'}"
            ),
        )

        logger.info(
            f"[BruteForce] Done: {report.cracked_count}/{report.target_count} cracked "
            f"({report.success_rate_pct:.1f}%) | "
            f"{report.attempts_per_sec:,.0f} attempts/sec"
        )
        return report
