"""
Base Attack Interface - CipherGuard Phase 3

Defines the abstract contract every attack module must implement.
Uses the Strategy Design Pattern (consistent with the hashing engine).

Every attack:
  - Accepts a list of PasswordHash records to attack
  - Returns an AttackReport with full metrics
  - Is time-bounded via max_attempts and timeout_sec
"""

import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Attack result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CrackedPassword:
    """A single successfully cracked password record."""
    record_id       : int
    algorithm       : str
    plain_password  : str      # recovered plaintext
    stored_hash     : str
    crack_time_ms   : float    # time taken to crack this single hash
    attempt_number  : int      # which attempt number cracked it


@dataclass
class AttackReport:
    """
    Full result report for one attack run.

    Contains all metrics needed for the security score engine and API responses.
    """
    attack_type          : str
    algorithm            : str
    target_count         : int    # number of hashes attacked
    cracked_count        : int    # number successfully cracked
    success_rate_pct     : float  # cracked_count / target_count * 100
    total_time_sec       : float  # wall-clock time for entire run
    total_attempts       : int    # total hash comparisons made
    attempts_per_sec     : float  # throughput
    cracked_passwords    : list[CrackedPassword] = field(default_factory=list)
    wordlist_size        : int    = 0    # size of dictionary/wordlist used
    max_crack_time_ms    : float  = 0.0  # slowest single crack
    avg_crack_time_ms    : float  = 0.0  # average single crack time
    stopped_early        : bool   = False  # True if timeout or limit hit
    notes                : str    = ""    # additional context


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class BaseAttack(ABC):
    """
    Abstract base class for all attack strategies.

    Subclasses must implement:
        run(targets, hasher) -> AttackReport
    """

    ATTACK_NAME: str = "base"

    def _make_report(
        self,
        algorithm       : str,
        target_count    : int,
        cracked         : list[CrackedPassword],
        total_attempts  : int,
        total_time_sec  : float,
        wordlist_size   : int = 0,
        stopped_early   : bool = False,
        notes           : str = "",
    ) -> AttackReport:
        """
        Build a complete AttackReport from raw metrics.
        All derived percentages and averages computed here.
        """
        cracked_count   = len(cracked)
        success_rate    = (cracked_count / target_count * 100) if target_count > 0 else 0.0
        attempts_per_sec = (total_attempts / total_time_sec) if total_time_sec > 0 else 0.0
        crack_times      = [c.crack_time_ms for c in cracked]

        return AttackReport(
            attack_type       = self.ATTACK_NAME,
            algorithm         = algorithm,
            target_count      = target_count,
            cracked_count     = cracked_count,
            success_rate_pct  = round(success_rate, 2),
            total_time_sec    = round(total_time_sec, 4),
            total_attempts    = total_attempts,
            attempts_per_sec  = round(attempts_per_sec, 2),
            cracked_passwords = cracked,
            wordlist_size     = wordlist_size,
            max_crack_time_ms = round(max(crack_times), 4) if crack_times else 0.0,
            avg_crack_time_ms = round(sum(crack_times) / len(crack_times), 4) if crack_times else 0.0,
            stopped_early     = stopped_early,
            notes             = notes,
        )

    @abstractmethod
    def run(
        self,
        targets     : list,   # list of PasswordHash ORM objects
        algorithm   : str,
        max_attempts: int       = 100_000,
        timeout_sec : float     = 60.0,
    ) -> AttackReport:
        """
        Execute the attack against the provided hashed password records.

        Args:
            targets      : List of PasswordHash DB records to crack
            algorithm    : The hashing algorithm used for these records
            max_attempts : Maximum number of hash comparisons before stopping
            timeout_sec  : Wall-clock timeout in seconds

        Returns:
            AttackReport with full metrics
        """
        ...
