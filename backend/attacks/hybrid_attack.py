"""
Hybrid Attack - CipherGuard Phase 3

Combines dictionary attack with rule-based mutation patterns.

Attackers know users modify common passwords predictably:
  - Append year:         password -> password2024
  - Capitalize first:   password -> Password
  - Leet substitution:  password -> p@ssw0rd
  - Append symbols:     password -> password!
  - Append numbers:     admin    -> admin123

This dramatically expands the effective dictionary without full brute force.
A 10,000-word dictionary with 50 mutation rules = 500,000 candidates —
still orders of magnitude smaller than true brute force.

Demonstrates:
  - Why "clever" password modifications are predictable
  - Why password managers with truly random passwords matter
  - Why bcrypt/Argon2id slow attackers even with smart rule engines
"""

import time
import logging
from typing import Optional

from backend.attacks.base_attack import BaseAttack, AttackReport, CrackedPassword
from backend.attacks.dictionary_attack import _load_wordlist
from backend.hashers.hasher_registry import get_hasher

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mutation rule functions
# Each rule takes a base word and returns a list of candidate strings
# ---------------------------------------------------------------------------

def _rule_identity(word: str) -> list[str]:
    """Return the word as-is."""
    return [word]

def _rule_capitalize(word: str) -> list[str]:
    """Capitalize first letter."""
    return [word.capitalize()]

def _rule_uppercase(word: str) -> list[str]:
    """Full uppercase."""
    return [word.upper()]

def _rule_append_years(word: str) -> list[str]:
    """Append common years."""
    return [word + y for y in ["2023", "2024", "2025", "22", "23", "24"]]

def _rule_append_numbers(word: str) -> list[str]:
    """Append common number suffixes."""
    return [word + n for n in ["1", "12", "123", "1234", "01", "99", "007", "0"]]

def _rule_append_symbols(word: str) -> list[str]:
    """Append common symbols."""
    return [word + s for s in ["!", "@", "#", "$", "!!", "123!", "@123"]]

def _rule_prepend_numbers(word: str) -> list[str]:
    """Prepend numbers."""
    return [n + word for n in ["1", "123", "0", "00"]]

def _rule_leet_basic(word: str) -> list[str]:
    """Basic leet speak substitutions."""
    candidates = []
    # Single substitutions
    for orig, repl in [("a", "@"), ("e", "3"), ("i", "1"), ("o", "0"), ("s", "$")]:
        mutated = word.replace(orig, repl)
        if mutated != word:
            candidates.append(mutated)
    return candidates

def _rule_leet_full(word: str) -> list[str]:
    """Combined leet speak."""
    result = word
    for orig, repl in [("a","@"), ("e","3"), ("i","1"), ("o","0"), ("s","$"), ("t","7")]:
        result = result.replace(orig, repl)
    return [result] if result != word else []

def _rule_capitalize_append(word: str) -> list[str]:
    """Capitalize + append numbers or symbols (very common pattern)."""
    cap = word.capitalize()
    return [
        cap + "1", cap + "123", cap + "!", cap + "1!", cap + "@123",
        cap + "2024", cap + "2024!", cap + "#1",
    ]

def _rule_double(word: str) -> list[str]:
    """Repeat the word."""
    return [word * 2] if len(word) <= 6 else []

def _rule_reverse(word: str) -> list[str]:
    """Reverse the word."""
    return [word[::-1]]

def _rule_mixed_case_symbol(word: str) -> list[str]:
    """Common mixed patterns seen in breach databases."""
    cap = word.capitalize()
    return [
        cap + "!",
        cap + "!1",
        word + "!@#",
        word[0].upper() + word[1:] + "99",
    ]


# Master rule list (ordered roughly by frequency in real breach data)
ALL_RULES = [
    _rule_identity,
    _rule_capitalize,
    _rule_append_numbers,
    _rule_append_years,
    _rule_append_symbols,
    _rule_leet_basic,
    _rule_capitalize_append,
    _rule_prepend_numbers,
    _rule_uppercase,
    _rule_leet_full,
    _rule_double,
    _rule_reverse,
    _rule_mixed_case_symbol,
]


# ---------------------------------------------------------------------------
# Hybrid Attack implementation
# ---------------------------------------------------------------------------

class HybridAttack(BaseAttack):
    """
    Hybrid Attack: dictionary words + mutation rules.

    Attack flow:
      1. Load base wordlist (rockyou.txt or built-in)
      2. For each word, apply all mutation rules
      3. Test each mutated candidate against target hashes
      4. Track which rule patterns succeed most often

    Rule statistics are collected to show which mutations are most dangerous.
    """

    ATTACK_NAME = "hybrid"

    def __init__(
        self,
        max_wordlist_size : int = 10_000,
        rules             : Optional[list] = None,
    ):
        self._max_wordlist_size = max_wordlist_size
        self._rules = rules or ALL_RULES
        self._wordlist: Optional[list[str]] = None

    @property
    def wordlist(self) -> list[str]:
        if self._wordlist is None:
            self._wordlist = _load_wordlist(self._max_wordlist_size)
        return self._wordlist

    def _generate_candidates(self, word: str) -> list[tuple[str, str]]:
        """
        Apply all rules to a base word.

        Returns:
            List of (candidate_string, rule_name) tuples
        """
        candidates = []
        for rule_fn in self._rules:
            for candidate in rule_fn(word):
                if 1 <= len(candidate) <= 72:   # 72 = bcrypt max password length
                    candidates.append((candidate, rule_fn.__name__))
        return candidates

    def run(
        self,
        targets     : list,
        algorithm   : str,
        max_attempts: int   = 200_000,
        timeout_sec : float = 120.0,
    ) -> AttackReport:
        """
        Run hybrid attack.

        Args:
            targets      : PasswordHash ORM records to attack
            algorithm    : Hashing algorithm
            max_attempts : Total attempt cap
            timeout_sec  : Timeout in seconds

        Returns:
            AttackReport with rule effectiveness stats in notes
        """
        # ── Plaintext instant compromise ────────────────────────────────────
        if algorithm == "plaintext":
            attack_start = time.perf_counter()
            cracked = []
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
                    "INSTANTLY COMPROMISED: Plaintext passwords require zero cracking effort. "
                    "Direct database read exposes every password immediately. "
                    "100% of accounts compromised upon any database breach."
                ),
            )

        hasher         = get_hasher(algorithm)
        words          = self.wordlist
        cracked        : list[CrackedPassword] = []
        total_attempts = 0
        attack_start   = time.perf_counter()
        stopped_early  = False
        rule_hits: dict[str, int] = {}  # rule_name -> crack count

        # Precount total candidates for logging
        sample_candidates = self._generate_candidates(words[0]) if words else []
        est_total = len(words) * len(sample_candidates)

        logger.info(
            f"[Hybrid] Starting: {len(targets)} targets | "
            f"algorithm={algorithm} | wordlist={len(words):,} | "
            f"rules={len(self._rules)} | est candidates={est_total:,}"
        )

        uncracked = {t.id: t for t in targets}

        for base_word in words:
            if stopped_early or not uncracked:
                break

            candidates = self._generate_candidates(base_word)

            for candidate, rule_name in candidates:
                if total_attempts >= max_attempts:
                    stopped_early = True
                    break
                elapsed = time.perf_counter() - attack_start
                if elapsed >= timeout_sec:
                    stopped_early = True
                    break

                for tid in list(uncracked.keys()):
                    target = uncracked[tid]
                    total_attempts += 1
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
                            rule_hits[rule_name] = rule_hits.get(rule_name, 0) + 1
                            del uncracked[tid]
                    except Exception:
                        pass

                if stopped_early:
                    break

        total_time = time.perf_counter() - attack_start

        # Build rule effectiveness summary for notes
        top_rules = sorted(rule_hits.items(), key=lambda x: x[1], reverse=True)[:5]
        top_rules_str = ", ".join(f"{r}={c}" for r, c in top_rules)

        report = self._make_report(
            algorithm      = algorithm,
            target_count   = len(targets),
            cracked        = cracked,
            total_attempts = total_attempts,
            total_time_sec = total_time,
            wordlist_size  = len(words) * len(sample_candidates),
            stopped_early  = stopped_early,
            notes          = (
                f"Base words: {len(words):,} | Rules: {len(self._rules)} | "
                f"Est candidates: {est_total:,} | "
                f"Top cracking rules: [{top_rules_str}] | "
                f"{'Stopped early.' if stopped_early else 'Completed.'}"
            ),
        )

        logger.info(
            f"[Hybrid] Done: {report.cracked_count}/{report.target_count} cracked "
            f"({report.success_rate_pct:.1f}%) | "
            f"{report.attempts_per_sec:,.0f} attempts/sec"
        )
        return report
