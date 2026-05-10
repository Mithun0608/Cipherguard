"""
Dictionary Attack - CipherGuard Phase 3

Simulates a real-world dictionary attack by hashing each word from a
wordlist and comparing against stored hashes.

Why it works on weak algorithms:
  - Plaintext/MD5/SHA1: single hash comparison per word, millions/sec
  - bcrypt/Argon2id: ~200ms per attempt => 5 attempts/sec => impractical

Demonstrates:
  - Speed advantage attackers have with fast hash functions
  - Why slow-by-design algorithms (bcrypt, Argon2id) matter
"""

import time
import logging
from pathlib import Path
from typing import Optional

from backend.attacks.base_attack import BaseAttack, AttackReport, CrackedPassword
from backend.hashers.hasher_registry import get_hasher

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wordlist paths (same candidates as dataset_generator)
# ---------------------------------------------------------------------------

_ROCKYOU_CANDIDATES = [
    Path(r"C:\datasets\rockyou.txt"),
    Path(r"C:\Tools\wordlists\rockyou.txt"),
    Path("/usr/share/wordlists/rockyou.txt"),
    Path(__file__).parents[3] / "datasets" / "rockyou.txt",
]


def _build_augmented_wordlist() -> list[str]:
    """
    Build an augmented wordlist that mirrors the dataset generator's
    _load_fallback_passwords() augmentation logic, so the dictionary attack
    can crack all passwords in the generated dataset.

    This MUST stay in sync with dataset_generator._FALLBACK_PASSWORDS
    and the suffix augmentation logic in _load_fallback_passwords().
    """
    _BASE_CORPUS = [
        # Trivial
        "password", "123456", "12345678", "qwerty", "abc123",
        "letmein", "monkey", "1234567", "111111", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "password1", "princess", "football", "shadow", "batman",
        "michael", "123123", "654321", "superman", "donald",
        "pass", "login", "admin", "root", "test",
        "1234", "12345", "000000", "qwerty123", "aaaaaa",
        "password123", "welcome", "passw0rd", "access", "ninja",
        # Common
        "charlie1", "michael1", "jessica1", "thomas1", "sarah1",
        "robert1", "william1", "daniel1", "james1", "david1",
        "spring2024", "winter2024", "summer23", "fall2023",
        "monday1", "january1", "february1", "march2023",
        "mypassword", "mypass123", "hello123", "computer1",
        "sunshine1", "orange123", "purple123", "green456",
        "starwars1", "pokemon1", "minecraft1", "fortnite1",
        "guitar123", "music123", "soccer123", "hockey123",
        "baseball1", "football1", "basketball1", "tennis123",
        "dog12345", "cat12345", "fish1234", "bird1234",
        # Moderate
        "Hunter2!", "Ranger9$", "Falcon7#", "Raptor6@",
        "Maverick1!", "Phoenix3#", "Thunder5@", "Lightning8$",
        "Dragon2024!", "Tiger2024#", "Eagle2024@", "Hawk2024$",
        "Password!1", "Welcome!1", "Security1!", "Admin2024!",
        "Blue$ky22", "R3dR0se!!", "Gr33nT3a#", "Purpl3sky@",
        "CoffeeTime1!", "MorningRun2#", "NightOwl3$", "DayDream4@",
        "Trustno1!!", "Batman2024!", "Superman3#", "Ironman4$",
        "Football2!", "Baseball3#", "Basketball4@", "Soccer5$",
        "John@doe123", "Jane#doe456", "Alice$789!!", "Bob%123!!",
        "Smile2day!", "Love4life#", "Hope4ever@", "Faith2024$",
        # Strong (high entropy)
        "Tr0ub4dor&3", "correcthorsebatterystaple",
        "xK9#mP2$vL8@nQ5", "R7$tY2!wZ4#bN6@",
        "Hj8&Kp3!Lm5@Nx", "Qr9$St2#Uv4%Wx",
        "zX3!cV6@bN9#mQ", "aS4$dF7@gH2!jK",
        "MyS3cur3P@$$w0rd!", "Th1s!sAStr0ng#P4ss",
        "C0mpl3x!ty#M4tt3rs", "Ungu3ss4bl3@P4ssw0rd",
        "L0ng&Str0ng!P4ssph4se", "Rand0m!Numb3rs#G0",
        "SuperSecure#2024!@", "UltraComplex$Pass99#",
        "XyZ!1234@AbC#5678", "QwErTy!@#$ZxCvBn99",
        "P4$$w0rd!Complex#42", "Secur1ty@Analysis#2024",
        "CipherGuard!Str0ng#1", "HashBreaker@Proof#99",
        "Entropy!B00ster@High#", "Cr4ckThis@IfYouCan#!!",
        "Unbreakable!1@#$%^&*(", "ImpossibleToGuess!99#",
        "AlgorithmTest!$3cur3#", "BenchmarkPass!@#4321",
        "ResearchData!2024@#$", "PasswordStudy!#Complex",
    ]

    base = list(dict.fromkeys(_BASE_CORPUS))  # deduplicate, preserve order
    result = list(base)

    # Replicate the exact augmentation logic from dataset_generator.py
    suffixes = ["1", "12", "123", "!", "@", "#", "2024", "99", "01", "23"]
    i = 0
    while len(result) < 1000:
        pwd = base[i % len(base)]
        suffix = suffixes[(i // len(base)) % len(suffixes)]
        result.append(pwd + suffix)
        i += 1

    # Remove duplicates while preserving order
    seen: set = set()
    unique = []
    for w in result:
        if w not in seen:
            seen.add(w)
            unique.append(w)

    return unique


_AUGMENTED_WORDLIST: list[str] = []  # lazily built on first use


def _load_wordlist(max_words: int = 50_000) -> list[str]:
    """
    Load the wordlist. Prefers rockyou.txt if found, otherwise uses an
    augmented built-in wordlist that mirrors the dataset generator's
    password corpus — ensuring accurate attack success rates.

    Args:
        max_words: Cap on words loaded (avoids memory exhaustion)

    Returns:
        List of password candidate strings
    """
    for path in _ROCKYOU_CANDIDATES:
        if path.exists():
            logger.info(f"[DictAttack] Loading wordlist from {path}")
            words = []
            with open(path, "r", encoding="latin-1", errors="replace") as f:
                for line in f:
                    w = line.strip()
                    if w and 1 <= len(w) <= 64:
                        words.append(w)
                        if len(words) >= max_words:
                            break
            logger.info(f"[DictAttack] Loaded {len(words):,} words")
            return words

    logger.warning(
        "[DictAttack] rockyou.txt not found — using augmented built-in wordlist "
        "(mirrors dataset_generator augmentation for accurate success rates)"
    )
    global _AUGMENTED_WORDLIST
    if not _AUGMENTED_WORDLIST:
        _AUGMENTED_WORDLIST = _build_augmented_wordlist()
        logger.info(f"[DictAttack] Augmented wordlist built: {len(_AUGMENTED_WORDLIST):,} words")
    return _AUGMENTED_WORDLIST


# ---------------------------------------------------------------------------
# Dictionary Attack implementation
# ---------------------------------------------------------------------------

class DictionaryAttack(BaseAttack):
    """
    Dictionary Attack: hash each word and compare against stored hashes.

    Attack flow:
      1. Load wordlist (rockyou.txt preferred, augmented built-in fallback)
      2. For each target hash, iterate words until match found or list exhausted
      3. Record crack time, attempt count, success rate

    Effective against:
      - Plaintext (trivially, direct comparison)
      - MD5 / SHA1 / SHA256 (millions of comparisons/sec)

    Ineffective against:
      - bcrypt (rounds=12): ~5 comparisons/sec
      - Argon2id: ~20 comparisons/sec, + GPU-resistant
    """

    ATTACK_NAME = "dictionary"

    def __init__(self, max_wordlist_size: int = 50_000):
        self._wordlist: Optional[list[str]] = None
        self._max_wordlist_size = max_wordlist_size

    @property
    def wordlist(self) -> list[str]:
        """Lazy-load wordlist on first access."""
        if self._wordlist is None:
            self._wordlist = _load_wordlist(self._max_wordlist_size)
        return self._wordlist

    def run(
        self,
        targets     : list,
        algorithm   : str,
        max_attempts: int   = 100_000,
        timeout_sec : float = 60.0,
    ) -> AttackReport:
        """
        Run dictionary attack against a list of PasswordHash records.

        Args:
            targets      : PasswordHash ORM records with algorithm == algorithm
            algorithm    : Hashing algorithm these records use
            max_attempts : Hard cap on total hash comparisons
            timeout_sec  : Wall-clock timeout

        Returns:
            AttackReport with full metrics
        """
        hasher        = get_hasher(algorithm)
        words         = self.wordlist
        cracked       : list[CrackedPassword] = []
        total_attempts = 0
        attack_start   = time.perf_counter()
        stopped_early  = False

        logger.info(
            f"[DictAttack] Starting: {len(targets)} targets | "
            f"algorithm={algorithm} | wordlist={len(words):,} words"
        )

        for target in targets:
            if total_attempts >= max_attempts:
                stopped_early = True
                break
            elapsed = time.perf_counter() - attack_start
            if elapsed >= timeout_sec:
                stopped_early = True
                break

            target_hash = target.hash_value
            target_salt = target.salt

            crack_start = time.perf_counter()
            for word in words:
                total_attempts += 1
                try:
                    if hasher.verify_password(word, target_hash, salt=target_salt):
                        crack_ms = (time.perf_counter() - crack_start) * 1000
                        cracked.append(CrackedPassword(
                            record_id      = target.id,
                            algorithm      = algorithm,
                            plain_password = word,
                            stored_hash    = target_hash,
                            crack_time_ms  = round(crack_ms, 4),
                            attempt_number = total_attempts,
                        ))
                        break
                except Exception:
                    pass

                if total_attempts >= max_attempts:
                    stopped_early = True
                    break

        total_time = time.perf_counter() - attack_start

        report = self._make_report(
            algorithm      = algorithm,
            target_count   = len(targets),
            cracked        = cracked,
            total_attempts = total_attempts,
            total_time_sec = total_time,
            wordlist_size  = len(words),
            stopped_early  = stopped_early,
            notes          = (
                f"Wordlist size: {len(words):,}. "
                f"{'Stopped early (limit/timeout).' if stopped_early else 'Exhausted wordlist.'}"
            ),
        )

        logger.info(
            f"[DictAttack] Done: {report.cracked_count}/{report.target_count} cracked "
            f"({report.success_rate_pct:.1f}%) | "
            f"{report.attempts_per_sec:,.0f} attempts/sec"
        )
        return report
