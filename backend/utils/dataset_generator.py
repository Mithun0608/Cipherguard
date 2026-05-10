"""
Dataset Generator — CipherGuard

Generates a large test dataset of hashed passwords for security analysis.

Pipeline:
  1. Attempt to load real passwords from rockyou.txt
  2. Fall back to a built-in list of representative passwords if not found
  3. Randomly sample up to 1000 unique passwords
  4. Analyze each password's strength and classify it
  5. Hash every password with all 7 algorithms
  6. Persist all records to the database

Expected output: 1000 passwords × 7 algorithms = 7000 database rows.

Each row stores the hash, salt, algorithm, timing, and strength metadata,
enabling direct comparison of algorithm security and performance.
"""

import os
import random
import logging
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from backend.hashers.hasher_registry import HASHER_REGISTRY, ALL_ALGORITHMS
from backend.models.password_hash_model import PasswordHash
from backend.utils.password_analyzer import analyze_password

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path to rockyou.txt — check multiple common locations
# ---------------------------------------------------------------------------

_ROCKYOU_CANDIDATES = [
    Path(r"C:\datasets\rockyou.txt"),
    Path(r"C:\Tools\wordlists\rockyou.txt"),
    Path("/usr/share/wordlists/rockyou.txt"),
    Path("/opt/wordlists/rockyou.txt"),
    Path(__file__).parents[3] / "datasets" / "rockyou.txt",
]

# ---------------------------------------------------------------------------
# Fallback password corpus — representative of real-world password patterns
# Covers all four strength categories for meaningful analysis
# ---------------------------------------------------------------------------

_FALLBACK_PASSWORDS = [
    # Trivial
    "password", "123456", "12345678", "qwerty", "abc123",
    "letmein", "monkey", "1234567", "111111", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "password1", "princess", "football", "shadow", "batman",
    "michael", "123123", "654321", "superman", "donald",
    "pass", "login", "admin", "root", "test",
    "1234", "12345", "000000", "qwerty123", "aaaaaa",
    "password123", "welcome", "passw0rd", "access", "ninja",

    # Common (slightly better)
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

    # Very common duplicates (intentional for dataset realism)
    "password", "123456", "qwerty", "abc123", "letmein",
    "password", "123456", "qwerty", "abc123", "letmein",
    "iloveyou", "monkey", "dragon", "sunshine", "master",
    "princess", "football", "shadow", "michael", "superman",
]


def _find_rockyou() -> Optional[Path]:
    """Check candidate paths and return the first found rockyou.txt."""
    for path in _ROCKYOU_CANDIDATES:
        if path.exists():
            logger.info(f"Found rockyou.txt at: {path}")
            return path
    return None


def _load_passwords_from_rockyou(path: Path, sample_size: int = 1000) -> list[str]:
    """
    Stream-read rockyou.txt and return a random sample of valid passwords.

    Passwords are filtered to:
      - Be decodable as latin-1 (rockyou uses latin-1)
      - Be between 4 and 64 characters
      - Not be empty

    Args:
        path       : Path to rockyou.txt
        sample_size: Number of passwords to sample

    Returns:
        List of up to `sample_size` unique password strings
    """
    passwords = []
    seen: set = set()

    logger.info(f"Loading passwords from {path}...")

    with open(path, "r", encoding="latin-1", errors="replace") as f:
        for line in f:
            pwd = line.strip()
            if not pwd or len(pwd) < 4 or len(pwd) > 64:
                continue
            if pwd in seen:
                continue
            seen.add(pwd)
            passwords.append(pwd)

            # Early exit after reading 200k unique passwords to avoid memory bloat
            if len(passwords) >= 200_000:
                break

    logger.info(f"Loaded {len(passwords):,} candidate passwords from rockyou.txt")

    # Random sample
    sample = random.sample(passwords, min(sample_size, len(passwords)))
    logger.info(f"Sampled {len(sample):,} passwords")
    return sample


def _load_fallback_passwords(sample_size: int = 1000) -> list[str]:
    """
    Return passwords from the built-in fallback corpus.

    To reach ~1000 records, the corpus is repeated/augmented with
    variations so the dataset remains realistic.
    """
    base = list(set(_FALLBACK_PASSWORDS))  # deduplicate
    result: list[str] = []

    # Add base passwords
    result.extend(base)

    # Generate augmented variations to hit the sample_size target
    suffixes  = ["1", "12", "123", "!", "@", "#", "2024", "99", "01", "23"]
    prefixes  = ["My", "The", "A", "New", "Old"]
    i = 0
    while len(result) < sample_size:
        pwd = base[i % len(base)]
        suffix = suffixes[(i // len(base)) % len(suffixes)]
        result.append(pwd + suffix)
        i += 1

    unique = list(dict.fromkeys(result))  # preserve order, remove dupes
    sample = unique[:sample_size]
    logger.info(f"Using {len(sample)} fallback passwords (rockyou.txt not found)")
    return sample


def load_passwords(sample_size: int = 1000) -> list[str]:
    """
    Load passwords from rockyou.txt if available, else use fallback corpus.

    Args:
        sample_size: Target number of passwords to return (default 1000)

    Returns:
        List of password strings
    """
    rockyou_path = _find_rockyou()
    if rockyou_path:
        return _load_passwords_from_rockyou(rockyou_path, sample_size)
    else:
        logger.warning(
            "rockyou.txt not found. Using built-in fallback password corpus. "
            "To use rockyou.txt, place it at: datasets/rockyou.txt"
        )
        return _load_fallback_passwords(sample_size)


# ---------------------------------------------------------------------------
# Core dataset generation
# ---------------------------------------------------------------------------

def generate_dataset(
    db: Session,
    sample_size: int = 1000,
    pepper: Optional[str] = None,
    algorithms: Optional[list] = None,
    clear_existing: bool = False,
) -> dict:
    """
    Generate and persist the full hashed password dataset.

    For each password:
      1. Analyze strength
      2. Hash with every requested algorithm
      3. Persist to `password_hashes` table

    Args:
        db           : SQLAlchemy database session
        sample_size  : Number of passwords to process (default 1000)
        pepper       : Optional server-side pepper for hashing
        algorithms   : List of algorithm names (defaults to ALL_ALGORITHMS)
        clear_existing: If True, delete existing records before generation

    Returns:
        Summary dict with counts and timing statistics
    """
    if algorithms is None:
        algorithms = ALL_ALGORITHMS

    # Validate all requested algorithms exist
    invalid = [a for a in algorithms if a not in HASHER_REGISTRY]
    if invalid:
        raise ValueError(f"Unknown algorithms: {invalid}")

    # Optionally clear existing dataset
    if clear_existing:
        deleted = db.query(PasswordHash).delete()
        db.commit()
        logger.info(f"Cleared {deleted} existing records")

    # Load passwords
    passwords = load_passwords(sample_size)
    total_passwords = len(passwords)
    total_hashes    = 0

    # Category counters
    category_counts = {"trivial": 0, "common": 0, "moderate": 0, "strong": 0}
    timing_stats    = {algo: [] for algo in algorithms}

    logger.info(
        f"Starting dataset generation: {total_passwords} passwords × "
        f"{len(algorithms)} algorithms = "
        f"{total_passwords * len(algorithms)} expected records"
    )

    batch: list[PasswordHash] = []
    BATCH_SIZE = 200   # commit in batches for performance

    for idx, password in enumerate(passwords, 1):
        # Analyze password strength
        analysis = analyze_password(password)
        category_counts[analysis.strength_category] += 1

        # Hash with every algorithm
        for algo_name in algorithms:
            hasher = HASHER_REGISTRY[algo_name]

            try:
                hash_result = hasher.hash_password(password, pepper=pepper)
                timing_stats[algo_name].append(hash_result.time_to_hash_ms)

                record = PasswordHash(
                    plain_password    = password,
                    strength_category = analysis.strength_category,
                    length            = analysis.length,
                    has_uppercase     = int(analysis.has_uppercase),
                    has_lowercase     = int(analysis.has_lowercase),
                    has_digits        = int(analysis.has_digits),
                    has_symbols       = int(analysis.has_symbols),
                    entropy_bits      = analysis.entropy_bits,
                    strength_score    = analysis.strength_score,
                    algorithm         = hash_result.algorithm,
                    hash_value        = hash_result.hash_value,
                    salt              = hash_result.salt,
                    hash_version      = hash_result.hash_version,
                    time_to_hash_ms   = hash_result.time_to_hash_ms,
                )
                batch.append(record)
                total_hashes += 1

            except Exception as e:
                logger.error(
                    f"Error hashing password #{idx} with {algo_name}: {e}"
                )

        # Commit in batches
        if len(batch) >= BATCH_SIZE:
            db.add_all(batch)
            db.commit()
            batch.clear()
            logger.info(f"  Progress: {idx}/{total_passwords} passwords processed...")

    # Commit remaining records
    if batch:
        db.add_all(batch)
        db.commit()
        batch.clear()

    # Build timing summary
    avg_timing = {}
    for algo_name, times in timing_stats.items():
        if times:
            avg_timing[algo_name] = {
                "avg_ms"    : round(sum(times) / len(times), 4),
                "min_ms"    : round(min(times), 4),
                "max_ms"    : round(max(times), 4),
                "total_hashes": len(times),
            }

    logger.info(
        f"Dataset generation complete: {total_hashes} records created."
    )

    return {
        "status"             : "success",
        "total_passwords"    : total_passwords,
        "total_hashes_created": total_hashes,
        "algorithms_used"    : algorithms,
        "category_distribution": category_counts,
        "timing_stats_ms"    : avg_timing,
    }
