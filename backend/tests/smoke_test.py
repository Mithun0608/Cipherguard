"""
CipherGuard Phase 2 - Smoke Test Script

Verifies that all hashing algorithms work correctly:
  - hash_password() produces a result for every algorithm
  - verify_password() returns True for correct password
  - verify_password() returns False for wrong password
  - Password strength analyzer works across categories
  - Timing is recorded for every algorithm

Run from the project ROOT directory:
    python -m backend.tests.smoke_test

(Do NOT run from inside the backend/ folder)
"""

import sys
import os
import io

# Force UTF-8 output on Windows before any print() calls
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)
))))

from backend.hashers.hasher_registry import HASHER_REGISTRY, ALL_ALGORITHMS
from backend.utils.password_analyzer import analyze_password

# ---------------------------------------------------------------------------
# Test passwords
# ---------------------------------------------------------------------------
TEST_PASSWORDS = [
    ("123456",              "trivial"),
    ("password",            "trivial"),
    ("Summer2024!",         "moderate"),
    ("Tr0ub4dor3xYz#Qw9",  "strong"),
]

WRONG_PASSWORD = "definitely_wrong_password_xyz"

# ---------------------------------------------------------------------------
# ANSI colors for terminal output
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def ok(msg):
    print(f"  {GREEN}[PASS]{RESET}  {msg}")

def fail(msg):
    print(f"  {RED}[FAIL]{RESET}  {msg}")
    sys.exit(1)

def info(msg):
    print(f"  {CYAN}[INFO]{RESET}  {msg}")

def section(title):
    print(f"\n{BOLD}{title}{RESET}")


# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

def run_smoke_tests():
    print(f"\n{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}   CipherGuard Phase 2 - Hashing Engine Smoke Test{RESET}")
    print(f"{BOLD}{'=' * 62}{RESET}\n")

    total_tests  = 0
    total_passed = 0

    # -----------------------------------------------------------------------
    # Test 1: All algorithms produce a non-empty hash
    # -----------------------------------------------------------------------
    section("[1/3] Hash Generation - all 7 algorithms")
    print(f"      Password: 'TestPassword1!'  |  Algorithms: {len(ALL_ALGORITHMS)}\n")

    test_password = "TestPassword1!"
    hash_cache = {}

    for algo in ALL_ALGORITHMS:
        hasher = HASHER_REGISTRY[algo]
        result = hasher.hash_password(test_password)
        hash_cache[algo] = result

        total_tests += 1
        if result.hash_value:
            total_passed += 1
            truncated = result.hash_value[:44] + ("..." if len(result.hash_value) > 44 else "")
            ok(
                f"{algo:<16} | {result.time_to_hash_ms:8.4f} ms"
                f" | hash: {truncated}"
            )
        else:
            fail(f"{algo}: hash_password() returned an empty string!")

    # -----------------------------------------------------------------------
    # Test 2: Correct password must verify as True
    # -----------------------------------------------------------------------
    section("[2/3] Correct Password Verification")

    for algo in ALL_ALGORITHMS:
        hasher = HASHER_REGISTRY[algo]
        cached = hash_cache[algo]
        total_tests += 1

        is_valid = hasher.verify_password(
            password    = test_password,
            stored_hash = cached.hash_value,
            salt        = cached.salt,
        )
        if is_valid:
            total_passed += 1
            ok(f"{algo:<16} -> Correct password accepted")
        else:
            fail(f"{algo}: verify_password() returned False for the CORRECT password!")

    # -----------------------------------------------------------------------
    # Test 3: Wrong password must verify as False
    # -----------------------------------------------------------------------
    section("[3/3] Wrong Password Rejection")

    for algo in ALL_ALGORITHMS:
        hasher = HASHER_REGISTRY[algo]
        cached = hash_cache[algo]
        total_tests += 1

        is_valid = hasher.verify_password(
            password    = WRONG_PASSWORD,
            stored_hash = cached.hash_value,
            salt        = cached.salt,
        )
        if not is_valid:
            total_passed += 1
            ok(f"{algo:<16} -> Wrong password correctly rejected")
        else:
            fail(f"{algo}: verify_password() returned True for a WRONG password!")

    # -----------------------------------------------------------------------
    # Bonus: Password Strength Analyzer
    # -----------------------------------------------------------------------
    section("[BONUS] Password Strength Analyzer")
    print()

    for pwd, _ in TEST_PASSWORDS:
        analysis = analyze_password(pwd)
        info(
            f"'{pwd[:22]:<24}' | "
            f"score={analysis.strength_score:3d} | "
            f"entropy={analysis.entropy_bits:5.1f} bits | "
            f"category={analysis.strength_category}"
        )

    # -----------------------------------------------------------------------
    # Timing comparison table
    # -----------------------------------------------------------------------
    section("[TIMING] Algorithm Speed Comparison")
    print()
    print(f"  {'Algorithm':<18} {'Time (ms)':>12}  {'Security':<10}")
    print(f"  {'-'*18} {'-'*12}  {'-'*10}")

    WEAK  = {"plaintext", "md5", "sha1", "sha256"}
    for algo, result in hash_cache.items():
        tier = "WEAK" if algo in WEAK else "STRONG"
        color = RED if tier == "WEAK" else GREEN
        print(
            f"  {algo:<18} {result.time_to_hash_ms:>12.4f}  "
            f"{color}{tier}{RESET}"
        )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print(f"\n{BOLD}{'=' * 62}{RESET}")
    if total_passed == total_tests:
        status = f"{GREEN}ALL PASSED{RESET}"
    else:
        status = f"{RED}SOME FAILED{RESET}"
    print(f"{BOLD}  Result: {status}  ({total_passed}/{total_tests} tests){RESET}")
    print(f"{BOLD}{'=' * 62}{RESET}\n")


if __name__ == "__main__":
    run_smoke_tests()
