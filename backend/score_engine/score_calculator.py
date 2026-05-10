"""
Security Score Engine - CipherGuard Phase 3

Calculates a 0-100 security score for each hashing algorithm based on
how it performed under simulated attack conditions.

Scoring philosophy:
  - High crack rate      -> low score (attacker wins)
  - Fast crack time      -> low score (attacker is efficient)
  - Slow algorithm       -> high score (each attempt is costly for attacker)
  - Salted              -> high score (rainbow tables defeated)
  - Memory-hard         -> bonus points (GPU resistance)

Also generates a comparative breach analysis report across all algorithms.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from backend.attacks.base_attack import AttackReport
from backend.hashers.hasher_registry import WEAK_ALGORITHMS, STRONG_ALGORITHMS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Algorithm properties (used as score priors before attack results)
# ---------------------------------------------------------------------------

ALGORITHM_PROPERTIES = {
    "plaintext"     : {"salted": False, "memory_hard": False, "speed_class": "instant",   "baseline_score": 0},
    "md5"           : {"salted": False, "memory_hard": False, "speed_class": "fast",      "baseline_score": 5},
    "sha1"          : {"salted": False, "memory_hard": False, "speed_class": "fast",      "baseline_score": 8},
    "sha256"        : {"salted": False, "memory_hard": False, "speed_class": "fast",      "baseline_score": 12},
    "salted_sha256" : {"salted": True,  "memory_hard": False, "speed_class": "fast",      "baseline_score": 35},
    "bcrypt"        : {"salted": True,  "memory_hard": False, "speed_class": "slow",      "baseline_score": 75},
    "argon2id"      : {"salted": True,  "memory_hard": True,  "speed_class": "slow",      "baseline_score": 90},
}


# ---------------------------------------------------------------------------
# Score result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AlgorithmScore:
    """Security score and breakdown for one algorithm."""
    algorithm        : str
    score            : int              # 0-100
    grade            : str              # A/B/C/D/F
    tier             : str              # weak/moderate/strong
    crack_rate_pct   : float            # average across attack types
    avg_time_sec     : float            # average total attack time
    is_salted        : bool
    is_memory_hard   : bool
    recommendations  : list[str]        = field(default_factory=list)
    attack_breakdown : dict             = field(default_factory=dict)


@dataclass
class BreachReport:
    """Full comparative security analysis across all tested algorithms."""
    total_algorithms_tested : int
    strongest_algorithm     : str
    weakest_algorithm       : str
    algorithm_scores        : list[AlgorithmScore]
    overall_risk_level      : str   # LOW / MEDIUM / HIGH / CRITICAL
    summary                 : str
    recommendations         : list[str]


# ---------------------------------------------------------------------------
# Score calculator
# ---------------------------------------------------------------------------

def _grade(score: int) -> str:
    if score >= 85: return "A"
    elif score >= 70: return "B"
    elif score >= 55: return "C"
    elif score >= 35: return "D"
    else: return "F"

def _tier(score: int, algorithm: str) -> str:
    if algorithm in STRONG_ALGORITHMS: return "strong"
    elif algorithm == "salted_sha256": return "moderate"
    else: return "weak"


def calculate_score(
    algorithm : str,
    reports   : list[AttackReport],
) -> AlgorithmScore:
    """
    Calculate security score for one algorithm from its attack reports.

    Scoring components (total = 100):
      1. Crack resistance (40 pts) — based on success_rate across attacks
      2. Time resistance  (30 pts) — how long attacks take per attempt
      3. Algorithm design (20 pts) — salting, memory-hardness, baseline
      4. Speed penalty    (10 pts) — penalize fast/cheap hashing

    Args:
        algorithm : Algorithm name
        reports   : All AttackReport objects for this algorithm

    Returns:
        AlgorithmScore with full breakdown
    """
    props = ALGORITHM_PROPERTIES.get(algorithm, {
        "salted": False, "memory_hard": False,
        "speed_class": "fast", "baseline_score": 10,
    })

    if not reports:
        # No attack data — use baseline score from known properties
        score = props["baseline_score"]
        return AlgorithmScore(
            algorithm       = algorithm,
            score           = score,
            grade           = _grade(score),
            tier            = _tier(score, algorithm),
            crack_rate_pct  = 0.0,
            avg_time_sec    = 0.0,
            is_salted       = props["salted"],
            is_memory_hard  = props["memory_hard"],
            recommendations = _build_recommendations(algorithm, score, 0.0),
            attack_breakdown= {},
        )

    # --- Component 1: Crack Resistance (40 pts) ---
    # Average success rate across all attack types (lower = better for defender)
    avg_success_rate = sum(r.success_rate_pct for r in reports) / len(reports)
    crack_resistance = max(0, 40 - (avg_success_rate / 100 * 40))

    # --- Component 2: Time Resistance (30 pts) ---
    # Higher attempts_per_sec = easier for attacker = lower score
    avg_attempts_per_sec = sum(r.attempts_per_sec for r in reports) / len(reports)
    if avg_attempts_per_sec < 10:          # < 10/sec = very slow (argon2/bcrypt)
        time_resistance = 30
    elif avg_attempts_per_sec < 100:       # 10-100/sec
        time_resistance = 22
    elif avg_attempts_per_sec < 10_000:    # fast but limited
        time_resistance = 12
    elif avg_attempts_per_sec < 1_000_000: # very fast
        time_resistance = 4
    else:                                   # millions/sec = terrible
        time_resistance = 0

    # --- Component 3: Algorithm Design (20 pts) ---
    design_score = 0
    if props["salted"]:       design_score += 10
    if props["memory_hard"]:  design_score += 7
    if props["speed_class"] == "slow": design_score += 3

    # --- Component 4: Speed penalty bonus (10 pts) ---
    # Reward algorithms where attackers get < 100 attempts/sec
    if avg_attempts_per_sec < 10:
        speed_bonus = 10
    elif avg_attempts_per_sec < 1000:
        speed_bonus = 5
    else:
        speed_bonus = 0

    raw_score = crack_resistance + time_resistance + design_score + speed_bonus
    final_score = max(0, min(100, int(raw_score)))

    # Per-attack-type breakdown
    breakdown = {
        r.attack_type: {
            "success_rate_pct": r.success_rate_pct,
            "attempts_per_sec": r.attempts_per_sec,
            "cracked_count"   : r.cracked_count,
            "total_time_sec"  : r.total_time_sec,
        }
        for r in reports
    }

    avg_time = sum(r.total_time_sec for r in reports) / len(reports)

    return AlgorithmScore(
        algorithm       = algorithm,
        score           = final_score,
        grade           = _grade(final_score),
        tier            = _tier(final_score, algorithm),
        crack_rate_pct  = round(avg_success_rate, 2),
        avg_time_sec    = round(avg_time, 4),
        is_salted       = props["salted"],
        is_memory_hard  = props["memory_hard"],
        recommendations = _build_recommendations(algorithm, final_score, avg_success_rate),
        attack_breakdown= breakdown,
    )


def _build_recommendations(algorithm: str, score: int, crack_rate: float) -> list[str]:
    """Generate contextual security recommendations."""
    recs = []
    if algorithm == "plaintext":
        recs.append("CRITICAL: Never store plaintext passwords. Use bcrypt or Argon2id immediately.")
    if algorithm in ("md5", "sha1"):
        recs.append(f"{algorithm.upper()} is cryptographically broken. Migrate to bcrypt or Argon2id.")
    if algorithm == "sha256":
        recs.append("Unsalted SHA-256 is vulnerable to rainbow tables. Use salted_sha256 at minimum.")
    if algorithm == "salted_sha256":
        recs.append("Salted SHA-256 resists rainbow tables but is still fast. Consider upgrading to bcrypt.")
    if crack_rate > 50:
        recs.append(f"Over {crack_rate:.0f}% of passwords were cracked. Immediate algorithm migration required.")
    if score >= 75:
        recs.append(f"{algorithm} provides strong password protection. Maintain current cost parameters.")
    if algorithm == "bcrypt":
        recs.append("Monitor server hardware — increase rounds when login time < 100ms.")
    if algorithm == "argon2id":
        recs.append("Argon2id is the current OWASP recommendation. Ensure memory_cost >= 64MB.")
    return recs


# ---------------------------------------------------------------------------
# Breach analysis report generator
# ---------------------------------------------------------------------------

def generate_breach_report(
    scores: list[AlgorithmScore],
) -> BreachReport:
    """
    Generate a comparative breach analysis report from AlgorithmScore objects.

    Args:
        scores: List of AlgorithmScore objects (one per algorithm)

    Returns:
        BreachReport with rankings, risk level, and recommendations
    """
    if not scores:
        return BreachReport(
            total_algorithms_tested = 0,
            strongest_algorithm     = "N/A",
            weakest_algorithm       = "N/A",
            algorithm_scores        = [],
            overall_risk_level      = "UNKNOWN",
            summary                 = "No algorithms tested.",
            recommendations         = [],
        )

    sorted_scores = sorted(scores, key=lambda s: s.score, reverse=True)
    strongest = sorted_scores[0]
    weakest   = sorted_scores[-1]

    # Overall risk = driven by weakest algorithm in use
    weakest_score = weakest.score
    if weakest_score < 20:
        risk_level = "CRITICAL"
    elif weakest_score < 40:
        risk_level = "HIGH"
    elif weakest_score < 65:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    avg_crack_rate = sum(s.crack_rate_pct for s in scores) / len(scores)

    summary = (
        f"Tested {len(scores)} algorithms. "
        f"Strongest: {strongest.algorithm} (score={strongest.score}, grade={strongest.grade}). "
        f"Weakest: {weakest.algorithm} (score={weakest.score}, grade={weakest.grade}). "
        f"Average crack rate: {avg_crack_rate:.1f}%. "
        f"Overall risk: {risk_level}."
    )

    # Global recommendations
    global_recs = []
    weak_algos_found = [s.algorithm for s in scores if s.score < 40]
    if weak_algos_found:
        global_recs.append(
            f"Remove or replace these insecure algorithms immediately: "
            f"{', '.join(weak_algos_found)}"
        )
    global_recs.append("Implement account lockout after 5 failed attempts to defeat online attacks.")
    global_recs.append("Enable breach monitoring (HaveIBeenPwned API) to detect compromised credentials.")
    global_recs.append("Enforce a minimum password length of 12 characters with complexity requirements.")
    if any(s.algorithm == "argon2id" for s in scores):
        global_recs.append("Argon2id detected — ensure PEPPER is configured in production via environment variable.")

    return BreachReport(
        total_algorithms_tested = len(scores),
        strongest_algorithm     = strongest.algorithm,
        weakest_algorithm       = weakest.algorithm,
        algorithm_scores        = sorted_scores,
        overall_risk_level      = risk_level,
        summary                 = summary,
        recommendations         = global_recs,
    )
