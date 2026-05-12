"""
Security Score Engine - CipherGuard Phase 3 (Fixed)

Calculates a 0-100 security score for each hashing algorithm based on
real-world cryptographic properties AND attack simulation results.

Scoring philosophy (CORRECTED):
  - Algorithm properties define a FLOOR and CEILING for each algorithm.
    No amount of "lucky" simulation can make MD5 score above 25.
    No amount of "unlucky" timeout can make Argon2id score below 90.
  - Within the floor/ceiling range, actual performance matters.
  - Timeout ≠ secure: a fast algorithm that times out still gets
    penalized by its speed factor (high attempts/sec = bad design).

Correct score ranges:
  Argon2id     : 90-100  (memory-hard, OWASP #1 recommendation)
  bcrypt       : 80-90   (adaptive, slow-by-design)
  Salted SHA256: 65-80   (salted, but still fast)
  SHA256       : 50-65   (strong crypto, but fast & unsalted)
  SHA1         : 25-45   (deprecated, collision-vulnerable)
  MD5          : 10-25   (broken, extremely fast, rainbow tables)
  Plaintext    : 0-5     (zero protection, instantly exposed)
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from backend.attacks.base_attack import AttackReport
from backend.utils.attack_utils import estimate_search_space, estimate_gpu_crack_time

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Algorithm properties with scientifically correct score bounds
# ---------------------------------------------------------------------------

ALGORITHM_PROPERTIES = {
    "plaintext": {
        "salted": False, "memory_hard": False, "adaptive": False,
        "speed_class": "instant",
        "score_floor": 0,   "score_ceiling": 5,
        "baseline_crack_rate": 100.0,
        "owasp_recommended": False,
        "gpu_resistance": "none",
        "real_world_note": (
            "Plaintext storage provides zero security. "
            "All passwords are immediately exposed upon database compromise."
        ),
    },
    "md5": {
        "salted": False, "memory_hard": False, "adaptive": False,
        "speed_class": "fast",
        "score_floor": 10,  "score_ceiling": 25,
        "baseline_crack_rate": 95.0,
        "owasp_recommended": False,
        "gpu_resistance": "none",
        "real_world_note": (
            "MD5 is cryptographically broken. Collision attacks are trivial. "
            "GPU clusters compute >10 billion MD5 hashes/sec. "
            "MD5 remains vulnerable to optimized GPU brute-force attacks."
        ),
    },
    "sha1": {
        "salted": False, "memory_hard": False, "adaptive": False,
        "speed_class": "fast",
        "score_floor": 25,  "score_ceiling": 45,
        "baseline_crack_rate": 90.0,
        "owasp_recommended": False,
        "gpu_resistance": "none",
        "real_world_note": (
            "SHA-1 was deprecated by NIST in 2011. Practical collision attacks exist (SHAttered, 2017). "
            "SHA1 is deprecated and vulnerable despite incomplete brute-force execution in simulation."
        ),
    },
    "sha256": {
        "salted": False, "memory_hard": False, "adaptive": False,
        "speed_class": "fast",
        "score_floor": 50,  "score_ceiling": 65,
        "baseline_crack_rate": 85.0,
        "owasp_recommended": False,
        "gpu_resistance": "low",
        "real_world_note": (
            "SHA-256 is cryptographically strong but was NOT designed for password hashing. "
            "Without salting or key-stretching, GPU hardware can compute ~10B SHA-256 hashes/sec. "
            "SHA256 is cryptographically strong but insufficient for password hashing "
            "without adaptive slowing mechanisms."
        ),
    },
    "salted_sha256": {
        "salted": True,  "memory_hard": False, "adaptive": False,
        "speed_class": "fast",
        "score_floor": 65,  "score_ceiling": 80,
        "baseline_crack_rate": 40.0,
        "owasp_recommended": False,
        "gpu_resistance": "moderate",
        "real_world_note": (
            "Salted SHA-256 defeats rainbow-table attacks but remains vulnerable to GPU brute force. "
            "Each password gets a unique hash, but the algorithm is still too fast for password storage. "
            "Upgrade to bcrypt or Argon2id for production use."
        ),
    },
    "bcrypt": {
        "salted": True,  "memory_hard": False, "adaptive": True,
        "speed_class": "slow",
        "score_floor": 80,  "score_ceiling": 90,
        "baseline_crack_rate": 2.0,
        "owasp_recommended": True,
        "gpu_resistance": "high",
        "real_world_note": (
            "bcrypt demonstrated strong resistance due to adaptive computational cost. "
            "At cost factor 12: ~100-200ms per hash. GPU clusters are limited to ~100 bcrypt/sec. "
            "Increase cost factor as hardware improves."
        ),
    },
    "argon2id": {
        "salted": True,  "memory_hard": True,  "adaptive": True,
        "speed_class": "slow",
        "score_floor": 90,  "score_ceiling": 100,
        "baseline_crack_rate": 0.0,
        "owasp_recommended": True,
        "gpu_resistance": "maximum",
        "real_world_note": (
            "Argon2id demonstrated strongest resistance because of memory-hard password hashing. "
            "Winner of the 2015 Password Hashing Competition. "
            "OWASP #1 recommendation. Requires 64MB RAM per attempt — GPU farms impractical."
        ),
    },
}

# Correct security ranking (strongest to weakest)
ALGORITHM_SECURITY_RANK = [
    "argon2id", "bcrypt", "salted_sha256", "sha256", "sha1", "md5", "plaintext"
]


# ---------------------------------------------------------------------------
# Score result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AlgorithmScore:
    """Security score and breakdown for one algorithm."""
    algorithm        : str
    score            : int              # 0-100
    grade            : str              # A/B/C/D/F
    tier             : str              # weak/moderate/strong
    crack_rate_pct   : float
    avg_time_sec     : float
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
# Core scoring helpers
# ---------------------------------------------------------------------------

def _grade(score: int) -> str:
    if score >= 90: return "A+"
    elif score >= 80: return "A"
    elif score >= 70: return "B"
    elif score >= 55: return "C"
    elif score >= 35: return "D"
    else: return "F"


def _tier(score: int) -> str:
    """Tier based purely on score thresholds — no hardcoded string matching."""
    if score >= 70:
        return "strong"
    elif score >= 45:
        return "moderate"
    else:
        return "weak"


def _speed_factor(avg_attempts_per_sec: float) -> float:
    """
    Normalize speed to 0.0 (very fast = bad) → 1.0 (very slow = good).
    Based on realistic hash rates:
      <5/sec    = bcrypt/argon2id territory (excellent)
      5-100/sec = salted/slow (acceptable)
      >10k/sec  = fast hash (dangerous)
      >1M/sec   = very fast (critical)
    """
    if avg_attempts_per_sec < 5:
        return 1.0
    elif avg_attempts_per_sec < 50:
        return 0.8
    elif avg_attempts_per_sec < 1_000:
        return 0.5
    elif avg_attempts_per_sec < 10_000:
        return 0.2
    elif avg_attempts_per_sec < 100_000:
        return 0.05
    else:
        return 0.0


# ---------------------------------------------------------------------------
# Main score calculator
# ---------------------------------------------------------------------------

def calculate_score(
    algorithm : str,
    reports   : list[AttackReport],
) -> AlgorithmScore:
    """
    Calculate security score for one algorithm from its attack reports.

    Uses property-based floor/ceiling bounds so known-weak algorithms
    (MD5, SHA1, plaintext) can NEVER score above their cryptographic ceiling
    regardless of simulation timeout — and strong algorithms (bcrypt, Argon2id)
    always score within their known-strong range.

    Within the floor-ceiling range, actual attack performance determines
    where the score falls.

    Args:
        algorithm : Algorithm name
        reports   : All AttackReport objects for this algorithm

    Returns:
        AlgorithmScore with full breakdown
    """
    props = ALGORITHM_PROPERTIES.get(algorithm, {
        "salted": False, "memory_hard": False, "adaptive": False,
        "speed_class": "fast", "score_floor": 10, "score_ceiling": 30,
        "baseline_crack_rate": 80.0, "owasp_recommended": False,
    })

    floor   = props["score_floor"]
    ceiling = props["score_ceiling"]
    rng     = ceiling - floor  # score range within bounds

    if not reports:
        # No attack data: use midpoint of the algorithm's known score range
        baseline_score = (floor + ceiling) // 2
        baseline_crack  = props.get("baseline_crack_rate", 0.0)
        return AlgorithmScore(
            algorithm       = algorithm,
            score           = baseline_score,
            grade           = _grade(baseline_score),
            tier            = _tier(baseline_score),
            crack_rate_pct  = baseline_crack,
            avg_time_sec    = 0.0,
            is_salted       = props["salted"],
            is_memory_hard  = props["memory_hard"],
            recommendations = _build_recommendations(algorithm, baseline_score, baseline_crack),
            attack_breakdown= {},
        )

    # --- Aggregate attack metrics ---
    avg_success_rate     = sum(r.success_rate_pct for r in reports) / len(reports)
    avg_attempts_per_sec = sum(r.attempts_per_sec for r in reports) / len(reports)
    avg_time             = sum(r.total_time_sec for r in reports) / len(reports)

    # Crack resistance: 0 = all cracked, 1 = none cracked
    crack_factor = 1.0 - (avg_success_rate / 100.0)

    # Speed factor: slow hash = good, fast hash = bad
    speed = _speed_factor(avg_attempts_per_sec)

    # Weighted performance score within the algorithm's range
    # crack_factor dominates (60%) — if algorithm is cracked, it's bad
    # speed factor matters (40%) — fast algorithms remain dangerous even if not cracked in simulation
    perf_ratio  = (crack_factor * 0.60) + (speed * 0.40)
    raw_score   = floor + (perf_ratio * rng)
    final_score = max(floor, min(ceiling, int(round(raw_score))))

    # Per-attack-type breakdown
    breakdown = {
        r.attack_type: {
            "success_rate_pct": r.success_rate_pct,
            "attempts_per_sec": r.attempts_per_sec,
            "cracked_count"   : r.cracked_count,
            "total_time_sec"  : r.total_time_sec,
            "stopped_early"   : r.stopped_early,
        }
        for r in reports
    }

    return AlgorithmScore(
        algorithm       = algorithm,
        score           = final_score,
        grade           = _grade(final_score),
        tier            = _tier(final_score),
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
    props = ALGORITHM_PROPERTIES.get(algorithm, {})

    if algorithm == "plaintext":
        recs.append("CRITICAL: Plaintext storage provides ZERO security. Migrate to Argon2id immediately.")
        recs.append("A single database breach instantly exposes every user password in the system.")
    elif algorithm == "md5":
        recs.append("CRITICAL: MD5 is cryptographically broken. Collision attacks are trivial.")
        recs.append("Migrate to bcrypt (cost=12) or Argon2id immediately. MD5 is not safe for any security use.")
    elif algorithm == "sha1":
        recs.append("SHA-1 was deprecated by NIST in 2011. Practical collision attacks exist (SHAttered 2017).")
        recs.append("Migrate to bcrypt or Argon2id. SHA-1 provides no meaningful password protection.")
    elif algorithm == "sha256":
        recs.append("SHA-256 is cryptographically strong as a general hash but was NOT designed for passwords.")
        recs.append("Without key-stretching, GPU hardware cracks SHA-256 at ~10 billion hashes/sec.")
        recs.append("Use salted_sha256 as a minimum, or better: migrate to bcrypt or Argon2id.")
    elif algorithm == "salted_sha256":
        recs.append("Salted SHA-256 defeats rainbow-table attacks, but SHA-256 is still fast for GPUs.")
        recs.append("Consider upgrading to bcrypt (cost=12) or Argon2id for stronger brute-force resistance.")
    elif algorithm == "bcrypt":
        recs.append("bcrypt is OWASP-recommended. Ensure cost factor >= 12 (doubles time per +1).")
        recs.append("Monitor login time: if hashing takes < 100ms, increase the cost factor.")
    elif algorithm == "argon2id":
        recs.append("Argon2id is the OWASP #1 recommendation for password hashing (2024).")
        recs.append("Ensure memory_cost >= 64MB and time_cost >= 3 in production configuration.")

    if crack_rate > 50:
        recs.append(
            f"ALERT: {crack_rate:.0f}% of passwords were cracked in simulation. "
            "Immediate algorithm migration required."
        )

    if not props.get("owasp_recommended") and algorithm not in ("argon2id", "bcrypt"):
        recs.append(f"{algorithm} is NOT OWASP-recommended for password storage.")

    return recs


def get_attack_interpretation(
    algorithm    : str,
    success_rate : float,
    stopped_early: bool,
    attack_type  : str,
) -> str:
    """
    Return a scientifically accurate interpretation of attack results.

    CRITICAL RULE: Timeout does NOT mean the algorithm is secure.
    Fast algorithms (MD5, SHA1, SHA256) that timeout are still vulnerable —
    the simulation simply ran out of time before cracking everything.
    """
    props = ALGORITHM_PROPERTIES.get(algorithm, {})

    if algorithm == "plaintext":
        return (
            "Plaintext storage provides zero security. "
            "All passwords are immediately exposed upon database compromise. "
            "No cracking effort is required — passwords are stored in readable form."
        )

    if stopped_early and success_rate == 0:
        # Timeout with no cracks — must explain this correctly per algorithm
        if algorithm in ("md5", "sha1", "sha256"):
            algo_note = {
                "md5"   : "MD5 remains vulnerable to optimized GPU brute-force attacks despite timeout during this simulation.",
                "sha1"  : "SHA1 is deprecated and vulnerable despite incomplete brute-force execution in this simulation.",
                "sha256": "SHA256 is cryptographically strong but insufficient for password hashing without adaptive slowing mechanisms.",
            }[algorithm]
            return (
                f"Attack terminated before exhaustive search completion. "
                f"Result does NOT imply cryptographic security. "
                f"{algo_note} "
                f"Real-world GPU hardware can perform this attack orders of magnitude faster."
            )
        elif algorithm == "salted_sha256":
            return (
                "Attack terminated before completion. "
                "Salted SHA-256 resists rainbow tables but remains vulnerable to targeted GPU brute force. "
                "The salt prevents precomputed lookup, but SHA-256 speed is still a concern."
            )
        elif algorithm == "bcrypt":
            return (
                "bcrypt demonstrated strong resistance due to adaptive computational cost. "
                "At cost factor 12, ~100-200ms per hash limits attackers to <100 attempts/sec. "
                "This resistance is by design — not simulation timeout."
            )
        elif algorithm == "argon2id":
            return (
                "Argon2id demonstrated strongest resistance because of memory-hard password hashing. "
                "64MB RAM required per attempt makes GPU/ASIC attacks physically impractical. "
                "This is the OWASP #1 recommended algorithm for 2024."
            )

    if success_rate >= 80:
        return (
            f"{algorithm.upper()} offers virtually no protection. "
            f"{success_rate:.1f}% of passwords were recovered. "
            f"{props.get('real_world_note', '')}"
        )

    if success_rate >= 30:
        return (
            f"{algorithm} offers limited protection — {success_rate:.1f}% of passwords were cracked. "
            "A significant portion of accounts would be compromised in a real breach. "
            "Consider migrating to bcrypt or Argon2id."
        )

    if success_rate > 0:
        return (
            f"{algorithm} resisted most attacks — only {success_rate:.1f}% of passwords cracked. "
            "Weak or common passwords remain vulnerable. Strong unique passwords are safer here."
        )

    # 0% cracked, not stopped early = algorithm actually resisted
    if algorithm in ("bcrypt", "argon2id", "salted_sha256"):
        return props.get("real_world_note", f"{algorithm} resisted all simulated attacks.")

    # Shouldn't reach here for weak algos, but handle it
    return (
        f"No passwords were cracked in this simulation, but {algorithm} is NOT cryptographically secure. "
        "Real-world GPU hardware would crack these hashes significantly faster than this simulation."
    )


# ---------------------------------------------------------------------------
# Search space and GPU time estimators are in backend.utils.attack_utils
# Re-exported here for backward compatibility with other modules
# ---------------------------------------------------------------------------
# estimate_search_space, estimate_gpu_crack_time already imported above


# ---------------------------------------------------------------------------
# Breach analysis report generator
# ---------------------------------------------------------------------------

def generate_breach_report(
    scores: list[AlgorithmScore],
) -> BreachReport:
    """
    Generate a comparative breach analysis report from AlgorithmScore objects.
    Sorts algorithms by their cryptographic security rank, not just simulation score.
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

    # Overall risk driven by the weakest algorithm
    weakest_score = weakest.score
    if weakest_score < 10:
        risk_level = "CRITICAL"
    elif weakest_score < 30:
        risk_level = "HIGH"
    elif weakest_score < 65:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    avg_crack_rate = sum(s.crack_rate_pct for s in scores) / len(scores)

    summary = (
        f"Analyzed {len(scores)} algorithms. "
        f"Most secure: {strongest.algorithm} (score={strongest.score}, grade={strongest.grade}). "
        f"Most vulnerable: {weakest.algorithm} (score={weakest.score}, grade={weakest.grade}). "
        f"Average simulated crack rate: {avg_crack_rate:.1f}%. "
        f"Overall system risk: {risk_level}. "
        f"NOTE: Timeout ≠ security. Weak algorithms remain vulnerable regardless of simulation limits."
    )

    global_recs = []
    weak_algos = [s.algorithm for s in scores if s.score < 45]
    if weak_algos:
        global_recs.append(
            f"CRITICAL: Remove or replace these insecure algorithms immediately: "
            f"{', '.join(a.upper() for a in weak_algos)}"
        )
    if any(s.algorithm == "plaintext" for s in scores):
        global_recs.append(
            "CRITICAL: Plaintext password storage detected. "
            "This is catastrophic — all passwords are instantly exposed in any breach."
        )
    global_recs.append(
        "Migration path: plaintext → MD5 → SHA1 → SHA256 → salted_sha256 → bcrypt → Argon2id (target)."
    )
    global_recs.append("Implement account lockout after 5 failed attempts to defeat online attacks.")
    global_recs.append("Enable breach monitoring (HaveIBeenPwned API) to detect compromised credentials.")
    global_recs.append("Enforce minimum password length of 12+ characters with complexity requirements.")
    if any(s.algorithm == "argon2id" for s in scores):
        global_recs.append(
            "Argon2id detected — ensure memory_cost >= 64MB and PEPPER is set in production environment."
        )

    return BreachReport(
        total_algorithms_tested = len(scores),
        strongest_algorithm     = strongest.algorithm,
        weakest_algorithm       = weakest.algorithm,
        algorithm_scores        = sorted_scores,
        overall_risk_level      = risk_level,
        summary                 = summary,
        recommendations         = global_recs,
    )
