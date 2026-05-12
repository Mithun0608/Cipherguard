import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.password_hash_model import PasswordHash
from backend.models.attack_result_model import AttackResult
from backend.attacks.attack_registry    import get_attack, ALL_ATTACK_TYPES
from backend.attacks.base_attack        import AttackReport
from backend.logs.attack_logger         import log_attack_run, get_recent_logs
from backend.score_engine.score_calculator import (
    calculate_score,
    generate_breach_report,
    estimate_gpu_crack_time,
)
from backend.schemas.attack_schemas import (
    RunAttackRequest,
    RunAttackResponse,
    AttackResultSummary,
    SecurityScoreResponse,
    AlgorithmScoreOut,
    CrackedPasswordOut,
)
from backend.hashers.hasher_registry import ALL_ALGORITHMS, WEAK_ALGORITHMS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Attack Simulation"])



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_security_interpretation(
    algorithm    : str,
    success_rate : float,
    stopped_early: bool,
    attack_type  : str,
) -> str:
    """
    Return a scientifically accurate interpretation of attack results.

    CRITICAL RULE: Timeout does NOT mean the algorithm is secure.
    Fast algorithms (MD5, SHA1, SHA256) that time out during simulation
    are still highly vulnerable — real GPU hardware is orders of magnitude faster.
    """
    if algorithm == "plaintext":
        return (
            "Plaintext storage provides zero security. "
            "All passwords are immediately exposed upon database compromise. "
            "No cracking effort required — passwords are stored in readable form."
        )

    if stopped_early and success_rate == 0.0:
        algo_msgs = {
            "md5"          : "MD5 remains vulnerable to optimized GPU brute-force attacks despite timeout during this simulation.",
            "sha1"         : "SHA1 is deprecated and vulnerable despite incomplete brute-force execution in this simulation.",
            "sha256"       : "SHA256 is cryptographically strong but insufficient for password hashing without adaptive slowing mechanisms.",
            "salted_sha256": "Salted SHA-256 resists rainbow tables but remains vulnerable to targeted GPU brute force.",
            "bcrypt"       : "bcrypt demonstrated strong resistance due to adaptive computational cost. This is by design, not simulation timeout.",
            "argon2id"     : "Argon2id demonstrated strongest resistance because of memory-hard password hashing. 64MB RAM per attempt makes GPU attacks impractical.",
        }
        base_msg = algo_msgs.get(algorithm, f"{algorithm} resisted this simulation.")
        if algorithm in ("md5", "sha1", "sha256", "salted_sha256"):
            return (
                "Attack terminated before exhaustive search completion. "
                "Result does NOT imply cryptographic security. "
                + base_msg
                + " Real-world GPU hardware performs this attack orders of magnitude faster than this simulation."
            )
        return base_msg

    if success_rate >= 80:
        return (
            f"{algorithm.upper()} offers virtually no protection. "
            f"{success_rate:.1f}% of passwords were recovered in simulation. "
            "Attackers using GPU hardware would crack the entire database within seconds."
        )
    if success_rate >= 30:
        return (
            f"{algorithm} offers limited protection — {success_rate:.1f}% of passwords cracked. "
            "A significant portion of accounts would be compromised in a real breach."
        )
    if success_rate > 0:
        return (
            f"{algorithm} resisted most attacks — only {success_rate:.1f}% of passwords cracked. "
            "Only weak or common passwords were recovered."
        )
    # 0% cracked, not stopped early
    if algorithm in ("bcrypt", "argon2id"):
        algo_msgs = {
            "bcrypt"  : "bcrypt demonstrated strong resistance due to adaptive computational cost.",
            "argon2id": "Argon2id demonstrated strongest resistance because of memory-hard password hashing.",
        }
        return algo_msgs[algorithm]
    return (
        f"No passwords cracked in this simulation, but {algorithm} should not be considered secure. "
        "Real-world GPU hardware is significantly faster than this educational simulation."
    )


def _get_owasp_status(algorithm: str) -> str:
    owasp_recommended = {"argon2id", "bcrypt"}
    owasp_acceptable  = {"salted_sha256"}
    owasp_deprecated  = {"sha256", "sha1", "md5", "plaintext"}
    if algorithm in owasp_recommended:
        return f"✅ OWASP Recommended — {algorithm} is the current top recommendation for password hashing."
    elif algorithm in owasp_acceptable:
        return "⚠️ OWASP Acceptable — salted SHA-256 is a minimum baseline. Upgrade to bcrypt/Argon2id recommended."
    elif algorithm == "sha256":
        return "❌ OWASP Not Recommended — SHA-256 is not designed for password storage (no key stretching)."
    elif algorithm in ("sha1", "md5"):
        return f"🚨 OWASP Forbidden — {algorithm.upper()} is cryptographically broken and must not be used."
    else:
        return "🚨 OWASP Critical — plaintext storage is catastrophically insecure."


def _get_timeout_note(algorithm: str, stopped_early: bool, success_rate: float) -> str:
    if not stopped_early:
        return ""
    if algorithm in ("md5", "sha1", "sha256"):
        return (
            "⚠️ TIMEOUT ≠ SECURE: This simulation timed out before completing the search space. "
            f"{algorithm.upper()} remains highly vulnerable to real GPU hardware "
            "which is 100,000x+ faster than this Python simulation."
        )
    if algorithm == "salted_sha256":
        return (
            "⚠️ TIMEOUT: Salted SHA-256 resists rainbow tables but GPU brute-force remains feasible. "
            "Simulation timeout does not indicate full cryptographic security."
        )
    if algorithm in ("bcrypt", "argon2id"):
        return (
            "✅ Timeout here reflects genuine computational difficulty, not simulation limits. "
            f"{algorithm} is intentionally slow by design to defeat brute-force attacks."
        )
    return "Attack stopped before exhaustive completion."



def _save_result(
    db         : Session,
    report     : AttackReport,
    run_label  : Optional[str],
    score      : Optional[float],
) -> AttackResult:
    """Persist an AttackReport to the attack_results table."""
    record = AttackResult(
        attack_type       = report.attack_type,
        algorithm         = report.algorithm,
        run_label         = run_label,
        target_count      = report.target_count,
        cracked_count     = report.cracked_count,
        success_rate      = report.success_rate_pct,
        total_time_sec    = report.total_time_sec,
        total_attempts    = report.total_attempts,
        attempts_per_sec  = report.attempts_per_sec,
        avg_crack_time_ms = report.avg_crack_time_ms,
        max_crack_time_ms = report.max_crack_time_ms,
        wordlist_size     = report.wordlist_size,
        stopped_early     = report.stopped_early,
        notes             = report.notes,
        security_score    = score,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


# ---------------------------------------------------------------------------
# POST /run-attack
# ---------------------------------------------------------------------------

@router.post(
    "/run-attack",
    response_model=RunAttackResponse,
    summary="Run a password attack simulation",
    description=(
        "Simulates a real-world password attack against hashed passwords in the dataset. "
        "Returns crack rate, timing, and security analysis. "
        "**NOTE:** bcrypt and Argon2id attacks are intentionally slow."
    ),
)
def run_attack(
    request: RunAttackRequest,
    db     : Session = Depends(get_db),
):
    """
    Execute one attack type against stored hashes for a given algorithm.

    - **attack_type**: dictionary | brute_force | rainbow_table | hybrid
    - **algorithm**: Any of the 7 supported algorithms
    - **target_limit**: How many stored hashes to attack (default 50)
    - **max_attempts**: Computation cap (default 50,000)
    - **timeout_sec**: Hard time limit in seconds (default 30)
    """
    # Fetch targets from DB
    targets = (
        db.query(PasswordHash)
        .filter(PasswordHash.algorithm == request.algorithm)
        .limit(request.target_limit)
        .all()
    )

    if not targets:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No password hashes found for algorithm '{request.algorithm}'. "
                "Run POST /api/v1/generate-dataset first to populate the dataset."
            ),
        )

    run_id = str(uuid.uuid4())
    logger.info(
        f"[AttackAPI] run_id={run_id} | "
        f"attack={request.attack_type} | algo={request.algorithm} | "
        f"targets={len(targets)}"
    )

    # Execute attack
    try:
        attacker = get_attack(request.attack_type)
        # Pass demo_mode to brute force for educational short-password cracking
        if request.attack_type == "brute_force":
            report = attacker.run(
                targets      = targets,
                algorithm    = request.algorithm,
                max_attempts = request.max_attempts,
                timeout_sec  = request.timeout_sec,
                demo_mode    = request.demo_mode,
            )
        else:
            report = attacker.run(
                targets      = targets,
                algorithm    = request.algorithm,
                max_attempts = request.max_attempts,
                timeout_sec  = request.timeout_sec,
            )
    except Exception as e:
        logger.error(f"[AttackAPI] Attack failed: {e}")
        raise HTTPException(status_code=500, detail=f"Attack execution failed: {str(e)}")

    # Build response enrichment
    interpretation  = _get_security_interpretation(
        request.algorithm, report.success_rate_pct, report.stopped_early, report.attack_type
    )
    owasp_status    = _get_owasp_status(request.algorithm)
    timeout_note    = _get_timeout_note(request.algorithm, report.stopped_early, report.success_rate_pct)

    # Search space estimation for brute force
    search_space_info = ""
    gpu_crack_est     = ""
    if request.attack_type == "brute_force":
        charset_size   = 36  # default lower+digits
        max_len        = 5
        space          = sum(charset_size ** l for l in range(1, max_len + 1))
        search_space_info = f"{charset_size}^{max_len} search space ≈ {space:,} combinations (lower+digits, len 1-{max_len})"
        gpu_crack_est  = estimate_gpu_crack_time(request.algorithm, space)
    elif request.attack_type == "rainbow_table":
        search_space_info = f"Precomputed table: {report.wordlist_size:,} hash→plaintext entries"
        gpu_crack_est  = "O(1) lookup — instant after table is built"


    # Persist to DB
    saved_to_db = False
    if request.save_to_db:
        try:
            algo_score = calculate_score(request.algorithm, [report])
            _save_result(db, report, request.run_label, float(algo_score.score))
            saved_to_db = True
        except Exception as e:
            logger.warning(f"[AttackAPI] DB save failed: {e}")


    # Write JSON log
    config = {
        "max_attempts" : request.max_attempts,
        "timeout_sec"  : request.timeout_sec,
        "target_limit" : request.target_limit,
        "target_count" : len(targets),
    }
    log_attack_run(report, config, run_id)

    # Build response
    cracked_sample = [
        CrackedPasswordOut(
            record_id      = c.record_id,
            plain_password = c.plain_password,
            crack_time_ms  = c.crack_time_ms,
            attempt_number = c.attempt_number,
        )
        for c in report.cracked_passwords[:10]
    ]

    return RunAttackResponse(
        run_id               = run_id,
        attack_type          = report.attack_type,
        algorithm            = report.algorithm,
        target_count         = report.target_count,
        cracked_count        = report.cracked_count,
        success_rate_pct     = report.success_rate_pct,
        total_time_sec       = report.total_time_sec,
        total_attempts       = report.total_attempts,
        attempts_per_sec     = report.attempts_per_sec,
        avg_crack_time_ms    = report.avg_crack_time_ms,
        max_crack_time_ms    = report.max_crack_time_ms,
        wordlist_size        = report.wordlist_size,
        stopped_early        = report.stopped_early,
        notes                = report.notes,
        cracked_sample       = cracked_sample,
        security_tier_note   = interpretation,
        saved_to_db          = saved_to_db,
        attack_interpretation= interpretation,
        search_space_info    = search_space_info,
        gpu_crack_estimate   = gpu_crack_est,
        owasp_status         = owasp_status,
        timeout_note         = timeout_note,
    )


# ---------------------------------------------------------------------------
# GET /attack-results
# ---------------------------------------------------------------------------

@router.get(
    "/attack-results",
    summary="List attack simulation results",
    description="Returns stored attack run results from the database, optionally filtered by algorithm or attack type.",
)
def get_attack_results(
    algorithm  : Optional[str] = Query(None, description="Filter by algorithm"),
    attack_type: Optional[str] = Query(None, description="Filter by attack type"),
    limit      : int           = Query(50, ge=1, le=500, description="Max records to return"),
    db         : Session       = Depends(get_db),
):
    """
    Retrieve stored attack results.

    Optional filters:
    - **algorithm**: e.g. `md5`, `bcrypt`
    - **attack_type**: e.g. `dictionary`, `rainbow_table`
    - **limit**: Number of results (default 50)
    """
    query = db.query(AttackResult)
    if algorithm:
        query = query.filter(AttackResult.algorithm == algorithm.lower())
    if attack_type:
        query = query.filter(AttackResult.attack_type == attack_type.lower())

    results = query.order_by(AttackResult.created_at.desc()).limit(limit).all()

    return {
        "total"  : len(results),
        "filters": {"algorithm": algorithm, "attack_type": attack_type},
        "results": [
            {
                "id"              : r.id,
                "attack_type"     : r.attack_type,
                "algorithm"       : r.algorithm,
                "run_label"       : r.run_label,
                "target_count"    : r.target_count,
                "cracked_count"   : r.cracked_count,
                "success_rate_pct": r.success_rate,
                "total_time_sec"  : r.total_time_sec,
                "attempts_per_sec": r.attempts_per_sec,
                "security_score"  : r.security_score,
                "stopped_early"   : r.stopped_early,
                "notes"           : r.notes,
                "created_at"      : r.created_at.isoformat() if r.created_at else None,
            }
            for r in results
        ],
    }


# ---------------------------------------------------------------------------
# GET /security-score
# ---------------------------------------------------------------------------

@router.get(
    "/security-score",
    response_model=SecurityScoreResponse,
    summary="Compute security scores for all algorithms",
    description=(
        "Calculates 0-100 security scores based on stored attack results. "
        "Returns a full breach analysis report with rankings and recommendations."
    ),
)
def get_security_score(
    db: Session = Depends(get_db),
):
    """
    Compute and return comparative security scores for all algorithms.

    Scores are calculated from attack results stored in the database.
    Algorithms with no stored results use property-based baseline scores.
    """
    # Fetch all stored results
    all_results = db.query(AttackResult).all()

    # Group reports by algorithm
    from collections import defaultdict
    from backend.attacks.base_attack import AttackReport as AR, CrackedPassword as CP

    results_by_algo: dict[str, list] = defaultdict(list)
    for row in all_results:
        # Reconstruct a lightweight AttackReport from DB row for scoring
        pseudo_report = AR(
            attack_type       = row.attack_type,
            algorithm         = row.algorithm,
            target_count      = row.target_count,
            cracked_count     = row.cracked_count,
            success_rate_pct  = row.success_rate,
            total_time_sec    = row.total_time_sec or 0.0,
            total_attempts    = row.total_attempts or 0,
            attempts_per_sec  = row.attempts_per_sec or 0.0,
            avg_crack_time_ms = row.avg_crack_time_ms or 0.0,
            max_crack_time_ms = row.max_crack_time_ms or 0.0,
            wordlist_size     = row.wordlist_size or 0,
            stopped_early     = row.stopped_early or False,
            notes             = row.notes or "",
        )
        results_by_algo[row.algorithm].append(pseudo_report)

    # Calculate score for every known algorithm
    scores = []
    for algo in ALL_ALGORITHMS:
        algo_reports = results_by_algo.get(algo, [])
        score = calculate_score(algo, algo_reports)
        scores.append(score)

    breach = generate_breach_report(scores)

    return SecurityScoreResponse(
        total_algorithms_tested = breach.total_algorithms_tested,
        strongest_algorithm     = breach.strongest_algorithm,
        weakest_algorithm       = breach.weakest_algorithm,
        overall_risk_level      = breach.overall_risk_level,
        summary                 = breach.summary,
        recommendations         = breach.recommendations,
        algorithm_scores        = [
            AlgorithmScoreOut(
                algorithm        = s.algorithm,
                score            = s.score,
                grade            = s.grade,
                tier             = s.tier,
                crack_rate_pct   = s.crack_rate_pct,
                avg_time_sec     = s.avg_time_sec,
                is_salted        = s.is_salted,
                is_memory_hard   = s.is_memory_hard,
                recommendations  = s.recommendations,
                attack_breakdown = s.attack_breakdown,
            )
            for s in breach.algorithm_scores
        ],
    )


# ---------------------------------------------------------------------------
# POST /benchmark
# ---------------------------------------------------------------------------

@router.post(
    "/benchmark",
    summary="Run full benchmark: all attacks x selected algorithms",
    description=(
        "Runs all 4 attack types against a set of algorithms and returns a "
        "comparative security report. "
        "WARNING: This may take several minutes due to bcrypt/Argon2id slowness."
    ),
)
def run_benchmark(
    payload: dict,
    db     : Session = Depends(get_db),
):
    """
    Run all 4 attacks against specified algorithms (default: weak algorithms only).

    Request body example:
    ```json
    {
      "algorithms": ["md5", "sha1", "salted_sha256"],
      "target_limit": 20,
      "max_attempts": 20000,
      "timeout_sec": 15.0
    }
    ```

    **TIP**: Exclude bcrypt/argon2id or set a low timeout to keep this fast.
    """
    algorithms   = payload.get("algorithms", ["md5", "sha1", "sha256", "salted_sha256"])
    target_limit = int(payload.get("target_limit", 20))
    max_attempts = int(payload.get("max_attempts", 20_000))
    timeout_sec  = float(payload.get("timeout_sec", 15.0))

    invalid = [a for a in algorithms if a not in ALL_ALGORITHMS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown algorithms: {invalid}")

    benchmark_results = []
    all_reports_by_algo: dict[str, list] = {}

    for algo in algorithms:
        targets = (
            db.query(PasswordHash)
            .filter(PasswordHash.algorithm == algo)
            .limit(target_limit)
            .all()
        )
        if not targets:
            benchmark_results.append({
                "algorithm": algo,
                "error": "No dataset records found. Run /generate-dataset first."
            })
            continue

        algo_reports = []
        algo_attacks  = {}

        for attack_type in ALL_ATTACK_TYPES:
            try:
                attacker = get_attack(attack_type)
                report   = attacker.run(
                    targets      = targets,
                    algorithm    = algo,
                    max_attempts = max_attempts,
                    timeout_sec  = timeout_sec,
                )
                algo_reports.append(report)
                algo_attacks[attack_type] = {
                    "cracked_count"   : report.cracked_count,
                    "success_rate_pct": report.success_rate_pct,
                    "attempts_per_sec": report.attempts_per_sec,
                    "total_time_sec"  : report.total_time_sec,
                }
                # Persist to DB
                _save_result(db, report, "benchmark", None)
                # Log to JSON
                log_attack_run(report, {
                    "benchmark": True,
                    "target_limit": target_limit,
                    "max_attempts": max_attempts,
                    "timeout_sec": timeout_sec,
                }, run_id=str(uuid.uuid4()))

            except Exception as e:
                algo_attacks[attack_type] = {"error": str(e)}
                logger.error(f"[Benchmark] {algo}/{attack_type}: {e}")

        # Score this algorithm
        score = calculate_score(algo, algo_reports)
        all_reports_by_algo[algo] = algo_reports

        benchmark_results.append({
            "algorithm"   : algo,
            "score"       : score.score,
            "grade"       : score.grade,
            "tier"        : score.tier,
            "crack_rate"  : score.crack_rate_pct,
            "is_salted"   : score.is_salted,
            "is_memory_hard": score.is_memory_hard,
            "attacks"     : algo_attacks,
        })

    # Generate breach report
    all_scores = []
    for algo in algorithms:
        reports = all_reports_by_algo.get(algo, [])
        all_scores.append(calculate_score(algo, reports))
    breach = generate_breach_report(all_scores)

    return {
        "benchmark_summary": {
            "algorithms_tested"  : algorithms,
            "attack_types_used"  : ALL_ATTACK_TYPES,
            "target_limit"       : target_limit,
            "strongest_algorithm": breach.strongest_algorithm,
            "weakest_algorithm"  : breach.weakest_algorithm,
            "overall_risk_level" : breach.overall_risk_level,
            "summary"            : breach.summary,
        },
        "per_algorithm" : benchmark_results,
        "recommendations": breach.recommendations,
    }


# ---------------------------------------------------------------------------
# GET /attack-logs
# ---------------------------------------------------------------------------

@router.get(
    "/attack-logs",
    summary="List recent attack JSON logs",
    description="Returns the most recent structured JSON attack log files.",
)
def get_attack_logs(
    limit: int = Query(10, ge=1, le=50),
):
    """
    Retrieve recent JSON attack logs from disk.

    Returns up to `limit` most recent log files (newest first).
    """
    logs = get_recent_logs(limit=limit)
    return {
        "total" : len(logs),
        "logs"  : logs,
    }
