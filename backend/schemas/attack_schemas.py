"""
Attack API Schemas - CipherGuard Phase 3

Pydantic v2 models for:
  - POST /run-attack
  - GET  /attack-results
  - GET  /security-score
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional

VALID_ATTACK_TYPES = ["dictionary", "brute_force", "rainbow_table", "hybrid"]
VALID_ALGORITHMS   = [
    "plaintext", "md5", "sha1", "sha256",
    "salted_sha256", "bcrypt", "argon2id",
]


# ---------------------------------------------------------------------------
# POST /run-attack
# ---------------------------------------------------------------------------

class RunAttackRequest(BaseModel):
    """Request body to trigger an attack simulation."""

    attack_type : str = Field(
        ...,
        description="Attack type to run",
        examples=["dictionary", "brute_force", "rainbow_table", "hybrid"],
    )
    algorithm   : str = Field(
        ...,
        description="Hashing algorithm to attack",
        examples=["md5", "bcrypt"],
    )
    max_attempts: int = Field(
        default=50_000,
        ge=100, le=500_000,
        description="Maximum hash comparison attempts",
    )
    timeout_sec : float = Field(
        default=30.0,
        ge=1.0, le=300.0,
        description="Wall-clock timeout in seconds",
    )
    target_limit: int = Field(
        default=50,
        ge=1, le=500,
        description="Max number of hashes to attack from the dataset",
    )
    run_label   : Optional[str] = Field(
        default=None,
        description="Optional label for this run (e.g. 'benchmark_v1')",
    )
    save_to_db  : bool = Field(
        default=True,
        description="Persist result to attack_results table",
    )

    @field_validator("attack_type")
    @classmethod
    def validate_attack(cls, v: str) -> str:
        if v.lower() not in VALID_ATTACK_TYPES:
            raise ValueError(
                f"Unknown attack type '{v}'. "
                f"Valid: {', '.join(VALID_ATTACK_TYPES)}"
            )
        return v.lower()

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        if v.lower() not in VALID_ALGORITHMS:
            raise ValueError(f"Unknown algorithm '{v}'.")
        return v.lower()


class CrackedPasswordOut(BaseModel):
    """Serialized cracked password entry."""
    record_id      : int
    plain_password : str
    crack_time_ms  : float
    attempt_number : int


class AttackBreakdownItem(BaseModel):
    success_rate_pct : float
    attempts_per_sec : float
    cracked_count    : int
    total_time_sec   : float


class RunAttackResponse(BaseModel):
    """Response body returned after attack simulation."""
    run_id             : str
    attack_type        : str
    algorithm          : str
    target_count       : int
    cracked_count      : int
    success_rate_pct   : float
    total_time_sec     : float
    total_attempts     : int
    attempts_per_sec   : float
    avg_crack_time_ms  : float
    max_crack_time_ms  : float
    wordlist_size      : int
    stopped_early      : bool
    notes              : str
    cracked_sample     : list[CrackedPasswordOut]
    security_tier_note : str   # narrative about why this algorithm succeeded/failed
    saved_to_db        : bool


# ---------------------------------------------------------------------------
# GET /attack-results
# ---------------------------------------------------------------------------

class AttackResultSummary(BaseModel):
    """Summary of a stored attack result row."""
    id               : int
    attack_type      : str
    algorithm        : str
    target_count     : int
    cracked_count    : int
    success_rate     : float
    total_time_sec   : Optional[float]
    attempts_per_sec : Optional[float]
    security_score   : Optional[float]
    stopped_early    : Optional[bool]
    notes            : Optional[str]
    created_at       : str

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# GET /security-score
# ---------------------------------------------------------------------------

class AlgorithmScoreOut(BaseModel):
    """Serialized AlgorithmScore for API response."""
    algorithm       : str
    score           : int
    grade           : str
    tier            : str
    crack_rate_pct  : float
    avg_time_sec    : float
    is_salted       : bool
    is_memory_hard  : bool
    recommendations : list[str]
    attack_breakdown: dict


class SecurityScoreResponse(BaseModel):
    """Response for GET /security-score."""
    total_algorithms_tested : int
    strongest_algorithm     : str
    weakest_algorithm       : str
    overall_risk_level      : str
    summary                 : str
    recommendations         : list[str]
    algorithm_scores        : list[AlgorithmScoreOut]
