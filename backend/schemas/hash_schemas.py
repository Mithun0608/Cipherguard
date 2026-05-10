"""
Pydantic schemas for the hashing API — CipherGuard Phase 2.

Covers:
  - HashRequest / HashResponse         : POST /hash
  - VerifyRequest / VerifyResponse     : POST /verify
  - DatasetRequest / DatasetResponse   : POST /generate-dataset
  - PasswordAnalysisResponse           : password strength data
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional


# ---------------------------------------------------------------------------
# Supported algorithm enum (used for validation)
# ---------------------------------------------------------------------------

VALID_ALGORITHMS = [
    "plaintext", "md5", "sha1", "sha256",
    "salted_sha256", "bcrypt", "argon2id",
]


# ---------------------------------------------------------------------------
# POST /hash
# ---------------------------------------------------------------------------

class HashRequest(BaseModel):
    """Request body for hashing a password."""
    password : str = Field(..., min_length=1, max_length=256,
                           description="Plaintext password to hash")
    algorithm: str = Field(..., description="Hashing algorithm to use",
                           examples=["bcrypt", "argon2id", "md5"])
    pepper   : Optional[str] = Field(None, description="Optional server-side pepper")

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        if v.lower() not in VALID_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm '{v}'. "
                f"Valid options: {', '.join(VALID_ALGORITHMS)}"
            )
        return v.lower()


class HashResponse(BaseModel):
    """Response body returned after hashing."""
    algorithm       : str
    hash_value      : str
    salt            : Optional[str]
    hash_version    : str
    time_to_hash_ms : float
    security_tier   : str   # "weak" | "strong"
    warning         : Optional[str] = None   # shown for weak algorithms


# ---------------------------------------------------------------------------
# POST /verify
# ---------------------------------------------------------------------------

class VerifyRequest(BaseModel):
    """Request body for verifying a password against a stored hash."""
    password    : str = Field(..., min_length=1, max_length=256,
                              description="Plaintext password to verify")
    stored_hash : str = Field(..., description="The hash string to verify against")
    algorithm   : str = Field(..., description="Algorithm that produced the hash")
    salt        : Optional[str] = Field(None,
                              description="Salt used during hashing (if applicable)")
    pepper      : Optional[str] = Field(None, description="Optional server-side pepper")

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        if v.lower() not in VALID_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm '{v}'.")
        return v.lower()


class VerifyResponse(BaseModel):
    """Response body returned after password verification."""
    is_valid    : bool
    algorithm   : str
    message     : str


# ---------------------------------------------------------------------------
# POST /generate-dataset
# ---------------------------------------------------------------------------

class DatasetRequest(BaseModel):
    """Request body for triggering dataset generation."""
    sample_size    : int = Field(
        default=1000, ge=1, le=5000,
        description="Number of passwords to generate (1–5000)"
    )
    algorithms     : Optional[list[str]] = Field(
        default=None,
        description="Algorithms to use (default: all 7)"
    )
    pepper         : Optional[str] = Field(
        default=None,
        description="Optional server-side pepper"
    )
    clear_existing : bool = Field(
        default=False,
        description="Delete existing dataset records before generation"
    )

    @field_validator("algorithms")
    @classmethod
    def validate_algorithms(cls, v):
        if v is None:
            return v
        invalid = [a for a in v if a.lower() not in VALID_ALGORITHMS]
        if invalid:
            raise ValueError(f"Unknown algorithms: {invalid}")
        return [a.lower() for a in v]


class AlgorithmTimingStat(BaseModel):
    avg_ms       : float
    min_ms       : float
    max_ms       : float
    total_hashes : int


class DatasetResponse(BaseModel):
    """Response body returned after dataset generation."""
    status                 : str
    total_passwords        : int
    total_hashes_created   : int
    algorithms_used        : list[str]
    category_distribution  : dict
    timing_stats_ms        : dict[str, AlgorithmTimingStat]


# ---------------------------------------------------------------------------
# Password strength analysis (used inside HashResponse and standalone)
# ---------------------------------------------------------------------------

class PasswordAnalysisResponse(BaseModel):
    """Password strength analysis result."""
    password          : str
    length            : int
    has_uppercase     : bool
    has_lowercase     : bool
    has_digits        : bool
    has_symbols       : bool
    entropy_bits      : float
    strength_score    : int
    strength_category : str
