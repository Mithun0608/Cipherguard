"""
Hashing API Routes — CipherGuard Phase 2

Endpoints:
  POST /hash              — Hash a password with a chosen algorithm
  POST /verify            — Verify a password against a stored hash
  POST /generate-dataset  — Generate the full 1000×7 hashed password dataset
  GET  /algorithms        — List all supported algorithms
  POST /analyze           — Analyze password strength without hashing

All endpoints return JSON responses with detailed metadata.
"""

import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.hashers.hasher_registry import (
    get_hasher,
    HASHER_REGISTRY,
    WEAK_ALGORITHMS,
    STRONG_ALGORITHMS,
    ALL_ALGORITHMS,
)
from backend.schemas.hash_schemas import (
    HashRequest,
    HashResponse,
    VerifyRequest,
    VerifyResponse,
    DatasetRequest,
    DatasetResponse,
    PasswordAnalysisResponse,
)
from backend.utils.password_analyzer import analyze_password
from backend.utils.dataset_generator import generate_dataset

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Hashing"])

# ---------------------------------------------------------------------------
# Security tier helper
# ---------------------------------------------------------------------------

def _security_tier(algorithm: str) -> str:
    return "weak" if algorithm in WEAK_ALGORITHMS else "strong"


def _weak_warning(algorithm: str) -> Optional[str]:
    warnings = {
        "plaintext"    : "⚠️  CRITICAL: Password stored as plaintext. Never use in production.",
        "md5"          : "⚠️  INSECURE: MD5 is cryptographically broken. Avoid for passwords.",
        "sha1"         : "⚠️  INSECURE: SHA-1 is deprecated. Practical collision attacks exist.",
        "sha256"       : "⚠️  WEAK: Unsalted SHA-256 is fast — vulnerable to rainbow tables & GPU brute-force.",
    }
    return warnings.get(algorithm)


# ---------------------------------------------------------------------------
# GET /algorithms
# ---------------------------------------------------------------------------

@router.get(
    "/algorithms",
    summary="List supported hashing algorithms",
    description="Returns all supported algorithms categorized by security tier.",
)
def list_algorithms():
    """
    Returns all supported hashing algorithms with their security classification.
    """
    return {
        "weak_algorithms"  : WEAK_ALGORITHMS,
        "strong_algorithms": STRONG_ALGORITHMS,
        "all_algorithms"   : ALL_ALGORITHMS,
        "total"            : len(ALL_ALGORITHMS),
        "recommended"      : ["argon2id", "bcrypt"],
    }


# ---------------------------------------------------------------------------
# POST /hash
# ---------------------------------------------------------------------------

@router.post(
    "/hash",
    response_model=HashResponse,
    summary="Hash a password",
    description="Hash a plaintext password using the specified algorithm. Returns the hash, salt, timing, and a security assessment.",
)
def hash_password(request: HashRequest):
    """
    Hash a password and return full metadata.

    - **password**: Plaintext password to hash
    - **algorithm**: One of: plaintext, md5, sha1, sha256, salted_sha256, bcrypt, argon2id
    - **pepper**: Optional server-side secret (leave blank to use .env PEPPER)
    """
    # Resolve pepper: use request pepper or fall back to env variable
    effective_pepper = request.pepper or os.getenv("PEPPER")

    try:
        hasher = get_hasher(request.algorithm)
        result = hasher.hash_password(request.password, pepper=effective_pepper)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Hashing error [{request.algorithm}]: {e}")
        raise HTTPException(status_code=500, detail=f"Hashing failed: {str(e)}")

    return HashResponse(
        algorithm       = result.algorithm,
        hash_value      = result.hash_value,
        salt            = result.salt,
        hash_version    = result.hash_version,
        time_to_hash_ms = round(result.time_to_hash_ms, 4),
        security_tier   = _security_tier(request.algorithm),
        warning         = _weak_warning(request.algorithm),
    )


# ---------------------------------------------------------------------------
# POST /verify
# ---------------------------------------------------------------------------

@router.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Verify a password",
    description="Verify a plaintext password against a stored hash using the specified algorithm.",
)
def verify_password(request: VerifyRequest):
    """
    Verify a password against its stored hash.

    - **password**: Plaintext password to check
    - **stored_hash**: The hash from the database
    - **algorithm**: Algorithm used when the hash was created
    - **salt**: Salt used during hashing (required for salted_sha256)
    - **pepper**: Optional server-side secret
    """
    effective_pepper = request.pepper or os.getenv("PEPPER")

    try:
        hasher = get_hasher(request.algorithm)
        is_valid = hasher.verify_password(
            password    = request.password,
            stored_hash = request.stored_hash,
            salt        = request.salt,
            pepper      = effective_pepper,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Verification error [{request.algorithm}]: {e}")
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

    return VerifyResponse(
        is_valid  = is_valid,
        algorithm = request.algorithm,
        message   = "✅ Password is correct." if is_valid else "❌ Password does not match.",
    )


# ---------------------------------------------------------------------------
# POST /generate-dataset
# ---------------------------------------------------------------------------

@router.post(
    "/generate-dataset",
    summary="Generate hashed password dataset",
    description=(
        "Generate a dataset of hashed passwords for security analysis. "
        "Hashes up to 1000 passwords × 7 algorithms = 7000 records. "
        "Supports rockyou.txt if placed at datasets/rockyou.txt."
    ),
)
def generate_dataset_endpoint(
    request: DatasetRequest,
    db: Session = Depends(get_db),
):
    """
    Generate the full test dataset.

    This may take several minutes due to bcrypt and Argon2id being intentionally slow.

    - **sample_size**: Number of passwords to hash (default 1000, max 5000)
    - **algorithms**: Subset of algorithms to use (default: all 7)
    - **clear_existing**: Delete previous dataset records before generation
    - **pepper**: Optional server-side pepper
    """
    effective_pepper = request.pepper or os.getenv("PEPPER")

    try:
        result = generate_dataset(
            db             = db,
            sample_size    = request.sample_size,
            pepper         = effective_pepper,
            algorithms     = request.algorithms,
            clear_existing = request.clear_existing,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Dataset generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Dataset generation failed: {str(e)}")

    return result


# ---------------------------------------------------------------------------
# POST /analyze
# ---------------------------------------------------------------------------

@router.post(
    "/analyze",
    response_model=PasswordAnalysisResponse,
    summary="Analyze password strength",
    description="Analyze a password's strength without hashing it. Returns entropy, score, and category.",
)
def analyze_password_endpoint(payload: dict):
    """
    Analyze the strength of a password.

    Request body: `{"password": "your_password_here"}`

    Returns strength score (0-100), entropy estimate, and category
    (trivial / common / moderate / strong).
    """
    password = payload.get("password", "")
    if not password:
        raise HTTPException(status_code=400, detail="'password' field is required.")

    analysis = analyze_password(password)

    return PasswordAnalysisResponse(
        password          = password,
        length            = analysis.length,
        has_uppercase     = analysis.has_uppercase,
        has_lowercase     = analysis.has_lowercase,
        has_digits        = analysis.has_digits,
        has_symbols       = analysis.has_symbols,
        entropy_bits      = analysis.entropy_bits,
        strength_score    = analysis.strength_score,
        strength_category = analysis.strength_category,
    )


# ---------------------------------------------------------------------------
# POST /hash-all
# ---------------------------------------------------------------------------

@router.post(
    "/hash-all",
    summary="Hash a password with all 7 algorithms",
    description="Hash the same password using all supported algorithms simultaneously for comparison.",
)
def hash_all_algorithms(payload: dict):
    """
    Hash a single password with every supported algorithm.

    Request body: `{"password": "your_password", "pepper": "optional"}`

    Useful for demonstrating the timing difference between weak and strong algorithms.
    """
    password = payload.get("password", "")
    if not password:
        raise HTTPException(status_code=400, detail="'password' field is required.")

    pepper = payload.get("pepper") or os.getenv("PEPPER")
    results = {}

    for algo_name in ALL_ALGORITHMS:
        try:
            hasher = get_hasher(algo_name)
            result = hasher.hash_password(password, pepper=pepper)
            results[algo_name] = {
                "hash_value"     : result.hash_value,
                "salt"           : result.salt,
                "hash_version"   : result.hash_version,
                "time_to_hash_ms": round(result.time_to_hash_ms, 4),
                "security_tier"  : _security_tier(algo_name),
                "warning"        : _weak_warning(algo_name),
            }
        except Exception as e:
            results[algo_name] = {"error": str(e)}

    return {
        "password"       : password,
        "algorithm_count": len(ALL_ALGORITHMS),
        "results"        : results,
    }
