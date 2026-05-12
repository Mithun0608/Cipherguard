"""
CipherGuard FastAPI Application - Phase 3

Registers all routes: hashing engine (Phase 2) + attack simulation (Phase 3).
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import engine, Base
from backend.models import User, AttackResult, PasswordHash
from backend.routes.hash_routes    import router as hash_router
from backend.routes.attack_routes  import router as attack_router
from backend.routes.stream_routes  import router as stream_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cipherguard")

# ---------------------------------------------------------------------------
# Create all database tables
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title       = "CipherGuard API",
    description = (
        "Cybersecurity research platform for password security analysis.\n\n"
        "**Phase 2**: Password hashing engine, dataset generation, strength analysis.\n\n"
        "**Phase 3**: Attack simulation engine, security scoring, breach analysis.\n\n"
        "Algorithms: plaintext, MD5, SHA-1, SHA-256, Salted-SHA-256, bcrypt, Argon2id\n\n"
        "Attacks: Dictionary, Brute Force, Rainbow Table, Hybrid"
    ),
    version     = "3.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ---------------------------------------------------------------------------
# Register routers
# ---------------------------------------------------------------------------
app.include_router(hash_router)
app.include_router(attack_router)
app.include_router(stream_router)

# ---------------------------------------------------------------------------
# Root / health
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
def read_root():
    return {
        "service"  : "CipherGuard API",
        "version"  : "3.0.0",
        "phases"   : ["Phase 2 - Hashing Engine", "Phase 3 - Attack Simulation"],
        "docs"     : "/docs",
        "health"   : "/health",
        "endpoints": {
            "hashing"  : ["/api/v1/hash", "/api/v1/verify", "/api/v1/analyze",
                          "/api/v1/algorithms", "/api/v1/hash-all", "/api/v1/generate-dataset"],
            "attacks"  : ["/api/v1/run-attack", "/api/v1/attack-results",
                          "/api/v1/security-score", "/api/v1/benchmark", "/api/v1/attack-logs"],
            "streaming": ["/api/v1/stream-attack (SSE)"],
        },
    }


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "running", "version": "3.0.0", "database": "connected"}


# ---------------------------------------------------------------------------
# Startup event
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("CipherGuard Backend - Phase 3 Starting Up")
    logger.info("Hashing: plaintext, MD5, SHA1, SHA256, Salted-SHA256, bcrypt, Argon2id")
    logger.info("Attacks: Dictionary, Brute Force, Rainbow Table, Hybrid")
    logger.info("Score Engine: 0-100 security scoring + breach analysis")
    logger.info("Logging: JSON structured logs in backend/logs/attack_runs/")
    logger.info("API docs: http://localhost:8000/docs")
    logger.info("=" * 60)
