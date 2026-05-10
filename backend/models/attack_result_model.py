"""
Enhanced AttackResult model - CipherGuard Phase 3

Replaces the minimal Phase 1 schema with a full record capturing
every metric produced by the attack simulation engine.
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.sql import func
from backend.database import Base


class AttackResult(Base):
    """
    Stores one complete attack run result.

    Each row = one attack type against one algorithm on a set of targets.
    Multiple runs of the same attack accumulate as separate rows,
    enabling trend analysis over time.
    """
    __tablename__ = "attack_results"

    id = Column(Integer, primary_key=True, index=True)

    # Attack metadata
    attack_type       = Column(String,  nullable=False, index=True)  # dictionary/brute_force/rainbow/hybrid
    algorithm         = Column(String,  nullable=False, index=True)  # md5/bcrypt/etc.
    run_label         = Column(String,  nullable=True)               # optional human label

    # Target metrics
    target_count      = Column(Integer, nullable=False)   # hashes attacked
    cracked_count     = Column(Integer, nullable=False)   # hashes cracked
    success_rate      = Column(Float,   nullable=False)   # 0.0 – 100.0 percent

    # Performance metrics
    total_time_sec    = Column(Float,   nullable=True)    # wall-clock seconds
    total_attempts    = Column(Integer, nullable=True)    # total hash comparisons
    attempts_per_sec  = Column(Float,   nullable=True)    # throughput

    # Per-crack timing
    avg_crack_time_ms = Column(Float,   nullable=True)
    max_crack_time_ms = Column(Float,   nullable=True)

    # Extra context
    wordlist_size     = Column(Integer, nullable=True)
    stopped_early     = Column(Boolean, nullable=True, default=False)
    notes             = Column(Text,    nullable=True)

    # Security score (computed post-run)
    security_score    = Column(Float,   nullable=True)   # 0–100 (higher = more secure)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
