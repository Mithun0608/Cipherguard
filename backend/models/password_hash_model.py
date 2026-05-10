"""
PasswordHash model — stores one hash record per password per algorithm.

For 1000 generated passwords × 7 algorithms = 7000 records.
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.sql import func
from backend.database import Base


class PasswordHash(Base):
    """
    Stores a hashed password entry with full metadata.

    Each row represents one password hashed by one algorithm, enabling
    side-by-side comparison of weak vs. strong hashing strategies.
    """
    __tablename__ = "password_hashes"

    id            = Column(Integer, primary_key=True, index=True)

    # Original password (stored for research/demo purposes only)
    plain_password = Column(String, nullable=False, index=True)

    # Password strength classification
    strength_category = Column(String, nullable=False, index=True)  # trivial/common/moderate/strong

    # Strength analyzer scores
    length           = Column(Integer,  nullable=True)
    has_uppercase    = Column(Integer,  nullable=True)  # 0 or 1
    has_lowercase    = Column(Integer,  nullable=True)
    has_digits       = Column(Integer,  nullable=True)
    has_symbols      = Column(Integer,  nullable=True)
    entropy_bits     = Column(Float,    nullable=True)
    strength_score   = Column(Integer,  nullable=True)   # 0-100

    # Hashing details
    algorithm        = Column(String,   nullable=False, index=True)
    hash_value       = Column(Text,     nullable=False)
    salt             = Column(String,   nullable=True)
    hash_version     = Column(String,   nullable=True, default="1.0")
    time_to_hash_ms  = Column(Float,    nullable=True)  # milliseconds

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
