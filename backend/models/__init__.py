"""
CipherGuard — Models Package

Exports all SQLAlchemy models so they are registered with
Base.metadata before create_all() is called in app.py.
"""

from backend.database import Base
from backend.models.user_model import User
from backend.models.attack_result_model import AttackResult
from backend.models.password_hash_model import PasswordHash

__all__ = ["Base", "User", "AttackResult", "PasswordHash"]
