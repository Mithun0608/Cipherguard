from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from backend.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=True)
    algorithm = Column(String, nullable=False)
    hash_version = Column(String, nullable=True)
    time_to_hash = Column(Float, nullable=True) # duration in milliseconds
    created_at = Column(DateTime(timezone=True), server_default=func.now())
