import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cipherguard.db")
    SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")

settings = Settings()
