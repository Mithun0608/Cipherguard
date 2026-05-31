import sys
import logging
logging.basicConfig(level=logging.DEBUG)
import os
import sys
sys.path.insert(0, os.path.abspath('.'))

from backend.database import SessionLocal
from backend.utils.dataset_generator import generate_dataset

db = SessionLocal()

print("Generating dataset...")
res = generate_dataset(db, sample_size=10, clear_existing=True)
print(res)

from backend.models.password_hash_model import PasswordHash
print([(a, db.query(PasswordHash).filter(PasswordHash.algorithm == a).count()) for a in ['plaintext', 'md5', 'sha1', 'sha256', 'salted_sha256', 'bcrypt', 'argon2id']])
