import sys
import logging
logging.basicConfig(level=logging.DEBUG)
import os
import sys
# Add project root to sys.path so imports work
sys.path.insert(0, os.path.abspath('.'))

from backend.database import SessionLocal
from backend.models.password_hash_model import PasswordHash
from backend.hashers.hasher_registry import get_hasher
from backend.attacks.dictionary_attack import DictionaryAttack

db = SessionLocal()

targets = db.query(PasswordHash).filter(PasswordHash.algorithm == "plaintext").all()
print(f"Found {len(targets)} plaintext targets")

if not targets:
    print("No plaintext targets found.")
    sys.exit(0)

print(f"Sample target 0: id={targets[0].id}, plain_password={targets[0].plain_password}, hash_value={targets[0].hash_value}, salt={targets[0].salt}")

attack = DictionaryAttack(max_wordlist_size=1000)
report = attack.run(targets, "plaintext", timeout_sec=10)
print(f"Dictionary attack on plaintext: cracked {report.cracked_count}/{report.target_count} ({report.success_rate_pct}%)")

hasher = get_hasher("plaintext")
try:
    print(f"Manual verify: {hasher.verify_password(targets[0].plain_password, targets[0].hash_value)}")
except Exception as e:
    print(f"Manual verify failed with exception: {repr(e)}")
